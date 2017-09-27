
#define _GNU_SOURCE //for setns(2)
#include <srlb/srlb-sa-apache.h>
#include <fcntl.h>

typedef struct srlb_sa_apache_policy {
  u32 opaque;
  u8 * scoreboard_shm;
  int accept_threshold;
  size_t sizeof_process_score;
  size_t sizeof_worker_score;
} srlb_sa_apache_policy_t;

typedef struct srlb_sa_apache_policy_main {
  srlb_sa_apache_policy_t * policies;
} srlb_sa_apache_policy_main_t;

srlb_sa_apache_policy_main_t sa_apache_main = {};

typedef struct srlb_sa_apache_policy_conf_args {
  u32 opaque;
  u32 is_del;
  int threshold;
  int namespace_pid;
  u8 * scoreboard_file;
} srlb_sa_apache_policy_conf_args_t;


/**
 * @param filename_orig: scoreboard filename as specified in Apache's config
 * @param filename:      handle to the scoreboard as visible from VPP
 * 			 eg - <filename_orig> if VPP/Apache share the same FS
 * 			    - /proc/$PID/mnt/<filename_orig> otherwise
 * @param shm_size:	 will be set to the size of the shared memory segment
 */
static inline u8 *
open_apache_shmem (const char * filename_orig, const char * filename,
		   size_t * shm_size)
{
  u8 *apache_shm;
  int shmid;
  struct shmid_ds ds;
  key_t shmkey = our_ftok(filename_orig, filename);

  if ((shmid = shmget(shmkey, 0, SHM_R)) < 0)
    {
      clib_warning("shmget() failed with %s", strerror(errno));
      return NULL;
    }

  if ((apache_shm = shmat(shmid, NULL, SHM_RDONLY)) == (void*)-1)
    {
      clib_warning("shmat() failed with %s", strerror(errno));
      return NULL;
    }


   if (shmctl(shmid, IPC_STAT, &ds) < 0)
     {
       clib_warning("shmctl() failed with %s", strerror(errno));
     }

   *shm_size = ds.shm_segsz;

   return apache_shm;
}

static inline u8 *
open_apache_shmem_with_namespace (const char * filename, int namespace_pid,
				  size_t * shm_size)
{
  u8 *apache_shm = NULL;
  int ns_fd, ns_fd_orig;
  char path[sizeof("/proc/4194304/ns/ipc")+1]; /* max pid is 4194304 */
  char * path_in_ns = 0;


  snprintf(path, sizeof(path), "/proc/self/ns/ipc");
  if ((ns_fd_orig = open(path, O_RDONLY)) < 0)
    {
      clib_warning("open() failed with %s", strerror(errno));
      goto clean1;
    }


  snprintf(path, sizeof(path), "/proc/%d/ns/ipc", namespace_pid);
  if ((ns_fd = open(path, O_RDONLY)) < 0)
    {
      clib_warning("open() failed with %s", strerror(errno));
      goto clean2;
    }

  if (setns(ns_fd, 0) < 0)
    {
      clib_warning("setns() failed with %s", strerror(errno));
      goto clean3;
    }
#define PROC_PID_ROOT_STR "/proc/4194304/root"
  vec_alloc(path_in_ns, strlen(filename) + strlen(PROC_PID_ROOT_STR) + 1);
  snprintf(path_in_ns, strlen(filename) + strlen(PROC_PID_ROOT_STR) + 1,
	   "/proc/%d/root%s", namespace_pid, filename);

  apache_shm = open_apache_shmem (filename, path_in_ns, shm_size);

  if (setns(ns_fd_orig, 0) < 0)
    {
      clib_warning("setns() failed with %s", strerror(errno));
    }

  clean3:
  close (ns_fd);
  clean2:
  close (ns_fd_orig);
  clean1:
  vec_free (path_in_ns);
  return apache_shm;
}

static inline void
close_apache_shmem(u8 *apache_shm)
{
  if (apache_shm) {
      shmdt(apache_shm);
  }
}


static inline void
apache_shmem_detect_struct_layout(const u8 * apache_shm, size_t shm_size,
				  size_t * sizeof_process_score,
				  size_t * sizeof_worker_score)
{
  int num_servers = ((global_score *) apache_shm)->server_limit;
  int num_threads = ((global_score *) apache_shm)->thread_limit;
  static const size_t possible_sizeof_worker_scores[] = {248, 256, 264, 272};
  static const size_t possible_sizeof_process_scores[] = {32, 40};
  int worker_scores = num_servers * num_threads;
  int i, j;

  for (i = 0; i < ARRAY_LEN(possible_sizeof_worker_scores); i++)
    {
      for (j = 0; j < ARRAY_LEN(possible_sizeof_process_scores); j++)
	{
	  if (shm_size ==
	      sizeof(global_score)
	      + num_servers * possible_sizeof_process_scores[j]
	      + worker_scores * possible_sizeof_worker_scores[i])
	    {
	      *sizeof_worker_score = possible_sizeof_worker_scores[i];
	      *sizeof_process_score = possible_sizeof_process_scores[j];
	      return;
	    }
	}
    }

  clib_warning("Unable to detect Apache's shm struct layout");
  *sizeof_worker_score = sizeof(worker_score);
  *sizeof_process_score = sizeof(process_score);
}

static inline int
apache_busy_servers_count(srlb_sa_apache_policy_t * p)
{
  int i;
  u8 * apache_shm = p->scoreboard_shm;
  int num_busy_threads = 0;

  int num_servers = ((global_score *) apache_shm)->server_limit;
  int num_threads = ((global_score *) apache_shm)->thread_limit;
  worker_score *ws = (worker_score *) (apache_shm + sizeof(global_score)
      + p->sizeof_process_score * num_servers);

  for (i = 0; i < num_servers*num_threads; i++) {
      if (ws->start_time == 0) {
	  /* ignore non-running threads */
	  break;
      }
      if (ws->status == SERVER_BUSY_WRITE) {
	  num_busy_threads++;
      }
      ws = (worker_score *)((char *)ws + p->sizeof_worker_score);
  }
  return num_busy_threads;
}

static inline int
srlb_sa_apache_policy_server_is_available(srlb_sa_apache_policy_t * p)
{
  ASSERT(p && p->scoreboard_shm);
  return (apache_busy_servers_count(p) < p->accept_threshold);
}

static srlb_sa_apache_policy_t *
srlb_sa_apache_policy_get_by_opaque (u32 opaque)
{
  srlb_sa_apache_policy_main_t * saam = &sa_apache_main;
  srlb_sa_apache_policy_t * p;
  pool_foreach(p, saam->policies, {
      if (p->opaque == opaque) {
	  return p;
      }
  });

  return 0;
}

static void
srlb_sa_apache_policy_delete (srlb_sa_apache_policy_t * p)
{
  srlb_sa_apache_policy_main_t * saam = &sa_apache_main;
  close_apache_shmem(p->scoreboard_shm);
  pool_put(saam->policies, p);
}

static int
srlb_sa_apache_policy_accept_fn(u32 ai_index, u32 remaining_choices)
{
  u32 opaque = srlb_sa_main.ais[ai_index].policy_opaque;
  srlb_sa_apache_policy_t * p = srlb_sa_apache_policy_get_by_opaque(opaque);
  if (!p || !p->scoreboard_shm) {
      return (remaining_choices == 0) ? 0 : -1;
  }
  return srlb_sa_apache_policy_server_is_available (p);
}

static void
srlb_sa_apache_policy_register ()
{
  srlb_sa_accept_policy_t policy;
  policy.name = "apache-threshold";
  policy.description = "Accept according to Apache's busy thread count";
  policy.conf_ai = NULL;
  policy.accept = srlb_sa_apache_policy_accept_fn;
  srlb_sa_accept_policy_register(&policy, 0);
}



static srlb_sa_apache_policy_t *
srlb_sa_apache_policy_create (u32 opaque, int threshold,
			      const char * scoreboard_file,
			      int ns_pid)
{
  srlb_sa_apache_policy_main_t * saam = &sa_apache_main;
  srlb_sa_apache_policy_t * p;
  size_t shm_size = 0;

  u8 * shm = (ns_pid > 0) ?
      open_apache_shmem_with_namespace(scoreboard_file, ns_pid, &shm_size) :
      open_apache_shmem(scoreboard_file, scoreboard_file, &shm_size);
  if (shm == NULL)
    {
      return 0;
    }

  if (saam->policies == 0) {
      srlb_sa_apache_policy_register();
  }
  pool_get(saam->policies, p);
  p->opaque = opaque;
  p->accept_threshold = threshold;
  p->scoreboard_shm = shm;

  apache_shmem_detect_struct_layout(shm, shm_size, &p->sizeof_process_score,
				    &p->sizeof_worker_score);

  return p;
}

static int
srlb_sa_apache_policy_conf (srlb_sa_apache_policy_conf_args_t * args)
{
  if (args->is_del)
    {
      srlb_sa_apache_policy_t * p =
	  srlb_sa_apache_policy_get_by_opaque(args->opaque);
      if (!p) {
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
      }
      srlb_sa_apache_policy_delete (p);
    } else {
	srlb_sa_apache_policy_t * p =
	    srlb_sa_apache_policy_get_by_opaque(args->opaque);
	if (p) {
	    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	}
	p = srlb_sa_apache_policy_create(args->opaque,
					 args->threshold,
					 (char*)args->scoreboard_file,
					 args->namespace_pid);
	if (!p) {
	    return -errno;
	}
    }
  return 0;
}

static clib_error_t *
srlb_sa_apache_policy_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  srlb_sa_apache_policy_conf_args_t args = {};
  u32 has_scoreboard = 0, has_threshold = 0;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  if (!unformat (line_input, "opaque %u", &args.opaque))
    {
      error = clib_error_return (0, "Opaque index not specified");
      goto done;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "namespace_pid %d", &args.namespace_pid))
	;
      else if (unformat (line_input, "scoreboard %s", &args.scoreboard_file))
	has_scoreboard = 1;
      else if (unformat (line_input, "threshold %d", &args.threshold))
	has_threshold = 1;
      else if (unformat (line_input, "del"))
	args.is_del = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!has_scoreboard && !args.is_del)
    {
      error = clib_error_return (0, "Apache scoreboard file not specified");
      goto done;
    }

  if (!has_threshold && !args.is_del)
    {
      error = clib_error_return (0, "Apache acceptance threshold not specified");
      goto done;
    }

  if ((rv = srlb_sa_apache_policy_conf(&args)))
    error = clib_error_return (0, "srlb_sa_apache_policy_conf returned %d", rv);

  done:
  vec_free (args.scoreboard_file);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (srlb_sa_apache_policy_command, static) =
    {
	.path = "srlb sa apache-policy ",
	.short_help = "srlb sa apache-policy "
	    "opaque <opaque> "
	    "[scoreboard <scoreboard_file>] "
	    "[threshold <threshold>] "
	    "[namespace_pid <pid>] "
	    "[del]",
	    .function = srlb_sa_apache_policy_command_fn,
    };
