
#include <srlb/srlb-sa.h>
       #include <sys/stat.h>
#include <fcntl.h>


typedef struct srlb_sa_nginx_policy {
  u32 opaque;
  u8 * shm;
  size_t shm_size;
  int accept_threshold;
} srlb_sa_nginx_policy_t;

typedef struct srlb_sa_nginx_policy_main {
  srlb_sa_nginx_policy_t * policies;
} srlb_sa_nginx_policy_main_t;

srlb_sa_nginx_policy_main_t sa_nginx_main = {};

typedef struct srlb_sa_nginx_policy_conf_args {
  u32 opaque;
  u32 is_del;
  int threshold;
  int pid;
} srlb_sa_nginx_policy_conf_args_t;



static inline u8 *
open_nginx_shmem (int pid, size_t * shm_size)
{
  FILE * map_files_fp;
  char line[1024];
  char path[256];
  int fd;
  struct stat st;
  u8 * shm = 0;

  /* Find first line in /proc/$PID/maps that contains "/dev/zero (deleted)"
   * and extract first field of this line
   */
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  if ((map_files_fp = fopen(path, "r")) == 0)
    {
      clib_warning("fopen() failed with %s", strerror(errno));
      return 0;
    }

  while (fgets(line, sizeof(line), map_files_fp) != 0)
    {
      if (strstr(line, "/dev/zero (deleted)") != 0)
	{
	  char * sp;
	  if ((sp = strchr(line, ' ')) == 0)
	    {
	      goto clean1;
	    }
	  *sp = 0;
	  break;
	}
    }

  /* Map the shared memory pointed to by the just found anonymous backend */
  snprintf(path, sizeof(path), "/proc/%d/map_files/%s", pid, line);

  if ((fd = open(path, O_RDONLY)) < 0)
    {
      clib_warning("open() failed with %s", strerror(errno));
      goto clean1;
    }

  if (fstat(fd, &st) < 0)
    {
      clib_warning("stat() failed with %s", strerror(errno));
      goto clean2;
    }

  *shm_size = st.st_size;

  if ((shm = mmap(0, *shm_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
    {
      goto clean2;
    }

clean2:
  close (fd);
clean1:
  fclose(map_files_fp);
  return shm;
}


static inline void
close_nginx_shmem(u8 * nginx_shm, size_t shm_size)
{
  if (nginx_shm) {
      munmap(nginx_shm, shm_size);
  }
}


static inline int
nginx_busy_servers_count(srlb_sa_nginx_policy_t * p)
{
  /* From src/event/ngx_event.c:543, number of writing threads is right there! */
  return *(uword *)(p->shm + 128 * 8);
}

static inline int
srlb_sa_nginx_policy_server_is_available(srlb_sa_nginx_policy_t * p)
{
  ASSERT(p && p->shm);
  return (nginx_busy_servers_count(p) < p->accept_threshold);
}

static srlb_sa_nginx_policy_t *
srlb_sa_nginx_policy_get_by_opaque (u32 opaque)
{
  srlb_sa_nginx_policy_main_t * sanm = &sa_nginx_main;
  srlb_sa_nginx_policy_t * p;
  pool_foreach(p, sanm->policies, {
      if (p->opaque == opaque) {
	  return p;
      }
  });

  return 0;
}

static void
srlb_sa_nginx_policy_delete (srlb_sa_nginx_policy_t * p)
{
  srlb_sa_nginx_policy_main_t * sanm = &sa_nginx_main;
  close_nginx_shmem(p->shm, p->shm_size);
  pool_put(sanm->policies, p);
}

static int
srlb_sa_nginx_policy_accept_fn(u32 ai_index, u32 remaining_choices,
                               u64 vip_low)
{
  u32 opaque = srlb_sa_main.ais[ai_index].policy_opaque;
  srlb_sa_nginx_policy_t * p = srlb_sa_nginx_policy_get_by_opaque(opaque);
  if (!p || !p->shm) {
      return (remaining_choices == 0) ? 0 : -1;
  }
  return srlb_sa_nginx_policy_server_is_available (p);
}

static void
srlb_sa_nginx_policy_register ()
{
  srlb_sa_accept_policy_t policy;
  policy.name = "nginx-threshold";
  policy.description = "Accept according to Nginx's busy thread count";
  policy.conf_ai = NULL;
  policy.accept = srlb_sa_nginx_policy_accept_fn;
  srlb_sa_accept_policy_register(&policy, 0);
}



static srlb_sa_nginx_policy_t *
srlb_sa_nginx_policy_create (u32 opaque, int threshold, int pid)
{
  srlb_sa_nginx_policy_main_t * sanm = &sa_nginx_main;
  srlb_sa_nginx_policy_t * p;
  size_t shm_size;

  u8 * shm = open_nginx_shmem(pid, &shm_size);
  if (shm == NULL)
    {
      return 0;
    }

  if (sanm->policies == 0) {
      srlb_sa_nginx_policy_register();
  }
  pool_get(sanm->policies, p);
  p->opaque = opaque;
  p->accept_threshold = threshold;
  p->shm = shm;
  p->shm_size = shm_size;

  return p;
}

static int
srlb_sa_nginx_policy_conf (srlb_sa_nginx_policy_conf_args_t * args)
{
  if (args->is_del)
    {
      srlb_sa_nginx_policy_t * p =
	  srlb_sa_nginx_policy_get_by_opaque(args->opaque);
      if (!p) {
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
      }
      clib_warning("%d busy threads", nginx_busy_servers_count(p));
      srlb_sa_nginx_policy_delete (p);
    } else {
	srlb_sa_nginx_policy_t * p =
	    srlb_sa_nginx_policy_get_by_opaque(args->opaque);
	if (p) {
	    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	}
	p = srlb_sa_nginx_policy_create(args->opaque, args->threshold,
					args->pid);
	if (!p) {
	    return -errno;
	}
    }
  return 0;
}

static clib_error_t *
srlb_sa_nginx_policy_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  srlb_sa_nginx_policy_conf_args_t args = {};
  u32 has_threshold = 0, has_pid = 0;
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
      if (unformat (line_input, "pid %d", &args.pid))
	has_pid = 1;
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


  if (!has_pid && !args.is_del)
    {
      error = clib_error_return (0, "Nginx PID not specified");
      goto done;
    }

  if (!has_threshold && !args.is_del)
    {
      error = clib_error_return (0, "Nginx acceptance threshold not specified");
      goto done;
    }

  if ((rv = srlb_sa_nginx_policy_conf(&args)))
    error = clib_error_return (0, "srlb_sa_nginx_policy_conf returned %d", rv);

  done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (srlb_sa_nginx_policy_command, static) =
    {
	.path = "srlb sa nginx-policy ",
	.short_help = "srlb sa nginx-policy "
	    "opaque <opaque> "
	    "[pid <pid>] "
	    "[threshold <threshold>] "
	    "[del]",
	    .function = srlb_sa_nginx_policy_command_fn,
    };
