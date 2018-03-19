
#include <srlb/srlb-sa.h>
#include <fcntl.h>

typedef struct srlb_sa_cpuacct_policy {
  u32 opaque;
  int accept_threshold;
  int fd;
  u64 prev_cpuacct;
  u64 curr_cpuacct;
  f64 curr_cpu_usage_pcent;
} srlb_sa_cpuacct_policy_t;

typedef struct srlb_sa_cpuacct_policy_main {
  srlb_sa_cpuacct_policy_t * policies;
} srlb_sa_cpuacct_policy_main_t;

srlb_sa_cpuacct_policy_main_t sa_cpuacct_main = {};

typedef struct srlb_sa_cpuacct_policy_conf_args {
  u32 opaque;
  u32 is_del;
  u8 * filename;
  int threshold;
} srlb_sa_cpuacct_policy_conf_args_t;






static inline int
srlb_sa_cpuacct_policy_server_is_available(srlb_sa_cpuacct_policy_t * p)
{
  ASSERT(p);
  return (p->curr_cpu_usage_pcent) < p->accept_threshold;
}

static srlb_sa_cpuacct_policy_t *
srlb_sa_cpuacct_policy_get_by_opaque (u32 opaque)
{
  srlb_sa_cpuacct_policy_main_t * saam = &sa_cpuacct_main;
  srlb_sa_cpuacct_policy_t * p;
  pool_foreach(p, saam->policies, {
      if (p->opaque == opaque) {
	  return p;
      }
  });

  return 0;
}

static void
srlb_sa_cpuacct_policy_delete (srlb_sa_cpuacct_policy_t * p)
{
  srlb_sa_cpuacct_policy_main_t * saam = &sa_cpuacct_main;
  pool_put(saam->policies, p);
}

static int
srlb_sa_cpuacct_policy_accept_fn(u32 ai_index, u32 remaining_choices,
                               u64 vip_low)
{
  u32 opaque = srlb_sa_main.ais[ai_index].policy_opaque;
  srlb_sa_cpuacct_policy_t * p = srlb_sa_cpuacct_policy_get_by_opaque(opaque);
  if (!p) {
      return (remaining_choices == 0) ? 0 : -1;
  }
  return srlb_sa_cpuacct_policy_server_is_available (p);
}

static void
srlb_sa_cpuacct_policy_register ()
{
  srlb_sa_accept_policy_t policy;
  policy.name = "cpu-threshold";
  policy.description = "Accept according to CPU load consumed by cgroup";
  policy.conf_ai = NULL;
  policy.accept = srlb_sa_cpuacct_policy_accept_fn;
  srlb_sa_accept_policy_register(&policy, 0);
}

#define NS_IN_SEC ((f64)1e9)
#define CPUACCT_PROBE_INTERVAL ((f64) 0.01)

static void
srlb_sa_cpuacct_set_curr_usage(srlb_sa_cpuacct_policy_t * p)
{
  if (!p) {
      return;
  }
  char buf[1024];
  lseek(p->fd, 0, SEEK_SET);
  read(p->fd, buf, sizeof(buf));
  p->prev_cpuacct = p->curr_cpuacct;
  p->curr_cpuacct = strtoull(buf, 0, 10);
  p->curr_cpu_usage_pcent = 100 * (p->curr_cpuacct - p->prev_cpuacct) / (NS_IN_SEC * CPUACCT_PROBE_INTERVAL);
}

static uword
srlb_sa_cpuacct_process (vlib_main_t * vm,
		     vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword event_type;
  uword *event_data = 0;
  srlb_sa_cpuacct_policy_main_t *saam = &sa_cpuacct_main;
  srlb_sa_cpuacct_policy_t *p;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, CPUACCT_PROBE_INTERVAL);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0: //timeout
	  pool_foreach (p, saam->policies,
          ({
            srlb_sa_cpuacct_set_curr_usage(p);
          }));

	  break;
	}

      vec_reset_length (event_data);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srlb_sa_cpuacct_process_node, static) = {
    .function = srlb_sa_cpuacct_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "srlb-cpuacct-policy-process",
    .process_log2_n_stack_bytes = 16,
};
/* *INDENT-ON* */


static int
srlb_sa_cpuacct_open_file(u8 * filename)
{
  return open((char*)filename, O_RDONLY);
}

static srlb_sa_cpuacct_policy_t *
srlb_sa_cpuacct_policy_create (u32 opaque, int threshold, u8 * filename)
{
  srlb_sa_cpuacct_policy_main_t * saam = &sa_cpuacct_main;
  srlb_sa_cpuacct_policy_t * p;
  int fd;

  if ((fd = srlb_sa_cpuacct_open_file(filename)) < 0) {
      clib_warning("Couldn't open %s: %s", filename, strerror(errno));
      return 0;
  }


  if (saam->policies == 0) {
      srlb_sa_cpuacct_policy_register();
  }
  pool_get(saam->policies, p);

  p->fd = fd;
  p->opaque = opaque;
  p->accept_threshold = threshold;
  p->curr_cpuacct = p->prev_cpuacct = 0;
  p->curr_cpu_usage_pcent = 0.;
  return p;
}

static int
srlb_sa_cpuacct_policy_conf (srlb_sa_cpuacct_policy_conf_args_t * args)
{
  srlb_sa_cpuacct_policy_t * p =
      srlb_sa_cpuacct_policy_get_by_opaque(args->opaque);
  if (args->is_del)
    {
      if (!p) {
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
      }
      srlb_sa_cpuacct_policy_delete (p);
    } else {
 	if (p) {
	    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	}
	p = srlb_sa_cpuacct_policy_create(args->opaque, args->threshold, args->filename);
	if (!p) {
	    return -errno;
	}
    }
  return 0;
}

static clib_error_t *
srlb_sa_cpuacct_policy_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  srlb_sa_cpuacct_policy_conf_args_t args = {};
  u32 has_threshold = 0, has_filename = 0;
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
      if (unformat (line_input, "threshold %d", &args.threshold))
	has_threshold = 1;
      else if (unformat (line_input, "filename %s", &args.filename))
	has_filename = 1;
      else if (unformat (line_input, "del"))
	args.is_del = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }


  if (!has_filename && !args.is_del)
    {
      error = clib_error_return (0, "Filename for cgroup cpuacct not specified");
      goto done;
    }

  if (!has_threshold && !args.is_del)
    {
      error = clib_error_return (0, "CPU acceptance threshold not specified");
      goto done;
    }

  if ((rv = srlb_sa_cpuacct_policy_conf(&args)))
    error = clib_error_return (0, "srlb_sa_cpuacct_policy_conf returned %d", rv);

  done:
  unformat_free (line_input);
  vec_free (args.filename);
  return error;
}

VLIB_CLI_COMMAND (srlb_sa_cpuacct_policy_command, static) =
    {
	.path = "srlb sa cpuacct-policy ",
	.short_help = "srlb sa cpuacct-policy "
	    "opaque <opaque> "
	    "filename <cpuacct-file> "
	    "threshold <threshold-in-percent> "
	    "[del]",
	    .function = srlb_sa_cpuacct_policy_command_fn,
    };
