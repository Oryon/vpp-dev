
#include <srlb/srlb-sa.h>


clib_error_t *
srlb_sa_app_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  srlb_sa_ai_conf_args_t args = {};
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  if (!unformat (line_input, "%U", unformat_ip6_address, &args.sr_prefix))
    {
      error = clib_error_return (0, "Invalid SR prefix");
      goto done;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "policy %U %u",
		    unformat_srlb_sa_accept_policy_index, &args.policy_index,
		    &args.policy_opaque))
	args.flags |= SRLB_SA_API_FLAGS_POLICY_SET;
      else if (unformat (line_input, "del"))
	args.flags |= SRLB_SA_API_FLAGS_IS_DEL;
      else if (unformat (line_input, "via %U", unformat_ip6_address,
                         &args.routing_address))
      	args.flags |= SRLB_SA_API_FLAGS_TO_ADDRESS_SET;
      else if (unformat (line_input, "thread %u", &args.handoff_thread))
        args.flags |= SRLB_SA_API_FLAGS_THREAD_SET;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if ((rv = srlb_sa_ai_conf(&args)))
    error = clib_error_return (0, "srlb_sa_ai_conf returned %d", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (srlb_sa_app_command, static) =
    {
	.path = "srlb sa application ",
	.short_help = "srlb sa application <sr-prefix> "
	    "[via <dest-address>] "
	    "[policy <policy-name> <opaque>] "
	    "[thread <thread>] "
	    "[del]",
	.function = srlb_sa_app_command_fn,
    };


static clib_error_t *
srlb_sa_conf_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  srlb_sa_conf_args_t args = {
      .flowhash_fixed_entries = sam->flowhash_fixed_entries,
      .flowhash_collision_buckets = sam->flowhash_collision_buckets,
      .flow_active_timeout = sam->flow_active_timeout,
      .flow_teardown_timeout = sam->flow_teardown_timeout,
  };
  clib_error_t *error = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "fixed_entries %u",
                   &args.flowhash_fixed_entries)) {
	  ;
      } else if (unformat(line_input, "collision_buckets %u",
                          &args.flowhash_collision_buckets)) {
	  ;
      } else if (unformat(line_input, "active_timeout %u",
                          &args.flow_active_timeout)) {
      	  ;
      } else if (unformat(line_input, "teardown_timeout %u",
                          &args.flow_teardown_timeout)) {
            	  ;
      } else {
	  error = clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
      }
    }

  unformat_free (line_input);

  if ((rv = srlb_sa_conf(&args)))
    return clib_error_return (0, "srlb_conf returned %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (srlb_sa_conf_command, static) =
    {
	.path = "srlb sa conf",
	.short_help = "srlb sa conf [fixed_buckets <n>] "
	    "[chained_buckets <n>] [active_timeout <s>] [teardown_timeout <s>]",
	.function = srlb_sa_conf_command_fn,
    };

clib_error_t *
srlb_debug_sa_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  srlb_sa_main_t *sam = &srlb_sa_main;
  u8 level = sam->log_level;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "error"))
	  level = 0;
      else if (unformat (line_input, "warning"))
	  level = 1;
      else if (unformat (line_input, "debug"))
      	  level = 2;
      else if (unformat (line_input, "data"))
	{
	  if (!SRLB_SA_LOG_ENABLE_DATA)
	    {
	      error = clib_error_return (0, "data log level is not compiled in this binary");
	      goto done;
	    }
	  else
	    level = 3;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  sam->log_level = level;

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (srlb_debug_sa_command, static) = {
    .path = "debug srlb sa",
    .short_help = "debug srlb sa <error|warning|debug|data>",
    .function = srlb_debug_sa_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
srlb_show_sa_conf_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  u8 *s = 0;
  s = format(s, "per cpu fixed buckets: %d\n", sam->flowhash_fixed_entries);
  s = format(s, "per cpu chained buckets: %d\n", sam->flowhash_collision_buckets);
  s = format(s, "active flows timeout: %d\n", sam->flow_active_timeout);
  s = format(s, "teardown flows timeout: %d\n", sam->flow_teardown_timeout);
  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return 0;
}

VLIB_CLI_COMMAND (srlb_show_sa_conf_command, static) =
    {
	.path = "show srlb sa conf",
	.short_help = "show srlb sa conf",
	.function = srlb_show_sa_conf_command_fn,
    };

static clib_error_t *
srlb_show_sa_flows_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u8 *s = 0;
  int v = 0;
  unformat_input_t _line_input, *line_input = &_line_input;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%U", unformat_verbosity, &v))
	    v = 1;
	  else
	    {
	      clib_error_t *error = clib_error_return (0, "unknown input `%U'",
					format_unformat_error, line_input);
	      unformat_free (line_input);
	      return error;
	    }
	}
      unformat_free (line_input);
    }

  u32 ti;
  for (ti=0; ti < tm->n_vlib_mains; ti++)
    {
      s = format(s, "thread %d:\n", vlib_mains[ti]->thread_index);
      s = format(s, "  %U\n", format_srlb_sa_flows_with_verbosity, ti, v);
    }

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return NULL;
}

VLIB_CLI_COMMAND (srlb_show_sa_flows_command, static) =
    {
	.path = "show srlb sa flows",
	.short_help = "show srlb sa flows [verbose]",
	.function = srlb_show_sa_flows_command_fn,
    };

static clib_error_t *
srlb_show_sa_ai_command_fn (vlib_main_t * vm,
			    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip6_address_t sr_prefix;
  u8 address_set = 0;
  clib_error_t *error;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_parse;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "%U", unformat_ip6_address, &sr_prefix)) {
	  address_set = 1;
      } else {
	  error = clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
      }
    }

  unformat_free (line_input);

no_parse:
  if (address_set)
    {
      srlb_sa_ai_t *ai = srlb_sa_ai_get(&sr_prefix);
      if (ai == NULL)
	return clib_error_return (0, "AI not found");

      vlib_cli_output(vm, "%U", format_srlb_sa_ai, ai);
    }
  else
    {
      srlb_sa_ai_t *ai;
      pool_foreach(ai, sam->ais, {
	  vlib_cli_output(vm, "[%d] %U", ai - sam->ais,
			  format_srlb_sa_ai, ai);
      });
    }

  return 0;
}

VLIB_CLI_COMMAND (srlb_show_sa_ai_command, static) =
    {
	.path = "show srlb sa applications",
	.short_help = "show srlb sa applications [<sr-prefix>]",
	.function = srlb_show_sa_ai_command_fn,
    };

static clib_error_t *
srlb_show_sa_counters_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  u8 *s = 0;

#define _(t,str) s = format(s, str": %lu\n", \
  vlib_get_simple_counter(&sam->counters, SRLB_SA_CTR_##t));
  srlb_sa_foreach_counter
#undef _

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return 0;
}

VLIB_CLI_COMMAND (srlb_show_sa_counters_command, static) =
    {
        .path = "show srlb sa counters",
        .short_help = "show srlb sa counters",
        .function = srlb_show_sa_counters_command_fn,
    };



static clib_error_t *
srlb_show_sa_accept_policies_command_fn (vlib_main_t * vm,
			    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  u32 i;
  pool_foreach_index(i, sam->accept_policies, {
      vlib_cli_output(vm, "[%d] %U", i,
		      format_srlb_sa_accept_policy_index, i);
  });

  return 0;
}

VLIB_CLI_COMMAND (srlb_show_sa_accept_policies_command, static) =
    {
	.path = "show srlb sa accept-policies",
	.short_help = "show srlb sa accept-policies",
	.function = srlb_show_sa_accept_policies_command_fn,
    };


clib_error_t *
test_srlb_sa_accept_callback_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u64 vip = 0;
  ip6_address_t sr_prefix = {};
  u32 choices_left = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  if (!unformat (line_input, "%U", unformat_ip6_address, &sr_prefix))
    {
      error = clib_error_return (0, "Invalid SR prefix");
      goto done;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "vip %U",
                   unformat_half_ip6_address, &vip))
        ;
      else if (unformat (line_input, "choices-left %u", &choices_left))
        ;
      else
        {
          error = clib_error_return (0, "parse error: '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }
  unformat_free (line_input);

  srlb_sa_ai_t *ai = srlb_sa_ai_get(&sr_prefix);
  if (ai == NULL)
    return clib_error_return (0, "Application instance with prefix %U not found",
                                 format_ip6_address, &sr_prefix);

  srlb_sa_main_t *sam = &srlb_sa_main;
  u8 accept = !sam->accept_policies[ai->policy_index].
      accept(ai - sam->ais, choices_left, vip);

  vlib_cli_output(vm, "policy: %U %s", format_srlb_sa_accept_policy_index,
                  ai->policy_index, accept?"accepted":"rejected");

  done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (test_srlb_sa_accept_callback_command, static) =
    {
        .path = "test srlb sa accept-policy callback ",
        .short_help = "test srlb sa accept-policy callback "
            "<sr-prefix> choices-left <n> vip <0123:4567:89ab:cdef>",
        .function = test_srlb_sa_accept_callback_command_fn,
    };
