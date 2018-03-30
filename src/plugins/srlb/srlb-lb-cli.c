/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <plugins/srlb/srlb-lb.h>
#include <vlib/cli.h>

static uword unformat_ip6_prefix (unformat_input_t * input, va_list * args)
{
  ip6_address_t *ip6 = va_arg (*args, ip6_address_t *);
  u8 *len = va_arg (*args, u8 *);
  u32 l;
  return unformat(input, "%U/%u", unformat_ip6_address, ip6, &l) &&
      (*len = l) <= 128;
}

static clib_error_t *
srlb_vip_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  srlb_lb_vip_conf_args_t args = {};
  clib_error_t *error = NULL;
  u32 table_id;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing arguments");

  if (!unformat(line_input, "%U", unformat_ip6_prefix,
                &args.vip_address, &args.vip_prefix_length)) {
      error = clib_error_return (0, "invalid vip prefix: '%U'",
                                 format_unformat_error, line_input);
      goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "consistent-hash-size %d",
                   &args.consistent_hashtable_size)) {
	  args.flags |= SRLB_LB_API_FLAGS_CONSISTENT_HASHTABLE_SIZE_SET;
      } else if (unformat(line_input, "sr %U", unformat_ip6_address,
                          &args.sr_prefix)) {
          args.flags |= SRLB_LB_API_FLAGS_SR_PREFIX_SET;
      } else if (unformat(line_input, "hash %U",
                          unformat_srlb_lb_vip_hash, &args.hash)) {
          args.flags |= SRLB_LB_API_FLAGS_HASH_SET;
      } else if (unformat(line_input, "client-rx-table-id %d", &table_id)) {
          if ((args.client_rx_fib_index = fib_table_find(FIB_PROTOCOL_IP6, table_id)) == ~0)
            {
              error = clib_error_return (0, "ipv6 table %d does not exist", table_id);
              goto done;
            }
          args.flags |= SRLB_LB_API_FLAGS_CLIENT_RX_FIB_SET;
      } else if (unformat(line_input, "client-tx-table-id %d", &table_id)) {
          if ((args.client_tx_fib_index = fib_table_find(FIB_PROTOCOL_IP6, table_id)) == ~0)
            {
              error = clib_error_return (0, "ipv6 table %d does not exist", table_id);
              goto done;
            }
          args.flags |= SRLB_LB_API_FLAGS_CLIENT_TX_FIB_SET;
      } else if (unformat(line_input, "sr-rx-table-id %d", &table_id)) {
          if ((args.sr_rx_fib_index = fib_table_find(FIB_PROTOCOL_IP6, table_id)) == ~0)
            {
              error = clib_error_return (0, "ipv6 table %d does not exist", table_id);
              goto done;
            }
          args.flags |= SRLB_LB_API_FLAGS_SR_RX_FIB_SET;
      } else if (unformat(line_input, "sr-tx-table-id %d", &table_id)) {
          if ((args.sr_tx_fib_index = fib_table_find(FIB_PROTOCOL_IP6, table_id)) == ~0)
            {
              error = clib_error_return (0, "ipv6 table %d does not exist", table_id);
              goto done;
            }
          args.flags |= SRLB_LB_API_FLAGS_SR_TX_FIB_SET;
      } else if (unformat(line_input, "del")) {
          args.flags |= SRLB_LB_API_FLAGS_IS_DEL;
      } else {
	  error = clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	  goto done;
      }
    }

  if ((rv = srlb_lb_vip_conf(&args)))
    error = clib_error_return (0, "srlb_conf returned %d", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (srlb_vip_command, static) =
    {
	.path = "srlb lb vip",
	.short_help = "srlb lb vip <vip-prefix> [sr <sr-prefix>] "
	    "[client-rx-table-id <n>] [client-tx-table-id <n>] "
	    "[sr-rx-table-id <n>] [sr-tx-table-id <n>] "
	    "[consistent-hash-size <n>] [hash <vip|5-tuple>] [del]",
	.function = srlb_vip_command_fn,
	.is_mp_safe = 1,
    };

static clib_error_t *
srlb_server_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  srlb_lb_server_add_del_args_t args = {};
  ip6_address_t server_address;

  int rv;
  clib_error_t *error = 0;
  u32 table_id;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U %U", unformat_ip6_prefix,
                &args.vip_address, &args.vip_prefix_length,
                unformat_u32_bitmask_list, &args.pool_bitmask)) {
      error = clib_error_return (0, "invalid vip prefix or pool bitmask: '%U'",
				 format_unformat_error, line_input);
      goto done;
  }

  if (unformat(line_input, "add"))
    ;
  else if (unformat(line_input, "del"))
    args.flags |= SRLB_LB_API_FLAGS_IS_DEL;
  else
    {
      error = clib_error_return (0, "Expecting 'add' or 'del'");
      goto done;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "%U", unformat_ip6_address, &server_address)) {
	  vec_add1(args.server_addresses, server_address);
      } else if (unformat(line_input, "client-rx-table-id %d", &table_id)) {
          if ((args.client_rx_fib_index = fib_table_find(FIB_PROTOCOL_IP6, table_id)) == ~0)
            {
              error = clib_error_return (0, "ipv6 table %d does not exist", table_id);
              goto done;
            }
        args.flags |= SRLB_LB_API_FLAGS_CLIENT_RX_FIB_SET;
      } else {
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
      }
    }

  if (!(args.server_count = vec_len(args.server_addresses))) {
      error = clib_error_return (0, "No server address provided");
      goto done;
  }

  if ((rv = srlb_lb_server_add_del(&args)))
    error = clib_error_return (0, "srlb_server_add_del returned %d", rv);

  done:
  unformat_free (line_input);
  vec_free(args.server_addresses);
  return error;
}

VLIB_CLI_COMMAND (srlb_server_command, static) =
    {
	.path = "srlb lb server",
	.short_help = "srlb lb server <vip-prefix> <pool-list> (add|del) "
	    "[client-rx-table-id <n>] <s1> [<s2> [<s3> ...]]",
	.function = srlb_server_command_fn,
	.is_mp_safe = 1,
    };


static clib_error_t *
srlb_conf_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  srlb_lb_conf_args_t args = {
      .flowhash_fixed_entries = srlbm->flowhash_fixed_entries,
      .flowhash_collision_buckets = srlbm->flowhash_collision_buckets,
      .flow_active_timeout = srlbm->flow_active_timeout,
      .flow_teardown_timeout = srlbm->flow_teardown_timeout,
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

  if ((rv = srlb_lb_conf(&args)))
    return clib_error_return (0, "srlb_conf returned %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (srlb_conf_command, static) =
    {
	.path = "srlb lb conf",
	.short_help = "srlb lb conf [fixed_entries <n>] "
	    "[collision_buckets <n>] [active_timeout <s>] [teardown_timeout <s>]",
	.function = srlb_conf_command_fn,
	.is_mp_safe = 1,
    };

static clib_error_t *
srlb_show_lb_flows_command_fn (vlib_main_t * vm,
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
      s = format(s, "  %U\n", format_srlb_lb_flows_with_verbosity, ti, v);
    }

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return NULL;
}

VLIB_CLI_COMMAND (srlb_show_lb_flows_command, static) =
    {
	.path = "show srlb lb flows",
	.short_help = "srlb lb flows [verbose]",
	.function = srlb_show_lb_flows_command_fn,
    };

static clib_error_t *
srlb_show_lb_vip_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip6_address_t vip_address;
  u8 plen;
  u8 address_set = 0;
  int verbosity = 0;
  clib_error_t *error;
  u32 client_rx_fib_index = 0;
  u32 table_id;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_parse;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "%U", unformat_ip6_prefix, &vip_address, &plen)) {
	  address_set = 1;
      } else if (unformat(line_input, "%U", unformat_verbosity, &verbosity)) {
	  ;
      } else if (unformat(line_input, "client-rx-table-id %d", &table_id)) {
          if ((client_rx_fib_index = fib_table_find(FIB_PROTOCOL_IP6, table_id)) == ~0)
            {
              error = clib_error_return (0, "ipv6 table %d does not exist", table_id);
              unformat_free (line_input);
              return error;
            }
          ;
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
      srlb_lb_vip_t *vip = srlb_get_vip(&vip_address, plen, client_rx_fib_index);
      if (vip == NULL)
	return clib_error_return (0, "VIP not found");

      vlib_cli_output(vm, "%U", format_srlb_lb_vip_with_verbosity,
                      vip, verbosity);
    }
  else
    {
      srlb_lb_vip_t *vip;
      pool_foreach(vip, srlbm->vips, {
	  vlib_cli_output(vm, "[%d] %U", vip - srlbm->vips,
	                  format_srlb_lb_vip_with_verbosity, vip,
	                  verbosity);
      });
    }

  return 0;
}

VLIB_CLI_COMMAND (srlb_show_lb_vip_command, static) =
    {
	.path = "show srlb lb vip",
	.short_help = "show srlb lb vip [<vip-prefix>] [client-rx-table-id <n>] [verbose|v<n>]",
	.function = srlb_show_lb_vip_command_fn,
    };

clib_error_t *
srlb_debug_lb_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u8 level = srlbm->log_level;

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
	  if (!SRLB_LB_LOG_ENABLE_DATA)
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

  srlbm->log_level = level;

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (srlb_debug_lb_command, static) = {
    .path = "debug srlb lb",
    .short_help = "debug srlb lb <error|warning|debug|data>",
    .function = srlb_debug_lb_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
srlb_show_lb_conf_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  u8 *s = 0;
  s = format(s, "per cpu fixed entries: %d\n",
             srlbm->flowhash_fixed_entries);
  s = format(s, "per cpu collision buckets: %d\n",
             srlbm->flowhash_collision_buckets);
  s = format(s, "active flows timeout: %d\n",
             srlbm->flow_active_timeout);
  s = format(s, "teardown flows timeout: %d\n",
             srlbm->flow_teardown_timeout);
  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return 0;
}

VLIB_CLI_COMMAND (srlb_show_lb_conf_command, static) =
    {
	.path = "show srlb lb conf",
	.short_help = "show srlb lb conf",
	.function = srlb_show_lb_conf_command_fn,
    };

static clib_error_t *
srlb_show_lb_counters_command_fn (vlib_main_t * vm,
                      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  u8 *s = 0;

#define _(t,str) s = format(s, str": %lu\n", \
  vlib_get_simple_counter(&srlbm->counters, SRLB_LB_CTR_##t));
  srlb_lb_foreach_counter
#undef _

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return 0;
}

VLIB_CLI_COMMAND (srlb_show_lb_counters_command, static) =
    {
        .path = "show srlb lb counters",
        .short_help = "show srlb lb counters",
        .function = srlb_show_lb_counters_command_fn,
    };

static clib_error_t *
srlb_lb_test_state_command_fn (vlib_main_t * vm,
                      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u32 thread_index = 0;
  flowhash_lkey_srlb_lb_t key;
  ip6_address_t client_max = {};
  u8 client_max_set = 0;
  flowhash_value_srlb_lb_t value = {};
  //u32 server, i;
  i32 lifetime = 0;
  clib_error_t *error = NULL;
  u32 port;
  u32 ei = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "thread %d", &thread_index))
        ;
      else if (unformat (line_input, "cport %u", &port) && port < (1 << 16))
        key.client_port = clib_host_to_net_u16((u16) port);
      else if (unformat (line_input, "sport %u", &port) && port < (1 << 16))
        key.server_port = clib_host_to_net_u16((u16) port);
      else if (unformat (line_input, "server %U", unformat_ip6_address, &key.server))
        ;
      else if (unformat (line_input, "entry %u", &ei))
        ;
      else if (unformat (line_input, "client %U",
                         unformat_ip6_address, &key.client))
        ;
      else if (unformat (line_input, "client-max %U",
                         unformat_ip6_address, &client_max))
        {
          client_max_set = 1;
        }
      else if (unformat (line_input, "state %U",
                         unformat_srlb_lb_flow_state, &value.state))
        ;
      /*else if (unformat (line_input, "choice %d %d", &i, &server))
        value.server_list[i] = server; */ // FIXME
      else if (unformat (line_input, "server %d", &value.index))
        ;
      else if (unformat (line_input, "lifetime %d", &lifetime))
        ;
      else
        {
          error = clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  u32 time_now = srlb_lb_time_now(vlib_mains[thread_index]);
  flowhash_srlb_lb_t *h;
  u32 overflow = 0;
  if (srlbm->per_core[thread_index].flow_table == NULL)
    srlbm->per_core[thread_index].flow_table =
        flowhash_alloc_srlb_lb(srlbm->flowhash_fixed_entries,
                               srlbm->flowhash_collision_buckets);

  h = srlbm->per_core[thread_index].flow_table;

  if (ei != ~0)
    {
      if (!flowhash_is_valid_entry_index(h, ei))
        {
          error = clib_error_return (0, "Out of bound entry index (%u)",
                                     ei);
          goto done;
        }

      if (flowhash_is_timeouted(h, ei, time_now))
        {
          error = clib_error_return (0, "Entry with index (%u) is not"
              "currently valid (may be timeouted)", ei);
          goto done;
        }

      flowhash_skey_srlb_lb_t *sk = flowhash_key(h, ei);
      key.as_u64[0] = sk->as_u64[0];
      key.as_u64[1] = sk->as_u64[1];
      key.as_u64[2] = sk->as_u64[2];
    }

  if (!client_max_set)
      client_max = key.client;

  while (clib_net_to_host_u32(client_max.as_u32[3]) >=
        clib_net_to_host_u32(key.client.as_u32[3]))
    {
      u32 hash = flowhash_hash_srlb_lb(&key);
      flowhash_get_srlb_lb(h, &key, hash, time_now, &ei);

      if (flowhash_is_overflow(ei))
        overflow++;

      memcpy(flowhash_value(h, ei), &value, sizeof(value));
      flowhash_timeout(h, ei) = time_now + lifetime;

      key.client.as_u32[3] =
          clib_host_to_net_u32(clib_net_to_host_u32(
              key.client.as_u32[3]) + 1);
  };

  if (overflow)
    vlib_cli_output(vm, "Could not set state for %u entries", overflow);

  done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (srlb_lb_test_state_command, static) =
    {
        .path = "test srlb lb state",
        .short_help = "test srlb lb state [thread <idx>] "
            "[client <addr>] [vip <idx>] "
            "[cport <port>] [sport <port>] "
            "[entry <index>] "
            "[state <state>] [server <idx>] "
            "[choices <n> <idx>] [lifetime <n>] ",
        .function = srlb_lb_test_state_command_fn,
    };
