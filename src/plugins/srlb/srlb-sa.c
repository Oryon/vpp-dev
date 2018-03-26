#include <srlb/srlb-sa.h>

#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/format.h>
#include <vnet/dpo/load_balance.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "SRv6 Application-Aware Load Balancer Agent",
};
/* *INDENT-ON* */

srlb_sa_main_t srlb_sa_main = {};

const char *srlb_sa_flow_state_strings[] = {
#define _(t) [SRLB_SA_FLOW_STATE_##t] = #t,
  srlb_for_each_sa_flow_state
#undef _
};

uword
unformat_srlb_sa_accept_policy_index (unformat_input_t * input, va_list * args)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  u32 *index = va_arg (*args, u32 *);
  if (unformat(input, "%d", index))
    return !pool_is_free_index(sam->accept_policies, *index);

  srlb_sa_accept_policy_t *p;
  pool_foreach(p, sam->accept_policies, {
      if (unformat (input, p->name))
	{
	  *index = p - sam->accept_policies;
	  return 1;
	}
  });
  return 0;
}

u8 *format_srlb_sa_accept_policy_index (u8 *s, va_list * args)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  u32 pi = va_arg (*args, u32);
  if (pool_is_free_index(sam->accept_policies, pi))
    return format (s, "invalid");

  srlb_sa_accept_policy_t *p = &sam->accept_policies[pi];
  if (p->description)
    s = format(s, "%s (%s)", p->name, p->description);
  else
    s = format(s, "%s", p->name);
  return s;
}

uword unformat_srlb_sa_flow_state (unformat_input_t * input, va_list * args)
{
  u32 *state = va_arg (*args, u32 *);
  int i;
  for (i=0; i<ARRAY_LEN(srlb_sa_flow_state_strings); i++)
    {
      if (unformat(input, srlb_sa_flow_state_strings[i]))
	{
	  *state = i;
	  return 1;
	}
    }
  return 0;
}

u8 *format_srlb_sa_flow_state (u8 * s, va_list * args)
{
  srlb_sa_flow_state state = va_arg (*args, srlb_sa_flow_state);
  if (state >= ARRAY_LEN(srlb_sa_flow_state_strings))
    return format(s, "unknown");
  return format(s, "%s", srlb_sa_flow_state_strings[state]);
}

#define FORMAT_NEWLINE(s, i) format(s, "\n%U", format_white_space, i)
#define FORMAT_WNL(s, i, ...) format(FORMAT_NEWLINE(s, i), __VA_ARGS__)

u8 *format_srlb_sa_ai (u8 * s, va_list * args)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  srlb_sa_ai_t *ai = va_arg (*args, srlb_sa_ai_t *);
  uword i = format_get_indent (s);
  s = format(s, "index: %d", ai - sam->ais);
  s = FORMAT_WNL(s, i, "sr-prefix: %U", format_ip6_address, &ai->sr_prefix);
  s = FORMAT_WNL(s, i, "policy: %U [%d]",
                 format_srlb_sa_accept_policy_index,
                 ai->policy_index, ai->policy_opaque);
  s = FORMAT_WNL(s, i, "via: %U", format_ip6_address, &ai->routing_address);
  s = FORMAT_WNL(s, i, "handoff-thread: %s (%d)",
                 vlib_worker_threads[ai->handoff_thread].name,
                 ai->handoff_thread);

  vlib_main_t *vm = vlib_get_main();
  vlib_node_t *node = vlib_get_next_node(vm,
                                         srlb_sa_ca_node.index,
                                         ai->dpo.dpoi_next_node);
  s = FORMAT_WNL(s, i, "next_node: %s dpo_index: %d",
                 node->name, ai->dpo.dpoi_index);

  /* Most of the time it will be a ip6-load-balance DPO.
   * Let's try to get deeper and be more useful.
   * See ip6_forward.c to understand this code. */
  vlib_node_t *ip6_lb_node = vlib_get_node_by_name(vm,
                                                   (u8*)"ip6-load-balance");
  if (ip6_lb_node != NULL && node->index == ip6_lb_node->index)
    {
      load_balance_t *lb0 = load_balance_get (ai->dpo.dpoi_index);
      if (lb0->lb_n_buckets == 1)
        {
          const dpo_id_t *dpo0 = load_balance_get_bucket_i (lb0, 0);
          node = vlib_get_next_node(vm, ip6_lb_node->index,
                                    dpo0->dpoi_next_node);
          s = FORMAT_WNL(s, i, "next_node: %s dpo_index: %d",
                         node->name, dpo0->dpoi_index);

          vlib_node_t *ip6_rewrite = vlib_get_node_by_name(vm,
                                                           (u8*)"ip6-rewrite");
          if (ip6_rewrite != NULL && node->index == ip6_rewrite->index)
            {
              s = FORMAT_WNL(s, i, "adj %d : %U", dpo0->dpoi_index,
                             format_ip_adjacency, dpo0->dpoi_index,
                             FORMAT_IP_ADJACENCY_NONE);
            }
        }
    }

  return s;
}

u8 *format_flowhash_skey_srlb_sa (u8 * s, va_list * args)
{
  flowhash_skey_srlb_sa_t *key =
      va_arg (*args, flowhash_skey_srlb_sa_t *);
  uword i = format_get_indent (s);
  s = format(s,        "client: %U", format_ip6_address, &key->client);
  s = FORMAT_WNL(s, i, "vip: %U", format_ip6_address, &key->vip);
  s = FORMAT_WNL(s, i, "client_port: %d", clib_net_to_host_u16(key->client_port));
  s = FORMAT_WNL(s, i, "server_port: %d", clib_net_to_host_u16(key->server_port));
  return s;
}

u8 *format_flowhash_value_srlb_sa (u8 * s, va_list * args)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  flowhash_value_srlb_sa_t *val =
      va_arg (*args, flowhash_value_srlb_sa_t *);
  uword i = format_get_indent (s);
  s = format(s,        "state: %U", format_srlb_sa_flow_state, val->state);
  s = FORMAT_WNL(s, i, "load balancer: %U", format_ip6_address, &val->lb_address);
  s = FORMAT_WNL(s, i, "application instance:");
  s = FORMAT_WNL(s, i, "  %U", format_srlb_sa_ai,
	     pool_elt_at_index(sam->ais, val->ai_index));
  return s;
}

u8 *format_srlb_sa_flows_with_verbosity (u8 *s, va_list * args)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  u32 ti = va_arg (*args, u32);
  int verbosity = va_arg (*args, int);
  uword i = format_get_indent (s);
  flowhash_srlb_sa_t *h = sam->per_core[ti].flow_table;
  u32 ei;
  u32 time_now = srlb_sa_time_now(vlib_mains[ti]);

  if (h == NULL)
    return format(s, "(nil)");

  s = format(s,        "memory: %p %U", h->mem, format_memory_size, flowhash_memory_size(h));
  s = FORMAT_WNL(s, i, "fixed-entries: %d", h->fixed_entries_mask + 1);
  s = FORMAT_WNL(s, i, "collision-buckets-total: %d", h->collision_buckets_mask + 1);
  s = FORMAT_WNL(s, i, "collision-buckets-free: %d", -h->free_buckets_position);

  if (verbosity == 0)
    return s;

  s = FORMAT_WNL(s, i, "table:");
  flowhash_foreach_valid_entry(h, ei, time_now)
  {
    u32 timeout = flowhash_timeout(h, ei);
    s = FORMAT_WNL(s, i, "  [%u]", ei);
    s = FORMAT_WNL(s, i, "    %U", format_flowhash_skey_srlb_sa,
	       flowhash_key(h, ei));
    s = FORMAT_WNL(s, i, "    %U", format_flowhash_value_srlb_sa,
               flowhash_value(h, ei));
    s = FORMAT_WNL(s, i, "    remaining lifetime: %d", timeout - time_now);
  }

  return s;
}

u32 srlb_sa_accept_policy_get_index_by_name(const char *name)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  srlb_sa_accept_policy_t *p;
  pool_foreach(p, sam->accept_policies, {
      if (!strcmp(p->name, name))
	return p - sam->accept_policies;
  });
  return ~0;
}

int srlb_sa_accept_policy_register(srlb_sa_accept_policy_t *policy,
				   u32 *policy_index)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  srlb_sa_accept_policy_t *p;
  if (srlb_sa_accept_policy_get_index_by_name(policy->name) != ~0)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  pool_get(sam->accept_policies, p);
  p->name = (char *)format(0, "%s", policy->name);
  p->description = (char *)format(0, "%s", policy->description);
  p->accept = policy->accept;
  p->conf_ai = policy->conf_ai;
  return 0;
}

static int srlb_sa_ap_always_accept_fn(CLIB_UNUSED(u32 ai_index),
				       CLIB_UNUSED(u32 remaining_choices),
				       CLIB_UNUSED(u64 vip_low))
{
  return 0;
}

static int srlb_sa_ap_always_reject_fn(CLIB_UNUSED(u32 ai_index),
				       CLIB_UNUSED(u32 remaining_choices),
				       CLIB_UNUSED(u64 vip_low))
{
  return -1;
}

static int srlb_sa_ap_only_last_fn(CLIB_UNUSED(u32 ai_index),
				   u32 remaining_choices,
				   CLIB_UNUSED(u64 vip_low))
{
  SRLB_SA_LOG_DATA("Hunting request for %d rem %d", ai_index, remaining_choices);
  return (remaining_choices == 0) ? 0 : -1;
}

static inline void
srlb_sa_add_sr_adjacencies(srlb_sa_ai_t *ai)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  dpo_id_t dpo = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_addr.ip6 = ai->sr_prefix,
    .fp_len = 80,
    .fp_proto = FIB_PROTOCOL_IP6,
  };

  /* Connect and recover do not have specific cores. Only the
   * function is matched. */
  srlb_sr_set_fn(&pfx.fp_addr.ip6, SRLB_SA_FN_CONNECT_IF_AVAILABLE);
  dpo_set(&dpo, sam->dpo_handoff_type, DPO_PROTO_IP6, ai - sam->ais);
  fib_table_entry_special_dpo_add(0, &pfx,
				  FIB_SOURCE_PLUGIN_HI,
				  FIB_ENTRY_FLAG_EXCLUSIVE,
				  &dpo);
  dpo_reset(&dpo);
}

static inline void
srlb_sa_del_sr_adjacencies(srlb_sa_ai_t *ai)
{
  fib_prefix_t pfx = {
      .fp_addr.ip6 = ai->sr_prefix,
      .fp_len = 80,
      .fp_proto = FIB_PROTOCOL_IP6,
  };

  fib_table_entry_special_remove(0, &pfx, FIB_SOURCE_PLUGIN_HI);
}


int srlb_sa_conf(srlb_sa_conf_args_t *args)
{
  srlb_sa_main_t * sam = &srlb_sa_main;
  flowhash_validate_sizes(&args->flowhash_fixed_entries,
                          &args->flowhash_collision_buckets);
  sam->flowhash_collision_buckets = args->flowhash_collision_buckets;
  sam->flowhash_fixed_entries = args->flowhash_fixed_entries;
  sam->flow_active_timeout = args->flow_active_timeout;
  sam->flow_teardown_timeout = args->flow_teardown_timeout;
  return 0;
}


int srlb_sa_feature_enable_disable(u32 sw_if_index, int is_enable)
{
  return vnet_feature_enable_disable ("ip6-unicast", "srlb-sa-app",
			       sw_if_index, is_enable, 0, 0);
}

srlb_sa_ai_t *
srlb_sa_ai_get(ip6_address_t *sr_prefix)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  srlb_sa_ai_t *ai;
  pool_foreach(ai, sam->ais, {
      if (!memcmp(&ai->sr_prefix, sr_prefix, sizeof(*sr_prefix)))
        return ai;
  });
  return NULL;
}

#define _(n,s) \
const static char* const srlb_sa_dpo_##n##_nodes_ip6[] = { s , NULL }; \
const static char* const * const srlb_sa_dpo_##n##_nodes[DPO_PROTO_NUM] = { \
   [DPO_PROTO_IP6]  = srlb_sa_dpo_##n##_nodes_ip6, \
}; \
static void srlb_sa_dpo_##n##_lock(dpo_id_t *dpo) { } \
static void srlb_sa_dpo_##n##_unlock(dpo_id_t *dpo) { } \
static u8 * format_srlb_sa_dpo_##n (u8 * str, va_list * args) { \
  return format (str, "dpo-"s) ; \
}

foreach_srlb_sa_dpo

#undef _

static fib_node_t *
srlb_sa_fib_node_get_node (fib_node_index_t index)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  srlb_sa_ai_t *ai = pool_elt_at_index (sam->ais, index);
  return (&ai->fib_node);
}

static void
srlb_sa_fib_node_last_lock_gone (fib_node_t *node)
{
  /*
   * This is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

static srlb_sa_ai_t *
srlb_sa_ai_from_fib_node (fib_node_t *node)
{
  return ((srlb_sa_ai_t*)(((char*)node) -
      STRUCT_OFFSET_OF(srlb_sa_ai_t, fib_node)));
}

static void
srlb_sa_ai_stack (srlb_sa_ai_t *ai)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  dpo_stack(sam->dpo_as_type,
	    DPO_PROTO_IP6,
	    &ai->dpo,
	    fib_entry_contribute_ip_forwarding(
		ai->next_hop_fib_entry_index));
}

static fib_node_back_walk_rc_t
srlb_sa_fib_node_back_walk_notify (fib_node_t *node,
			           fib_node_back_walk_ctx_t *ctx)
{
  srlb_sa_ai_stack(srlb_sa_ai_from_fib_node(node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}


int srlb_sa_ai_conf(srlb_sa_ai_conf_args_t *args)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  srlb_sa_ai_t *ai = srlb_sa_ai_get(&args->sr_prefix);

  if ((args->flags & SRLB_SA_API_FLAGS_IS_DEL) && ai == NULL)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if ((args->flags & SRLB_SA_API_FLAGS_POLICY_SET)
      && pool_is_free_index(sam->accept_policies, args->policy_index))
    return VNET_API_ERROR_INVALID_VALUE;

  if ((args->flags & SRLB_SA_API_FLAGS_THREAD_SET) &&
      args->handoff_thread >= vlib_thread_main.n_vlib_mains)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if ((args->flags & SRLB_SA_API_FLAGS_IS_DEL))
    {
      fib_entry_child_remove(ai->next_hop_fib_entry_index,
			     ai->next_hop_child_index);
      fib_table_entry_delete_index(ai->next_hop_fib_entry_index,
				   FIB_SOURCE_RR);
      ai->next_hop_fib_entry_index = FIB_NODE_INDEX_INVALID;
      srlb_sa_del_sr_adjacencies(ai);
      pool_put(sam->ais, ai);
      return 0;
    }

  if (sam->fq_indexes[0] == ~0)
    {
      SRLB_SA_LOG_DEBUG("Initializing thread handoff queues");
      vlib_worker_thread_barrier_sync (vlib_get_main());
      sam->fq_indexes[SRLB_SA_FN_ACK_STICKINESS] =
          vlib_frame_queue_main_init (srlb_sa_as_node.index, 0);
      sam->fq_indexes[SRLB_SA_FN_CONNECT_IF_AVAILABLE] =
          vlib_frame_queue_main_init (srlb_sa_ca_node.index, 0);
      sam->fq_indexes[SRLB_SA_FN_RECOVER_STICKINESS] =
          vlib_frame_queue_main_init (srlb_sa_rs_node.index, 0);
      vlib_worker_thread_barrier_release (vlib_get_main());
    }

  if (ai == NULL)
    {
      if (!(args->flags & SRLB_SA_API_FLAGS_TO_ADDRESS_SET))
	return VNET_API_ERROR_INVALID_ARGUMENT;

      pool_get(sam->ais, ai);
      ai->routing_address = args->routing_address;
      ai->sr_prefix = args->sr_prefix;
      ai->sr_prefix.as_u32[3] = 0;
      ai->sr_prefix.as_u16[5] = 0;
      ai->policy_index = SRLB_SA_POLICY_ALWAYS_ACCEPT;

      if (!(args->flags & SRLB_SA_API_FLAGS_THREAD_SET))
        {
          ai->handoff_thread = 0;
          if (vlib_thread_main.n_vlib_mains > 1)
            ai->handoff_thread = 1;
        }

      /*
       * become a child of the FIB entry
       * so we are informed when its forwarding changes
       */
      fib_prefix_t nh = {};
      nh.fp_addr.ip6 = ai->routing_address;
      nh.fp_len = 128;
      nh.fp_proto = FIB_PROTOCOL_IP6;

      ai->next_hop_fib_entry_index =
	  fib_table_entry_special_add(0,
				      &nh,
				      FIB_SOURCE_RR,
				      FIB_ENTRY_FLAG_NONE);
      ai->next_hop_child_index =
	  fib_entry_child_add(ai->next_hop_fib_entry_index,
			      sam->fib_node_type,
			      ai - sam->ais);

      srlb_sa_add_sr_adjacencies(ai);
      srlb_sa_ai_stack(ai);
    }
  else if ((args->flags & SRLB_SA_API_FLAGS_TO_ADDRESS_SET) &&
      !ip6_address_is_equal(&ai->routing_address, &args->routing_address))
    {
      return VNET_API_ERROR_INVALID_DST_ADDRESS;
    }

  if ((args->flags & SRLB_SA_API_FLAGS_POLICY_SET))
    {
      if (ai->policy_index != args->policy_index)
        {
          if (sam->accept_policies[ai->policy_index].conf_ai)
            sam->accept_policies[ai->policy_index].conf_ai(ai - sam->ais, 1);
          ai->policy_index = args->policy_index;
          ai->policy_opaque = args->policy_opaque;
          if (sam->accept_policies[ai->policy_index].conf_ai)
            sam->accept_policies[ai->policy_index].conf_ai(ai - sam->ais, 0);
        }
      else
        {
          ai->policy_opaque = args->policy_opaque;
        }
    }

  if (args->flags & SRLB_SA_API_FLAGS_THREAD_SET)
    ai->handoff_thread = args->handoff_thread;

  return 0;
}

clib_error_t *
srlb_sa_init (vlib_main_t * vm)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  vlib_thread_main_t * tm = vlib_get_thread_main ();
  srlb_sa_ai_t *ai;
  dpo_vft_t dpo = {};
  srlb_sa_accept_policy_t policy;
  u32 i;
  srlb_sa_per_core_t *pc;

  vlib_validate_simple_counter (&sam->counters, SRLB_SA_CTR_N - 1);
  vlib_clear_simple_counters (&sam->counters);

  vec_validate(sam->per_core, tm->n_vlib_mains - 1);
  vec_foreach(pc, sam->per_core)
  {
    pc->flow_table = NULL;
    pc->time_shift = 1000;

    int fn;
    for (fn = 0; fn < 3; fn++)
      {
        vec_validate(pc->handoff_per_fn[fn].per_worker, tm->n_vlib_mains - 1);
      }
  }

#define _(n,s) do {\
    dpo.dv_lock = srlb_sa_dpo_##n##_lock; \
    dpo.dv_unlock = srlb_sa_dpo_##n##_unlock; \
    dpo.dv_format = format_srlb_sa_dpo_##n; \
    sam->dpo_##n##_type = dpo_register_new_type(&dpo, srlb_sa_dpo_##n##_nodes); \
} while (0);

  foreach_srlb_sa_dpo

#undef _

  fib_node_vft_t fib_node_vft = {
      .fnv_get = srlb_sa_fib_node_get_node,
      .fnv_last_lock = srlb_sa_fib_node_last_lock_gone,
      .fnv_back_walk = srlb_sa_fib_node_back_walk_notify,
  };
  sam->fib_node_type = fib_node_register_new_type(&fib_node_vft);

  /** Allocate error ai with index 0 */
  pool_get(sam->ais, ai);
  ai->dpo.dpoi_next_node = SRLB_SA_NEXT_DROP;
  ai->dpo.dpoi_index = ~0;
  ai->routing_address.as_u64[0] = 0;
  ai->routing_address.as_u64[1] = 0;
  ai->policy_index = SRLB_SA_POLICY_ALWAYS_ACCEPT;
  ai->policy_opaque = ~0;

  policy.name = "always-reject";
  policy.description = "Always rejects requests";
  policy.conf_ai = NULL;
  policy.accept = srlb_sa_ap_always_reject_fn;
  srlb_sa_accept_policy_register(&policy, &i);

  policy.name = "always-accept";
  policy.description = "Always accepts requests";
  policy.conf_ai = NULL;
  policy.accept = srlb_sa_ap_always_accept_fn;
  srlb_sa_accept_policy_register(&policy, &i);

  policy.name = "only-last";
  policy.description = "Only accept if last hope";
  policy.conf_ai = NULL;
  policy.accept = srlb_sa_ap_only_last_fn;
  srlb_sa_accept_policy_register(&policy, &i);

  sam->flow_active_timeout = SRLB_SA_DEFAULT_FLOW_ACTIVE_TIMEOUT;
  sam->flow_teardown_timeout = SRLB_SA_DEFAULT_FLOW_TEARDOWN_TIMEOUT;

  sam->flowhash_fixed_entries = SRLB_SA_DEFAULT_FIXED_ENTRIES;
  sam->flowhash_collision_buckets = SRLB_SA_DEFAULT_COLLISION_BUCKETS;
  flowhash_validate_sizes(&sam->flowhash_fixed_entries,
                          &sam->flowhash_collision_buckets);

  sam->log_level = SRLB_SA_LOG_DEFAULT_LEVEL;

  for (i = 0; i < ARRAY_LEN(sam->fq_indexes); i++)
    sam->fq_indexes[i] = ~0;

  return NULL;
}

VLIB_INIT_FUNCTION (srlb_sa_init);
