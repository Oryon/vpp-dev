#include <srlb/srlb-sa.h>
#include <vnet/srv6/sr.h>
#include <vnet/feature/feature.h>

#define SRH_LEN(sids) (sizeof(ip6_sr_header_t) + (sids) * sizeof(ip6_address_t))

static_always_inline
flowhash_srlb_sa_t *srlb_sa_get_flow_table(u32 thread_index, u32 time_now)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  flowhash_srlb_sa_t *h = sam->per_core[thread_index].flow_table;

  //Check if size changed
  if (PREDICT_FALSE(h != NULL &&
		    (sam->flowhash_fixed_entries !=
		        h->fixed_entries_mask + 1 ||
			sam->flowhash_collision_buckets !=
			    h->collision_buckets_mask + 1)))
    {
      flowhash_free_srlb_sa(h);
      h = NULL;
    }

  //Create if necessary
  if (PREDICT_FALSE(h == NULL)) {
    sam->per_core[thread_index].flow_table =
	flowhash_alloc_srlb_sa(sam->flowhash_fixed_entries,
			       sam->flowhash_collision_buckets);
    h = sam->per_core[thread_index].flow_table;
    SRLB_SA_LOG_WARN("Regenerated flow table for thread %u "
        "with %u static buckets and %u chained buckets", thread_index,
        sam->flowhash_fixed_entries, sam->flowhash_collision_buckets);
  }

  ASSERT(h);
  return h;
}

/********* SRLB encap (server->client) node **********/

#define foreach_srlb_sa_app_error \
	_(NONE, "no error") \
	_(NO_STATE, "no state for this connection")

typedef enum {
#define _(sym,str) SRLB_SA_APP_ERROR_##sym,
  foreach_srlb_sa_app_error
#undef _
  SRLB_SA_APP_N_ERROR,
} srlb_sa_app_error_t;

static char *srlb_sa_app_error_strings[] = {
#define _(sym,string) string,
    foreach_srlb_sa_app_error
#undef _
};

typedef struct {
  u8 no_state;
  u8 is_fin;
  flowhash_skey_srlb_sa_t key;
  flowhash_value_srlb_sa_t value;
} srlb_sa_app_trace_t;

#define FORMAT_NEWLINE(s, i) format(s, "\n%U", format_white_space, i)

u8 *
format_srlb_sa_app_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srlb_sa_app_trace_t *tr = va_arg (*args, srlb_sa_app_trace_t *);
  uword indent = format_get_indent (s);
  s = format(s, "SRLB Server Agent application node");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "fin: %s", tr->is_fin?"yes":"no");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "key: %U", format_flowhash_skey_srlb_sa, &tr->key);
  s = FORMAT_NEWLINE(s, indent);
  if (tr->no_state)
    s = format(s, "value: no state (error)");
  else
    s = format(s, "value: %U", format_flowhash_value_srlb_sa, &tr->value);
  s = FORMAT_NEWLINE(s, indent);
  return s;
}

static uword
srlb_sa_app_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 time_now = srlb_sa_time_now(vm);
  flowhash_srlb_sa_t *h = srlb_sa_get_flow_table(vm->thread_index, time_now);
  u32 freed_index, freed_len;
  flowhash_gc_srlb_sa(h, time_now,
                      &freed_index, &freed_len); /* Garbage collection */

#if SRLB_SA_OPTION_FORWARD_WHEN_NO_STATE == 1
  u32 no_state = 0;
#endif

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u32 next0;
	  ip6_header_t *ip60;
	  u8 is_fin0;
	  u32 ei0;
	  flowhash_value_srlb_sa_t *val0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);

	  {
	    u32 hash0;
	    flowhash_lkey_srlb_sa_t key0;
	    srlb_parse_packet(ip60, &key0.vip, &key0.client,
			      &key0.server_port, &key0.client_port,
			      NULL, NULL, &is_fin0);
	    key0.pad = 0;
	    hash0 = flowhash_hash_srlb_sa (&key0);
	    flowhash_get_srlb_sa (h, &key0, hash0, time_now, &ei0);
	  }

	  val0 = flowhash_value(h, ei0);
	  /* Test if entry was found. This also works in case of overflow. */
	  val0->state = flowhash_is_timeouted(h, ei0, time_now)?
	      SRLB_SA_FLOW_STATE_NONE : val0->state;

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srlb_sa_app_trace_t * tr = vlib_add_trace (vm, node, p0, sizeof (srlb_sa_app_trace_t));
	      tr->no_state = val0->state == SRLB_SA_FLOW_STATE_NONE;
	      tr->is_fin = is_fin0;
	      clib_memcpy(&tr->key, flowhash_key(h, ei0),
			  sizeof(tr->key));
	      clib_memcpy(&tr->value, flowhash_value(h, ei0),
			  sizeof(tr->value));
	    }

	  /* If FIN and we have some valid state, go to teardown state */
	  val0->state = (is_fin0 && val0->state != SRLB_SA_FLOW_STATE_NONE)?
	      SRLB_SA_FLOW_STATE_TEARDOWN:val0->state;

	  switch (val0->state) {
	    case SRLB_SA_FLOW_STATE_NONE:
	    case SRLB_SA_FLOW_STATE_DIRECT:
	      /* Forward direct. State NONE will be dropped later. */
	      break;
	    case SRLB_SA_FLOW_STATE_TEARDOWN:
	      flowhash_timeout(h, ei0) = time_now +
	                                  sam->flow_teardown_timeout;
	      goto insert;

	    case SRLB_SA_FLOW_STATE_WAIT:
	      flowhash_timeout(h, ei0) = time_now +
	                                  sam->flow_active_timeout;

insert:
	      {
		ip6_sr_header_t *srh0;
		/* Forwarding through the load balancer using 3 SR SIDs:
		 * 1: LB SID based on current state.
		 * 2: AI SID with flow information.
		 * 3: Client address
		 */
		srh0 = (ip6_sr_header_t *)(ip60 + 1);
		vlib_buffer_advance(p0, -SRH_LEN(3));
		vnet_buffer (p0)->l3_hdr_offset = p0->current_data;
		clib_memcpy(((u8 *)ip60) -SRH_LEN(3), ip60, sizeof(*ip60));
		ip60 = (ip6_header_t *)vlib_buffer_get_current(p0);
		srh0 = (ip6_sr_header_t *)(ip60 + 1);
		srh0->protocol = ip60->protocol;
		srh0->segments_left = 2;
		srh0->flags = 0;
		srh0->reserved = 0;
		srh0->type = ROUTING_HEADER_TYPE_SR;
		srh0->first_segment = 2;
		srh0->length = (sizeof(*srh0) + 3*sizeof(ip6_address_t)) / 8 - 1;
		srh0->segments[0] = ip60->dst_address;
		srh0->segments[1].as_u64[0] = sam->ais[val0->ai_index].sr_prefix.as_u64[0];
		srh0->segments[1].as_u16[4] = sam->ais[val0->ai_index].sr_prefix.as_u16[4];

		{
		  srlb_sa_sid_t *sid = (srlb_sa_sid_t *)(&srh0->segments[1].as_u64[1]);
		  sid->entry_index = ei0;
		  sid->core = vm->thread_index;
		  sid->function_and_offset = 0;
		}
		srh0->segments[2] = val0->lb_address;
		srlb_sr_set_fn (&srh0->segments[2],
			     (val0->state == SRLB_SA_FLOW_STATE_TEARDOWN)?
				 SRLB_LB_FN_DELETE_STICKINESS:
				 SRLB_LB_FN_CREATE_STICKINESS);
		ip60->dst_address = srh0->segments[2];
		ip60->protocol = IP_PROTOCOL_IPV6_ROUTE;
		ip60->payload_length =
		    clib_host_to_net_u16 (clib_net_to_host_u16 (ip60->payload_length) +
					  SRH_LEN(3));
	      }
	      break;
	  }

	  vnet_feature_next (vnet_buffer (p0)->sw_if_index[VLIB_RX], &next0, p0);

	  /* Drop in case of no state */
	  if (PREDICT_FALSE(val0->state == SRLB_SA_FLOW_STATE_NONE))
	    {
#if SRLB_SA_OPTION_FORWARD_WHEN_NO_STATE == 1
	      no_state += (val0->state == SRLB_SA_FLOW_STATE_NONE);
#else
	      next0 = SRLB_SA_NEXT_DROP;
	      p0->error = node->errors[SRLB_SA_APP_ERROR_NO_STATE];
#endif
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

#if SRLB_SA_OPTION_FORWARD_WHEN_NO_STATE == 1
  vlib_node_increment_counter (vm, node->node_index,
			       SRLB_SA_APP_ERROR_NO_STATE,
			       no_state);
#endif

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srlb_sa_app_node) =
    {
	.function = srlb_sa_app_node_fn,
	.name = "srlb-sa-app",
	.vector_size = sizeof (u32),
	.format_trace = format_srlb_sa_app_trace,
	.n_errors = SRLB_SA_APP_N_ERROR,
	.error_strings = srlb_sa_app_error_strings,
	.n_next_nodes = SRLB_SA_N_NEXT,
	.next_nodes =
	    {
		[SRLB_SA_NEXT_LOOKUP] = "ip6-lookup",
		[SRLB_SA_NEXT_DROP] = "error-drop"
	    },
    };

VNET_FEATURE_INIT (srlb_agent_encap_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srlb-sa-app",
  .runs_before = VNET_FEATURES ("ip6-lookup")
};

/********* SRLB Server Agent SR Functions **********/
#define foreach_srlb_sa_sr_error \
		_(NONE, "no error") \
		_(NO_SR_HEADER, "no SR header") \
		_(SR_HEADER_TOO_SMALL, "SR header too small") \
		_(MISSING_SIDS, "not enough SR SIDs") \
		_(OFFSET_TOO_SMALL, "SRLB offset < 2") \
		_(WORKER_MISMATCH, "packet processed by incorrect worker") \
		_(INVALID_AI_INDEX, "provided AI index is invalid") \
		_(LAST_REJECT, "rejected as last candidate")

typedef enum {
#define _(sym,str) SRLB_SA_SR_ERROR_##sym,
  foreach_srlb_sa_sr_error
#undef _
  SRLB_SA_SR_N_ERROR,
} srlb_sa_sr_error_t;

static char *srlb_sa_sr_error_strings[] = {
#define _(sym,string) string,
    foreach_srlb_sa_sr_error
#undef _
};

typedef struct {
  srlb_sa_function_t fn;
  flowhash_skey_srlb_sa_t key;
  flowhash_value_srlb_sa_t value;
  u8 accept;
  u8 overflow;
  u8 no_state;
  u32 entry;
  i32 lifetime;
} srlb_sa_sr_trace_t;

u8 *
format_srlb_sa_sr_trace (u8 * s, va_list * args, srlb_sa_function_t fn)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srlb_sa_sr_trace_t *tr = va_arg (*args, srlb_sa_sr_trace_t *);
  uword indent = format_get_indent (s);
  s = format(s, "SRLB Server Agent SR node: %U",
	     format_srlb_sa_function, (int) fn);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "function: %U", format_srlb_sa_function,(int) tr->fn);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "key: %U", format_flowhash_skey_srlb_sa, &tr->key);
  s = FORMAT_NEWLINE(s, indent);
  if (tr->no_state)
    s = format(s, "value: no state");
  else
    s = format(s, "value: %U", format_flowhash_value_srlb_sa, &tr->value);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "overflow: %s", tr->overflow?"yes":"no");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "accept: %s", tr->accept?"yes":"no");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "entry-index: %u", tr->entry);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "lifetime: %d", tr->lifetime);
  return s;
}

/**
 * Node used for receiving SR packets.
 * Functions may be Hunting, Recover or Ack Stickiness
 *
 */
static uword
srlb_sa_sr_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame,
		    srlb_sa_function_t fn)
{
  /* This is used to do business as usual when the SR header is missing. */
  static CLIB_PACKED(struct {
    ip6_sr_header_t srh;
    ip6_address_t sid[3];
  }) ip6_sr_dummy = {
      .srh = {
	  .length = SRH_LEN(3)/8 - 1,
	  .segments_left = 2,
      },
  };

  srlb_sa_main_t *sam = &srlb_sa_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 time_now = srlb_sa_time_now(vm);
  u32 freed_index, freed_len;
  flowhash_srlb_sa_t *h = srlb_sa_get_flow_table(vm->thread_index, time_now);
  flowhash_gc_srlb_sa(h, time_now, &freed_index, &freed_len); /* Garbage collection */

  u32 table_overflows = 0;
  u32 moved_flows = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u32 error0 = SRLB_SA_SR_ERROR_NONE;
	  ip6_header_t *ip60;
	  ip6_sr_header_t *srh0 = &ip6_sr_dummy.srh;
	  flowhash_lkey_srlb_sa_t key0;
	  flowhash_value_srlb_sa_t *val0;
	  u32 ei0;
	  u32 next0;
	  u8 accept0;
	  u8 arg_sid0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current(p0);

	  /* Find ports and SR header */
	  srlb_parse_packet (ip60, &key0.client, NULL,
			     &key0.client_port, &key0.server_port,
			     (ip6_ext_header_t **) &srh0, NULL, NULL);
	  key0.pad = 0;

	  /* No SR header in the packet */
	  error0 = (srh0 == &ip6_sr_dummy.srh)?SRLB_SA_SR_ERROR_NO_SR_HEADER:error0;

	  /* SR header length is too small */
	  error0 = (srh0->length < (SRH_LEN(srh0->segments_left + 1) / 8) - 1) ?
	      SRLB_SA_SR_ERROR_SR_HEADER_TOO_SMALL : error0;

	  if (fn == SRLB_SA_FN_ACK_STICKINESS)
	    {
	      /* Offset to VIP is fixed */
	      arg_sid0 = srh0->segments_left - 2;
	    }
	  else
	    {
	      /* Offset to VIP depends */
	      arg_sid0 = srh0->segments_left -
		  srlb_sr_offset(&srh0->segments[srh0->segments_left]);

	      /* Invalid offset value */
	      error0 = (arg_sid0 >= srh0->segments_left - 1)?
		  SRLB_SA_SR_ERROR_OFFSET_TOO_SMALL:error0;
	    }

	  /* Check if argument sid can be found */
	  error0 = (srh0->length < (SRH_LEN(arg_sid0 + 1) / 8) - 1) ?
	  	      SRLB_SA_SR_ERROR_MISSING_SIDS : error0;

	  /* Use dummy srh for any observed errors so far */
	  if (PREDICT_FALSE(error0 != SRLB_SA_SR_ERROR_NONE))
	    {
	      srh0 = &ip6_sr_dummy.srh;
	      arg_sid0 = 0;
	    }

	  /* Get the flow */
	  {
	    val0 = NULL;
	    key0.vip = srh0->segments[arg_sid0]; /* Get the VIP address */

	    if (fn == SRLB_SA_FN_ACK_STICKINESS)
	      {
		/* Use the hint in the SID to find the flow without a full
		 * lookup. */
		srlb_sa_sid_t *sid0 =
		    (srlb_sa_sid_t *) &ip60->dst_address.as_u64[1];

		/* The traffic must be hitting the same core as the one used
		 * when storing state.
		 * TODO: Dispatch packet to correct core. */
		error0 = (sid0->core != vm->thread_index &&
		    error0 == SRLB_SA_SR_ERROR_NONE) ?
			SRLB_SA_SR_ERROR_WORKER_MISMATCH : error0;

		/* Get the hint flow indexes from the SID. */
		ei0 = sid0->entry_index;

		/* Erroneous bucket index is not a critical error.
		 * We verify later anyway. */
		ei0 = (flowhash_is_valid_entry_index(h, ei0)) ?
		    ei0 : FLOWHASH_INVALID_ENTRY_INDEX;
	      }

	    /* If hunting, or in case no state was found */
	    if (fn != SRLB_SA_FN_ACK_STICKINESS || PREDICT_FALSE(
	        flowhash_cmp_key_srlb_sa(flowhash_key(h, ei0), &key0) ||
			      flowhash_is_timeouted(h, ei0, time_now)))
	      {
		/* Try harder to find the flow */
		u32 hash0 = flowhash_hash_srlb_sa(&key0);
		flowhash_get_srlb_sa (h, &key0, hash0, time_now, &ei0);

		if (flowhash_is_timeouted(h, ei0, time_now))
		  {
		    flowhash_value(h, ei0)->state =
			SRLB_SA_FLOW_STATE_NONE;
		  }
		else if (fn == SRLB_SA_FN_ACK_STICKINESS)
		  {
		    /* We went up here just to figure the flow was somewhere
		     * else... */
		    moved_flows++;
		  }
		table_overflows += flowhash_is_overflow(ei0);
	      }
	  }

	  val0 = flowhash_value(h, ei0);
	  val0->ai_index = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  /* Decide what to do with the SR header */
	  if (fn == SRLB_SA_FN_ACK_STICKINESS)
	    {
	      accept0 = 1;
	    }
	  else if (fn == SRLB_SA_FN_CONNECT_IF_AVAILABLE)
	    {
	      /* FIXME: Define and use acceptation API */
	      srlb_sa_ai_t *ai0 = &sam->ais[val0->ai_index];
	      accept0 = !sam->accept_policies[ai0->policy_index].
		  accept(ai0 - sam->ais, srh0->segments_left - arg_sid0 - 2);
	    }
	  else /* fn == SRLB_SA_FN_RECOVER_STICKINESS */
	    {
	      accept0 = val0->state != SRLB_SA_FLOW_STATE_NONE;
	    }

	  /* Never accept in case of overflow */
	  accept0 = flowhash_is_overflow(ei0) ? 0 : accept0;

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srlb_sa_sr_trace_t * tr = vlib_add_trace (vm, node, p0, sizeof (srlb_sa_sr_trace_t));
	      tr->fn = fn;
	      clib_memcpy(&tr->key, flowhash_key(h, ei0), sizeof(tr->key));
	      clib_memcpy(&tr->value, flowhash_value(h, ei0), sizeof(tr->value));
	      tr->accept = accept0;
	      tr->overflow = flowhash_is_overflow(ei0);
	      tr->entry = ei0;
	      tr->lifetime = flowhash_timeout(h, ei0) - time_now;
	    }

	  if (fn == SRLB_SA_FN_ACK_STICKINESS || PREDICT_TRUE(accept0))
	    {
	      /* Update state and timeout */
	      if (fn == SRLB_SA_FN_ACK_STICKINESS)
		{
		  /* Go direct if not in teardown. Also remember value for
		   * later teardown. */
		  val0->state = (val0->state == SRLB_SA_FLOW_STATE_TEARDOWN)?
		      val0->state : SRLB_SA_FLOW_STATE_DIRECT;
		  val0->lb_address = srh0->segments[arg_sid0 + 1];
		}
	      else
		{
		  /* Hunting done, go to wait unless if in teardown already. */
		  val0->state = (val0->state == SRLB_SA_FLOW_STATE_TEARDOWN)?
		      val0->state : SRLB_SA_FLOW_STATE_WAIT;
		  val0->lb_address = srh0->segments[arg_sid0 + 1];
		}

	      flowhash_timeout(h, ei0) =
		  time_now + ((val0->state == SRLB_SA_FLOW_STATE_TEARDOWN)?
		      sam->flow_teardown_timeout :
		      sam->flow_active_timeout);

	      /* Pop SR header and forward to application instance */
	      u32 srh_len = sizeof(*srh0) + srh0->length * 8;
	      ip60->dst_address = srh0->segments[arg_sid0];
	      ip60->protocol = srh0->protocol;
	      ip60->payload_length =
		  clib_host_to_net_u16 (clib_net_to_host_u16 (ip60->payload_length) -
					srh_len);
	      clib_memcpy(((u8 *)ip60) + srh_len, ip60, sizeof(*ip60));
	      vlib_buffer_advance(p0, srh_len);
	      vnet_buffer (p0)->l3_hdr_offset = p0->current_data;

	      /* Forward to AI */
	      vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
	      		  sam->ais[val0->ai_index].dpo.dpoi_index;
	      next0 = sam->ais[val0->ai_index].dpo.dpoi_next_node;
	    }
	  else if (PREDICT_TRUE(arg_sid0 != srh0->segments_left - 2))
	    {
	      /* Forward to next candidate */
	      srh0->segments_left--;
	      ip60->dst_address = srh0->segments[srh0->segments_left];
	      next0 = SRLB_SA_NEXT_LOOKUP;
	    }
	  else if (arg_sid0 != 0)
	    {
	      /* Forward after argument sids */
	      srh0->segments_left = arg_sid0 - 1;
	      ip60->dst_address = srh0->segments[srh0->segments_left];
	      next0 = SRLB_SA_NEXT_LOOKUP;
	    }
	  else
	    {
	      /* Last candidate and no further hope... */
	      error0 = (error0 == SRLB_SA_SR_ERROR_NONE) ?
		  SRLB_SA_SR_ERROR_LAST_REJECT : error0;
	    }

	  if (PREDICT_FALSE(error0 != SRLB_SA_SR_ERROR_NONE))
	    {
	      next0 = SRLB_SA_NEXT_DROP;
	      p0->error = node->errors[error0];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}



/** SRLB SA Connect if Available node */

static u8 *
format_srlb_sa_ca_trace (u8 * s, va_list * args)
{
  return format_srlb_sa_sr_trace (s, args, SRLB_SA_FN_CONNECT_IF_AVAILABLE);
}

static uword
srlb_sa_ca_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return srlb_sa_sr_node_fn(vm, node, frame,
			    SRLB_SA_FN_CONNECT_IF_AVAILABLE);
}

VLIB_REGISTER_NODE (srlb_sa_ca_node) =
    {
	.function = srlb_sa_ca_node_fn,
	.name = "srlb-sa-ca",
	.vector_size = sizeof (u32),
	.format_trace = format_srlb_sa_ca_trace,
	.n_errors = SRLB_SA_SR_N_ERROR,
	.error_strings = srlb_sa_sr_error_strings,
	.n_next_nodes = SRLB_SA_N_NEXT,
	.next_nodes =
	    {
		[SRLB_SA_NEXT_LOOKUP] = "ip6-lookup",
		[SRLB_SA_NEXT_DROP] = "error-drop"
	    },
    };

/** SRLB SA Recover Stickiness node */

static u8 *
format_srlb_sa_rs_trace (u8 * s, va_list * args)
{
  return format_srlb_sa_sr_trace (s, args, SRLB_SA_FN_RECOVER_STICKINESS);
}

static uword
srlb_sa_rs_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return srlb_sa_sr_node_fn(vm, node, frame,
			    SRLB_SA_FN_RECOVER_STICKINESS);
}

VLIB_REGISTER_NODE (srlb_sa_rs_node) =
    {
	.function = srlb_sa_rs_node_fn,
	.name = "srlb-sa-rs",
	.vector_size = sizeof (u32),
	.format_trace = format_srlb_sa_rs_trace,
	.n_errors = SRLB_SA_SR_N_ERROR,
	.error_strings = srlb_sa_sr_error_strings,
	.n_next_nodes = 0,
	.sibling_of = "srlb-sa-ca"
    };

/** SRLB SA Acknowledge Stickiness node */

static u8 *
format_srlb_sa_as_trace (u8 * s, va_list * args)
{
  return format_srlb_sa_sr_trace (s, args, SRLB_SA_FN_ACK_STICKINESS);
}

static uword
srlb_sa_as_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return srlb_sa_sr_node_fn(vm, node, frame,
			    SRLB_SA_FN_ACK_STICKINESS);
}

VLIB_REGISTER_NODE (srlb_sa_as_node) =
    {
	.function = srlb_sa_as_node_fn,
	.name = "srlb-sa-as",
	.vector_size = sizeof (u32),
	.format_trace = format_srlb_sa_as_trace,
	.n_errors = SRLB_SA_SR_N_ERROR,
	.error_strings = srlb_sa_sr_error_strings,
	.n_next_nodes = 0,
	.sibling_of = "srlb-sa-ca"
    };


typedef struct {
  u32 from_worker_index;
  u32 next_worker_index;
  srlb_sa_function_t fn;
} srlb_sa_handoff_trace_t;

static uword
srlb_sa_handoff_node_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame,
                         srlb_sa_function_t fn)
{
  srlb_sa_main_t *sam = &srlb_sa_main;
  u32 thread_index = vm->thread_index;

  /* Where to get packets from */
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;

  /* Enqueue to another thread thread */
  u32 current_worker_index = ~0;
  vlib_frame_queue_elt_t *hf = 0;

  /* Enqueue to the same thread */
  u32 *to_next;
  u32 n_left_to_next;
  u32 next_index = 0;

  u16 handoff_counter = 0;

  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
  while (n_left_from > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      u32 next_worker_index;

      pi0 = from[0];
      from++;
      n_left_from--;

      p0 = vlib_get_buffer (vm, pi0);

      /* Get worker and function from adjacency */
      if (fn == SRLB_SA_FN_ACK_STICKINESS)
        {
          /* Packets are dispatched to a specific core. */
          next_worker_index = vnet_buffer (p0)->ip.adj_index[VLIB_TX] >>
              SRLB_SA_HANDOFF_CORE_OFFSET;
          /* Only leave the VIP index in the adjacency */
          vnet_buffer (p0)->ip.adj_index[VLIB_TX] &=
              ~(SRLB_SA_HANDOFF_CORE_MASK);
        }
      else
        {
          /* Core depends on the ai */
          next_worker_index =
              sam->ais[vnet_buffer(p0)->ip.adj_index[VLIB_TX]].handoff_thread;
        }

      if (next_worker_index != thread_index)
        {
          handoff_counter++;

          /* do handoff */
          if (next_worker_index != current_worker_index)
            {
              u32 queue_index;

allocate_hf:
              if (fn == SRLB_SA_FN_CONNECT_IF_AVAILABLE)
                queue_index = sam->fq_ca_index;
              else if (fn == SRLB_SA_FN_ACK_STICKINESS)
                queue_index = sam->fq_as_index;
              else
                queue_index = sam->fq_rs_index;

              hf = vlib_get_worker_handoff_queue_elt (queue_index,
                                                      next_worker_index,
                                                      sam->per_core[thread_index].handoff_per_fn[fn].per_worker);

              current_worker_index = next_worker_index;
            }

          if (PREDICT_FALSE(hf->n_vectors == VLIB_FRAME_SIZE))
            {
              vlib_put_frame_queue_elt (hf);
              current_worker_index = ~0;
              sam->per_core[thread_index].handoff_per_fn[fn].per_worker[current_worker_index] = 0;
              goto allocate_hf;
            }

          hf->buffer_index[hf->n_vectors] = pi0;
          hf->n_vectors++;
        }
      else
        {
          /* predictive enaueue */
          to_next[0] = pi0;
          to_next += 1;
          n_left_to_next--;

          /* Validate correct node */
          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, pi0, 0);

          if (n_left_to_next == 0)
            {
              vlib_put_next_frame (vm, node, next_index, n_left_to_next);
              vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
            }
        }

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                         && (p0->flags & VLIB_BUFFER_IS_TRACED)))
        {
          srlb_sa_handoff_trace_t *t =
              vlib_add_trace (vm, node, p0, sizeof (*t));
          t->next_worker_index = next_worker_index;
          t->from_worker_index = thread_index;
          t->fn = fn;
        }
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  /* Ship frames to the worker nodes */
  int i;
  vec_foreach_index(i, sam->per_core[thread_index].handoff_per_fn[fn].per_worker)
  {
    hf = sam->per_core[thread_index].handoff_per_fn[fn].per_worker[i];
    sam->per_core[thread_index].handoff_per_fn[fn].per_worker[i] = 0;
    if (hf)
      vlib_put_frame_queue_elt (hf);
  }

    vlib_increment_simple_counter(&sam->counters, vm->thread_index,
                                  SRLB_SA_CTR_HANDOFF, handoff_counter);

  return frame->n_vectors;
}

u8 *
format_srlb_sa_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srlb_sa_handoff_trace_t * t =
      va_arg (*args, srlb_sa_handoff_trace_t *);
  uword indent = format_get_indent (s);
  s = format (s, "function: %U", format_srlb_sa_function, t->fn);
  s = FORMAT_NEWLINE(s, indent);
  s = format (s, "from:%u to:%u",
              t->from_worker_index, t->next_worker_index);
  return s;
}

static uword
srlb_sa_handoff_ca_node_fn (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame)
{
  return srlb_sa_handoff_node_fn(vm, node, frame,
                                 SRLB_SA_FN_CONNECT_IF_AVAILABLE);
}

VLIB_REGISTER_NODE (srlb_sa_handoff_ca_node) =
    {
        .function = srlb_sa_handoff_ca_node_fn,
        .name = "srlb-sa-handoff-ca",
        .vector_size = sizeof (u32),
        .format_trace = format_srlb_sa_handoff_trace,
        .n_errors = 0,
        .error_strings = NULL,
        .n_next_nodes = 1,
        .next_nodes = { [0] = "srlb-sa-ca" },
    };

static uword
srlb_sa_handoff_as_node_fn (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame)
{
  return srlb_sa_handoff_node_fn(vm, node, frame,
                                 SRLB_SA_FN_ACK_STICKINESS);
}

VLIB_REGISTER_NODE (srlb_sa_handoff_as_node) =
    {
        .function = srlb_sa_handoff_as_node_fn,
        .name = "srlb-sa-handoff-as",
        .vector_size = sizeof (u32),
        .format_trace = format_srlb_sa_handoff_trace,
        .n_errors = 0,
        .error_strings = NULL,
        .n_next_nodes = 1,
        .next_nodes = { [0] = "srlb-sa-as" },
    };

static uword
srlb_sa_handoff_rs_node_fn (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame)
{
  return srlb_sa_handoff_node_fn(vm, node, frame,
                                 SRLB_SA_FN_RECOVER_STICKINESS);
}

VLIB_REGISTER_NODE (srlb_sa_handoff_rs_node) =
    {
        .function = srlb_sa_handoff_rs_node_fn,
        .name = "srlb-sa-handoff-rs",
        .vector_size = sizeof (u32),
        .format_trace = format_srlb_sa_handoff_trace,
        .n_errors = 0,
        .error_strings = NULL,
        .n_next_nodes = 1,
        .next_nodes = { [0] = "srlb-sa-rs" },
    };



clib_error_t *
srlb_sa_init_node (vlib_main_t * vm)
{

  return NULL;
}

VLIB_INIT_FUNCTION (srlb_sa_init_node);
