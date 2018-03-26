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
#include <vnet/srv6/sr.h>

#define foreach_srlb_lb_error \
		_(NONE, "no error") \
		_(NO_SR_HEADER, "no SR header") \
		_(MISSING_SIDS, "not enough SR SIDs") \
		_(SR_HEADER_TOO_SMALL, "SR header is too small") \
		_(INVALID_VIP, "invalid vip in SID argument") \
		_(WORKER_MISMATCH, "returned worker index does not match") \
		_(FLOW_TABLE_OVERFLOW, "packet was forwarded without state") \
		_(MOVED_FLOW, "flow was moved in flow table (non-critical)")

typedef enum {
#define _(sym,str) SRLB_LB_ERROR_##sym,
  foreach_srlb_lb_error
#undef _
  SRLB_LB_N_ERROR,
} srlb_lb_error_t;

static char *srlb_lb_error_strings[] = {
#define _(sym,string) string,
    foreach_srlb_lb_error
#undef _
};

#define FORMAT_NEWLINE(s, i) format(s, "\n%U", format_white_space, i)

static_always_inline
flowhash_srlb_lb_t *srlb_get_flow_table(u32 thread_index, u32 time_now)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  flowhash_srlb_lb_t *h = srlbm->per_core[thread_index].flow_table;

  //Check if size changed
  if (PREDICT_FALSE(h != NULL &&
		    (srlbm->flowhash_fixed_entries !=
		        h->fixed_entries_mask + 1 ||
			srlbm->flowhash_collision_buckets !=
			    h->collision_buckets_mask + 1)))
    {
      flowhash_free_srlb_lb(h);
      h = NULL;
    }

  //Create if necessary
  if (PREDICT_FALSE(h == NULL)) {
    srlbm->per_core[thread_index].flow_table =
        flowhash_alloc_srlb_lb(srlbm->flowhash_fixed_entries,
                               srlbm->flowhash_collision_buckets);
    h = srlbm->per_core[thread_index].flow_table;
    SRLB_LB_LOG_WARN("Regenerated flow table for thread %u "
        "with %u static buckets and %u chained buckets", thread_index,
	srlbm->flowhash_fixed_entries, srlbm->flowhash_collision_buckets);
  }

  ASSERT(h);
  return h;
}

#define SRH_LEN(sids) (sizeof(ip6_sr_header_t) + (sids) * sizeof(ip6_address_t))

/********* SRLB client (client -> LB) node **********/

typedef struct {
  u8 is_overflow;
  u8 is_syn;
  u32 entry_index;
  flowhash_skey_srlb_lb_t key;
  flowhash_value_srlb_lb_t value;
} srlb_client_trace_t;

u8 *
format_srlb_client_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (srlb_client_trace_t *tr) =
      va_arg (*args, srlb_client_trace_t *);
  uword indent = format_get_indent (s);
  s = format(s, "SRLB LB client node");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "key: %U", format_flowhash_skey_srlb_lb, &tr->key);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "value: %U", format_flowhash_value_srlb_lb, &tr->value);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "entry_index: %u", tr->entry_index);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "overflow: %s", tr->is_overflow?"yes":"no");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "syn: %s", tr->is_syn?"yes":"no");
  return s;
}

static_always_inline
void srlb_client_get_key (vlib_main_t * vm, u32 pi,
			  u8 *next_hunting_function,
			  flowhash_lkey_srlb_lb_t *key)
{
  vlib_buffer_t *p = vlib_get_buffer (vm, pi);
  ip6_header_t *ip6 = vlib_buffer_get_current(p);
  key->pad = 0;
  srlb_parse_packet (ip6, &key->client, &key->server,
		     &key->client_port, &key->server_port,
		     NULL, next_hunting_function, NULL);
  *next_hunting_function = *next_hunting_function ?
      SRLB_SA_FN_CONNECT_IF_AVAILABLE:
      SRLB_SA_FN_RECOVER_STICKINESS;
}

static_always_inline
void srlb_client_get_hash (vlib_main_t * vm,
                           flowhash_srlb_lb_t *h,
			    u32 *next_hash,
			    flowhash_lkey_srlb_lb_t *key)
{
  *next_hash = flowhash_hash_srlb_lb(key);
  flowhash_prefetch(h, *next_hash);
}

typedef struct {
  u32 hash;
  u8 hunting_function;
  flowhash_lkey_srlb_lb_t key;
} srlb_client_parsing_t;

static uword
srlb_client_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 time_now = srlb_lb_time_now(vm);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  flowhash_srlb_lb_t *h =
      srlb_get_flow_table(vm->thread_index, time_now);
  u16 table_overflow = 0;
  u16 connect_sent = 0;
  u16 recover_sent = 0;
  u16 new_sessions = 0;

  u32 freed_index, freed_len;
  flowhash_gc_srlb_lb(h, time_now, &freed_index, &freed_len); /* Garbage collection */
  while (freed_len < 0)
    {
      flowhash_value_srlb_lb_t *val = flowhash_value(h, freed_index);
      if (val->state != SRLB_LB_FLOW_STATE_LISTEN)
        {
          vlib_refcount_add(&srlbm->refcount[srlb_lb_state_to_refcnt(val->state)],
                            vm->thread_index, val->index, -1);
          val->state = SRLB_LB_FLOW_STATE_LISTEN;
        }
    }

  {
    static int flow_gc_counter = 0;
    flowhash_value_srlb_lb_t *val = flowhash_value(h, flow_gc_counter + 1);
    if (val->state != SRLB_LB_FLOW_STATE_LISTEN &&
        flowhash_is_timeouted(h,  flow_gc_counter + 1, time_now))
      {
        vlib_refcount_add(&srlbm->refcount[srlb_lb_state_to_refcnt(val->state)],
                          vm->thread_index, val->index, -1);
        val->state = SRLB_LB_FLOW_STATE_LISTEN;
      }

    if (flow_gc_counter == h->fixed_entries_mask)
      flow_gc_counter = 0;
    else
      flow_gc_counter++;
  }

  /* Any access to srlb object pools is subject to a
   * multi-reader/single-writer lock */
  clib_spinlock_lock(&srlbm->per_core[vm->thread_index].resource_lock);

  srlb_client_parsing_t pa[4];

  if (PREDICT_TRUE(n_left_from > 0))
    {
      srlb_client_get_key(vm, from[0],
			  &pa[n_left_from & 3].hunting_function,
			  &pa[n_left_from & 3].key);
      srlb_client_get_hash(vm, h, &pa[n_left_from & 3].hash,
			  &pa[n_left_from & 3].key);
    }

  if (PREDICT_TRUE(n_left_from > 1))
    {
      srlb_client_get_key(vm, from[1],
			  &pa[(n_left_from - 1) & 3].hunting_function,
			  &pa[(n_left_from - 1) & 3].key);
      srlb_client_get_hash(vm, h, &pa[(n_left_from - 1) & 3].hash,
			  &pa[(n_left_from - 1) & 3].key);
    }

  if (PREDICT_TRUE(n_left_from > 2))
    {
      srlb_client_get_key(vm, from[2],
			  &pa[(n_left_from - 2) & 3].hunting_function,
			  &pa[(n_left_from - 2) & 3].key);
      srlb_client_get_hash(vm, h, &pa[(n_left_from - 2) & 3].hash,
			   &pa[(n_left_from - 2) & 3].key);
    }

  if (PREDICT_TRUE(n_left_from > 3))
    {
      srlb_client_get_key(vm, from[3],
			  &pa[(n_left_from - 3) & 3].hunting_function,
			  &pa[(n_left_from - 3) & 3].key);
      srlb_client_get_hash(vm, h, &pa[(n_left_from - 3) & 3].hash,
			   &pa[(n_left_from - 3) & 3].key);
    }

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip6_header_t *ip60;
	  srlb_lb_vip_t *vip0;
	  u32 ei0;
	  u32 next0 = SRLB_LB_NEXT_DROP;
	  u8 hunting_function;
	  u32 hash0;
	  srlb_client_parsing_t *parsing = &pa[n_left_from & 3];

	  flowhash_get_srlb_lb(h, &parsing->key,
	                       parsing->hash, time_now, &ei0);
	  hash0 = parsing->hash;
	  hunting_function = parsing->hunting_function;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  vip0 = pool_elt_at_index (srlbm->vips,
				    vnet_buffer (p0)->ip.adj_index[VLIB_TX]);
	  ip60 = vlib_buffer_get_current(p0);

	  if (PREDICT_TRUE(n_left_from > 5))
	    {
	      vlib_buffer_t *p1 = vlib_get_buffer (vm, from[5]);
	      CLIB_PREFETCH (vlib_buffer_get_current(p1),
			     sizeof(ip6_header_t)
			     + sizeof(udp_header_t), STORE);
	    }

	  /* Parse next packet */
	  if (PREDICT_TRUE(n_left_from > 3))
	    {
	      srlb_client_get_key(vm, from[3],
	      			  &parsing->hunting_function,
				  &parsing->key);
	    }

	  if (PREDICT_TRUE(n_left_from > 1))
	    {
	      vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (vlib_buffer_get_current(p1) - SRH_LEN(3),
			     SRH_LEN(3), STORE);
	    }

	  {
	    flowhash_value_srlb_lb_t *val0;
	    ip6_sr_header_t *srh0;

	    /* Use dummy entry in case of overflow */
	    val0 = flowhash_value(h, ei0);

	    /* Note that this is also detecting overflow cases */

	    new_sessions += (flowhash_is_timeouted(h, ei0, time_now) &&
	        !flowhash_is_overflow(ei0))?1:0;
	    table_overflow += (flowhash_is_overflow(ei0))?1:0;

	    if (PREDICT_FALSE(flowhash_is_timeouted(h, ei0, time_now)) &&
	        val0->state != SRLB_LB_FLOW_STATE_LISTEN)
	      {
	        vlib_refcount_add(&srlbm->refcount[srlb_lb_state_to_refcnt(val0->state)],
	                          vm->thread_index, val0->index, -1);
	        val0->state = SRLB_LB_FLOW_STATE_LISTEN;
	      }

	    /* Parse next packet */
	    if (PREDICT_TRUE(n_left_from > 3))
	      {
		srlb_client_get_hash(vm, h, &parsing->hash,
				     &parsing->key);
	      }

	    if (PREDICT_TRUE(srlb_lb_state_is_established(val0->state)))
	      {
		flowhash_timeout(h, ei0) =
		    time_now + ((val0->state == SRLB_LB_FLOW_STATE_STEER)?
			srlbm->flow_active_timeout:srlbm->flow_teardown_timeout);

		vlib_buffer_advance(p0, -SRH_LEN(3));
		vnet_buffer (p0)->l3_hdr_offset = p0->current_data;
		clib_memcpy((((u8*)ip60) -SRH_LEN(3)),
			    ip60, sizeof(*ip60));
		ip60 = (ip6_header_t *) (((u8*)ip60) -SRH_LEN(3));
		srh0 = (ip6_sr_header_t *)(ip60 + 1);

		srh0->protocol = ip60->protocol;
		srh0->segments_left = 2;
		srh0->flags = 0;
		srh0->reserved = 0;
		srh0->type = ROUTING_HEADER_TYPE_SR;
		srh0->first_segment = 2;
		srh0->length = (SRH_LEN(3)) / 8 - 1;
		srh0->segments[0] = ip60->dst_address;
		srh0->segments[1].as_u64[0] = vip0->sr_prefix.as_u64[0];
		srh0->segments[1].as_u16[4] = vip0->sr_prefix.as_u16[4];
		/* Setting return address */
		{
		  srlb_lb_flow_sid_t *sid =
		      (srlb_lb_flow_sid_t *) &srh0->segments[1].as_u64[1];
		  sid->function = 0;
		  sid->core = vm->thread_index;
		  sid->entry_index = ei0;
		}

		srh0->segments[2].as_u64[0] = srlbm->servers[val0->index].address.as_u64[0];
		srh0->segments[2].as_u64[1] = val0->opaque;
		srlb_sr_set_fn(&srh0->segments[2], SRLB_SA_FN_ACK_STICKINESS);

		ip60->dst_address.as_u64[0] = srlbm->servers[val0->index].address.as_u64[0];
		ip60->dst_address.as_u64[1] = val0->opaque;
		srlb_sr_set_fn(&ip60->dst_address, SRLB_SA_FN_ACK_STICKINESS);

		ip60->protocol = IP_PROTOCOL_IPV6_ROUTE;
		ip60->payload_length =
		    clib_host_to_net_u16 (
			clib_net_to_host_u16 (ip60->payload_length) +
			SRH_LEN(3));

		/* Set next node */
		next0 = srlbm->servers[val0->index].dpo.dpoi_next_node;
		vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
		    srlbm->servers[val0->index].dpo.dpoi_index;
	      }
	    else
	      {

	        if (PREDICT_TRUE(val0->state == SRLB_LB_FLOW_STATE_LISTEN))
		  {

	            if (PREDICT_FALSE(vip0->hash == SRLB_LB_VIP_HASH_VIP))
	              {
	                /* CHT uses dst based hashing */
	                hash0 = srlb_lb_hash_ip6_address(&ip60->dst_address);
	              }

		    /* The hunting state is optional. */
#ifndef SRLB_LB_NO_HUNTING_STATE
	            /* It is important to atomically read vip0->cht_index
	             * only once, as it can be changed by main thread.
	             * It is marked as volatile, so the compiler should
	             * not read it again. */
	            val0->index = vip0->cht_index;

	            srlb_lb_vip_cht_t *cht = &srlbm->chts[val0->index];
	            if (PREDICT_TRUE(!flowhash_is_overflow(ei0)))
	              {
	                val0->state = SRLB_LB_FLOW_STATE_HUNTING;
	                vlib_refcount_add(&srlbm->refcount[SRLB_LB_REFCOUNT_CHTS],
	                                  vm->thread_index, val0->index, 1);
	              }
		    val0->bucket_index = (hash0 & cht->mask) * cht->n_choices;
		    flowhash_timeout(h, ei0) =
			time_now + srlbm->flow_active_timeout;
#endif
		  }
		else
		  {
		    flowhash_timeout(h, ei0) =
			time_now + srlbm->flow_active_timeout;
		  }

		srlb_lb_vip_cht_t *cht = &srlbm->chts[val0->index];
		u32 *server_list = &cht->buckets[val0->bucket_index];
		u32 n_choices = cht->n_choices;

		/* hunting */
		/* Create SR header*/
		vlib_buffer_advance(p0, -SRH_LEN(2 + n_choices));
		vnet_buffer (p0)->l3_hdr_offset = p0->current_data;
		clib_memcpy(vlib_buffer_get_current(p0), ip60, sizeof(*ip60));
		ip60 = (ip6_header_t *)vlib_buffer_get_current(p0);
		srh0 = (ip6_sr_header_t *)(ip60 + 1);

		srh0->protocol = ip60->protocol;
		srh0->segments_left = n_choices + 1;
		srh0->flags = 0;
		srh0->reserved = 0;
		srh0->type = ROUTING_HEADER_TYPE_SR;
		srh0->first_segment = 3;
		srh0->length = (SRH_LEN(2 + n_choices)) / 8 - 1;
		srh0->segments[0] = ip60->dst_address;
		srh0->segments[1].as_u64[0] = vip0->sr_prefix.as_u64[0];
		srh0->segments[1].as_u16[4] = vip0->sr_prefix.as_u16[4];

		/* Setting return address */
		{
		  srlb_lb_flow_sid_t *sid = (srlb_lb_flow_sid_t *) &srh0->segments[1].as_u64[1];
		  sid->function = 0;
		  sid->core = vm->thread_index;
		  sid->entry_index = ei0;
		}

		/* Set hunting header */
		connect_sent += hunting_function == SRLB_SA_FN_CONNECT_IF_AVAILABLE;
		recover_sent += hunting_function == SRLB_SA_FN_RECOVER_STICKINESS;

		{
		  u32 i;
		  for (i = 0; i < n_choices; i++)
		    {
		      srh0->segments[2 + i] = srlbm->servers[server_list[n_choices - i - 1]].address;
		      srlb_sr_set_fn_and_offset(&srh0->segments[2 + i], hunting_function, 2 + i);
		    }
		}

		ip60->protocol = IP_PROTOCOL_IPV6_ROUTE;
		ip60->payload_length =
		    clib_host_to_net_u16 (clib_net_to_host_u16 (ip60->payload_length) +
					  SRH_LEN(2 + n_choices));
		ip60->dst_address = srh0->segments[n_choices + 1];

		/* Set next node */
		next0 = srlbm->servers[server_list[0]].dpo.dpoi_next_node;
		vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
		    srlbm->servers[server_list[0]].dpo.dpoi_index;
	      }

	    if (PREDICT_TRUE(n_left_from > 6))
	      {
		vlib_buffer_t *p1 = vlib_get_buffer (vm, from[6]);
		vlib_prefetch_buffer_header(p1, LOAD);
	      }

	    if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	      {
		srlb_client_trace_t * tr = vlib_add_trace (vm, node, p0, sizeof (srlb_client_trace_t));
		tr->entry_index = ei0;
		tr->is_overflow = flowhash_is_overflow(ei0);
		clib_memcpy(&tr->key, flowhash_key(h, ei0), sizeof(tr->key));
		clib_memcpy(&tr->value, flowhash_value(h, ei0), sizeof(tr->value));
		tr->is_syn = hunting_function == SRLB_SA_FN_CONNECT_IF_AVAILABLE;
	      }

	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					     n_left_to_next, pi0, next0);

	  }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Put shared objects lock */
  clib_spinlock_unlock(&srlbm->per_core[vm->thread_index].resource_lock);

  vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                SRLB_LB_CTR_OVERFLOW, table_overflow);
  vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                SRLB_LB_CTR_SESSIONS, new_sessions);
  vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                SRLB_LB_CTR_CONNECT, connect_sent);
  vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                SRLB_LB_CTR_RECOVER, recover_sent);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srlb_client_node) =
    {
	.function = srlb_client_node_fn,
	.name = "srlb-lb-client",
	.vector_size = sizeof (u32),
	.format_trace = format_srlb_client_trace,

	.n_errors = SRLB_LB_N_ERROR,
	.error_strings = srlb_lb_error_strings,

	.n_next_nodes = SRLB_LB_N_NEXT,
	.next_nodes =
	    {
		[SRLB_LB_NEXT_LOOKUP] = "ip6-lookup",
		[SRLB_LB_NEXT_DROP] = "error-drop"
	    },
    };

/** SRLB Common to Create Stickiness and Delete Stickiness */
typedef struct {
  u8 is_overflow;
  u8 no_state;
  flowhash_skey_srlb_lb_t key;
  flowhash_value_srlb_lb_t value;
  u32 entry_index;
  i32 lifetime;
} srlb_cs_ds_trace_t;

u8 *
format_srlb_cs_ds_trace (u8 * s, va_list * args, u8 delete_stickiness)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (srlb_cs_ds_trace_t *tr) =
      va_arg (*args, srlb_cs_ds_trace_t *);
  uword indent = format_get_indent (s);
  s = format(s, "SRLB LB %s Node",
	     delete_stickiness?"Delete Stickiness":"Create Stickiness");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "key: %U", format_flowhash_skey_srlb_lb, &tr->key);
  s = FORMAT_NEWLINE(s, indent);
  if (tr->no_state)
    s = format(s, "value: no state (error)");
  else
    s = format(s, "value: %U", format_flowhash_value_srlb_lb, &tr->value);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "overflow: %s", tr->is_overflow?"yes":"no");
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "entry_index: %u", tr->entry_index);
  s = FORMAT_NEWLINE(s, indent);
  s = format(s, "lifetime: %d", tr->lifetime);
  return s;
}

static_always_inline uword
srlb_cs_ds_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame,
		    u8 delete_sickyness)
{
  static CLIB_PACKED(struct {
    ip6_sr_header_t srh;
    ip6_address_t sid[3]; //FIXME
  }) ip6_sr_dummy = {
      .srh = {
	  .segments_left = 2,
      },
  };

  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 time_now = srlb_lb_time_now(vm);

  /* Any access to srlb object pools is subject to a
   * multi-reader/single-writer lock */
  clib_spinlock_lock(&srlbm->per_core[vm->thread_index].resource_lock);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  flowhash_srlb_lb_t *h = srlb_get_flow_table(vm->thread_index, time_now);

  u32 freed_index, freed_len;
  flowhash_gc_srlb_lb(h, time_now, &freed_index, &freed_len); /* Garbage collection */

  u16 table_overflows = 0;
  u16 moved_flows = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u32 error0 = SRLB_LB_ERROR_NONE;
	  ip6_header_t *ip60;
	  ip6_sr_header_t *srh0 = &ip6_sr_dummy.srh;
	  flowhash_lkey_srlb_lb_t key0;
	  flowhash_value_srlb_lb_t *val0;
	  u32 ei0;
	  u32 old_rc_state, old_rc_index;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current(p0);

	  /* Find ports and SR header */
	  key0.pad = 0;
	  key0.server = ip60->src_address; /* server is source address */
	  srlb_parse_packet (ip60, NULL, NULL,
			     &key0.server_port, &key0.client_port,
			     (ip6_ext_header_t **) &srh0, NULL, NULL);

	  /* No SR header in the packet */
	  error0 = (srh0 == &ip6_sr_dummy.srh)?SRLB_LB_ERROR_NO_SR_HEADER:error0;

	  /* Not enough SIDs in the SR header */
	  error0 = (srh0->segments_left != 2)?
	      SRLB_LB_ERROR_MISSING_SIDS:error0;

	  error0 = (srh0->length < (SRH_LEN(3) / 8))?
	      SRLB_LB_ERROR_SR_HEADER_TOO_SMALL:error0;

	  {
	    /* Get the VIP from the sid arguments */
	    srlb_lb_flow_sid_t *sid0 =
		(srlb_lb_flow_sid_t *) &ip60->dst_address.as_u64[1];

	    /* The return traffic must be hitting the same core as the
	     * one that was used for the input.
	     * TODO: Dispatch packet to correct core. */
	    error0 = (sid0->core != vm->thread_index &&
		error0 == SRLB_LB_ERROR_NONE) ?
		SRLB_LB_ERROR_WORKER_MISMATCH : error0;

	    ei0 = sid0->entry_index;

	    /* Erroneous bucket index is not a critical error.
	     * We verify later anyway. */
	    ei0 = (flowhash_is_valid_entry_index(h, ei0)) ?
	        ei0 : FLOWHASH_INVALID_ENTRY_INDEX;
	  }

	  /* Verify if flow corresponds */
	  {
	    key0.client = srh0->segments[0]; /* Client is last segment */
	    if (PREDICT_FALSE(
		flowhash_cmp_key_srlb_lb(flowhash_key(h, ei0), &key0)))
	      {
		/* Mismatch may happen in erroneous situations,
		 * or when a flow was moved or timeouted.
		 * In this case we need to try harder to find the flow entry. */
		u32 hash0 = flowhash_hash_srlb_lb (&key0);
		flowhash_get_srlb_lb (h, &key0, hash0, time_now, &ei0);
		/* We went up here just to figure the flow was not were
		 * we thought... */
		moved_flows++;
		table_overflows += (ei0 == FLOWHASH_INVALID_ENTRY_INDEX);
	      }
	  }

	  val0 = flowhash_value(h, ei0);

	  /* Remember old reference counter */
	  old_rc_state = val0->state;
	  old_rc_index = val0->index;

	  if (PREDICT_FALSE(flowhash_is_timeouted (h, ei0, time_now)))
	      val0->state = SRLB_LB_FLOW_STATE_LISTEN;

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srlb_cs_ds_trace_t *tr = vlib_add_trace(vm, node, p0, sizeof (srlb_cs_ds_trace_t));
	      tr->no_state = val0->state == SRLB_LB_FLOW_STATE_LISTEN;
	      tr->is_overflow = flowhash_is_overflow(ei0);
	      clib_memcpy(&tr->key, flowhash_key(h, ei0), sizeof(tr->key));
	      clib_memcpy(&tr->value, flowhash_value(h, ei0), sizeof(tr->value));
	      tr->entry_index = ei0;
	      tr->lifetime = flowhash_timeout(h, ei0) - time_now;
	    }

	  if (PREDICT_FALSE((!srlb_lb_state_is_established(val0->state)) ||
			    (srh0->segments[1].as_u64[0] !=
				srlbm->servers[val0->index].address.as_u64[0]) ||
				(srh0->segments[1].as_u16[4] !=
				    srlbm->servers[val0->index].address.as_u16[4])))
	    {
	      /* The steering request does not corresponds to the current state
	       * so we need to find out the server index.*/
	      clib_bihash_kv_16_8_t kv, value;
	      kv.key[0] = srh0->segments[1].as_u64[0];
	      kv.key[1] = (vnet_buffer (p0)->ip.adj_index[VLIB_TX]) |
	          (((u64) srh0->segments[1].as_u16[4]) << 32);
	      value.value = 0; /* Will stay to 0 in case of lookup failure */

	      clib_bihash_search_16_8 (&srlbm->server_index_by_vip_and_address,
	           &kv, &value);

	      val0->index = (u32) value.value;
	    }

	  /* Process state machine. */
	  if (delete_sickyness)
	    {
	      val0->state = SRLB_LB_FLOW_STATE_TEARDOWN;
	      val0->opaque = srh0->segments[1].as_u64[1];
	      flowhash_timeout(h, ei0) =
		  time_now + srlbm->flow_teardown_timeout;
	    }
	  else
	    {
	      u8 is_teardown = val0->state == SRLB_LB_FLOW_STATE_TEARDOWN;

	      /* Go to steer state, except in teardown state. */
	      val0->state = (is_teardown)?val0->state:
		  SRLB_LB_FLOW_STATE_STEER;

	      /* Remember provided opaque value */
	      val0->opaque = srh0->segments[1].as_u64[1];

	      /* Set timeout */
	      flowhash_timeout(h, ei0) =
		      time_now + ((is_teardown) ?
			  srlbm->flow_teardown_timeout:
			  srlbm->flow_active_timeout);
	    }

	  if (old_rc_state == SRLB_LB_FLOW_STATE_LISTEN)
	    {
	      vlib_refcount_add(&srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS],
	                        vm->thread_index, val0->index, 1);
	    }
	  else if (old_rc_state == SRLB_LB_FLOW_STATE_HUNTING)
	    {
	      vlib_refcount_add(&srlbm->refcount[SRLB_LB_REFCOUNT_CHTS],
	                        vm->thread_index, old_rc_index, -1);
	      vlib_refcount_add(&srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS],
	                        vm->thread_index, val0->index, 1);
	    }
	  else if (old_rc_index != val0->index)
	    {
	      vlib_refcount_add(&srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS],
	                        vm->thread_index, old_rc_index, -1);
	      vlib_refcount_add(&srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS],
	                        vm->thread_index, val0->index, 1);
	    }

	  if (PREDICT_FALSE(flowhash_is_overflow(ei0)))
	    {
	      /* In case of overflow, roll-back reference counter and
	       * reset state */
	      vlib_refcount_add(&srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS],
	                        vm->thread_index, old_rc_index, -1);
	      val0->state = SRLB_LB_FLOW_STATE_LISTEN;
	    }

	  {
	    /* Pop SRH and move IP6 header*/
	    u32 srh_len = sizeof(*srh0) + srh0->length * 8;
	    ip60->dst_address = srh0->segments[0];
	    ip60->protocol = srh0->protocol;
	    ip60->payload_length =
		clib_host_to_net_u16 (clib_net_to_host_u16 (ip60->payload_length) -
				  srh_len);
	    clib_memcpy(((u8 *)srh0) + srh_len - sizeof(*ip60),
			ip60, sizeof(*ip60));
	    vlib_buffer_advance(p0, srh_len);
	    vnet_buffer (p0)->l3_hdr_offset = p0->current_data;
	  }

	  if (PREDICT_FALSE(error0 != SRLB_LB_ERROR_NONE))
	    p0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0,
					   SRLB_LB_NEXT_LOOKUP);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                SRLB_LB_CTR_OVERFLOW , table_overflows);
  vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                SRLB_LB_CTR_MOVED , moved_flows);

  if (delete_sickyness)
    vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                  SRLB_LB_CTR_DS, frame->n_vectors);
  else
    vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                  SRLB_LB_CTR_CS, frame->n_vectors);

  clib_spinlock_unlock(&srlbm->per_core[vm->thread_index].resource_lock);

  return frame->n_vectors;
}


/** SRLB Create Stickiness SID node */

u8 *
format_srlb_cs_trace (u8 * s, va_list * args)
{
  return format_srlb_cs_ds_trace (s, args, 0);
}

static uword
srlb_cs_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return srlb_cs_ds_node_fn(vm, node, frame, 0);
}

VLIB_REGISTER_NODE (srlb_cs_node) =
    {
	.function = srlb_cs_node_fn,
	.name = "srlb-lb-cs",
	.vector_size = sizeof (u32),
	.format_trace = format_srlb_cs_trace,

	.n_errors = SRLB_LB_N_ERROR,
	.error_strings = srlb_lb_error_strings,

	.n_next_nodes = SRLB_LB_N_NEXT,
	.next_nodes =
	    {
		[SRLB_LB_NEXT_LOOKUP] = "ip6-lookup",
		[SRLB_LB_NEXT_DROP] = "error-drop"
	    },
    };

/** SRLB Delete Stickiness SID node */

u8 *
format_srlb_ds_trace (u8 * s, va_list * args)
{
  return format_srlb_cs_ds_trace (s, args, 1);
}

static uword
srlb_ds_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return srlb_cs_ds_node_fn(vm, node, frame, 1);
}

VLIB_REGISTER_NODE (srlb_ds_node) =
    {
	.function = srlb_ds_node_fn,
	.name = "srlb-lb-ds",
	.vector_size = sizeof (u32),
	.format_trace = format_srlb_ds_trace,

	.n_errors = SRLB_LB_N_ERROR,
	.error_strings = srlb_lb_error_strings,

	.n_next_nodes = SRLB_LB_N_NEXT,
	.next_nodes =
	    {
		[SRLB_LB_NEXT_LOOKUP] = "ip6-lookup",
		[SRLB_LB_NEXT_DROP] = "error-drop"
	    },
    };


/** SRLB Handoff node */

#define foreach_srlb_lb_handoff_error \
                _(NONE, "no error") \
                _(INVALID_THREAD_INDEX, "invalid thread index") \
                _(INVALID_FUNCTION, "invalid function")

typedef enum {
#define _(sym,str) SRLB_LB_HANDOFF_ERROR_##sym,
  foreach_srlb_lb_handoff_error
#undef _
  SRLB_LB_HANDOFF_N_ERROR,
} srlb_lb_handoff_error_t;

static char *srlb_lb_handoff_error_strings[] = {
#define _(sym,string) string,
    foreach_srlb_lb_handoff_error
#undef _
};

typedef struct {
  u32 from_worker_index;
  u32 next_worker_index;
  u32 next_delete_stickyness;
} srlb_lb_handoff_trace_t;

u8 *
format_srlb_lb_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srlb_lb_handoff_trace_t * t =
      va_arg (*args, srlb_lb_handoff_trace_t *);
  s = format (s, "%s handoff from:%u to:%u",
              t->next_delete_stickyness ? "ds" : "cs",
                  t->from_worker_index, t->next_worker_index);

  return s;
}

static uword
srlb_lb_handoff_node_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u32 thread_index = vlib_get_thread_index ();
  u32 thread_max = vlib_get_thread_main()->n_vlib_mains;

  /* Where to get packets from */
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;

  /* Enqueue to another thread thread */
  u32 current_worker_index = ~0;
  u32 current_ds = 0;
  vlib_frame_queue_elt_t *hf = 0;

  /* Enqueue to the same thread */
  u32 *to_next;
  u32 n_left_to_next;
  u32 next_index = node->cached_next_index;

  u16 handoff_counter = 0;

  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
  while (n_left_from > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      u8 next_ds;
      u32 next_worker_index;
      ip6_header_t *ip60;
      u32 error0 = SRLB_LB_HANDOFF_ERROR_NONE;

      pi0 = from[0];
      from++;
      n_left_from--;

      p0 = vlib_get_buffer (vm, pi0);
      ip60 = vlib_buffer_get_current(p0);

      /* Get worker and function from adjacency */
      next_ds = ip60->dst_address.as_u8[10] >> 4;
      if (PREDICT_TRUE(next_ds == SRLB_LB_FN_CREATE_STICKINESS))
        next_ds = SRLB_LB_HANDOFF_NEXT_CS;
      else if (PREDICT_TRUE(next_ds == SRLB_LB_FN_DELETE_STICKINESS))
        next_ds = SRLB_LB_HANDOFF_NEXT_DS;
      else
        error0 = SRLB_LB_HANDOFF_ERROR_INVALID_FUNCTION;

      next_worker_index = ip60->dst_address.as_u8[11];
      if (PREDICT_FALSE(next_worker_index >= thread_max))
        {
          error0 = SRLB_LB_HANDOFF_ERROR_INVALID_THREAD_INDEX;
          next_worker_index = thread_index;
        }

      if (next_worker_index != thread_index)
        {
          handoff_counter++;

          /* do handoff */
          if (next_worker_index != current_worker_index ||
              next_ds != current_ds)
            {
allocate_hf:
              hf = vlib_get_worker_handoff_queue_elt ((next_ds == SRLB_LB_HANDOFF_NEXT_DS)?srlbm->fq_ds_index:srlbm->fq_cs_index,
                                                      next_worker_index,
                                                      srlbm->per_core[thread_index].handoff_per_fn[next_ds].per_worker);

              current_worker_index = next_worker_index;
              current_ds = next_ds;
            }

          if (PREDICT_FALSE(hf->n_vectors == VLIB_FRAME_SIZE))
            {
              vlib_put_frame_queue_elt (hf);
              srlbm->per_core[thread_index].handoff_per_fn[current_ds].per_worker[current_worker_index] = 0;
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
          if (PREDICT_FALSE(error0 != SRLB_LB_HANDOFF_ERROR_NONE))
            {
              next_ds = SRLB_LB_HANDOFF_NEXT_DROP;
              p0->error = node->errors[error0];
            }

          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, pi0, next_ds);

          if (n_left_to_next == 0)
            {
              vlib_put_next_frame (vm, node, next_index, n_left_to_next);
              vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
            }
        }

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                         && (p0->flags & VLIB_BUFFER_IS_TRACED)))
        {
          srlb_lb_handoff_trace_t *t =
              vlib_add_trace (vm, node, p0, sizeof (*t));
          t->next_worker_index = next_worker_index;
          t->from_worker_index = thread_index;
          t->next_delete_stickyness = next_ds;
        }
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  /* Ship frames to the worker nodes */
  int i;
  for (current_ds = 0; current_ds < 2; current_ds++)
    vec_foreach_index(i, srlbm->per_core[thread_index].handoff_per_fn[current_ds].per_worker)
      {
        hf = srlbm->per_core[thread_index].handoff_per_fn[current_ds].per_worker[i];
        srlbm->per_core[thread_index].handoff_per_fn[current_ds].per_worker[i] = 0;
        if (hf)
          vlib_put_frame_queue_elt (hf);
      }

    vlib_increment_simple_counter(&srlbm->counters, vm->thread_index,
                                  SRLB_LB_CTR_HANDOFF, handoff_counter);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srlb_lb_handoff_node) =
    {
        .function = srlb_lb_handoff_node_fn,
        .name = "srlb-lb-handoff",
        .vector_size = sizeof (u32),
        .format_trace = format_srlb_lb_handoff_trace,

        .n_errors = SRLB_LB_HANDOFF_N_ERROR,
        .error_strings = srlb_lb_handoff_error_strings,

        .n_next_nodes = SRLB_LB_HANDOFF_N_NEXT,
        .next_nodes =
            {
                [SRLB_LB_HANDOFF_NEXT_CS] = "srlb-lb-cs",
                [SRLB_LB_HANDOFF_NEXT_DS] = "srlb-lb-ds",
                [SRLB_LB_HANDOFF_NEXT_DROP] = "error-drop"
            },
    };

