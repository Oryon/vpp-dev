#include <plugins/srlb/srlb-lb.h>

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

#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/format.h>

static void srlb_server_stack (srlb_lb_server_t *server);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "SRv6 Application-Aware Load Balancer",
};
/* *INDENT-ON* */

srlb_lb_main_t srlb_lb_main = {};

const char *srlb_lb_flow_state_strings[] = {
#define _(t, n) [SRLB_LB_FLOW_STATE_##t] = #t,
  srlb_for_each_lb_flow_state
#undef _
};

uword unformat_srlb_lb_flow_state (unformat_input_t * input, va_list * args)
{
  u32 *state = va_arg (*args, u32 *);
  int i;
  for (i=0; i<ARRAY_LEN(srlb_lb_flow_state_strings); i++)
    {
      if (unformat(input, srlb_lb_flow_state_strings[i]))
	{
	  *state = i;
	  return 1;
	}
    }
  return 0;
}

static
u8 *format_fib_index (u8 * s, va_list * args)
{
  u32 fib_index = va_arg (*args, u32);
  fib_table_t *fib_table = fib_table_get(fib_index, FIB_PROTOCOL_IP6);
  if (fib_table == NULL)
    return format(s, "invalid-fib-index");

  return format(s, "%d", fib_table->ft_table_id);
}

u8 *format_srlb_lb_flow_state (u8 * s, va_list * args)
{
  srlb_lb_flow_state state = va_arg (*args, srlb_lb_flow_state);
  if (state >= ARRAY_LEN(srlb_lb_flow_state_strings))
    return format (s, "invalid-state-value");

  return format(s, "%s", srlb_lb_flow_state_strings[state]);
}

#define FORMAT_NEWLINE(s, i) format(s, "\n%U", format_white_space, i)
#define FORMAT_WNL(s, i, ...) format(FORMAT_NEWLINE(s, i), __VA_ARGS__)

u8 *format_srlb_lb_flows_with_verbosity (u8 *s, va_list * args)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u32 ti = va_arg (*args, u32);
  int verbosity = va_arg (*args, u32);
  uword i = format_get_indent (s);
  flowhash_srlb_lb_t *h = srlbm->per_core[ti].flow_table;
  u32 ei;
  u32 time_now = srlb_lb_time_now(vlib_mains[ti]);

  if (h == NULL)
    return format(s, "(nil)");

  s = format(s, "memory: %p %U", h->mem, format_memory_size, flowhash_memory_size(h));
  s = FORMAT_WNL(s, i, "fixed-entries: %d", h->fixed_entries_mask + 1);
  s = FORMAT_WNL(s, i, "collision-buckets-total: %d", h->collision_buckets_mask + 1);
  s = FORMAT_WNL(s, i, "collision-buckets-free: %d", -h->free_buckets_position);

  if (verbosity == 0)
    return s;

  s = FORMAT_WNL(s, i, "table:");
  flowhash_foreach_valid_entry(h, ei, time_now)
  {
    flowhash_skey_srlb_lb_t *key = flowhash_key(h, ei);
    flowhash_value_srlb_lb_t *val = flowhash_value(h, ei);
    u32 timeout = flowhash_timeout(h, ei);
    s = FORMAT_WNL(s, i, "  [%d]", ei);
    s = FORMAT_WNL(s, i, "    %U", format_flowhash_skey_srlb_lb, key);
    s = FORMAT_WNL(s, i, "    %U", format_flowhash_value_srlb_lb, val);
    s = FORMAT_WNL(s, i, "    remaining lifetime: %d", timeout - time_now);
  }

  return s;
}

u8 *format_srlb_lb_server (u8 * s, va_list * args)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  srlb_lb_server_t *server = va_arg (*args, srlb_lb_server_t *);
  uword i = format_get_indent (s);
  s = format(s,        "server: %U", format_ip6_address, &server->address);
  s = FORMAT_WNL(s, i, "established: %u", vlib_refcount_get(
      &srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS], server - srlbm->servers));
  s = FORMAT_WNL(s, i, "pools: %U", format_u32_bitmask_list, server->pool_bitmask);
  s = FORMAT_WNL(s, i, "dpo_index: %d", server->dpo.dpoi_index);
  s = FORMAT_WNL(s, i, "dpo_next_index: %d", server->dpo.dpoi_next_node);
  s = FORMAT_WNL(s, i, "hunting references: %u", server->hunting_refcount);
  return s;
}

u8 *format_srlb_lb_vip_with_verbosity (u8 * s, va_list * args)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  srlb_lb_vip_t *vip = va_arg (*args, srlb_lb_vip_t *);
  int verbosity = va_arg (*args, int);
  uword i = format_get_indent (s);
  s = format(s, "%U/%u rx-client-table-id: %U", format_ip6_address, &vip->prefix,
             vip->prefix_length, format_fib_index, vip->client_rx_fib_index);

  if (verbosity == 0)
    return s;

  s = FORMAT_WNL(s, i, "sr-prefix: %U", format_ip6_address, &vip->sr_prefix);
  s = FORMAT_WNL(s, i, "client-rx-fib-index: %d", vip->client_rx_fib_index);
  s = FORMAT_WNL(s, i, "client-tx-fib-index: %d", vip->client_tx_fib_index);
  s = FORMAT_WNL(s, i, "sr-rx-fib-index: %d", vip->sr_rx_fib_index);
  s = FORMAT_WNL(s, i, "sr-tx-fib-index: %d", vip->sr_tx_fib_index);
  s = FORMAT_WNL(s, i, "hash: %U", format_srlb_lb_vip_hash, vip->hash);
  s = FORMAT_WNL(s, i, "buckets: %d", vip->cht_size);
  s = FORMAT_WNL(s, i, "servers:");

  u32 *sip;
  pool_foreach(sip, vip->server_indices, {
      if (verbosity >= 2)
        s = FORMAT_WNL(s, i, "  [%d] %d %U", sip - vip->server_indices, *sip,
                       format_srlb_lb_server, &srlbm->servers[*sip]);
      else
        s = FORMAT_WNL(s, i, "  [%d] %d %U", sip - vip->server_indices, *sip,
                       format_ip6_address, &srlbm->servers[*sip].address);
  });

  if (verbosity >=3)
    {
      /* buckets */
      s = FORMAT_WNL(s, i, "consistent-hash-table:");
      srlb_lb_vip_cht_t *cht = &srlbm->chts[vip->cht_index];
      u32 bi, c;
      for (bi = 0; bi <= cht->mask; bi++)
        {
          s = FORMAT_WNL(s, i, "  [%d]", bi);
          for (c = 0; c < cht->n_choices; c++)
            {
              u32 si = cht->buckets[bi * cht->n_choices + c];
              s = FORMAT_WNL(s, i, "    [%d] %d %U", c, si,
                             format_ip6_address, &srlbm->servers[si].address);
            }
        }
    }

  return s;
}

u8 *format_flowhash_skey_srlb_lb (u8 * s, va_list * args)
{
  flowhash_skey_srlb_lb_t *key = va_arg (*args, flowhash_skey_srlb_lb_t *);
  uword i = format_get_indent (s);
  s = format(s, "client: %U", format_ip6_address, &key->client);
  s = FORMAT_WNL(s, i, "server: %U", format_ip6_address, &key->server);
  s = FORMAT_WNL(s, i, "client_port: %d", clib_net_to_host_u16(key->client_port));
  s = FORMAT_WNL(s, i, "server_port: %d", clib_net_to_host_u16(key->server_port));
  return s;
}

u8 *format_flowhash_value_srlb_lb (u8 * s, va_list * args)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  flowhash_value_srlb_lb_t *val = va_arg (*args, flowhash_value_srlb_lb_t *);
  uword i = format_get_indent (s);
  s = format(s, "state: %U", format_srlb_lb_flow_state, val->state);
  if (val->state == SRLB_LB_FLOW_STATE_HUNTING)
    {
      srlb_lb_vip_cht_t *cht = &srlbm->chts[val->index];
      int j;
      s = FORMAT_WNL(s, i, "server list:");
      for (j = 0; j < cht->n_choices; j++)
          s = FORMAT_WNL(s, i, "[%d] %U", j, format_ip6_address,
                         &srlbm->servers[cht->buckets[val->bucket_index + j]].address);
    }
  else if (val->state != SRLB_LB_FLOW_STATE_LISTEN)
    {
      if (pool_is_free_index(srlbm->servers, val->index))
	{
	  s = FORMAT_WNL(s, i, "server: (%d) ERROR", val->index);
	}
      else
	{
	  ip6_address_t address;
	  address.as_u64[0] = srlbm->servers[val->index].address.as_u64[0];
	  address.as_u64[1] = val->opaque;
	  s = FORMAT_WNL(s, i, "server: (%d) %U", val->index,
		      format_ip6_address, &address);
	}
    }
  return s;
}

u8 *format_srlb_lb_vip_hash (u8 * s, va_list * args)
{
  srlb_lb_vip_hash_t hash = va_arg (*args, int);
  if (hash == SRLB_LB_VIP_HASH_VIP)
    return format (s, "vip");
  else if (hash == SRLB_LB_VIP_HASH_5_TUPLE)
    return format (s, "5-tuple");

  return format (s, "unknown");
}

uword unformat_srlb_lb_vip_hash (unformat_input_t * input, va_list * args)
{
  srlb_lb_vip_hash_t *hash = va_arg (*args, srlb_lb_vip_hash_t *);
  *hash = SRLB_LB_VIP_HASH_INVALID;
  if (unformat (input, "vip"))
    *hash = SRLB_LB_VIP_HASH_VIP;
  else if (unformat (input, "5-tuple"))
    *hash = SRLB_LB_VIP_HASH_5_TUPLE;

  return (*hash != SRLB_LB_VIP_HASH_INVALID);
}

static_always_inline void srlb_writer_lock()
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  srlb_lb_per_core_t *pc;
  SRLB_LB_LOG_DEBUG("Get writer lock");
  vec_foreach(pc, srlbm->per_core)
    clib_spinlock_lock(&pc->resource_lock);
}

static_always_inline void srlb_writer_unlock()
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  srlb_lb_per_core_t *pc;
  vec_foreach(pc, srlbm->per_core)
    clib_spinlock_unlock(&pc->resource_lock);
  SRLB_LB_LOG_DEBUG("Put writer lock");
}

/**
 * Thread protected way to allocate elements in SRLB object pools.
 * Lockless unless structure has to be resized, in which case it uses
 * SRLB global lock and doubles in size.
 */
#define srlb_lb_pool_get(pool, e) \
  do { \
    u32 __pryn; \
    pool_get_will_expand(pool, __pryn); \
    if (__pryn) \
      { \
        srlb_writer_lock(); \
        pool_alloc(pool, (pool_len(pool))?(pool_len(pool)):16); \
        srlb_writer_unlock(); \
      } \
    pool_get(pool,e); \
  } while (0);

static int srlb_server_sort (u32 *si1, u32 *si2)
{
  return memcmp(&srlb_lb_main.servers[*si1].address,
		&srlb_lb_main.servers[*si2].address, sizeof(ip6_address_t));
}

static void
srlb_lb_server_gc (srlb_lb_vip_t *vip, srlb_lb_server_t *s, u32 time_now);

/**
 * Garbage collect chts for a given vip
 */
static void
srlb_vip_gc(srlb_lb_vip_t * vip)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u32 time_now = srlb_lb_time_now(vlib_get_main());
  u32 *cht_index;
  u32 *server_index;

  SRLB_LB_LOG_DEBUG("Executing garbage collection for vip %U", format_srlb_lb_vip_with_verbosity, vip, 0);

  pool_foreach(cht_index, vip->cht_indices, {
      srlb_lb_vip_cht_t *cht = &srlbm->chts[*cht_index];
      if (cht->freed_timestamp == ~0 ||
          time_now <= cht->freed_timestamp + SRLB_LB_CHT_GC_TIMEOUT ||
          vlib_refcount_get(&srlbm->refcount[SRLB_LB_REFCOUNT_CHTS], *cht_index))
        continue;

      SRLB_LB_LOG_DEBUG("Freeing CHT index %d", *cht_index);

      /* Counting server references */
      int i;
      for (i = 0; i < (cht->mask + 1) * cht->n_choices; i++)
        {
          srlbm->servers[cht->buckets[i]].hunting_refcount--;
          srlb_lb_server_gc (vip, &srlbm->servers[cht->buckets[i]], time_now);
        }

      /* Freeing cht */
      vec_free(cht->buckets);
      pool_put(vip->cht_indices, cht_index);
      pool_put(srlbm->chts, cht);
  });

  pool_foreach(server_index, vip->server_indices, {
      srlb_lb_server_gc(vip, &srlbm->servers[*server_index], time_now);
  });
}

static void
srlb_generate_consistent_hash_table(srlb_lb_vip_t * vip)
{
  static u32 *server_indices = 0;
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  srlb_lb_vip_cht_t *cht;
  u32 n_buckets = vip->cht_size;
  u32 n_servers = pool_elts(vip->server_indices);
  u32 n_choices = 0;
  u8 bitposition_to_choice[32] = {};
  u8 choice_to_bitposition[32] = {};
  int i, c, n;

  SRLB_LB_LOG_DEBUG("Rebuilding consistent hash table for VIP:\n"
      "%U", format_srlb_lb_vip_with_verbosity, vip, 0);

  srlb_vip_gc(vip);

  /** Get a cht in a thread safe way. */
  srlb_lb_pool_get(srlbm->chts, cht);
  cht->buckets = 0;

  SRLB_LB_LOG_DEBUG("Allocated CHT index %d", cht - srlbm->chts);

  {
    u32 choice_bitmask;
    u32 *server_index_in_vip;

    /* Construct server list and global choices bitmask */
    choice_bitmask = 0;
    vec_reset_length(server_indices);
    pool_foreach(server_index_in_vip, vip->server_indices, {
        vec_add1(server_indices, *server_index_in_vip);
        choice_bitmask |= srlbm->servers[*server_index_in_vip].pool_bitmask;
    });

    /* Sorting servers list */
    vec_sort_with_function(server_indices, srlb_server_sort);

    /* Counting choices and creating bit index to choice mapping */
    n_choices = 0;
    for (i = 0; i < 32; i++)
      if (choice_bitmask & (1 << i))
        {
          SRLB_LB_LOG_DEBUG("  Server pool %u is choice #%u\n",
                            i, n_choices);
          bitposition_to_choice[i] = n_choices;
          choice_to_bitposition[n_choices] = i;
          n_choices++;
        }

  }

  /* No configured server */
  if (n_choices == 0)
    return;

  /* Allocating bucket array */
  vec_validate(cht->buckets, n_buckets * n_choices - 1);

  /* Zero everything ! */
  memset(cht->buckets, 0, n_buckets * n_choices * sizeof(u32));

  /* Random number generators.
   * Static, so they get reused. */
  static struct {
    u32 offset;
    u32 skip;
    u32 i;
    u32 pool_bitmask;
  } *generators = 0;
  vec_validate(generators, n_servers - 1);

  /* Initialize the pseudo random parameters */
  for (i=0; i<n_servers; i++)
    {
      srlb_lb_server_t *server = &srlbm->servers[server_indices[i]];
      generators[i].offset =
          hash_memory(&server->address, sizeof(ip6_address_t), 42) & (n_buckets - 1);
      generators[i].skip =
          (hash_memory(&server->address, sizeof(ip6_address_t), 0) & (n_buckets - 1)) | 1;
      generators[i].i = 0;
      generators[i].pool_bitmask = server->pool_bitmask;
    }

  /* Consistent hashing algorithm */
  i = 0; /* Step counter */
  c = 0; /* Server index */
  u32 n_servers_done = 0;
  while (n_servers_done != n_servers)
    {
next:
      /* This server permutation is exhausted */
      if (generators[c].i >= n_buckets)
        {
          c = (c+1) % n_servers; /* Next server */
          if (generators[c].i == n_buckets)
            {
              generators[c].i++;
              n_servers_done ++;
            }
          continue;
        }

      /* Compute bucket index */
      u32 bi = (generators[c].offset +
          generators[c].skip * generators[c].i) & (n_buckets - 1);
      generators[c].i++; /* Next permutation index */

      u32 bitmask_overlap = generators[c].pool_bitmask;
      u32 index;
      while ((n = ffs(bitmask_overlap)))
        {
          /* Clear lowest set bit */
          bitmask_overlap = bitmask_overlap & (bitmask_overlap-1);

          /* Check if already there */
          index = bi * n_choices + bitposition_to_choice[n - 1];
          if (cht->buckets[index] == 0)
            break;
        }

      if (n == 0)
        goto next;

      cht->buckets[index] = server_indices[c];
      c = (c+1) % n_servers; /* Next chance for next server. */
      i++;
    }

  /* Sometimes, the algorithm doesn't fill all the positions.
   * We need to fill the holes with already selected servers. */
  for (i = 0; i < n_buckets; i++) /* Check all buckets */
    for (c = 0; c < n_choices; c++) /* And all choices */
      if (cht->buckets[i * n_choices + c] == 0) /* If no server ther */
        for (n = 0; n < c; n++) /* Look at previous choices */
          if (srlbm->servers[cht->buckets[i * n_choices + n]].pool_bitmask &
              (1 << choice_to_bitposition[c]))
            {
              /* Found a server which is configured for that choice */
              cht->buckets[i * n_choices + c] =
                  cht->buckets[i * n_choices + n];
              break;
            }

  /* Init other cht fields */
  cht->n_choices = n_choices;
  cht->freed_timestamp = ~0;
  cht->mask = n_buckets - 1;

  /* Previously used cht is candidate for garbage collection,
   * but only after we make sure no one is referencing it. */
  srlbm->chts[vip->cht_index].freed_timestamp =
      srlb_lb_time_now(vlib_get_main());
  u32 *index;
  pool_get(vip->cht_indices, index);
  *index = cht - srlbm->chts;

  /* Atomic operation submitting the new cht to worker threads */
  vip->cht_index = cht - srlbm->chts;

  /* Counting server references */
  for (i = 0; i < n_buckets * n_choices; i++)
    srlbm->servers[cht->buckets[i]].hunting_refcount++;
}

static void
srlb_vip_add_adjacencies(srlb_lb_vip_t * vip)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  dpo_id_t dpo = DPO_INVALID;
  fib_prefix_t fib_prefix = {
      .fp_addr.ip6 = vip->prefix,
      .fp_len = vip->prefix_length,
      .fp_proto = FIB_PROTOCOL_IP6
  };

  /* Add client rx FIB entry */
  dpo_set(&dpo, srlbm->dpo_client_type, DPO_PROTO_IP6, vip - srlbm->vips);
  fib_table_entry_special_dpo_add(vip->client_rx_fib_index,
				  &fib_prefix,
				  FIB_SOURCE_PLUGIN_HI,
				  FIB_ENTRY_FLAG_EXCLUSIVE,
				  &dpo);
  dpo_reset(&dpo);

  /* Add SR rx FIB entry */
  fib_prefix_t pfx = {
      .fp_addr.ip6 = vip->sr_prefix,
      .fp_len = 80,
      .fp_proto = FIB_PROTOCOL_IP6,
  };

  dpo_set(&dpo, srlbm->dpo_handoff_type, DPO_PROTO_IP6, vip - srlbm->vips);
  fib_table_entry_special_dpo_add(vip->sr_rx_fib_index, &pfx,
                                  FIB_SOURCE_PLUGIN_HI,
                                  FIB_ENTRY_FLAG_EXCLUSIVE,
                                  &dpo);
  dpo_reset(&dpo);
}

static void
srlb_vip_del_adjacencies(srlb_lb_vip_t * vip)
{
  /* Remove client rx FIB entry */
  fib_prefix_t pfx0 = {
      .fp_addr.ip6 = vip->prefix,
      .fp_len = vip->prefix_length,
      .fp_proto = FIB_PROTOCOL_IP6
  };
  fib_table_entry_special_remove(vip->client_rx_fib_index,
                                 &pfx0, FIB_SOURCE_PLUGIN_HI);

  /* Remove SR rx FIB entry*/
  fib_prefix_t pfx1 = {
      .fp_addr.ip6 = vip->sr_prefix,
      .fp_len = 80,
      .fp_proto = FIB_PROTOCOL_IP6,
  };
  fib_table_entry_special_remove(vip->sr_rx_fib_index,
                                 &pfx1, FIB_SOURCE_PLUGIN_HI);
}

/** Returns server index from address and vip object. */
u32 srlb_get_server_index (srlb_lb_vip_t *vip, ip6_address_t *address)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  clib_bihash_kv_16_8_t kv, value;
  kv.key[0] = address->as_u64[0];
  kv.key[1] = (vip - srlbm->vips) | (((u64) address->as_u16[4]) << 32);

  if (clib_bihash_search_16_8 (&srlbm->server_index_by_vip_and_address,
			       &kv, &value))
      return ~0;

  return (u32) value.value;
}

/**
 * Frees server memory, called for garbage collection once no more
 * references are left.
 */
static void
srlb_server_free(srlb_lb_vip_t *vip, srlb_lb_server_t *s)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  /* Check that this server has been properly dereferenced */
  ASSERT(s->hunting_refcount == 0);
  ASSERT(s->freed_timestamp != ~0);
  ASSERT(vlib_refcount_get(&srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS],
                           s - srlbm->servers) == 0);

  SRLB_LB_LOG_DEBUG("Freeing server %U from VIP %U/%u",
                    format_ip6_address, &s->address,
                    format_ip6_address, &vip->prefix, vip->prefix_length);

  /* Delete from hash table */
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = s->address.as_u64[0];
  kv.key[1] = (vip - srlbm->vips) | (((u64) s->address.as_u16[4]) << 32);
  clib_bihash_add_del_16_8 (&srlbm->server_index_by_vip_and_address,
                            &kv, 0 /* is_add */ );

  /* Remove subscription to next hop */
  fib_entry_child_remove(s->next_hop_fib_entry_index,
                         s->next_hop_child_index);
  fib_table_entry_delete_index(s->next_hop_fib_entry_index,
                               FIB_SOURCE_RR);
  s->next_hop_fib_entry_index = FIB_NODE_INDEX_INVALID;

  /* Free elements */
  pool_put_index(vip->server_indices, s->index_in_vip);
  pool_put(srlbm->servers, s);
}

static void
srlb_lb_server_gc (srlb_lb_vip_t *vip, srlb_lb_server_t *s, u32 time_now)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u8 referenced = s->hunting_refcount || s->pool_bitmask ||
      vlib_refcount_get(&srlbm->refcount[SRLB_LB_REFCOUNT_SERVERS],
                        s - srlbm->servers);

  if (referenced)
    s->freed_timestamp = ~0;
  else if (s->freed_timestamp == ~0)
    s->freed_timestamp = time_now;
  else if (s->freed_timestamp < time_now + SRLB_LB_SERVER_GC_TIMEOUT)
    {
      srlb_server_free(vip, s);
    }
}

static srlb_lb_server_t *
srlb_server_alloc(srlb_lb_vip_t *vip, ip6_address_t *a)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  srlb_lb_server_t *s;
  /* Allocate new server */
  srlb_lb_pool_get(srlbm->servers, s);
  s->address = *a;
  s->address.as_u32[3] = 0;
  s->address.as_u16[5] = 0;
  s->pool_bitmask = 0;
  s->freed_timestamp = ~0;

  u32 *index_in_vip_p;
  pool_get(vip->server_indices, index_in_vip_p);
  *index_in_vip_p = s - srlbm->servers;
  s->index_in_vip = index_in_vip_p - vip->server_indices;

  /* Add to hash table */
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = s->address.as_u64[0];
  kv.key[1] = (vip - srlbm->vips) | (((u64) s->address.as_u16[4]) << 32);
  kv.value = s - srlbm->servers;

  if (clib_bihash_add_del_16_8 (&srlbm->server_index_by_vip_and_address,
                                &kv, 1 /* is_add */ ))
    {
      pool_put(srlbm->servers, s);
      pool_put_index(vip->server_indices, s->index_in_vip);
      return NULL;
    }

  /*
   * become a child of the FIB entry
   * so we are informed when its forwarding changes
   */
  fib_prefix_t nh = {};
  nh.fp_addr.ip6 = s->address;
  nh.fp_len = 128;
  nh.fp_proto = FIB_PROTOCOL_IP6;

  s->next_hop_fib_entry_index =
      fib_table_entry_special_add(vip->sr_tx_fib_index,
                                  &nh,
                                  FIB_SOURCE_RR,
                                  FIB_ENTRY_FLAG_NONE);
  s->next_hop_child_index =
      fib_entry_child_add(s->next_hop_fib_entry_index,
                          srlbm->fib_node_type,
                          s - srlbm->servers);

  srlb_server_stack(s);
  return s;
}


/** Remove servers from a VIP */
static int
srlb_server_del(srlb_lb_vip_t *vip, u32 pool_bitmask,
                ip6_address_t *addresses, u32 n)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  clib_bihash_kv_16_8_t kv;
  srlb_lb_server_t *s;
  u8 generate_consistent_hash_table = 0;
  u32 n_servers = pool_elts(vip->server_indices);
  u32 time_now = vlib_time_now(vlib_get_main());
  int i;
  for (i=0; i<n; i++)
    {
      u32 si = srlb_get_server_index(vip, &addresses[i]);
      if (si == ~0)
	{
	  SRLB_LB_LOG_WARN("Server %U is not configured for VIP %U/%u",
	  			   format_ip6_address, &addresses[i],
	  			   format_ip6_address, &vip->prefix, vip->prefix_length);
	  continue;
	}

      s = &srlbm->servers[si];
      if (!(pool_bitmask & s->pool_bitmask))
        {
          SRLB_LB_LOG_WARN("Server %U is not in none of pools %U of VIP %U/%u",
                           format_ip6_address, &addresses[i],
                           format_u32_bitmask_list, pool_bitmask,
                           format_ip6_address, &vip->prefix, vip->prefix_length);
          continue;
        }

      if ((pool_bitmask & s->pool_bitmask) != pool_bitmask)
        SRLB_LB_LOG_WARN("Server %U is not in pools %U of VIP %U/%u",
                         format_ip6_address, &addresses[i],
                         format_u32_bitmask_list, pool_bitmask & ~s->pool_bitmask,
                         format_ip6_address, &vip->prefix, vip->prefix_length);

      SRLB_LB_LOG_DEBUG("Deleting server %U from pools %U in VIP %U/%u",
			format_ip6_address, &addresses[i],
			format_u32_bitmask_list, pool_bitmask & s->pool_bitmask,
			format_ip6_address, &vip->prefix, vip->prefix_length);

      s->pool_bitmask &= ~pool_bitmask;
      srlb_lb_server_gc (vip, s, time_now);

      generate_consistent_hash_table = 1;

      if (s->pool_bitmask == 0)
        {
          /* Del from hash table */
          kv.key[0] = s->address.as_u64[0];
          kv.key[1] = (vip - srlbm->vips) | (((u64) s->address.as_u16[4]) << 32);
          kv.value = (s - srlbm->servers) | 1L << 32;

          /* Set server as removed in hash table */
          clib_bihash_add_del_16_8 (&srlbm->server_index_by_vip_and_address,
                                    &kv, 1 /* is_add */ );
        }
    }

  //TODO: Implement hard shutdown, removing state for existing flows

  /** Last server in VIP was removed */
  if (pool_elts(vip->server_indices) == 0 && n_servers)
    srlb_vip_del_adjacencies(vip);

  if (generate_consistent_hash_table)
    srlb_generate_consistent_hash_table(vip);

  return 0;
}

static int
srlb_server_add(srlb_lb_vip_t *vip, u32 pool_bitmask,
                ip6_address_t *addresses, u32 n)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u8 generate_consistent_hash_table = 0;
  u32 n_servers = pool_elts(vip->server_indices);
  int i;
  for (i=0; i<n; i++)
    {
      srlb_lb_server_t *s = NULL;
      u32 si = srlb_get_server_index(vip, &addresses[i]);
      if (si != ~0)
	{
          s = &srlbm->servers[si];
          if ((s->pool_bitmask & pool_bitmask))
            SRLB_LB_LOG_WARN("Server %U already configured for pools %U in VIP %U/%u",
                             format_ip6_address,  &addresses[i],
                             format_u32_bitmask_list, s->pool_bitmask & pool_bitmask,
                             format_ip6_address,  &vip->prefix, vip->prefix_length);


          if ((s->pool_bitmask & pool_bitmask) == pool_bitmask)
            continue;


	}
      else
        {
          SRLB_LB_LOG_DEBUG("Creating server %U to VIP %U/%u",
                            format_ip6_address, &addresses[i],
                            format_ip6_address, &vip->prefix, vip->prefix_length);

          if (!(s = srlb_server_alloc(vip, &addresses[i])))
            {
              SRLB_LB_LOG_ERR("Adding server %U to VIP %U/%u failed !",
                              format_ip6_address, &addresses[i],
                              format_ip6_address, &vip->prefix, vip->prefix_length);
              /* FIXME: Rollback may remove pools that were already there.
               * Fix would be to remember the previous pool state and
               * apply it again. */
              if (i)
                srlb_server_del(vip, pool_bitmask, addresses, i);

              return VNET_API_ERROR_TABLE_TOO_BIG;
            }
        }

      SRLB_LB_LOG_DEBUG("Adding server %U to pools %U in VIP %U/%u",
                       format_ip6_address,  &addresses[i],
                       format_u32_bitmask_list, (~s->pool_bitmask) & pool_bitmask,
                       format_ip6_address,  &vip->prefix, vip->prefix_length);

      s->pool_bitmask |= pool_bitmask;
      s->freed_timestamp = ~0; /* Reset free timeout */

      generate_consistent_hash_table = 1;
    }

  if (generate_consistent_hash_table)
    srlb_generate_consistent_hash_table(vip);

  if (pool_elts(vip->server_indices) != 0 && n_servers == 0)
    srlb_vip_add_adjacencies(vip);

  return 0;
}

srlb_lb_vip_t *
srlb_get_vip(ip6_address_t * vip_address, u8 plen, u32 client_rx_fib_index)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  srlb_lb_vip_t *vip;
  pool_foreach(vip, srlbm->vips, ({
    if ((vip->prefix_length == plen &&
        vip->client_rx_fib_index == client_rx_fib_index &&
        ip6_address_is_equal(vip_address, &vip->prefix)))
      return vip;
  }));
  return NULL;
}

int srlb_lb_server_add_del(srlb_lb_server_add_del_args_t *args)
{
  srlb_lb_vip_t *vip;

  if (!(args->flags & SRLB_LB_API_FLAGS_CLIENT_RX_FIB_SET))
    args->client_rx_fib_index = 0;

  vip = srlb_get_vip (&args->vip_address,
                     args->vip_prefix_length,
                     args->client_rx_fib_index);

  if (vip == NULL)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (args->flags & SRLB_LB_API_FLAGS_IS_DEL)
    return srlb_server_del(vip, args->pool_bitmask,
                           args->server_addresses, args->server_count);
  else
    return srlb_server_add(vip, args->pool_bitmask,
                           args->server_addresses, args->server_count);
}

int
srlb_lb_vip_conf (srlb_lb_vip_conf_args_t *args)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  srlb_lb_vip_t *vip;

  if (!(args->flags & SRLB_LB_API_FLAGS_CLIENT_RX_FIB_SET))
    args->client_rx_fib_index = 0;

  vip = srlb_get_vip (&args->vip_address,
                      args->vip_prefix_length,
                      args->client_rx_fib_index);

  if ((args->flags & SRLB_LB_API_FLAGS_IS_DEL) && vip == NULL)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if ((args->flags & SRLB_LB_API_FLAGS_IS_DEL))
    {
      ip6_address_t *addresses = 0;
      u32 *si;
      pool_foreach(si, vip->server_indices, {
	vec_add1(addresses, srlbm->servers[*si].address);
      });

      srlb_server_del(vip, 0xffffffff, addresses, vec_len(addresses));
      vec_free(addresses);

      SRLB_LB_LOG_DEBUG("Deleting VIP %U/%u",
			format_ip6_address, &args->vip_address, args->vip_prefix_length);

      pool_free(vip->server_indices);
      pool_free(vip->cht_indices);
      pool_put(srlbm->vips, vip);
      return 0;
    }

  if (srlbm->fq_cs_index == ~0)
    {
      SRLB_LB_LOG_DEBUG("Initializing thread handoff queues");
      vlib_worker_thread_barrier_sync (vlib_get_main());
      srlbm->fq_cs_index =
          vlib_frame_queue_main_init (srlb_cs_node.index, 0);
      srlbm->fq_ds_index =
          vlib_frame_queue_main_init (srlb_ds_node.index, 0);
      vlib_worker_thread_barrier_release (vlib_get_main());
    }

  /* Apply default */
  if (!(args->flags & SRLB_LB_API_FLAGS_CONSISTENT_HASHTABLE_SIZE_SET))
    args->consistent_hashtable_size =
        SRLB_LB_DEFAULT_CONSISTENT_HASH_SIZE;

  if (!(args->flags & SRLB_LB_API_FLAGS_HASH_SET))
      args->hash = SRLB_LB_VIP_HASH_5_TUPLE;

  /* Check values */
  if ((!is_pow2(args->consistent_hashtable_size) ||
          args->consistent_hashtable_size == 0))
    return VNET_API_ERROR_INVALID_MEMORY_SIZE;

  if (args->hash >= SRLB_LB_VIP_HASH_INVALID)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  if (vip == NULL)
    {
      if (!(args->flags & SRLB_LB_API_FLAGS_SR_PREFIX_SET))
        return VNET_API_ERROR_INVALID_ARGUMENT;

      if (!(args->flags & SRLB_LB_API_FLAGS_CLIENT_TX_FIB_SET))
        args->client_tx_fib_index = 0;

      if (!(args->flags & SRLB_LB_API_FLAGS_SR_RX_FIB_SET))
        args->sr_rx_fib_index = 0;

      if (!(args->flags & SRLB_LB_API_FLAGS_SR_TX_FIB_SET))
        args->sr_tx_fib_index = 0;

      SRLB_LB_LOG_DEBUG("Adding VIP %U",
      			format_ip6_address, &args->vip_address);

      srlb_lb_pool_get(srlbm->vips, vip);
      vip->prefix = args->vip_address;
      vip->prefix_length = args->vip_prefix_length;
      vip->sr_prefix = args->sr_prefix;
      vip->hash = args->hash;
      vip->cht_index = 0;
      vip->server_indices = 0;
      vip->cht_indices = 0;
      vip->client_rx_fib_index = args->client_rx_fib_index;
      vip->client_tx_fib_index = args->client_tx_fib_index;
      vip->sr_rx_fib_index = args->sr_rx_fib_index;
      vip->sr_tx_fib_index = args->sr_tx_fib_index;
      args->flags |= SRLB_LB_API_FLAGS_CONSISTENT_HASHTABLE_SIZE_SET |
          SRLB_LB_API_FLAGS_HASH_SET;
    }
  else /* VIP exists */
    {
      /** Found a VIP with mismatching SR prefix (they must be the same
       * as they are immutable) */
      if ((args->flags & SRLB_LB_API_FLAGS_SR_PREFIX_SET) &&
          (!ip6_address_is_equal(&vip->sr_prefix, &args->sr_prefix)))
        return VNET_API_ERROR_INVALID_SRC_ADDRESS;

      /* fib indexes are immutable */

      if ((args->flags & SRLB_LB_API_FLAGS_CLIENT_RX_FIB_SET) &&
          (vip->client_rx_fib_index != args->client_rx_fib_index))
        return VNET_API_ERROR_UNSUPPORTED;

      if ((args->flags & SRLB_LB_API_FLAGS_CLIENT_TX_FIB_SET) &&
          (vip->client_tx_fib_index != args->client_tx_fib_index))
        return VNET_API_ERROR_UNSUPPORTED;

      if ((args->flags & SRLB_LB_API_FLAGS_SR_RX_FIB_SET) &&
          (vip->sr_rx_fib_index != args->sr_rx_fib_index))
        return VNET_API_ERROR_UNSUPPORTED;

      if ((args->flags & SRLB_LB_API_FLAGS_SR_TX_FIB_SET) &&
          (vip->sr_tx_fib_index != args->sr_tx_fib_index))
        return VNET_API_ERROR_UNSUPPORTED;
    }

  if ((args->flags & SRLB_LB_API_FLAGS_CONSISTENT_HASHTABLE_SIZE_SET) &&
      vip->cht_size != args->consistent_hashtable_size)
    {
      SRLB_LB_LOG_DEBUG("Setting VIP %U consistent hash table size to %d",
            			format_ip6_address, &args->vip_address,
            			args->consistent_hashtable_size);
      vip->cht_size = args->consistent_hashtable_size;
      if (pool_elts(vip->server_indices))
	srlb_generate_consistent_hash_table(vip);
    }

  if ((args->flags & SRLB_LB_API_FLAGS_HASH_SET) &&
      args->hash != vip->hash)
    vip->hash = args->hash;

  return 0;
}

int srlb_lb_conf(srlb_lb_conf_args_t *args)
{
  srlb_lb_main_t * srlbm = &srlb_lb_main;
  flowhash_validate_sizes(&args->flowhash_fixed_entries,
                          &args->flowhash_collision_buckets);

  srlbm->flowhash_fixed_entries = args->flowhash_fixed_entries;
  srlbm->flowhash_collision_buckets = args->flowhash_collision_buckets;
  srlbm->flow_active_timeout = args->flow_active_timeout;
  srlbm->flow_teardown_timeout = args->flow_teardown_timeout;
  return 0;
}

#define _(n) \
const static char* const srlb_dpo_##n##_nodes_ip6[] = { "srlb-lb-"#n , NULL }; \
const static char* const * const srlb_dpo_##n##_nodes[DPO_PROTO_NUM] = { \
   [DPO_PROTO_IP6]  = srlb_dpo_##n##_nodes_ip6, \
}; \
static void srlb_dpo_##n##_lock(dpo_id_t *dpo) { } \
static void srlb_dpo_##n##_unlock(dpo_id_t *dpo) { } \
static u8 * format_srlb_dpo_##n (u8 * s, va_list * args) { \
  u32 dpo_index = va_arg (*args, u32); \
  return format (s, "dpo-srlb-lb-"#n" vip-index: %d", dpo_index) ; \
}

foreach_srlb_lb_dpo

#undef _

static fib_node_t *
srlb_fib_node_get_node (fib_node_index_t index)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  srlb_lb_server_t *s = pool_elt_at_index (srlbm->servers, index);
  return (&s->fib_node);
}

static void
srlb_fib_node_last_lock_gone (fib_node_t *node)
{
  /*
   * This is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

static srlb_lb_server_t *
srlb_server_from_fib_node (fib_node_t *node)
{
  return ((srlb_lb_server_t*)(((char*)node) -
      STRUCT_OFFSET_OF(srlb_lb_server_t, fib_node)));
}

static void
srlb_server_stack (srlb_lb_server_t *server)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  dpo_stack(srlbm->dpo_client_type,
	    DPO_PROTO_IP6,
	    &server->dpo,
	    fib_entry_contribute_ip_forwarding(
		server->next_hop_fib_entry_index));
}

static fib_node_back_walk_rc_t
srlb_fib_node_back_walk_notify (fib_node_t *node,
			       fib_node_back_walk_ctx_t *ctx)
{
  srlb_server_stack(srlb_server_from_fib_node(node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

clib_error_t *
srlb_lb_init (vlib_main_t * vm)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpo_vft_t dpo = {};
  srlb_lb_per_core_t *pc;
  int i;

  vlib_validate_simple_counter (&srlbm->counters, SRLB_LB_CTR_N - 1);
  vlib_clear_simple_counters (&srlbm->counters);

  vec_validate(srlbm->per_core, tm->n_vlib_mains - 1);
  vec_foreach(pc, srlbm->per_core)
  {
   int fn;
    pc->flow_table = NULL;
    pc->time_shift = 1000;
    for (fn = 0; fn < 2; fn++)
        vec_validate(pc->handoff_per_fn[fn].per_worker, tm->n_vlib_mains - 1);
    clib_spinlock_init(&pc->resource_lock);
  }

#define _(n) do {\
    dpo.dv_lock = srlb_dpo_##n##_lock; \
    dpo.dv_unlock = srlb_dpo_##n##_unlock; \
    dpo.dv_format = format_srlb_dpo_##n; \
    srlbm->dpo_##n##_type = dpo_register_new_type(&dpo, srlb_dpo_##n##_nodes); \
} while (0);

  foreach_srlb_lb_dpo

#undef _

  fib_node_vft_t srlb_fib_node_vft = {
      .fnv_get = srlb_fib_node_get_node,
      .fnv_last_lock = srlb_fib_node_last_lock_gone,
      .fnv_back_walk = srlb_fib_node_back_walk_notify,
  };
  srlbm->fib_node_type = fib_node_register_new_type(&srlb_fib_node_vft);

  clib_bihash_init_16_8(&srlbm->server_index_by_vip_and_address,
			"srlb lb servers", 256, 16 << 14);

  srlbm->flow_active_timeout = SRLB_LB_DEFAULT_FLOW_ACTIVE_TIMEOUT;
  srlbm->flow_teardown_timeout = SRLB_LB_DEFAULT_FLOW_TEARDOWN_TIMEOUT;
  srlbm->flowhash_fixed_entries = SRLB_LB_DEFAULT_FIXED_ENTRIES;
  srlbm->flowhash_collision_buckets = SRLB_LB_DEFAULT_COLLISION_BUCKETS;
  srlbm->log_level = SRLB_LB_LOG_DEFAULT_LEVEL;

  flowhash_validate_sizes(&srlbm->flowhash_fixed_entries,
                          &srlbm->flowhash_collision_buckets);

  /* Init reference counters */
  for (i = 0; i < SRLB_LB_REFCOUNT_N; i++)
    vlib_refcount_init(&srlbm->refcount[i]);

  /* Allocate first server (with index 0) */
  srlb_lb_server_t *server;
  pool_get(srlbm->servers, server);
  ASSERT(server == srlbm->servers);
  server->dpo.dpoi_next_node = SRLB_LB_NEXT_DROP;
  server->address.as_u64[0] = 0;
  server->address.as_u64[1] = 0;

  /* Allocate first CHT with a dummy srh to the dummy server
   * (which will cause drop if it ever occurs to be used) */
  srlb_lb_vip_cht_t *cht;
  pool_get(srlbm->chts, cht);
  cht->mask = 0;
  cht->n_choices = 1;
  cht->buckets = 0;
  vec_validate(cht->buckets, 0);
  cht->buckets[0] = 0;

  srlbm->fq_cs_index = ~0;
  srlbm->fq_ds_index = ~0;

  return NULL;
}

VLIB_INIT_FUNCTION (srlb_lb_init);
