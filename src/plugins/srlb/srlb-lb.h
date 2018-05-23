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

#ifndef SRLB_PLUGIN_SRLB_H

#define SRLB_PLUGIN_SRLB_H

#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>
#include <srlb/srlb-common.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/util/refcount.h>

#define SRLB_LB_LOG_ENABLE_DATA (CLIB_DEBUG > 0)
#define SRLB_LB_LOG_DEFAULT_LEVEL 0

#define SRLB_LB_LOG(level, args...) do {\
  if (level == 3) { \
    if (SRLB_LB_LOG_ENABLE_DATA && srlb_lb_main.log_level == 3) \
      clib_warning(args); } \
  else if (srlb_lb_main.log_level >= level) \
    clib_warning(args); } while (0)

#define SRLB_LB_LOG_DATA(args...) SRLB_LB_LOG(3, args)
#define SRLB_LB_LOG_DEBUG(args...) SRLB_LB_LOG(2, args)
#define SRLB_LB_LOG_WARN(args...) SRLB_LB_LOG(1, args)
#define SRLB_LB_LOG_ERR(args...) SRLB_LB_LOG(0, args)

typedef enum {
  SRLB_LB_NEXT_LOOKUP,
  SRLB_LB_NEXT_DROP,
  SRLB_LB_N_NEXT,
} srlb_lb_next_t;

typedef enum {
  SRLB_LB_HANDOFF_NEXT_CS,
  SRLB_LB_HANDOFF_NEXT_DS,
  SRLB_LB_HANDOFF_NEXT_DROP,
  SRLB_LB_HANDOFF_N_NEXT,
} srlb_lb_handoff_next_t;

#define srlb_for_each_lb_flow_state \
  _(LISTEN, 0) \
  _(HUNTING, 1) \
  _(STEER, 2) \
  _(TEARDOWN, 3)

/* SRLB flow state */
typedef enum {

#define _(t, n) SRLB_LB_FLOW_STATE_##t = n,
  srlb_for_each_lb_flow_state
#undef _

} srlb_lb_flow_state;

/* Better than using logical operations */
#define srlb_lb_state_is_established(state) ((state) & 2)

uword unformat_srlb_lb_flow_state (unformat_input_t * input, va_list * args);
u8 *format_srlb_lb_flow_state (u8 * s, va_list * args);

#define srlb_lb_foreach_counter \
  _(OVERFLOW, "table-overflow") \
  _(MOVED, "moved-flow") \
  _(CONNECT, "connect-sent") \
  _(RECOVER, "recover-sent") \
  _(SESSIONS, "new-sessions") \
  _(CS, "create-stickiness-received") \
  _(DS, "delete-stickiness-received") \
  _(HANDOFF, "packet-handoff")

/* SRLB LB counter indexes */
typedef enum {

#define _(t,s) SRLB_LB_CTR_##t,
  srlb_lb_foreach_counter
#undef _

  SRLB_LB_CTR_N
} srlb_lb_counters_t;

#define SRLB_LB_DEFAULT_FIXED_ENTRIES 1024
#define SRLB_LB_DEFAULT_COLLISION_BUCKETS 256

#define SRLB_LB_DEFAULT_FLOW_ACTIVE_TIMEOUT 40
#define SRLB_LB_DEFAULT_FLOW_TEARDOWN_TIMEOUT 2

#define SRLB_LB_DEFAULT_CONSISTENT_HASH_SIZE 256

typedef CLIB_PACKED(struct {
  u16 opaque;
  u8 function;
  u8 core;
  u32 entry_index;
}) srlb_lb_flow_sid_t;

#if defined (__SSE4_2__)
#include <immintrin.h>
#endif

#include <vppinfra/clib.h>

typedef union {
    struct {
      u32 pad;
      u16 client_port;
      u16 server_port;
      ip6_address_t client;
      ip6_address_t server;
    };
    u64 as_u64[5];
} flowhash_skey_srlb_lb_t;

typedef flowhash_skey_srlb_lb_t flowhash_lkey_srlb_lb_t;

u8 *format_flowhash_skey_srlb_lb (u8 * s, va_list * args);

typedef union {
  struct {
    /** cht or server index */
    u32 index;
    union {
      /** cht bucket index for HUNTING state */
      u32 bucket_index;

      /* as opaque value for STEER or TEARDOWN state */
      u64 opaque;
    };
    /** Current SRLB state */
    u32 state;
  };
  u64 as_u64[2];
} flowhash_value_srlb_lb_t;

u8 *format_flowhash_value_srlb_lb (u8 * s, va_list * args);

#ifdef __included_flowhash_template_h__
#undef __included_flowhash_template_h__
#endif

#define FLOWHASH_TYPE _srlb_lb
#include <vppinfra/flowhash_template.h>
#undef FLOWHASH_TYPE

static_always_inline
u32 flowhash_hash_srlb_lb(flowhash_lkey_srlb_lb_t *k)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) &k->as_u64[0], 40);
#else
  u64 val = 0;
  val ^= k->as_u64[0];
  val ^= k->as_u64[1];
  val ^= k->as_u64[2];
  val ^= k->as_u64[3];
  val ^= k->as_u64[4];
  return (u32)clib_xxhash (val);
#endif
}

static_always_inline
u32 srlb_lb_hash_ip6_address(ip6_address_t *a)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) a, 16);
#else
  u64 val = 0;
  val ^= a->as_u64[0];
  val ^= a->as_u64[1];
  return (u32)clib_xxhash (val);
#endif
}

static_always_inline
u8 flowhash_cmp_key_srlb_lb(flowhash_skey_srlb_lb_t *a,
                            flowhash_lkey_srlb_lb_t *b)
{
  u8 val = 0;
  val |= (a->as_u64[0] != b->as_u64[0]);
  val |= (a->as_u64[1] != b->as_u64[1]);
  val |= (a->as_u64[2] != b->as_u64[2]);
  val |= (a->as_u64[3] != b->as_u64[3]);
  val |= (a->as_u64[4] != b->as_u64[4]);
  return val;
}

static_always_inline
void flowhash_cpy_key_srlb_lb(flowhash_skey_srlb_lb_t *dst,
                              flowhash_lkey_srlb_lb_t *src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
  dst->as_u64[2] = src->as_u64[2];
  dst->as_u64[3] = src->as_u64[3];
  dst->as_u64[4] = src->as_u64[4];
}

typedef struct {
  /*
   * Data-path
   */

  /** The IPv6 address of the backend server */
  ip6_address_t address;

  /**
   * The child index on the FIB entry
   */
  u32 next_hop_child_index;

  /**
   * The next DPO in the graph to follow.
   */
  dpo_id_t dpo;

  /*
   * Control-plane only
   */

  /**
   * Registration to FIB event.
   */
  fib_node_t fib_node;

  /**
   * The FIB entry index for the next-hop
   */
  fib_node_index_t next_hop_fib_entry_index;

  /**
   * index of server index in vip->server_indices pool
   */
  u32 index_in_vip;

  /**
   * Bitmask of the pools this VIP belongs to.
   * When set to 0, the server is waiting to be deleted.
   */
  u32 pool_bitmask;

  /**
   * Number of times this server is referenced in consistent hash tables.
   * This is only looked at by the main thread.
   */
  u32 hunting_refcount;

  /** When the server was last dereferenced or ~0 otherwise. */
  u32 freed_timestamp;

} srlb_lb_server_t;

/** Wait for at least 10 seconds after dereferencing before freeing server. */
#define SRLB_LB_SERVER_GC_TIMEOUT 10

u8 *format_srlb_lb_server (u8 * s, va_list * args);

/** Different load balancing hash functions. */
typedef enum {
  /** Hash based on src-dst address, protocol and src-dst port */
  SRLB_LB_VIP_HASH_5_TUPLE,

  /** Hash based on destination address only.
   *  Used for content-based consistent hashing when the VIP is a prefix. */
  SRLB_LB_VIP_HASH_VIP,

  /** Inavlid value used internally */
  SRLB_LB_VIP_HASH_INVALID,
} srlb_lb_vip_hash_t;

u8 *format_srlb_lb_vip_hash (u8 * s, va_list * args);
uword unformat_srlb_lb_vip_hash (unformat_input_t * input, va_list * args);

/* Consistent hash table  */
typedef struct {
  /** Consistent hash table mask size minus 1 */
  u32 mask;

  /** Number of choices used in the consistent hashing table */
  u32 n_choices;

  /** A consistent hash table for new connections to this VIP.
   * Bi-dimensional array equivalent to u32 c[buckets][n_choices]. */
  u32 *buckets;

  /** When the cht was dereferenced as the VIP cht, or ~0 otherwise. */
  u32 freed_timestamp;
} srlb_lb_vip_cht_t;

/** Wait for at least 10 seconds after dereferencing before freeing cht. */
#define SRLB_LB_CHT_GC_TIMEOUT 10

typedef struct {
  /** The IPv6 address of this VIP */
  ip6_address_t prefix;

  /** IPv6 prefix length of this VIP */
  u8 prefix_length;

  /** Index of all servers associated with this VIP */
  u32 *server_indices;

  /** hash type */
  srlb_lb_vip_hash_t hash;

  /** fib index on client side to send packets */
  u32 client_tx_fib_index;

  /** /80 prefix used for SR functions. */
  ip6_address_t sr_prefix;

  /** Consistent hash table index currently in use.
   * This is updated by main thread when there is a cht update. */
  volatile u32 cht_index;

  /*
   * Variables not used by the data-plane from here
   */

  /** Currently configured consistent hash table size. */
  u32 cht_size;

  /** Pool of cht used by this VIP */
  u32 *cht_indices;

  /** fib index on client side to receive packets */
  u32 client_rx_fib_index;

  /** fib index on server side to receive packets */
  u32 sr_rx_fib_index;

  /** fib index on server side to send packets */
  u32 sr_tx_fib_index;

} srlb_lb_vip_t;

u8 *format_srlb_lb_vip_with_verbosity (u8 * s, va_list * args);

extern vlib_node_registration_t srlb_cs_node;
extern vlib_node_registration_t srlb_ds_node;

#define foreach_srlb_lb_dpo \
  _(handoff) \
  _(client)

typedef struct {
  /** SRLB flow table **/
  flowhash_srlb_lb_t *flow_table;
  u32 time_shift;
  /* handoff per core */
  struct {
    vlib_frame_queue_elt_t **per_worker;
  } handoff_per_fn[2];
  /**
   * SRLB is mostly lock free, but in some rare cases the main thread
   * must resize servers, vips or chts pools.
   * In such situation, we must make sure worker threads are not using
   * such resources. Thus we have this single-writer, multi-reader lock
   * that is global to SRLB LB.
   */
  clib_spinlock_t resource_lock;
} srlb_lb_per_core_t;

#define srlb_lb_time_now(vm) \
  (((u32) (vlib_time_now(vm))) + \
      srlb_lb_main.per_core[(vm)->thread_index].time_shift)

u8 *format_srlb_lb_flows_with_verbosity (u8 *s, va_list * args);

/* This is a little trick to make reference counting more efficient.
 * refcnt index can be easily computed from the state id */
#define srlb_lb_state_to_refcnt(state) ((state) >> 1)

/* enum to different reference counters kept by LB instance */
enum {
  SRLB_LB_REFCOUNT_CHTS = 0,
  SRLB_LB_REFCOUNT_SERVERS = 1,
  SRLB_LB_REFCOUNT_N
};

typedef struct {

  /* Flow timeout in seconds */
  u32 flow_active_timeout;
  u32 flow_teardown_timeout;

  /** Flow table buckets. */
  u32 flowhash_fixed_entries;
  u32 flowhash_collision_buckets;

  /** Handoff to both create and delete stickyness nodes **/
  u32 fq_cs_index;
  u32 fq_ds_index;

  /** A pool containing all VIPs handled by the SRLB plugin */
  srlb_lb_vip_t *vips;

  /** A pool containing all backend servers */
  srlb_lb_server_t *servers;

  /** Pool of consistent hash tables created */
  srlb_lb_vip_cht_t *chts;

  /**
   * Resources reference counter.
   */
  vlib_refcount_t refcount[SRLB_LB_REFCOUNT_N];

  /** Hash table mapping servers and vips to server index */
  clib_bihash_16_8_t server_index_by_vip_and_address;

  /** Per core stuff */
  srlb_lb_per_core_t *per_core;

  /** Various DPO types used by SRLB to receive packet from lookup. */
#define _(n) dpo_type_t dpo_##n##_type ;
  foreach_srlb_lb_dpo
#undef _

  /**
   * FIB Node type for sending packets toward servers without going through FIB
   * lookup.
   */
  fib_node_type_t fib_node_type;

  /**
   * Configured log level.
   */
  u8 log_level;

  /**
   * Global SRLB LB counters
   */
  vlib_simple_counter_main_t counters;

  /**
   * SRLB LB plugin API message origin
   */
  u32 msg_id_base;

} srlb_lb_main_t;

extern srlb_lb_main_t srlb_lb_main;

#define SRLB_LB_API_FLAGS_IS_DEL                        (1 << 0)
#define SRLB_LB_API_FLAGS_CONSISTENT_HASHTABLE_SIZE_SET (1 << 1)
#define SRLB_LB_API_FLAGS_HASH_SET                      (1 << 2)
#define SRLB_LB_API_FLAGS_SR_PREFIX_SET                 (1 << 3)
#define SRLB_LB_API_FLAGS_CLIENT_TX_FIB_SET             (1 << 4)
#define SRLB_LB_API_FLAGS_CLIENT_RX_FIB_SET             (1 << 5)
#define SRLB_LB_API_FLAGS_SR_TX_FIB_SET                 (1 << 6)
#define SRLB_LB_API_FLAGS_SR_RX_FIB_SET                 (1 << 7)

typedef struct {
  u32 flow_active_timeout;
  u32 flow_teardown_timeout;
  u32 flowhash_fixed_entries;
  u32 flowhash_collision_buckets;
} srlb_lb_conf_args_t;

/** Configures srlb flow table size and SR prefix. */
int srlb_lb_conf(srlb_lb_conf_args_t *args);

typedef struct {
  ip6_address_t vip_address;
  u8 vip_prefix_length;
  ip6_address_t sr_prefix;
  u32 consistent_hashtable_size;
  srlb_lb_vip_hash_t hash;
  u32 client_tx_fib_index;
  u32 client_rx_fib_index;
  u32 sr_tx_fib_index;
  u32 sr_rx_fib_index;
  u32 flags;
} srlb_lb_vip_conf_args_t;

/** Add, del, or configure a VIP */
int srlb_lb_vip_conf (srlb_lb_vip_conf_args_t *args);

typedef struct {
  ip6_address_t vip_address;
  u8 vip_prefix_length;
  u32 client_rx_fib_index;
  u32 pool_bitmask;
  u32 server_count;
  ip6_address_t *server_addresses;
  u32 flags;
} srlb_lb_server_add_del_args_t;

/** Add del some servers */
int srlb_lb_server_add_del(srlb_lb_server_add_del_args_t *args);

/** Get existing VIP object. */
srlb_lb_vip_t *
srlb_get_vip(ip6_address_t * vip_address, u8 plen, u32 client_rx_fib_index);

#endif /* SRLB_PLUGIN_SRLB_H */
