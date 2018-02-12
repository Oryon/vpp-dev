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

#ifndef SRLB_PLUGIN_SRLB_SA_H
#define SRLB_PLUGIN_SRLB_SA_H

#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>
#include <srlb/srlb-common.h>

/**
 * Forward application packets when no state is found.
 * 1: Yes
 * 0: No
 */
#define SRLB_SA_OPTION_FORWARD_WHEN_NO_STATE 1

#define SRLB_SA_HANDOFF_CORE_OFFSET 26
#define SRLB_SA_HANDOFF_CORE_MASK 0xfc000000

#define SRLB_SA_LOG_ENABLE_DATA (CLIB_DEBUG > 0)
#define SRLB_SA_LOG_DEFAULT_LEVEL 0

#define SRLB_SA_LOG(level, args...) do {\
  if (level == 3) { \
    if (SRLB_SA_LOG_ENABLE_DATA && srlb_sa_main.log_level == 3) \
      clib_warning(args); } \
  else if (srlb_sa_main.log_level >= level) \
    clib_warning(args); } while (0)

#define SRLB_SA_LOG_DATA(args...) SRLB_SA_LOG(3, args)
#define SRLB_SA_LOG_DEBUG(args...) SRLB_SA_LOG(2, args)
#define SRLB_SA_LOG_WARN(args...) SRLB_SA_LOG(1, args)
#define SRLB_SA_LOG_ERR(args...) SRLB_SA_LOG(0, args)

typedef enum {
  SRLB_SA_NEXT_LOOKUP,
  SRLB_SA_NEXT_DROP,
  SRLB_SA_N_NEXT,
} srlb_sa_next_t;

#define srlb_for_each_sa_flow_state \
  _(NONE) \
  _(WAIT) \
  _(DIRECT) \
  _(TEARDOWN)

/* SRLB LB Flow State */
typedef enum {

#define _(t) SRLB_SA_FLOW_STATE_##t,
  srlb_for_each_sa_flow_state
#undef _

} srlb_sa_flow_state;

uword unformat_srlb_sa_flow_state (unformat_input_t * input, va_list * args);
u8 *format_srlb_sa_flow_state (u8 * s, va_list * args);

#define SRLB_SA_DEFAULT_FIXED_ENTRIES 1024
#define SRLB_SA_DEFAULT_COLLISION_BUCKETS 256

#define SRLB_SA_DEFAULT_FLOW_ACTIVE_TIMEOUT 40
#define SRLB_SA_DEFAULT_FLOW_TEARDOWN_TIMEOUT 2

typedef CLIB_PACKED(struct {
  u16 opaque;
  u8 function_and_offset;
  u8 core;
  u32 entry_index;
}) srlb_sa_sid_t;

#if defined (__SSE4_2__)
#include <immintrin.h>
#endif

#include <vppinfra/clib.h>

typedef union {
    struct {
      ip6_address_t client;
      ip6_address_t vip;
      u16 client_port;
      u16 server_port;
      u32 pad;
    };
    u64 as_u64[5];
} flowhash_skey_srlb_sa_t;

typedef flowhash_skey_srlb_sa_t flowhash_lkey_srlb_sa_t;

u8 *format_flowhash_skey_srlb_sa (u8 * s, va_list * args);

typedef union {
  /** List of hunting servers.  */
  struct {
    /** Current SRLB state */
    srlb_sa_flow_state state;

    /** Selected application instance index */
    u32 ai_index;

    /** Load balancer return address */
    ip6_address_t lb_address;
  };
  u64 as_u64[2];
} flowhash_value_srlb_sa_t;

u8 *format_flowhash_value_srlb_sa (u8 * s, va_list * args);

#ifdef __included_flowhash_template_h__
#undef __included_flowhash_template_h__
#endif

#define FLOWHASH_TYPE _srlb_sa
#include <vppinfra/flowhash_template.h>
#undef FLOWHASH_TYPE

#if __SSE4_2__ && !defined (__i386__)
static_always_inline
u32 flowhash_hash_srlb_sa(flowhash_lkey_srlb_sa_t *k)
{
  /* crc32 costs multiple cycles, but multiple operations can be performed
   * in parallel. We can still achieve decent hash properties by splitting
   * the computation in two. */
  u32 val0 = 0;
  u32 val1 = 0;
  val0 = _mm_crc32_u64(val0, k->as_u64[0]);
  val1 = _mm_crc32_u64(val1, k->as_u64[0] >> 32);
  val0 = _mm_crc32_u64(val0, k->as_u64[1]);
  val1 = _mm_crc32_u64(val1, k->as_u64[1] >> 32);
  val0 = _mm_crc32_u64(val0, k->as_u64[2]);
  val1 = _mm_crc32_u64(val1, k->as_u64[2] >> 32);
  val0 = _mm_crc32_u64(val0, k->as_u64[3]);
  val1 = _mm_crc32_u64(val1, k->as_u64[3] >> 32);
  val0 = _mm_crc32_u64(val0, k->as_u64[4]);
  val1 = _mm_crc32_u64(val1, k->as_u64[4] >> 32);
  return val0 ^ val1;
}
#else
static_always_inline
u32 flowhash_hash_srlb_sa(flowhash_lkey_srlb_sa_t *k)
{
  u64 val = 0;
  val ^= k->as_u64[0];
  val ^= k->as_u64[1];
  val ^= k->as_u64[2];
  val ^= k->as_u64[3];
  val ^= k->as_u64[4];
  return (u32)clib_xxhash (val);
}
#endif

static_always_inline
u8 flowhash_cmp_key_srlb_sa(flowhash_skey_srlb_sa_t *a,
                            flowhash_lkey_srlb_sa_t *b)
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
void flowhash_cpy_key_srlb_sa(flowhash_skey_srlb_sa_t *dst,
                              flowhash_lkey_srlb_sa_t *src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
  dst->as_u64[2] = src->as_u64[2];
  dst->as_u64[3] = src->as_u64[3];
  dst->as_u64[4] = src->as_u64[4];
}


/*
 * @brief Application Instance object
 * An application instance object is uniquely identified by its VIP address,
 * and its routing address.
 */
typedef struct {

  /**
   * Prefix used by the server agent for SR functions.
   */
  ip6_address_t sr_prefix;

  /** Index of the enabled accept policy */
  u32 policy_index;

  /** Opaque value used by the enabled policy */
  u32 policy_opaque;

  /** Which core takes care of return traffic **/
  u32 handoff_thread;

  /**
   * The next DPO in the graph to follow.
   */
  dpo_id_t dpo;

  /* Control path after this */

  /**
   * VIP address for that Application Instance
   */
  ip6_address_t vip_prefix;

  /**
   * VIP prefix length for that Application Instance
   */
  u8 vip_prefix_length;

  /**
   * When sending packets to this Application Instance,
   * a route is used.
   */
  ip6_address_t routing_address;

  /**
   * The FIB entry index for the next-hop
   */
  fib_node_index_t next_hop_fib_entry_index;

  /**
   * The child index on the FIB entry
   */
  u32 next_hop_child_index;

  /**
   * Registration to FIB event.
   */
  fib_node_t fib_node;

} srlb_sa_ai_t;

u8 *format_srlb_sa_ai (u8 * s, va_list * args);

extern vlib_node_registration_t srlb_sa_ca_node;
extern vlib_node_registration_t srlb_sa_rs_node;
extern vlib_node_registration_t srlb_sa_as_node;

typedef struct {
  /** SRLB flow table */
  flowhash_srlb_sa_t *flow_table;
  u32 time_shift;

  /* handoff per core */
  struct {
    vlib_frame_queue_elt_t **per_worker;
  } handoff_per_fn[3];
} srlb_sa_per_core_t;

#define srlb_sa_time_now(vm) \
  (((u32) (vlib_time_now(vm))) + \
      srlb_sa_main.per_core[(vm)->thread_index].time_shift)

/** Format sa flow table for a given thread index and verbosity level */
u8 *format_srlb_sa_flows_with_verbosity (u8 *s, va_list * args);

/*
 * Handoff DPOs are used as FIB users to receive packets from the fib.
 * The AS DPO is used to send packets to the fib (to AIs).
 */
#define foreach_srlb_sa_dpo \
  _(handoff_ca, "srlb-sa-handoff-ca") \
  _(handoff_rs, "srlb-sa-handoff-rs") \
  _(handoff_as, "srlb-sa-handoff-as") \
  _(as, "srlb-sa-as")

/**
 * Server Agent Accept Policy
 * Used to register and hold policy information.
 */
typedef struct {
  /**
   * Single word and unique policy name
   */
  char *name;

  /**
   * Callback called when an application instance configuration is changed
   * to using this policy, or not using it anymore.
   * Returns 0 upon success, a different value upon failure, in which case the
   * AI policy is set to SRLB_SA_POLICY_ALWAYS_REJECT.
   */
  int (*conf_ai)(u32 ai_index, u8 is_del);

  /**
   * Callback called any time a new connection request is received.
   * ai_index is the Application Instance index.
   * remaining_choices is the number of remaining servers in the hunting list
   * (not including the current one).
   * The configured policy opaque index can be retrieved as
   * srlb_sa_main.ais[ai_index].policy_opaque.
   * vip_low is the lowest 64 bits part of the destination IP address.
   * Returns 0 when the connection should be accepted.
   */
  int (*accept)(u32 ai_index , u32 remaining_choices, u64 vip_low);

  /**
   * A description of the policy.
   */
  char *description;
} srlb_sa_accept_policy_t;

uword
unformat_srlb_sa_accept_policy_index (unformat_input_t * input, va_list * args);
u8 *format_srlb_sa_accept_policy_index (u8 *s, va_list * args);

typedef enum {
  SRLB_SA_POLICY_ALWAYS_REJECT,
  SRLB_SA_POLICY_ALWAYS_ACCEPT,
} srlb_sa_well_known_policies;

#define srlb_sa_foreach_counter \
  _(OVERFLOW, "table-overflow") \
  _(MOVED, "moved-flow") \
  _(ACCEPTED, "accepted") \
  _(REJECTED, "rejected") \
  _(RECOVERED, "recovered (Not implemented)") \
  _(AS, "ack-stickiness-sent (Not implemented)") \
  _(DS, "delete-stickiness-sent (Not implemented)") \
  _(HANDOFF, "packet-handoff")

/* SRLB LB counter indexes */
typedef enum {

#define _(t,s) SRLB_SA_CTR_##t,
  srlb_sa_foreach_counter
#undef _

  SRLB_SA_CTR_N
} srlb_sa_counters_t;

typedef struct {

  /**
   * Pool of application instance objects, identified by their IP Prefix.
   */
  srlb_sa_ai_t *ais;

  /**
   * Pool of acceptat policies.
   */
  srlb_sa_accept_policy_t *accept_policies;

  /* handoff queue indexes */
  u32 fq_ca_index;
  u32 fq_as_index;
  u32 fq_rs_index;

  /* Flow timeout in seconds */
  u32 flow_active_timeout;
  u32 flow_teardown_timeout;

  /** Flow table buckets. */
  u32 flowhash_fixed_entries;
  u32 flowhash_collision_buckets;

  /** Per core stuff */
  srlb_sa_per_core_t *per_core;

  /**
   * Global SRLB LB counters
   */
  vlib_simple_counter_main_t counters;

  /** Vector of interfaces (on Application Instance side) where
   * SRLB-SA is enabled */
  u32 *enabled_interfaces;

  /** Various DPO types used by SRLB to receive packet from lookup. */
#define _(n,s) dpo_type_t dpo_##n##_type ;
  foreach_srlb_sa_dpo
#undef _

  /** FIB node type used to register to FIB event for AI next hops */
  fib_node_type_t fib_node_type;

  /** Server Agent log level */
  u8 log_level;

} srlb_sa_main_t;

extern srlb_sa_main_t srlb_sa_main;

#define SRLB_SA_API_FLAGS_IS_DEL           (1 << 0)
#define SRLB_SA_API_FLAGS_POLICY_SET       (1 << 1)
#define SRLB_SA_API_FLAGS_THREAD_SET       (1 << 2)
#define SRLB_SA_API_FLAGS_TO_ADDRESS_SET   (1 << 3)

typedef struct {
  u32 flow_active_timeout;
  u32 flow_teardown_timeout;
  u32 flowhash_fixed_entries;
  u32 flowhash_collision_buckets;
} srlb_sa_conf_args_t;

/** Configures srlb flow table size and SR prefix. */
int srlb_sa_conf(srlb_sa_conf_args_t *args);

typedef struct {
  /** Next-hop address of the application instance */
  ip6_address_t routing_address;

  /** /80 prefix used by SRLB with SR */
  ip6_address_t sr_prefix;

  /** Core used for incoming **/
  u32 handoff_thread;

  /** Policy used for this instance */
  u32 policy_index;

  /** Opaque policy value set in the AI */
  u32 policy_opaque;

  /** Command argument flags */
  u8 flags;
} srlb_sa_ai_conf_args_t;

int srlb_sa_ai_conf(srlb_sa_ai_conf_args_t *args);

srlb_sa_ai_t *
srlb_sa_ai_get(ip6_address_t *sr_prefix);

int srlb_sa_feature_enable_disable(u32 sw_if_index, int is_enable);

/**
 * Registers a new accept policy.
 * Returns 0 on success, an API error code otherwise.
 * Upon success, policy_index is set to the allocated policy index.
 */
int srlb_sa_accept_policy_register(srlb_sa_accept_policy_t *policy,
				   u32 *policy_index);

u32 srlb_sa_accept_policy_get_index_by_name(const char *name);

#endif /* SRLB_PLUGIN_SRLB_SA_H */
