/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <srlb/srlb-lb.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#define vl_msg_id(n,h) n,
typedef enum {
#include <srlb/srlb_lb.api.h>
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <srlb/srlb_lb.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <srlb/srlb_lb.api.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <srlb/srlb_lb.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <srlb/srlb_lb.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE srlbm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <srlb/srlb_lb.api.h>
#undef vl_printfun

/* List of message types that this plugin understands */
#define foreach_srlb_lb_plugin_api_msg            \
_(SRLB_LB_VIP_CONF, srlb_lb_vip_conf)             \
_(SRLB_LB_SERVER_ADD_DEL, srlb_lb_server_add_del) \
_(SRLB_LB_CONF, srlb_lb_conf)                     \
_(SRLB_LB_GET_CONF, srlb_lb_get_conf)

void
  vl_api_srlb_lb_vip_conf_t_handler
  (vl_api_srlb_lb_vip_conf_t * mp)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  vl_api_srlb_lb_vip_conf_reply_t *rmp;
  int rv = 0;
  srlb_lb_vip_conf_args_t vc = {};

  if (mp->sr_prefix_length != 80)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  memcpy(&vc.vip_address, mp->vip_address, sizeof(vc.vip_address));
  vc.vip_prefix_length = mp->vip_prefix_length;
  memcpy(&vc.sr_prefix, mp->sr_prefix, sizeof(vc.sr_prefix));
  vc.hash = mp->hash_type;

  vc.consistent_hashtable_size =
      clib_host_to_net_u32(mp->consistent_hashtable_size);

#define foreach_fib \
  _(client_rx); \
  _(client_tx); \
  _(sr_rx); \
  _(sr_tx);

#define _(a)                                                     \
  if ((vc.a##_fib_index =                                        \
       fib_table_find(FIB_PROTOCOL_IP6,                          \
        clib_net_to_host_u32(mp->a##_vrf_id))) == ~0)            \
    {                                                            \
      rv = VNET_API_ERROR_NO_SUCH_FIB;                           \
      goto reply;                                                \
    }

  foreach_fib

#undef _
#undef foreach_fib

  vc.flags = SRLB_LB_API_FLAGS_CLIENT_RX_FIB_SET |
             SRLB_LB_API_FLAGS_CLIENT_TX_FIB_SET |
             SRLB_LB_API_FLAGS_SR_RX_FIB_SET |
             SRLB_LB_API_FLAGS_SR_TX_FIB_SET |
             SRLB_LB_API_FLAGS_CONSISTENT_HASHTABLE_SIZE_SET |
             SRLB_LB_API_FLAGS_HASH_SET |
             SRLB_LB_API_FLAGS_SR_PREFIX_SET;

  if (mp->is_del)
    vc.flags |= SRLB_LB_API_FLAGS_IS_DEL;

  rv = srlb_lb_vip_conf(&vc);

reply:
  REPLY_MACRO (VL_API_SRLB_LB_VIP_CONF_REPLY);
}


void
  vl_api_srlb_lb_server_add_del_t_handler
  (vl_api_srlb_lb_server_add_del_t * mp)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  vl_api_srlb_lb_server_add_del_reply_t *rmp;
 ;
  int rv = 0;
  srlb_lb_server_add_del_args_t vc = {};
  ip6_address_t *servers = 0;
  int i;

  if ((vc.client_rx_fib_index = fib_table_find(FIB_PROTOCOL_IP6,
                    clib_net_to_host_u32(mp->client_rx_vrf_id))) == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto reply;
    }

  vc.server_count = clib_net_to_host_u32(mp->count);
  vec_validate(servers, vc.server_count);
  vc.server_addresses = servers;
  for (i = 0; i < vc.server_count; i++)
    {
      vl_api_srlb_lb_server_t *mps = &mp->servers[i];
      if (mps->server_prefix_length != 80)
        {
          vec_free(servers);
          rv = VNET_API_ERROR_INVALID_ARGUMENT;
          goto reply;
        }
      memcpy (&servers[i], mps->server_prefix, sizeof(servers[i]));
    }

  memcpy(&vc.vip_address, mp->vip_prefix, sizeof(vc.vip_address));
  vc.vip_prefix_length = mp->vip_prefix_length;
  vc.pool_bitmask = clib_net_to_host_u32(mp->pool_bitmask);

  if (mp->is_del)
    vc.flags |= SRLB_LB_API_FLAGS_IS_DEL;

  rv = srlb_lb_server_add_del(&vc);
  vec_free(servers);

reply:
  REPLY_MACRO (VL_API_SRLB_LB_SERVER_ADD_DEL_REPLY);
}

void
  vl_api_srlb_lb_conf_t_handler
  (vl_api_srlb_lb_conf_t * mp)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  vl_api_srlb_lb_conf_reply_t *rmp;
  int rv = 0;
  srlb_lb_conf_args_t vc = {};
  vc.flow_active_timeout = clib_net_to_host_u32(mp->flow_active_timeout);
  vc.flow_teardown_timeout = clib_net_to_host_u32(mp->flow_teardown_timeout);
  vc.flowhash_fixed_entries = clib_net_to_host_u32(mp->flowhash_fixed_entries);
  vc.flowhash_collision_buckets = clib_net_to_host_u32(mp->flowhash_collision_buckets);
  rv = srlb_lb_conf(&vc);
  REPLY_MACRO (VL_API_SRLB_LB_CONF_REPLY);
}

void
  vl_api_srlb_lb_get_conf_t_handler
  (vl_api_srlb_lb_get_conf_t * mp)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  vl_api_srlb_lb_get_conf_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_SRLB_LB_GET_CONF_REPLY, {
      rmp->flow_active_timeout = clib_host_to_net_u32(srlbm->flow_active_timeout);
      rmp->flow_teardown_timeout = clib_host_to_net_u32(srlbm->flow_teardown_timeout);
      rmp->flowhash_fixed_entries = clib_host_to_net_u32(srlbm->flowhash_fixed_entries);
      rmp->flowhash_collision_buckets = clib_host_to_net_u32(srlbm->flowhash_collision_buckets);
  });
}

static void
setup_message_id_table (srlb_lb_main_t *srlbm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + srlbm->msg_id_base);
  foreach_vl_msg_name_crc_srlb_lb;
#undef _
}


static clib_error_t * srlb_lb_api_init (vlib_main_t * vm)
{
  srlb_lb_main_t *srlbm = &srlb_lb_main;
  u8 *name = format (0, "srlb_lb_%08x%c", api_version, 0);
  srlbm->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + srlbm->msg_id_base),  \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_srlb_lb_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (srlbm, &api_main);

  vec_free (name);
  return 0;
}

VLIB_INIT_FUNCTION (srlb_lb_api_init);


