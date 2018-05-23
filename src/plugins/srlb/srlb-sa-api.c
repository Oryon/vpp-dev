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

#include <srlb/srlb-sa.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#define vl_msg_id(n,h) n,
typedef enum {
#include <srlb/srlb_sa.api.h>
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <srlb/srlb_sa.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <srlb/srlb_sa.api.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <srlb/srlb_sa.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <srlb/srlb_sa.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE srlbm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <srlb/srlb_sa.api.h>
#undef vl_printfun

/* List of message types that this plugin understands */
#define foreach_srlb_sa_plugin_api_msg            \
_(SRLB_SA_APP_CONF, srlb_sa_app_conf)             \
_(SRLB_SA_CONF, srlb_sa_conf)                     \
_(SRLB_SA_GET_CONF, srlb_sa_get_conf)             \
_(SRLB_SA_FEATURE_ENABLE_DISABLE, srlb_sa_feature_enable_disable)

/**
 * @brief Message handler for memif_socket_filename_add_del API.
 * @param mp the vl_api_memif_socket_filename_add_del_t API message
 */
void
  vl_api_srlb_sa_app_conf_t_handler
  (vl_api_srlb_sa_app_conf_t * mp)
{
  srlb_sa_main_t *srlbm = &srlb_sa_main;
  vl_api_srlb_sa_app_conf_reply_t *rmp;
  int rv = 0;
  srlb_sa_ai_conf_args_t aic = {};

  if (mp->sr_prefix_length != 80)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }


  memcpy(&aic.routing_address, mp->routing_address, sizeof(aic.routing_address));
  memcpy(&aic.sr_prefix, mp->sr_prefix, sizeof(aic.sr_prefix));
  aic.handoff_thread = clib_net_to_host_u32(mp->handoff_thread);
  aic.policy_index = clib_net_to_host_u32(mp->policy_index);
  aic.policy_opaque = clib_net_to_host_u32(mp->policy_opaque);

  aic.flags = SRLB_SA_API_FLAGS_POLICY_SET |
  SRLB_SA_API_FLAGS_THREAD_SET |
  SRLB_SA_API_FLAGS_TO_ADDRESS_SET;

  if (mp->is_del)
    aic.flags |= SRLB_SA_API_FLAGS_IS_DEL;

  rv = srlb_sa_ai_conf(&aic);

reply:
  REPLY_MACRO (VL_API_SRLB_SA_APP_CONF_REPLY);
}

void
vl_api_srlb_sa_conf_t_handler
(vl_api_srlb_sa_conf_t * mp)
{
  srlb_sa_main_t *srlbm = &srlb_sa_main;
  vl_api_srlb_sa_conf_reply_t *rmp;
  ;
  int rv = 0;
  srlb_sa_conf_args_t vc = {};
  vc.flow_active_timeout = clib_net_to_host_u32(mp->flow_active_timeout);
  vc.flow_teardown_timeout = clib_net_to_host_u32(mp->flow_teardown_timeout);
  vc.flowhash_fixed_entries = clib_net_to_host_u32(mp->flowhash_fixed_entries);
  vc.flowhash_collision_buckets = clib_net_to_host_u32(mp->flowhash_collision_buckets);
  rv = srlb_sa_conf(&vc);
  REPLY_MACRO (VL_API_SRLB_SA_CONF_REPLY);
}

void
  vl_api_srlb_sa_get_conf_t_handler
  (vl_api_srlb_sa_get_conf_t * mp)
{
  srlb_sa_main_t *srlbm = &srlb_sa_main;
  vl_api_srlb_sa_get_conf_reply_t *rmp;
  int rv = 0;
  REPLY_MACRO2 (VL_API_SRLB_SA_GET_CONF_REPLY, {
      rmp->flow_active_timeout = clib_host_to_net_u32(srlbm->flow_active_timeout);
      rmp->flow_teardown_timeout = clib_host_to_net_u32(srlbm->flow_teardown_timeout);
      rmp->flowhash_fixed_entries = clib_host_to_net_u32(srlbm->flowhash_fixed_entries);
      rmp->flowhash_collision_buckets = clib_host_to_net_u32(srlbm->flowhash_collision_buckets);
  });
}

void
vl_api_srlb_sa_feature_enable_disable_t_handler
(vl_api_srlb_sa_feature_enable_disable_t * mp)
{
  srlb_sa_main_t *srlbm = &srlb_sa_main;
  vl_api_srlb_sa_feature_enable_disable_reply_t *rmp;
  int rv = 0;
  rv = srlb_sa_feature_enable_disable(clib_net_to_host_u32(mp->sw_if_index),
                                      mp->is_enable);
  REPLY_MACRO (VL_API_SRLB_SA_FEATURE_ENABLE_DISABLE_REPLY);
}

static void
setup_message_id_table (srlb_sa_main_t *srlbm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + srlbm->msg_id_base);
  foreach_vl_msg_name_crc_srlb_sa;
#undef _
}


static clib_error_t * srlb_sa_api_init (vlib_main_t * vm)
{
  srlb_sa_main_t *srlbm = &srlb_sa_main;
  u8 *name = format (0, "srlb_sa_%08x%c", api_version, 0);
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
  foreach_srlb_sa_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (srlbm, &api_main);

  vec_free (name);
  return 0;
}

VLIB_INIT_FUNCTION (srlb_sa_api_init);


