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


#include <inttypes.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <vnet/ip/ip.h>

#define __plugin_msg_base srlb_sa_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#define vl_msg_id(n,h) n,
typedef enum {
#include <srlb/srlb_sa.api.h>
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <srlb/srlb_sa.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun            /* define message structures */
#include <srlb/srlb_sa.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <srlb/srlb_sa.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <srlb/srlb_sa.api.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} srlb_sa_test_main_t;

srlb_sa_test_main_t srlb_sa_test_main;

/* standard reply handlers */
#define foreach_standard_reply_retval_handler           \
_(srlb_sa_app_conf_reply)                               \
_(srlb_sa_conf_reply)                                   \
_(srlb_sa_feature_enable_disable_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = srlb_sa_test_main.vat_main;  \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                       \
_(SRLB_SA_APP_CONF_REPLY, srlb_sa_app_conf_reply)       \
_(SRLB_SA_CONF_REPLY, srlb_sa_conf_reply)               \
_(SRLB_SA_GET_CONF_REPLY, srlb_sa_get_conf_reply)       \
_(SRLB_SA_FEATURE_ENABLE_DISABLE_REPLY, srlb_sa_feature_enable_disable_reply)

/* memif-create API */
static int
api_srlb_sa_app_conf (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_srlb_sa_app_conf_t *mp, mps = {};
  int ret = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "routing_address %U", unformat_ip6_address,
                    &mps.routing_address))
        ;
      else if (unformat (i, "sr %U/%u",  unformat_ip6_address,
                         &mps.sr_prefix, &mps.sr_prefix_length))
        ;
      else if (unformat (i, "handoff_thread %u", &mps.handoff_thread))
        mps.handoff_thread = clib_host_to_net_u32(mps.handoff_thread);
      else if (unformat (i, "policy_index %u", &mps.policy_index))
        mps.policy_index = clib_host_to_net_u32(mps.policy_index);
      else if (unformat (i, "policy_opaque %u", &mps.policy_opaque))
        mps.policy_opaque = clib_host_to_net_u32(mps.policy_opaque);
      else if (unformat (i, "is_del"))
        mps.is_del = 1;
      else
        {
          clib_warning ("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  M (SRLB_SA_APP_CONF, mp);

  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;

  S (mp);
  W (ret);
  return ret;
}

static int
api_srlb_sa_conf (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_srlb_sa_conf_t *mp, mps = {};
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "flow_active_timeout %u",
                    &mps.flow_active_timeout))
        ;
      else if (unformat (i, "flow_teardown_timeout %u",
                         &mps.flow_teardown_timeout))
        ;
      else if (unformat (i, "flowhash_fixed_entries %u",
                         &mps.flowhash_fixed_entries))
        ;
      else if (unformat (i, "flowhash_collision_buckets %u",
                         &mps.flowhash_collision_buckets))
        ;
      else
        {
          clib_warning ("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  M (SRLB_SA_CONF, mp);

  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;

  S (mp);
  W (ret);
  return ret;
}


static int
api_srlb_sa_get_conf (vat_main_t * vam)
{
  vl_api_srlb_sa_get_conf_t *mp, mps = {};
  int ret;
  M (SRLB_SA_GET_CONF, mp);
  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_srlb_sa_get_conf_reply_t_handler
(vl_api_srlb_sa_get_conf_reply_t * mp)
{
  vat_main_t * vam = srlb_sa_test_main.vat_main;
  i32 retval = ntohl(mp->retval);
  if (vam->async_mode) {
      vam->async_errors += (retval < 0);
  } else {
      vam->retval = retval;
      vam->result_ready = 1;
  }
  print (vam->ofp, "flow_active_timeout %u flow_teardown_timeout %u "
      "flowhash_fixed_entries %u flowhash_collision_buckets %u\n",
      mp->flow_active_timeout, mp->flow_teardown_timeout,
      mp->flowhash_fixed_entries, mp->flowhash_collision_buckets );
}

static int
api_srlb_sa_feature_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_srlb_sa_feature_enable_disable_t *mp, mps = {};
  int ret;
  mps.sw_if_index = ~0;
  mps.is_enable = 1;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%u", &mps.sw_if_index))
        ;
      else if (unformat (i, "enable"))
        mps.is_enable = 1;
      else if (unformat (i, "disable"))
        mps.is_enable = 0;
      else
        {
          clib_warning ("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  M (SRLB_SA_FEATURE_ENABLE_DISABLE, mp);

  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;

  S (mp);
  W (ret);
  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                       \
_(srlb_sa_app_conf, "[sr <ip6-prefix>] [routing_address <ip6-address>] " \
                "[handoff_thread <thread-index>] "   \
                "[policy_index <n>] [policy_opaque <m>]" \
                "[is_del <is_del>]") \
_(srlb_sa_conf, "[flow_active_timeout <n>] " \
		"[flow_teardown_timeout <n>] " \
		"[flowhash_fixed_entries <n>] " \
		"[flowhash_collision_buckets <n>]") \
_(srlb_sa_get_conf, "") \
_(srlb_sa_feature_enable_disable, "<interface> <enable|disable>")

static void
srlb_sa_vat_api_hookup (vat_main_t * vam)
{
  srlb_sa_test_main_t *st = &srlb_sa_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + st->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h)                                          \
  hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  srlb_sa_test_main_t *st = &srlb_sa_test_main;
  u8 *name;

  st->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "srlb_sa_%08x%c", api_version, 0);
  st->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  st->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (st->msg_id_base != (u16) ~ 0)
    srlb_sa_vat_api_hookup (vam);

  vec_free (name);
  return 0;
}
