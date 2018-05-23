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
#include <srlb/srlb-common.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <vnet/ip/ip.h>

#define __plugin_msg_base srlb_lb_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#define vl_msg_id(n,h) n,
typedef enum {
#include <srlb/srlb_lb.api.h>
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
#include <srlb/srlb_lb.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun            /* define message structures */
#include <srlb/srlb_lb.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <srlb/srlb_lb.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <srlb/srlb_lb.api.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} srlb_lb_test_main_t;

srlb_lb_test_main_t srlb_lb_test_main;

/* standard reply handlers */
#define foreach_standard_reply_retval_handler           \
_(srlb_lb_vip_conf_reply)                               \
_(srlb_lb_server_add_del_reply)                         \
_(srlb_lb_conf_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = srlb_lb_test_main.vat_main;  \
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
#define foreach_vpe_api_reply_msg                              \
_(SRLB_LB_VIP_CONF_REPLY, srlb_lb_vip_conf_reply)              \
_(SRLB_LB_SERVER_ADD_DEL_REPLY, srlb_lb_server_add_del_reply)  \
_(SRLB_LB_CONF_REPLY, srlb_lb_conf_reply) \
_(SRLB_LB_GET_CONF_REPLY, srlb_lb_get_conf_reply)


static int
api_srlb_lb_vip_conf (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_srlb_lb_vip_conf_t *mp, mps = {};
  int ret;
  int u;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vip %U/%u", unformat_ip6_address,
                    &mps.vip_address, &mps.vip_prefix_length))
        ;
      else if (unformat (i, "sr %U/%u",  unformat_ip6_address,
                         &mps.sr_prefix, &mps.sr_prefix_length))
        ;
      else if (unformat (i, "client_rx_vrf %u", &mps.client_rx_vrf_id))
        mps.client_rx_vrf_id = clib_host_to_net_u32(mps.client_rx_vrf_id);
      else if (unformat (i, "client_tx_vrf %u", &mps.client_tx_vrf_id))
        mps.client_tx_vrf_id = clib_host_to_net_u32(mps.client_tx_vrf_id);
      else if (unformat (i, "sr_tx_vrf %u", &mps.sr_tx_vrf_id))
        mps.sr_tx_vrf_id = clib_host_to_net_u32(mps.sr_tx_vrf_id);
      else if (unformat (i, "sr_rx_vrf %u", &mps.sr_rx_vrf_id))
        mps.sr_rx_vrf_id = clib_host_to_net_u32(mps.sr_rx_vrf_id);
      else if (unformat (i, "consistent_hashtable_size %u",
                         &mps.consistent_hashtable_size))
        mps.consistent_hashtable_size =
            clib_host_to_net_u32(mps.consistent_hashtable_size);
      else if (unformat (i, "is_del"))
        mps.is_del = 1;
      else if (unformat (i, "hash_type %u", &u))
        mps.hash_type = u;
      else
        {
          clib_warning ("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  if (mps.hash_type > 1)
    {
      errmsg ("invalid hash_type\n");
      return -99;
    }

  M (SRLB_LB_VIP_CONF, mp);

  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;

  S (mp);
  W (ret);
  return ret;
}

static int
api_srlb_lb_server_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_srlb_lb_server_add_del_t *mp, mps = {};
  int ret;
  int server_count = 0;
  vl_api_srlb_lb_server_t servers[17];

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vip %U/%u", unformat_ip6_address,
                    &mps.vip_prefix, &mps.vip_prefix_length))
        ;
      else if (unformat (i, "client_rx_vrf %u", &mps.client_rx_vrf_id))
        mps.client_rx_vrf_id = clib_host_to_net_u32(mps.client_rx_vrf_id);
      else if (unformat (i, "pool_bitmask %U", unformat_u32_bitmask_list,
                         &mps.pool_bitmask))
        mps.pool_bitmask = clib_host_to_net_u32(mps.pool_bitmask);
      else if (unformat (i, "server %U/%u", unformat_ip6_address,
                         &servers[server_count].server_prefix,
                         &servers[server_count].server_prefix_length))
        {
          if (server_count == 16)
            return VNET_API_ERROR_TABLE_TOO_BIG;

          server_count++;
        }
      else if (unformat (i, "is_del"))
        mps.is_del = 1;
      else
        {
          clib_warning ("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  M2 (SRLB_LB_SERVER_ADD_DEL, mp, sizeof(*servers) * server_count);

  mps.count = clib_host_to_net_u32(server_count);
  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;
  memcpy(mp->servers, servers, sizeof(servers[0]) * server_count);

  S (mp);
  W (ret);
  return ret;
}


static int
api_srlb_lb_conf (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_srlb_lb_conf_t *mp, mps = {};
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

  M (SRLB_LB_CONF, mp);

  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;

  S (mp);
  W (ret);
  return ret;
}

static int
api_srlb_lb_get_conf (vat_main_t * vam)
{
  vl_api_srlb_lb_get_conf_t *mp, mps = {};
  int ret;
  M (SRLB_LB_GET_CONF, mp);
  mps._vl_msg_id = mp->_vl_msg_id;
  mps.client_index = mp->client_index;
  mps.context = mp->context;
  *mp = mps;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_srlb_lb_get_conf_reply_t_handler
(vl_api_srlb_lb_get_conf_reply_t * mp)
{
  vat_main_t * vam = srlb_lb_test_main.vat_main;
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


/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                       \
_(srlb_lb_vip_conf, "[vip <ip6-prefix>] [sr <ip6-prefix>] " \
                "[consistent_hashtable_size <size>] "   \
                "[client_rx_vrf <vrf-id>] [client_tx_vrf <vrf-id>]" \
		"[sr_rx_vrf <vrf-id>] [sr_tx_vrf <vrf-id>]" \
		"[hash_type <n>]" \
                "[is_del <is_del>]") \
_(srlb_lb_server_add_del, "[vip <ip6-prefix>] [ pool_bitmask <bitmask>] " \
                "[client_rx_vrf <vrf-id>] "   \
                "[is_del <is_del>]") \
_(srlb_lb_conf, "[flow_active_timeout <n>] " \
                "[flow_teardown_timeout <n>] " \
		"[flowhash_fixed_entries <n>] " \
		"[flowhash_collision_buckets <n>]") \
_(srlb_lb_get_conf, "")

static void
srlb_lb_vat_api_hookup (vat_main_t * vam)
{
  srlb_lb_test_main_t *st = &srlb_lb_test_main;
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
  srlb_lb_test_main_t *st = &srlb_lb_test_main;
  u8 *name;

  st->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "srlb_lb_%08x%c", api_version, 0);
  st->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  st->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (st->msg_id_base != (u16) ~ 0)
    srlb_lb_vat_api_hookup (vam);

  vec_free (name);
  return 0;
}
