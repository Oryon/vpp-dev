
#ifndef SRC_PLUGINS_SRLB_SRLB_COMMON_H_
#define SRC_PLUGINS_SRLB_SRLB_COMMON_H_

#include <vnet/ip/ip.h>

/* SR functions implemented by the server agent. */
typedef enum {
  SRLB_SA_FN_CONNECT_IF_AVAILABLE = 0x0,  /* Service Hunting (SYN) */
  SRLB_SA_FN_RECOVER_STICKINESS = 0x1,    /* Existing flow hunting */
  SRLB_SA_FN_ACK_STICKINESS = 0x2,        /* Flow entry created (ACK) */
} __attribute__ ((packed)) srlb_sa_function_t;

u8 *format_srlb_sa_function (u8 * s, va_list * args);

typedef enum {
  SRLB_LB_FN_CREATE_STICKINESS = 0x8,        /* Connection accepted (SYN-ACK) */
  SRLB_LB_FN_DELETE_STICKINESS = 0x9, 	     /* End of connection (END,RESET) */
} __attribute__ ((packed)) srlb_lb_function_t;

u8 *format_srlb_lb_function (u8 * s, va_list * args);

#define srlb_sr_fn(sid) ((sid)->as_u8[10] >> 4)
#define srlb_sr_offset(sid) ((sid)->as_u8[10] & 0x0f)

#define srlb_sr_set_fn(sid, function) \
      (sid)->as_u8[10] = (((sid)->as_u8[10] & 0x0f) | ((function) << 4))

#define srlb_sr_set_fn_and_offset(sid, fn, offset) \
      (sid)->as_u8[10] = ((offset) | (fn << 4));

#define SRLB_CARE_ABOUT_IPV6_EXTENSION_HEADERS 1

static_always_inline void
srlb_parse_packet(ip6_header_t *iph,
		  ip6_address_t *src_address, ip6_address_t *dst_address,
		  u16 *src_port, u16 *dst_port,
		  ip6_ext_header_t **routing_header,
		  u8 *is_syn, u8 *is_fin)
{
  if (src_address)
    clib_memcpy(src_address, &iph->src_address, sizeof(ip6_address_t));
  if (dst_address)
    clib_memcpy(dst_address, &iph->dst_address, sizeof(ip6_address_t));

  u8 protocol = iph->protocol;
  u8* payload = (u8*) (iph + 1);

/* Extension headers may be present in this order.
 * Those followed by a 1 are ignored and ports 0 are used. */
#define foreach_ipv6_ext_header \
  _(IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS, 1) \
  _(IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 1) \
  _(IP_PROTOCOL_IPV6_ROUTE, 0) \
  _(IP_PROTOCOL_IPV6_FRAGMENTATION, 1) \
  _(IP_PROTOCOL_IPSEC_AH, 1) \
  _(IP_PROTOCOL_IPSEC_ESP, 1) \
  _(IP_PROTOCOL_IP6_DESTINATION_OPTIONS, 1) \
  _(IP_PROTOCOL_MOBILITY, 1)

#define _(proto, ignore)                                               \
  if (protocol == proto && !ignore)                                    \
    {                                                                  \
      if (proto == IP_PROTOCOL_IPV6_ROUTE && routing_header != NULL)   \
        *routing_header = (ip6_ext_header_t *) payload;                \
      protocol = ((ip6_ext_header_t *)payload)->next_hdr;              \
      payload += ip6_ext_header_len(payload);                          \
    }

  foreach_ipv6_ext_header

#undef foreach_ipv6_ext_header
#undef _

  u8 udp_or_tcp = (protocol == IP_PROTOCOL_UDP) ||
  (protocol == IP_PROTOCOL_TCP);
  if(src_port)
    *src_port = udp_or_tcp?((udp_header_t*)payload)->src_port:0;
  if(dst_port)
    *dst_port = udp_or_tcp?((udp_header_t*)payload)->dst_port:0;

  if (is_syn)
    {
      if (protocol == IP_PROTOCOL_TCP)
	*is_syn = ((tcp_header_t*)payload)->flags & TCP_FLAG_SYN;
      else
	*is_syn = 1;
    }

  if (is_fin)
    {
      if (protocol == IP_PROTOCOL_TCP)
	*is_fin = ((tcp_header_t*)payload)->flags & (TCP_FLAG_FIN | TCP_FLAG_RST);
      else
	*is_fin = 0;
    }
}

uword unformat_verbosity (unformat_input_t * input, va_list * args);

uword unformat_u32_bitmask_list (unformat_input_t * input, va_list * va);
u8 *format_u32_bitmask_list (u8 * s, va_list * args);

uword unformat_half_ip6_address (unformat_input_t * input, va_list * args);
u8 *format_half_ip6_address (u8 * s, va_list * va);

#endif /* SRC_PLUGINS_SRLB_SRLB_COMMON_H_ */
