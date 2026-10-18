/*
 * Copyright 2026 Hitoshi Irino <irino@sfc.wide.ad.jp> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS    OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _EXPORT_COMMON_H
#define _EXPORT_COMMON_H

/*
 * Definitions of softflowd shared by the exporters: the code common to them
 * (export_common.c), the encoder-based exporter (export.c) and the fixed-format
 * exporters (compat/*.c). The values defined by the RFCs are in ipfix.h.
 */

#include "ipfix.h"
#include "softflowd.h"

#define IPFIX_BIFLAG_OFF 0
#define IPFIX_BIFLAG_ON 1

/* Template IDs and template re-send interval (packets); shared with NetFlow v9
 */
#define IPFIX_SOFTFLOWD_V4_TEMPLATE_ID 1024
#define IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID 1025
#define IPFIX_SOFTFLOWD_V6_TEMPLATE_ID 2048
#define IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID 2049
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID 256
#define IPFIX_DEFAULT_TEMPLATE_INTERVAL 16

#define IPFIX_SOFTFLOWD_MAX_PACKET_SIZE 1428

struct ntp_time_t {
  uint32_t second;
  uint32_t fraction;
};

/* Force a resend of the flow template. */
void
ipfix_resend_template (void);
int
ipfix_init_fields (struct IPFIX_FIELD_SPECIFIER *dst, u_int *index,
                   const struct IPFIX_FIELD_SPECIFIER *src,
                   u_int field_number);
void
conv_unix_to_ntp (struct timeval tv, struct ntp_time_t *ntp);
void
conv_ntp_to_unix (struct ntp_time_t ntp, struct timeval *tv);
/* Determines flow template (v4/icmpv4/v6/icmpv6) index;
 * used to select from their TMPLMAX template arrays. */
enum { TMPLV4,
       TMPLICMPV4,
       TMPLV6,
       TMPLICMPV6,
       TMPLMAX };

/* Functions shared by the exporters in export.c and compat/ipfix.c. */
u_int8_t
ipfix_flow_direction (const struct FLOW *flow, int i,
                      const struct FLOWTRACKPARAMETERS *param);
u_int
ipfix_flow_to_template_index (const struct FLOW *flow);

/* Hooks called by send_ipfix_flows() in export.c; each exporter (encoder-based
 * in export.c, fixed-format in compat/ipfix.c) implements them. */
void
ipfix_init_exporter (const struct SENDPARAMETER *sp, u_int8_t bi_flag,
                     u_int16_t version);
void
ipfix_put_templates (u_char *packet, u_int *offset, u_int8_t bi_flag,
                     u_int16_t version, const struct SENDPARAMETER *sp);
int
ipfix_flow_to_flowset (const struct FLOW *flow, u_char *packet, u_int len,
                       const struct SENDPARAMETER *sp, u_int *len_used,
                       u_int8_t bi_flag, u_int16_t version);
u_int16_t
ipfix_template_set_id (u_int tmplindex);

/* Writes the export packet header; returns its size. Also used by the
 * encoder-based exporter in export.c. */
u_int
export_build_flow_header (u_char *packet, u_int16_t version,
                          const struct FLOWTRACKPARAMETERS *param);

#endif /* _EXPORT_COMMON_H */
