/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 * Copyright 2019 Hitoshi Irino <irino@sfc.wide.ad.jp> All rights reserved.
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

#ifndef _NETFLOW_H
#define _NETFLOW_H

#include "softflowd.h"

/* Cisco NetFlow v5 header format (shared with ipfix.c unified exporter).
 * NetFlow v1 shares the first 16 bytes (NF1_HEADER_SIZE).
 * Ref: https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html */
struct NF5_HEADER {
  u_int16_t version, flows;     // same as netflow v1
  u_int32_t uptime_ms, time_sec, time_nanosec;  // same as netflow v1
  u_int32_t flow_sequence;
  u_int8_t engine_type, engine_id;
  u_int16_t sampling_interval;
};

#define NF1_HEADER_SIZE 16

/* Cisco NetFlow v5 flow record (48 octets); NetFlow v1 records are the same size. */
struct NF5_FLOW {
  u_int32_t src_ip, dest_ip, nexthop_ip;        // same as netflow v1
  u_int16_t if_index_in, if_index_out;  // same as netflow v1
  u_int32_t flow_packets, flow_octets;  // same as netflow v1
  u_int32_t flow_start, flow_finish;    // same as netflow v1
  u_int16_t src_port, dest_port;        // same as netflow v1
  u_int8_t pad1;
  u_int8_t tcp_flags, protocol, tos;
  u_int16_t src_as, dest_as;
  u_int8_t src_mask, dst_mask;
  u_int16_t pad2;
};

/* Maximum number of flows per packet */
#define NF1_MAXFLOWS            24
#define NF5_MAXFLOWS            30
#define NF5_MAXPACKET_SIZE      (sizeof(struct NF5_HEADER) + \
                                 (NF5_MAXFLOWS * sizeof(struct NF5_FLOW)))

#define NFLOW9_TEMPLATE_SET_ID          0
#define NFLOW9_OPTION_TEMPLATE_SET_ID   1

/* Legacy (--enable-unified-export-type=none) NetFlow v9 exporter limits */
#define NF9_SOFTFLOWD_MAX_PACKET_SIZE                   512
#define NF9_SOFTFLOWD_TEMPLATE_NRECORDS                 16
#define NF9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS     1
#define NF9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS          2

struct NFLOW9_HEADER {
  u_int16_t version, flows;
  u_int32_t uptime_ms;
  u_int32_t export_time;        // in seconds
  u_int32_t sequence, od_id;
} __packed;

#if ENABLE_UNIFIED_EXPORT_TYPE == ENABLE_UNIFIED_EXPORT_TYPE_NONE
/* Prototypes for functions to send NetFlow packets, from netflow*.c */
int send_netflow_v9 (struct SENDPARAMETER sp);
/* Force a resend of the flow template */
void netflow9_resend_template (void);
#endif /* ENABLE_UNIFIED_EXPORT_TYPE == ENABLE_UNIFIED_EXPORT_TYPE_NONE */

#endif /* _NETFLOW_H */
