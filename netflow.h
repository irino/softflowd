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

/* Cisco NetFlow v1 header format (16 octets), the first NETFLOW1_HEADER_SIZE octets of the v5 one.
 * Shared by compat/netflow1.c and the ipfix.c exporter. */
struct NETFLOW1_HEADER {
  u_int16_t version, flows;
  u_int32_t sysUpTime;          // in milliseconds
  u_int32_t export_time;        // in seconds
  u_int32_t export_time_nanoseconds;
} __packed;

/* Cisco NetFlow v5 header format (shared with the ipfix.c exporter, EXPORT_MERGE_ALL).
 * NetFlow v1 shares the first 16 bytes (NETFLOW1_HEADER_SIZE).
 * Ref: https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html */
struct NETFLOW5_HEADER {
  u_int16_t version, flows;     // same as netflow v1
  u_int32_t sysUpTime;          // in milliseconds, same as netflow v1
  u_int32_t export_time;        // in seconds, same as netflow v1
  u_int32_t export_time_nanoseconds;    // same as netflow v1
  u_int32_t sequence_number;
  u_int8_t engine_type, engine_id;
  u_int16_t sampling_interval;
} __packed;

#define NETFLOW1_HEADER_SIZE 16

/* Cisco NetFlow v5 flow record (48 octets); NetFlow v1 records are the same size. */
struct NETFLOW5_FLOW {
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
#define NETFLOW1_MAXFLOWS            24
#define NETFLOW5_MAXFLOWS            30
#define NETFLOW5_MAXPACKET_SIZE      (sizeof(struct NETFLOW5_HEADER) + \
                                 (NETFLOW5_MAXFLOWS * sizeof(struct NETFLOW5_FLOW)))

#define NETFLOW9_TEMPLATE_SET_ID          0
#define NETFLOW9_OPTION_TEMPLATE_SET_ID   1

struct NETFLOW9_HEADER {
  u_int16_t version, flows;
  u_int32_t sysUpTime;          // in milliseconds
  u_int32_t export_time;        // in seconds
  u_int32_t sequence_number, observation_domain_id;
} __packed;

#if EXPORT_MERGE == EXPORT_MERGE_NONE
/* Force a resend of the flow template, from netflow9.c */
void netflow9_resend_template (void);
#endif /* EXPORT_MERGE == EXPORT_MERGE_NONE */

#endif /* _NETFLOW_H */
