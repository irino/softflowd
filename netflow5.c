/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#include "common.h"
#include "log.h"
#include "treetype.h"
#include "softflowd.h"

/*
 * This is the Cisco Netflow(tm) version 5 packet format
 * Based on:
 * http://www.cisco.com/en/US/products/sw/netmgtsw/ps1964/products_implementation_design_guide09186a00800d6a11.html 
 * https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1007472
 */
struct NF5_HEADER {
  u_int16_t version, flows;     // same as netflow v1
  u_int32_t uptime_ms, time_sec, time_nanosec;  // same as netflow v1
  u_int32_t flow_sequence;
  u_int8_t engine_type, engine_id;
  u_int16_t sampling_interval;
};
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
struct NF1_FLOW_PROTO_TOS_TCPF {
  u_int16_t pad1;
  u_int8_t protocol, tos, tcp_flags;
  u_int8_t pad2, pad3, pad4;
  u_int32_t reserved1;
};

#define NF5_MAXFLOWS		30
#define NF5_MAXPACKET_SIZE	(sizeof(struct NF5_HEADER) + \
				 (NF5_MAXFLOWS * sizeof(struct NF5_FLOW)))
#define NF1_HEADER_SIZE 16
#define NF5_NF1_FLOW_COMMON_SIZE (sizeof(struct NF5_FLOW) - \
                                  sizeof(struct NF1_FLOW_PROTO_TOS_TCPF))

static void
fill_netflow_v1_proto_tos_tcp (u_int8_t * pkt, u_int8_t proto, u_int8_t tos,
                               u_int8_t tcpf) {
  struct NF1_FLOW_PROTO_TOS_TCPF *flw =
    (struct NF1_FLOW_PROTO_TOS_TCPF *) pkt;
  memset (pkt, 0, sizeof (struct NF1_FLOW_PROTO_TOS_TCPF));
  flw->protocol = proto;
  flw->tos = tos;
  flw->tcp_flags = tcpf;
}

/*
 * Given an array of expired flows, send netflow v5 report packets
 * Returns number of packets sent or -1 on error
 */
static int
send_netflow_v5_v1 (struct SENDPARAMETER sp, u_int16_t version) {
  struct FLOW **flows = sp.flows;
  int num_flows = sp.num_flows;
  u_int16_t ifidx = sp.ifidx;
  struct FLOWTRACKPARAMETERS *param = sp.param;
  int verbose_flag = sp.verbose_flag;
  struct timeval now;
  u_int32_t uptime_ms;
  u_int8_t packet[NF5_MAXPACKET_SIZE];  /* Maximum allowed packet size (24 flows) */
  struct NF5_HEADER *hdr = NULL;
  struct NF5_FLOW *flw = NULL;
  int i, j, offset, num_packets;
  struct timeval *system_boot_time = &param->system_boot_time;
  u_int64_t *flows_exported = &param->flows_exported;
  struct OPTION *option = &param->option;

  if (version != 5 && version != 1)
    return (-1);

  if (param->adjust_time)
    now = param->last_packet_time;
  else
    gettimeofday (&now, NULL);
  uptime_ms = timeval_sub_ms (&now, system_boot_time);
  hdr = (struct NF5_HEADER *) packet;
  for (num_packets = offset = j = i = 0; i < num_flows; i++) {
    if (j >= NF5_MAXFLOWS - 1) {
      if (verbose_flag)
        logit (LOG_DEBUG, "Sending flow packet len = %d", offset);
      param->records_sent += hdr->flows;
      hdr->flows = htons (hdr->flows);
      if (send_multi_destinations
          (sp.target->num_destinations, sp.target->destinations,
           sp.target->is_loadbalance, packet, offset) < 0)
        return (-1);
      *flows_exported += j;
      j = 0;
      num_packets++;
    }
    if (j == 0) {
      memset (&packet, '\0', sizeof (packet));
      hdr->version = htons (version);
      hdr->flows = 0;           /* Filled in as we go */
      hdr->uptime_ms = htonl (uptime_ms);
      hdr->time_sec = htonl (now.tv_sec);
      hdr->time_nanosec = htonl (now.tv_usec * 1000);
      hdr->flow_sequence = htonl (*flows_exported);
      if (option->sample > 0) {
        hdr->sampling_interval =
          htons ((0x01 << 14) | (option->sample & 0x3FFF));
      }
      /* Other fields are left zero */
      offset = sizeof (*hdr);
      if (version == 1)
        offset = NF1_HEADER_SIZE;
    }
    flw = (struct NF5_FLOW *) (packet + offset);
    flw->if_index_in = flw->if_index_out = htons (ifidx);

    /* NetFlow v.5 doesn't do IPv6 */
    if (flows[i]->af != AF_INET)
      continue;
    if (flows[i]->octets[0] > 0) {
      flw->src_ip = flows[i]->addr[0].v4.s_addr;
      flw->dest_ip = flows[i]->addr[1].v4.s_addr;
      flw->src_port = flows[i]->port[0];
      flw->dest_port = flows[i]->port[1];
      flw->flow_packets = htonl (flows[i]->packets[0]);
      flw->flow_octets = htonl (flows[i]->octets[0]);
      flw->flow_start =
        htonl (timeval_sub_ms (&flows[i]->flow_start, system_boot_time));
      flw->flow_finish =
        htonl (timeval_sub_ms (&flows[i]->flow_last, system_boot_time));
      flw->tcp_flags = flows[i]->tcp_flags[0];
      flw->protocol = flows[i]->protocol;
      flw->tos = flows[i]->tos[0];
      if (version == 1) {
        fill_netflow_v1_proto_tos_tcp (packet + offset +
                                       NF5_NF1_FLOW_COMMON_SIZE,
                                       flows[i]->protocol, flows[i]->tos[0],
                                       flows[i]->tcp_flags[0]);
      }
      offset += sizeof (*flw);
      j++;
      hdr->flows++;
    }

    flw = (struct NF5_FLOW *) (packet + offset);
    flw->if_index_in = flw->if_index_out = htons (ifidx);

    if (flows[i]->octets[1] > 0) {
      flw->src_ip = flows[i]->addr[1].v4.s_addr;
      flw->dest_ip = flows[i]->addr[0].v4.s_addr;
      flw->src_port = flows[i]->port[1];
      flw->dest_port = flows[i]->port[0];
      flw->flow_packets = htonl (flows[i]->packets[1]);
      flw->flow_octets = htonl (flows[i]->octets[1]);
      flw->flow_start =
        htonl (timeval_sub_ms (&flows[i]->flow_start, system_boot_time));
      flw->flow_finish =
        htonl (timeval_sub_ms (&flows[i]->flow_last, system_boot_time));
      flw->tcp_flags = flows[i]->tcp_flags[1];
      flw->protocol = flows[i]->protocol;
      flw->tos = flows[i]->tos[1];
      if (version == 1) {
        fill_netflow_v1_proto_tos_tcp (packet + offset +
                                       NF5_NF1_FLOW_COMMON_SIZE,
                                       flows[i]->protocol, flows[i]->tos[1],
                                       flows[i]->tcp_flags[1]);
      }
      offset += sizeof (*flw);
      j++;
      hdr->flows++;
    }
  }

  /* Send any leftovers */
  if (j != 0) {
    if (verbose_flag)
      logit (LOG_DEBUG, "Sending v5 flow packet len = %d", offset);
    param->records_sent += hdr->flows;
    hdr->flows = htons (hdr->flows);
    if (send_multi_destinations
        (sp.target->num_destinations, sp.target->destinations,
         sp.target->is_loadbalance, packet, offset) < 0)
      return (-1);
    num_packets++;
  }

  *flows_exported += j;
  param->packets_sent += num_packets;
#ifdef ENABLE_PTHREAD
  if (use_thread)
    free (sp.flows);
#endif /* ENABLE_PTHREAD */
  return (num_packets);
}

int
send_netflow_v5 (struct SENDPARAMETER sp) {
  return send_netflow_v5_v1 (sp, 5);
}

#ifndef ENABLE_LEGACY
int
send_netflow_v1 (struct SENDPARAMETER sp) {
  return send_netflow_v5_v1 (sp, 1);
}
#endif /* ENABLE_LEGACY */
