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
#include "netflow.h"

/*
 * This is the Cisco Netflow(tm) version 5 packet format
 * Based on:
 * http://www.cisco.com/en/US/products/sw/netmgtsw/ps1964/products_implementation_design_guide09186a00800d6a11.html 
 * https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1007472
 */
struct NETFLOW1_FLOW_PROTO_TOS_TCPF {
  u_int16_t pad1;
  u_int8_t protocol, tos, tcp_flags;
  u_int8_t pad2, pad3, pad4;
  u_int32_t reserved1;
};

#define NETFLOW1_FLOW_COMMON_SIZE (sizeof(struct NETFLOW5_FLOW) - \
                                  sizeof(struct NETFLOW1_FLOW_PROTO_TOS_TCPF))

/**
 * @brief Fill the v1-only tail of a NetFlow v1 flow record.
 *
 * @param pkt   Start of the tail inside the record; struct NETFLOW1_FLOW_PROTO_TOS_TCPF is zeroed first.
 * @param proto IP protocol number.
 * @param tos   IP type of service.
 * @param tcpf  Cumulative TCP flags.
 */
static void
fill_netflow_v1_proto_tos_tcp (u_int8_t * pkt, u_int8_t proto, u_int8_t tos,
                               u_int8_t tcpf) {
  struct NETFLOW1_FLOW_PROTO_TOS_TCPF *flw =
    (struct NETFLOW1_FLOW_PROTO_TOS_TCPF *) pkt;
  memset (pkt, 0, sizeof (struct NETFLOW1_FLOW_PROTO_TOS_TCPF));
  flw->protocol = proto;
  flw->tos = tos;
  flw->tcp_flags = tcpf;
}

/**
 * @brief Send expired flows as NetFlow v5 or v1 export packets.
 *
 * IPv6 flows are skipped, as neither version can carry them. Each direction with traffic becomes one record.
 *
 * @param sp      Send parameters: flows to export, target destinations, interface index, tracking parameters and verbosity.
 * @param version Export version: 5 or 1.
 * @return Number of packets sent, or -1 on error.
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
  u_int8_t packet[NETFLOW5_MAXPACKET_SIZE];  /* Maximum allowed packet size (v1: 24, v5: 30 flows) */
  struct NETFLOW5_HEADER *hdr = NULL;
  struct NETFLOW5_FLOW *flw = NULL;
  int i, j, offset, num_packets;
  struct timeval *system_boot_time = &param->system_boot_time;
  u_int64_t *flows_exported = &param->flows_exported;
  struct OPTION *option = &param->option;
  int maxflows = (version == 1) ? NETFLOW1_MAXFLOWS : NETFLOW5_MAXFLOWS;
  int need;

  if (version != 5 && version != 1)
    return (-1);

  SET_EXPORT_NOW (now, param);
  uptime_ms = timeval_sub_ms (&now, system_boot_time);
  hdr = (struct NETFLOW5_HEADER *) packet;
  for (num_packets = offset = j = i = 0; i < num_flows; i++) {
    /* Records this flow adds: IPv4 only, one per direction with data. */
    need = (flows[i]->af == AF_INET) ?
      (flows[i]->octets[0] > 0) + (flows[i]->octets[1] > 0) : 0;
    if (j + need > maxflows) {
      param->records_sent += hdr->flows;
      hdr->flows = htons (hdr->flows);
      if (send_multi_destinations
          (sp.target->num_destinations, sp.target->destinations,
           sp.target->is_loadbalance, packet, offset, verbose_flag) < 0)
        return (-1);
      *flows_exported += j;
      j = 0;
      num_packets++;
    }
    if (j == 0) {
      memset (&packet, '\0', sizeof (packet));
      hdr->version = htons (version);
      hdr->flows = 0;           /* Filled in as we go */
      hdr->sysUpTime = htonl (uptime_ms);
      hdr->export_time = htonl (now.tv_sec);
      hdr->export_time_nanoseconds = htonl (now.tv_usec * 1000);
      hdr->sequence_number = htonl (*flows_exported);
      if (option->sample > 0) {
        hdr->sampling_interval =
          htons ((0x01 << 14) | (option->sample & 0x3FFF));
      }
      /* Other fields are left zero */
      offset = sizeof (*hdr);
      if (version == 1)
        offset = NETFLOW1_HEADER_SIZE;
    }
    /* NetFlow v.5 doesn't do IPv6 */
    if (flows[i]->af != AF_INET)
      continue;
    if (flows[i]->octets[0] > 0) {
      flw = (struct NETFLOW5_FLOW *) (packet + offset);
      flw->if_index_in = flw->if_index_out = htons (ifidx);
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
                                       NETFLOW1_FLOW_COMMON_SIZE,
                                       flows[i]->protocol, flows[i]->tos[0],
                                       flows[i]->tcp_flags[0]);
      }
      offset += sizeof (*flw);
      j++;
      hdr->flows++;
    }

    if (flows[i]->octets[1] > 0) {
      flw = (struct NETFLOW5_FLOW *) (packet + offset);
      flw->if_index_in = flw->if_index_out = htons (ifidx);
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
                                       NETFLOW1_FLOW_COMMON_SIZE,
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
    param->records_sent += hdr->flows;
    hdr->flows = htons (hdr->flows);
    if (send_multi_destinations
        (sp.target->num_destinations, sp.target->destinations,
         sp.target->is_loadbalance, packet, offset, verbose_flag) < 0)
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

/**
 * @brief Send expired flows as NetFlow v5 packets.
 *
 * @param sp Send parameters: flows to export, target destinations, interface index, tracking parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_netflow_v5 (struct SENDPARAMETER sp) {
  return send_netflow_v5_v1 (sp, 5);
}

#if EXPORT_MERGE != EXPORT_MERGE_NONE
/**
 * @brief Send expired flows as NetFlow v1 packets.
 *
 * @param sp Send parameters: flows to export, target destinations, interface index, tracking parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_netflow_v1 (struct SENDPARAMETER sp) {
  return send_netflow_v5_v1 (sp, 1);
}
#endif /* EXPORT_MERGE != EXPORT_MERGE_NONE */
