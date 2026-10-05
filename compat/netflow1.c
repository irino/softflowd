
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

#if EXPORT_MERGE == EXPORT_MERGE_NONE
/*
 * This is the Cisco Netflow(tm) version 1 packet format
 * Based on:
 * http://www.cisco.com/en/US/products/sw/netmgtsw/ps1964/products_implementation_design_guide09186a00800d6a11.html 
 */
/** NetFlow v1 flow record (48 octets). */
struct NETFLOW1_FLOW {
  u_int32_t sourceIPv4Address;  /**< Source IPv4 address */
  u_int32_t destinationIPv4Address;     /**< Destination IPv4 address */
  u_int32_t ipNextHopIPv4Address;       /**< Next hop (always 0) */
  u_int16_t ingressInterface;   /**< Input interface index */
  u_int16_t egressInterface;    /**< Output interface index */
  u_int32_t packetDeltaCount;   /**< Packets in the flow */
  u_int32_t octetDeltaCount;    /**< Octets in the flow */
  u_int32_t flowStartSysUpTime; /**< sysUpTime at flow start */
  u_int32_t flowEndSysUpTime;   /**< sysUpTime at flow end */
  u_int16_t sourceTransportPort;        /**< Source port */
  u_int16_t destinationTransportPort;   /**< Destination port */
  u_int16_t pad1;               /**< Padding */
  u_int8_t protocolIdentifier;  /**< IP protocol number */
  u_int8_t ipClassOfService;    /**< IP type of service */
  u_int8_t tcpControlBits;      /**< Cumulative TCP flags */
  u_int8_t pad2, pad3, pad4;    /**< Padding */
  u_int32_t reserved1;          /**< Reserved */
#if 0
  u_int8_t reserved2;           /* XXX: no longer used */
#endif
};
#define NETFLOW1_MAXPACKET_SIZE	(sizeof(struct NETFLOW1_HEADER) + \
				 (NETFLOW1_MAXFLOWS * sizeof(struct NETFLOW1_FLOW)))

/**
 * @brief Send expired flows as NetFlow v1 packets (independent exporter, export type "none").
 *
 * IPv6 flows are skipped, as NetFlow v1 cannot carry them. Each direction with traffic becomes one record.
 *
 * @param sp Send parameters: flows to export, target destinations, interface index, tracking parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_netflow_v1 (struct SENDPARAMETER sp) {
  struct FLOW **flows = sp.flows;
  int num_flows = sp.num_flows;
  u_int16_t ifidx = sp.ifidx;
  struct FLOWTRACKPARAMETERS *param = sp.param;
  int verbose_flag = sp.verbose_flag;
  struct timeval now;
  u_int32_t uptime_ms;
  u_int8_t packet[NETFLOW1_MAXPACKET_SIZE];  /* Maximum allowed packet size (24 flows) */
  struct NETFLOW1_HEADER *hdr = NULL;
  struct NETFLOW1_FLOW *flw = NULL;
  int i, j, offset, num_packets;
  struct timeval *system_boot_time = &param->system_boot_time;
  u_int64_t *flows_exported = &param->flows_exported;

  SET_EXPORT_NOW (now, param);
  uptime_ms = timeval_sub_ms (&now, system_boot_time);

  hdr = (struct NETFLOW1_HEADER *) packet;
  for (num_packets = offset = j = i = 0; i < num_flows; i++) {
    /* Records this flow adds: IPv4 only, one per direction with data. */
    int need = (flows[i]->af == AF_INET) ?
      (flows[i]->octets[0] > 0) + (flows[i]->octets[1] > 0) : 0;
    if (j + need > NETFLOW1_MAXFLOWS) {
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
      hdr->version = htons (1);
      hdr->flows = 0;           /* Filled in as we go */
      hdr->sysUpTime = htonl (uptime_ms);
      hdr->export_time = htonl (now.tv_sec);
      hdr->export_time_nanoseconds = htonl (now.tv_usec * 1000);
      offset = sizeof (*hdr);
    }

    /* NetFlow v.1 doesn't do IPv6 */
    if (flows[i]->af != AF_INET)
      continue;
    if (flows[i]->octets[0] > 0) {
      flw = (struct NETFLOW1_FLOW *) (packet + offset);
      flw->ingressInterface = flw->egressInterface = htons (ifidx);
      flw->sourceIPv4Address = flows[i]->addr[0].v4.s_addr;
      flw->destinationIPv4Address = flows[i]->addr[1].v4.s_addr;
      flw->sourceTransportPort = flows[i]->port[0];
      flw->destinationTransportPort = flows[i]->port[1];
      flw->packetDeltaCount = htonl (flows[i]->packets[0]);
      flw->octetDeltaCount = htonl (flows[i]->octets[0]);
      flw->flowStartSysUpTime =
        htonl (timeval_sub_ms (&flows[i]->flow_start, system_boot_time));
      flw->flowEndSysUpTime =
        htonl (timeval_sub_ms (&flows[i]->flow_last, system_boot_time));
      flw->protocolIdentifier = flows[i]->protocol;
      flw->tcpControlBits = flows[i]->tcp_flags[0];
      flw->ipClassOfService = flows[i]->tos[0];
      offset += sizeof (*flw);
      j++;
      hdr->flows++;
    }

    if (flows[i]->octets[1] > 0) {
      flw = (struct NETFLOW1_FLOW *) (packet + offset);
      flw->ingressInterface = flw->egressInterface = htons (ifidx);
      flw->sourceIPv4Address = flows[i]->addr[1].v4.s_addr;
      flw->destinationIPv4Address = flows[i]->addr[0].v4.s_addr;
      flw->sourceTransportPort = flows[i]->port[1];
      flw->destinationTransportPort = flows[i]->port[0];
      flw->packetDeltaCount = htonl (flows[i]->packets[1]);
      flw->octetDeltaCount = htonl (flows[i]->octets[1]);
      flw->flowStartSysUpTime =
        htonl (timeval_sub_ms (&flows[i]->flow_start, system_boot_time));
      flw->flowEndSysUpTime =
        htonl (timeval_sub_ms (&flows[i]->flow_last, system_boot_time));
      flw->protocolIdentifier = flows[i]->protocol;
      flw->tcpControlBits = flows[i]->tcp_flags[1];
      flw->ipClassOfService = flows[i]->tos[1];
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
#endif /* EXPORT_MERGE == EXPORT_MERGE_NONE */
