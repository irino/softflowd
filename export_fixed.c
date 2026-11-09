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

/**
 * @file export_fixed.c
 * @brief The fixed-format part of the encoder-based exporter: the senders of
 *   the NetFlow v1 and v5 records and the tables of their fields. Split from
 *   export.c.
 */

#include "export.h"
#include "export_common.h"
#include "ipfix.h"
#include "common.h"
#include "netflow.h"
#include "softflowd.h"

/* NetFlow v1/v5 fixed data records: same IEs as field_netflow_v1v5_common[]. */
/**
 * The first fields of a NetFlow v1 or v5 record, the same in both, with
 * their encoders: addresses, next hop, interfaces, packets, octets,
 * times and ports.
 */
static const struct EXPORT_FIELD_SPECIFIER_ENCODER
  field_netflow_v1v5_common_enc[] = {
    {{IPFIX_sourceIPv4Address, 4}, enc_sourceIPv4Address},
    {{IPFIX_destinationIPv4Address, 4}, enc_destinationIPv4Address},
    {{IPFIX_ipNextHopIPv4Address, 4}, enc_zero},
    {{IPFIX_ingressInterface, 2}, enc_ifidx16},
    {{IPFIX_egressInterface, 2}, enc_ifidx16},
    {{IPFIX_packetDeltaCount, 4}, enc_packetDeltaCount},
    {{IPFIX_octetDeltaCount, 4}, enc_octetDeltaCount},
    {{IPFIX_flowStartSysUpTime, 4}, enc_flowStartSysUpTime},
    {{IPFIX_flowEndSysUpTime, 4}, enc_flowEndSysUpTime},
    {{IPFIX_sourceTransportPort, 2}, enc_sourceTransportPort},
    {{IPFIX_destinationTransportPort, 2}, enc_destinationTransportPort},
};

/**
 * The last fields of a NetFlow v1 record, with their encoders: protocol,
 * type of service, TCP flags and padding.
 */
static const struct EXPORT_FIELD_SPECIFIER_ENCODER field_netflowv1_tail_enc[] = {
  {{IPFIX_paddingOctets, 2}, enc_zero},
  {{IPFIX_protocolIdentifier, 1}, enc_protocolIdentifier},
  {{IPFIX_ipClassOfService, 1}, enc_ipClassOfService},
  {{IPFIX_tcpControlBits, 1}, enc_tcpControlBits},
  {{IPFIX_paddingOctets, 7}, enc_zero},
};

/**
 * The last fields of a NetFlow v5 record, with their encoders: TCP
 * flags, protocol, type of service, AS numbers, prefix lengths and
 * padding.
 */
static const struct EXPORT_FIELD_SPECIFIER_ENCODER field_netflowv5_tail_enc[] = {
  {{IPFIX_paddingOctets, 1}, enc_zero},
  {{IPFIX_tcpControlBits, 1}, enc_tcpControlBits},
  {{IPFIX_protocolIdentifier, 1}, enc_protocolIdentifier},
  {{IPFIX_ipClassOfService, 1}, enc_ipClassOfService},
  {{IPFIX_bgpSourceAsNumber, 2}, enc_zero},
  {{IPFIX_bgpDestinationAsNumber, 2}, enc_zero},
  {{IPFIX_sourceIPv4PrefixLength, 1}, enc_zero},
  {{IPFIX_destinationIPv4PrefixLength, 1}, enc_zero},
  {{IPFIX_paddingOctets, 2}, enc_zero},
};

/**
 * @brief Complete a NetFlow v1 or v5 packet and send it.
 *
 * Writes the record count into the header, sends the packet to the
 * destinations and updates the export counters.
 *
 * @param sp     Send parameters: target, tracking parameters and verbosity.
 * @param packet Packet buffer holding the header and the records.
 * @param offset Length of the packet.
 * @param count  Number of records in the packet.
 * @return 0 on success, -1 on error.
 */
static int
send_fixed_packet (const struct SENDPARAMETER *sp, u_char *packet, u_int offset,
                   u_int count) {
  struct FLOWTRACKPARAMETERS *param = sp->param;

  param->records_sent += count;
  MEMCPY (packet + offsetof (struct NETFLOW5_HEADER, flows),
          &(u_int16_t) {htons (count)}, u_int16_t);
  if (send_multi_destinations (sp->target->num_destinations,
                               sp->target->destinations,
                               sp->target->is_loadbalance, packet, offset,
                               sp->verbose_flag) < 0)
    return (-1);
  param->flows_exported += count;
  return (0);
}

/**
 * @brief Send flows as NetFlow v1 or v5 packets with 48-octet data records.
 *
 * Uses the same field-list logic as the v9/IPFIX exporter. IPv6 flows are
 * skipped.
 *
 * @param sp      Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @param version Export version: 1 or 5.
 * @return Number of packets sent, or -1 on error.
 */
static int
send_fixed_flow (struct SENDPARAMETER sp, u_int16_t version) {
  struct FLOW **flows = sp.flows;
  int num_flows = sp.num_flows;
  struct FLOWTRACKPARAMETERS *param = sp.param;
  u_char packet[NETFLOW5_MAXPACKET_SIZE];
  const struct EXPORT_FIELD_SPECIFIER_ENCODER *tail_fields =
    (version == 1) ? field_netflowv1_tail_enc : field_netflowv5_tail_enc;
  u_int tail_nfields = (version == 1)
                         ? EXPORT_NFIELDS_ENC (field_netflowv1_tail_enc)
                         : EXPORT_NFIELDS_ENC (field_netflowv5_tail_enc);
  u_int maxflows = (version == 1) ? NETFLOW1_MAXFLOWS : NETFLOW5_MAXFLOWS;
  u_int offset, j, i, k, num_packets, need;
  u_int64_t *flows_exported = &param->flows_exported;
  struct EXPORT_CTX ctx = {.sp = &sp, .flow = NULL, .i = 0};

  if (version != 1 && version != 5)
    return (-1);

  num_packets = offset = j = 0;
  for (i = 0; i < (u_int) num_flows; i++) {
    /* Records this flow adds: IPv4 only, one per direction with data.
     * Flush first if they do not all fit, so that the two directions of
     * one flow are never split across packets (or emitted twice). */
    need = (flows[i]->af == AF_INET)
             ? (flows[i]->octets[0] > 0) + (flows[i]->octets[1] > 0)
             : 0;
    if (j + need > maxflows) {
      if (send_fixed_packet (&sp, packet, offset, j) < 0)
        return (-1);
      j = 0;
      num_packets++;
    }
    if (j == 0) {
      memset (packet, 0, sizeof (packet));
      offset = export_build_flow_header (packet, version, param);
      if (version == 5)
        MEMCPY (packet + offsetof (struct NETFLOW5_HEADER, sequence_number),
                &(u_int32_t) {htonl ((u_int32_t) *flows_exported)}, u_int32_t);
    }

    /* NetFlow v1/v5 carry IPv4 only, as in the original implementation. */
    if (flows[i]->af != AF_INET)
      continue;

    for (k = 0; k < 2; k++) {
      if (flows[i]->octets[k] == 0)
        continue;
      ctx.flow = flows[i];
      ctx.i = k;
      offset =
        export_emit_group_enc (field_netflow_v1v5_common_enc,
                               EXPORT_NFIELDS_ENC (field_netflow_v1v5_common_enc),
                               packet, offset, &ctx);
      offset =
        export_emit_group_enc (tail_fields, tail_nfields, packet, offset, &ctx);
      j++;
    }
  }

  if (j != 0) {
    if (send_fixed_packet (&sp, packet, offset, j) < 0)
      return (-1);
    num_packets++;
  }

  param->packets_sent += num_packets;
  return (num_packets);
}

/**
 * @brief Send expired flows as NetFlow v1 packets.
 *
 * @param sp Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_netflow_v1 (struct SENDPARAMETER sp) {
  return send_fixed_flow (sp, 1);
}

/**
 * @brief Send expired flows as NetFlow v5 packets.
 *
 * @param sp Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_netflow_v5 (struct SENDPARAMETER sp) {
  return send_fixed_flow (sp, 5);
}
