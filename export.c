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
 * @file export.c
 * @brief The encoder-based exporter (the default) of NetFlow v1, v5, v9 and
 *   IPFIX: the encoders of the fields and the senders of the fixed-format v1
 *   and v5 records. The templates of v9 and IPFIX are in export_template.c.
 */

#include "export.h"
#include "export_common.h"
#include "ipfix.h"
#include "common.h"
#include "netflow.h"
#include "psamp.h"
#include "softflowd.h"

/* Merged NetFlow v1/v5/v9/IPFIX exporter (default, encoder-based):
 * Consolidates all 4 versions into a single path by treating v1/v5 fields as
 * IPFIX IEs. Built unless --enable-compat-export or --enable-legacy is given;
 * compat/ipfix.c is built instead then (psamp.c remains separate). */

/**
 * @brief Store a host-order value as big-endian octets.
 *
 * Uses htobe64/htonl/htons for 8, 4 and 2 octets and falls back to a byte loop.
 *
 * @param dst Destination.
 * @param val Value; only its low len octets are stored.
 * @param len Number of octets to store.
 */
static inline void
hton (u_char *dst, u_int64_t val, u_int len) {
  switch (len) {
#if defined(htobe64) || defined(HAVE_DECL_HTOBE64)
    case 8: {
      u_int64_t v = htobe64 (val);
      memcpy (dst, &v, 8);
    }
      return;
#endif
    case 4: {
      u_int32_t v = htonl ((u_int32_t) val);
      memcpy (dst, &v, 4);
    }
      return;
    case 2: {
      u_int16_t v = htons ((u_int16_t) val);
      memcpy (dst, &v, 2);
    }
      return;
    default: {
      u_int k;
      for (k = 0; k < len; k++)
        dst[k] = (u_char) (val >> (8 * (len - 1 - k)));
    }
      return;
  }
}

/**
 * @brief Define an encoder that stores an integer value in network byte
 * order.
 *
 * The encoder is stored directly in the field tables, which removes any
 * run-time lookup. The compile-time constant width lets the compiler reduce
 * hton()'s switch to a single branch.
 *
 * @param name     Name of the encoder function to define.
 * @param val_expr Expression for the value; may use "flow", "i" and "ctx".
 * @param width    Number of octets to store.
 */
#define EXPORT_ENC_HTON(name, val_expr, width) \
  void name (u_char *dst, u_int16_t length,    \
             const struct EXPORT_CTX *ctx) {   \
    const struct FLOW *flow = ctx->flow;       \
    u_int i = ctx->i;                          \
    (void) flow;                               \
    (void) i;                                  \
    (void) length;                             \
    hton (dst, (val_expr), (width));           \
  }

/**
 * @brief Define an encoder that copies n octets from memory unchanged.
 *
 * There is no length check: the field tables match each encoder to its exact n,
 * so length >= n always holds and memcpy() can run unconditionally.
 *
 * @param name     Name of the encoder function to define.
 * @param src_expr Expression for the source address; may use "flow", "i" and
 * "ctx".
 * @param n        Number of octets to copy.
 */
#define EXPORT_ENC_COPY(name, src_expr, n)   \
  void name (u_char *dst, u_int16_t length,  \
             const struct EXPORT_CTX *ctx) { \
    const struct FLOW *flow = ctx->flow;     \
    u_int i = ctx->i;                        \
    (void) flow;                             \
    (void) i;                                \
    (void) length;                           \
    memcpy (dst, (src_expr), (n));           \
  }

/**
 * @brief Define an encoder that stores a single octet.
 *
 * @param name     Name of the encoder function to define.
 * @param val_expr Expression for the value; may use "flow", "i" and "ctx".
 */
#define EXPORT_ENC_BYTE(name, val_expr)      \
  void name (u_char *dst, u_int16_t length,  \
             const struct EXPORT_CTX *ctx) { \
    const struct FLOW *flow = ctx->flow;     \
    u_int i = ctx->i;                        \
    (void) length;                           \
    (void) flow;                             \
    (void) i;                                \
    *dst = (u_char) (val_expr);              \
  }

/**
 * @brief No-op encoder for NetFlow v1/v5 zero and padding fields (the buffer is
 * already zeroed).
 *
 * Calling this dummy directly is faster than testing for a NULL sentinel on the
 * hot path.
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_zero (u_char *dst, u_int16_t length,
          const struct EXPORT_CTX *ctx) {
  (void) dst;
  (void) length;
  (void) ctx; /* no value; buffer already zeroed */
}

EXPORT_ENC_HTON (enc_octetDeltaCount, flow->octets[i], 4)
EXPORT_ENC_HTON (enc_packetDeltaCount, flow->packets[i], 4)
EXPORT_ENC_BYTE (enc_protocolIdentifier, flow->protocol)
EXPORT_ENC_BYTE (enc_ipClassOfService, flow->tos[i])
EXPORT_ENC_BYTE (enc_tcpControlBits, flow->tcp_flags[i])
EXPORT_ENC_COPY (enc_sourceTransportPort, &flow->port[i], 2)
EXPORT_ENC_COPY (enc_destinationTransportPort, &flow->port[i ^ 1], 2)
EXPORT_ENC_COPY (enc_icmpTypeCode, &flow->port[i ^ 1], 2)
EXPORT_ENC_COPY (enc_sourceIPv4Address, &flow->addr[i].v4, 4)
EXPORT_ENC_COPY (enc_destinationIPv4Address, &flow->addr[i ^ 1].v4, 4)
EXPORT_ENC_COPY (enc_sourceIPv6Address, &flow->addr[i].v6, 16)
EXPORT_ENC_COPY (enc_destinationIPv6Address, &flow->addr[i ^ 1].v6, 16)
EXPORT_ENC_COPY (enc_sourceMacAddress, &flow->ethermac[i], 6)
EXPORT_ENC_COPY (enc_postDestinationMacAddress, &flow->ethermac[i ^ 1], 6)
/* Split into 16-bit and 32-bit encoders so each passes a literal width to
 * hton() for compile-time switch optimization instead of using runtime length.
 */
EXPORT_ENC_HTON (enc_ifidx16, ctx->sp->ifidx,
                 2) /* NetFlow v1/v5 ingress/egressInterface */
EXPORT_ENC_HTON (enc_ifidx32, ctx->sp->ifidx,
                 4) /* NetFlow v9/IPFIX ingress/egressInterface */
EXPORT_ENC_HTON (enc_flowStartSysUpTime,
                 timeval_sub_ms (&flow->flow_start,
                                 &ctx->sp->param->system_boot_time),
                 4)
EXPORT_ENC_HTON (enc_flowEndSysUpTime,
                 timeval_sub_ms (&flow->flow_last,
                                 &ctx->sp->param->system_boot_time),
                 4)
EXPORT_ENC_HTON (enc_flowStartSeconds, (u_int32_t) flow->flow_start.tv_sec, 4)
EXPORT_ENC_HTON (enc_flowEndSeconds, (u_int32_t) flow->flow_last.tv_sec, 4)
EXPORT_ENC_HTON (enc_flowStartMilliSeconds,
                 (u_int64_t) flow->flow_start.tv_sec * 1000 +
                   (u_int64_t) flow->flow_start.tv_usec / 1000,
                 8)
EXPORT_ENC_HTON (enc_flowEndMilliSeconds,
                 (u_int64_t) flow->flow_last.tv_sec * 1000 +
                   (u_int64_t) flow->flow_last.tv_usec / 1000,
                 8)
EXPORT_ENC_BYTE (enc_flowEndReason, flow->flowEndReason)

/**
 * @brief Encode the flow start time as a 64-bit NTP timestamp
 * (flowStartMicroseconds / flowStartNanoseconds).
 *
 * The micro and nano forms use the same encoding.
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_flowStartMicroSeconds (u_char *dst, u_int16_t length,
                           const struct EXPORT_CTX *ctx) {
  struct ntp_time_t ntptime;
  (void) length;
  conv_unix_to_ntp (ctx->flow->flow_start, &ntptime);
  hton (dst, (u_int64_t) ntptime.second << 32 | ntptime.fraction, 8);
}
/**
 * @brief Encode the flow end time as a 64-bit NTP timestamp
 * (flowEndMicroseconds / flowEndNanoseconds).
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_flowEndMicroSeconds (u_char *dst, u_int16_t length,
                         const struct EXPORT_CTX *ctx) {
  struct ntp_time_t ntptime;
  (void) length;
  conv_unix_to_ntp (ctx->flow->flow_last, &ntptime);
  hton (dst, (u_int64_t) ntptime.second << 32 | ntptime.fraction, 8);
}
EXPORT_ENC_HTON (enc_vlanId, ctx->flow->vlanid[ctx->i], 2)
EXPORT_ENC_HTON (enc_postVlanId, ctx->flow->vlanid[ctx->i ^ 1], 2)
#ifdef ENABLE_IFNAME
/**
 * @brief Encode the interface name (the capture interface, or the file name
 * with -r), truncated to the field length.
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_interfaceName (u_char *dst, u_int16_t length,
                   const struct EXPORT_CTX *ctx) {
  size_t n = strlen (ctx->sp->param->option.interfaceName);
  if (n > length)
    n = length;
  memcpy (dst, ctx->sp->param->option.interfaceName, n);
  /* Copies string up to its own length (capped at 'n'), leaving remaining field
   * bytes zeroed by the packet buffer's initial clearance. */
}
#endif /* ENABLE_IFNAME */

EXPORT_ENC_HTON (enc_nf9OptionScopeInterface, ctx->sp->ifidx, 4)
EXPORT_ENC_HTON (enc_samplingInterval,
                 ctx->sp->param->option.sample > 1 ? ctx->sp->param->option.sample
                                                   : 1,
                 length)
EXPORT_ENC_HTON (enc_systemInitTimeMilliseconds,
                 (u_int64_t) ctx->sp->param->system_boot_time.tv_sec * 1000 +
                   (u_int64_t) ctx->sp->param->system_boot_time.tv_usec / 1000,
                 8)
EXPORT_ENC_HTON (enc_meteringProcessId,
                 (u_int32_t) ctx->sp->param->option.meteringProcessId, 4)
EXPORT_ENC_HTON (enc_samplingPacketInterval,
                 ctx->sp->param->option.sample > 1 ? ctx->sp->param->option.sample
                                                   : 1,
                 length)
EXPORT_ENC_HTON (enc_samplingPacketSpace,
                 ctx->sp->param->option.sample > 0
                   ? ctx->sp->param->option.sample - 1
                   : 0,
                 length)
EXPORT_ENC_HTON (enc_selectorAlgorithm, PSAMP_selectorAlgorithm_count, length)
EXPORT_ENC_BYTE (enc_samplingAlgorithm, IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC)

/**
 * @brief Encode the exporter address (-e) matching the field length: 4 octets
 * for IPv4, 16 for IPv6.
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_exporterAddress (u_char *dst, u_int16_t length,
                     const struct EXPORT_CTX *ctx) {
  struct addrinfo *rp;
  for (rp = ctx->sp->param->option.exporterAddr; rp != NULL; rp = rp->ai_next) {
    if (length == 4 && rp->ai_family == AF_INET) {
      memcpy (dst, &((struct sockaddr_in *) rp->ai_addr)->sin_addr, 4);
      return;
    } else if (length == 16 && rp->ai_family == AF_INET6) {
      memcpy (dst, &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr, 16);
      return;
    }
  }
}

/**
 * @brief Encode the exporter address (-e) for the originalExporterIPv4/6Address
 * elements.
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_originalExporterAddress (u_char *dst, u_int16_t length,
                             const struct EXPORT_CTX *ctx) {
  struct addrinfo *rp;
  for (rp = ctx->sp->param->option.exporterAddr; rp != NULL; rp = rp->ai_next) {
    if (length == 4 && rp->ai_family == AF_INET) {
      memcpy (dst, &((struct sockaddr_in *) rp->ai_addr)->sin_addr, 4);
      return;
    } else if (length == 16 && rp->ai_family == AF_INET6) {
      memcpy (dst, &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr, 16);
      return;
    }
  }
}

/**
 * @brief Encode the IP version (4 or 6) of the flow.
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_ipVersion (u_char *dst, u_int16_t length,
               const struct EXPORT_CTX *ctx) {
  (void) length; /* Silence -Wunused-parameter warning */
  *dst = (ctx->flow->af == AF_INET) ? 4 : 6;
}

/**
 * @brief Encode the flowDirection element using ipfix_flow_direction().
 *
 * @param dst    Where to write the encoded value.
 * @param length Length of the field in octets.
 * @param ctx    Flow, endpoint index and send parameters.
 */
void
enc_flowDirection (u_char *dst, u_int16_t length,
                   const struct EXPORT_CTX *ctx) {
  (void) length; /* Silence -Wunused-parameter warning */
  *dst = ipfix_flow_direction (ctx->flow, ctx->i, ctx->sp->param);
}

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
 * @brief Emit every field of a data record group by calling the encoder of each
 * entry.
 *
 * The encoders are resolved at compile time, so no lookup is needed at run
 * time.
 *
 * @param fields  Field table with one encoder per entry.
 * @param nfields Number of entries.
 * @param packet  Packet buffer.
 * @param offset  Offset in packet to write at.
 * @param ctx     Flow, endpoint index and send parameters.
 * @return Offset after the last emitted field.
 */
u_int
export_emit_group_enc (const struct EXPORT_FIELD_SPECIFIER_ENCODER *fields,
                       u_int nfields, u_char *packet, u_int offset,
                       const struct EXPORT_CTX *ctx) {
  u_int i;
  for (i = 0; i < nfields; i++) {
    fields[i].encoder (packet + offset, fields[i].field.length, ctx);
    offset += fields[i].field.length;
  }
  return offset;
}

/* ------------------------------------------------------------------ */
/* NetFlow v1 / v5: fixed (non-templated) export.                      */
/* ------------------------------------------------------------------ */

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
