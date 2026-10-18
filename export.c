/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 * Copyright 2012 Hitoshi Irino <irino@sfc.wide.ad.jp> All rights reserved.
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

#include "export_common.h"
#include "ipfix.h"
#include "ipfix_fields.h"
#include "common.h"
#include "log.h"
#include "netflow.h"
#include "psamp.h"
#include "softflowd.h"
#include "treetype.h"

#define EXPORT_NFIELDS_ENC(a) \
  (sizeof (a) / sizeof (struct EXPORT_FIELD_SPECIFIER_ENCODER))

/* Merged NetFlow v1/v5/v9/IPFIX exporter (default, encoder-based):
 * Consolidates all 4 versions into a single path by treating v1/v5 fields as
 * IPFIX IEs. Built unless --enable-compat-export or --enable-legacy is given;
 * compat/ipfix.c is built instead then (psamp.c remains separate). */

/** Context for resolving field values: flow, endpoint index, and send
 * parameters. */
struct EXPORT_CTX {
  const struct SENDPARAMETER
    *sp;                   /**< Send parameters (tracking parameters, interface index) */
  const struct FLOW *flow; /**< Flow being encoded */
  u_int i;                 /**< Which endpoint (0/1) is "source" here */
};

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
 * @brief Define a static encoder that stores an integer value in network byte
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
#define EXPORT_ENC_HTON(name, val_expr, width)      \
  static void name (u_char *dst, u_int16_t length,  \
                    const struct EXPORT_CTX *ctx) { \
    const struct FLOW *flow = ctx->flow;            \
    u_int i = ctx->i;                               \
    (void) flow;                                    \
    (void) i;                                       \
    (void) length;                                  \
    hton (dst, (val_expr), (width));                \
  }

/**
 * @brief Define a static encoder that copies n octets from memory unchanged.
 *
 * There is no length check: the field tables match each encoder to its exact n,
 * so length >= n always holds and memcpy() can run unconditionally.
 *
 * @param name     Name of the encoder function to define.
 * @param src_expr Expression for the source address; may use "flow", "i" and
 * "ctx".
 * @param n        Number of octets to copy.
 */
#define EXPORT_ENC_COPY(name, src_expr, n)          \
  static void name (u_char *dst, u_int16_t length,  \
                    const struct EXPORT_CTX *ctx) { \
    const struct FLOW *flow = ctx->flow;            \
    u_int i = ctx->i;                               \
    (void) flow;                                    \
    (void) i;                                       \
    (void) length;                                  \
    memcpy (dst, (src_expr), (n));                  \
  }

/**
 * @brief Define a static encoder that stores a single octet.
 *
 * @param name     Name of the encoder function to define.
 * @param val_expr Expression for the value; may use "flow", "i" and "ctx".
 */
#define EXPORT_ENC_BYTE(name, val_expr)             \
  static void name (u_char *dst, u_int16_t length,  \
                    const struct EXPORT_CTX *ctx) { \
    const struct FLOW *flow = ctx->flow;            \
    u_int i = ctx->i;                               \
    (void) length;                                  \
    (void) flow;                                    \
    (void) i;                                       \
    *dst = (u_char) (val_expr);                     \
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
static void
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
static void
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
static void
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
static void
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
static void
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
static void
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
static void
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
static void
enc_flowDirection (u_char *dst, u_int16_t length,
                   const struct EXPORT_CTX *ctx) {
  (void) length; /* Silence -Wunused-parameter warning */
  *dst = ipfix_flow_direction (ctx->flow, ctx->i, ctx->sp->param);
}

/* NetFlow v1/v5 fixed data records: same IEs as field_netflow_v1v5_common[]. */
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

static const struct EXPORT_FIELD_SPECIFIER_ENCODER field_netflowv1_tail_enc[] = {
  {{IPFIX_paddingOctets, 2}, enc_zero},
  {{IPFIX_protocolIdentifier, 1}, enc_protocolIdentifier},
  {{IPFIX_ipClassOfService, 1}, enc_ipClassOfService},
  {{IPFIX_tcpControlBits, 1}, enc_tcpControlBits},
  {{IPFIX_paddingOctets, 7}, enc_zero},
};

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
static u_int
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

/* ------------------------------------------------------------------ */
/* NetFlow v9 / IPFIX: templated export.                                */
/* ------------------------------------------------------------------ */

/** A NetFlow v9 / IPFIX template (struct IPFIX_SOFTFLOWD_TEMPLATE) together
 * with the encoders used to fill its data records. */
struct IPFIX_SOFTFLOWD_TEMPLATE_ENCODER {
  struct IPFIX_SOFTFLOWD_TEMPLATE t; /**< Template as sent, in network byte order */
  struct EXPORT_FIELD_SPECIFIER_ENCODER
    hr[IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS]; /**< Per-record encoders */
  u_int hr_count;                          /**< Number of entries in hr[] */
  struct EXPORT_FIELD_SPECIFIER_ENCODER
    hbi[IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS]; /**< Encoders of the reverse-direction fields */
  u_int hbi_count;                             /**< Number of entries in hbi[] */
};

/** Templates indexed by TMPLV4, TMPLICMPV4, TMPLV6 and TMPLICMPV6. */
static struct IPFIX_SOFTFLOWD_TEMPLATE_ENCODER templates[TMPLMAX];

/* Emits NFv9/IPFIX Options Templates and Data Records using
 * export_emit_group_enc(). Reuses struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE to
 * avoid duplicate padded declarations. */
struct IPFIX_OPTION_TEMPLATE {
  struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE
    tmpl; /**< Options template as sent on the wire */
  /* Host-order copies for the Data Record -- see IPFIX_SOFTFLOWD_TEMPLATE_ENCODER.hr[]. */
  struct EXPORT_FIELD_SPECIFIER_ENCODER
    hs[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS]; /**< Encoders of the
                                                            scope fields */
  u_int hs_count;                                      /**< Number of entries in hs[] */
  struct EXPORT_FIELD_SPECIFIER_ENCODER
    hr[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS]; /**< Encoders of the option
                                                       fields */
  u_int hr_count;                                 /**< Number of entries in hr[] */
  u_int16_t total_len;                            /**< Bytes of tmpl.h+s+r actually in use */
};

/** The options template and data record, built once by ipfix_init_option(). */
static struct IPFIX_OPTION_TEMPLATE option_template;
/** Non-zero once option_template has been built. */
static int option_initialized = 0;

/**
 * @brief Build the options template for the given version into option_template.
 *
 * @param version Export version: 9 or 10.
 */
static void
ipfix_init_option (u_int16_t version) {
  const struct EXPORT_FIELD_SPECIFIER_ENCODER *scope_src, *opt_src;
  u_int scope_n, opt_n, i, scope_speclen, opt_speclen;

  memset (&option_template, 0, sizeof (option_template));
  if (version == 10) {
    scope_src = field_scope;
    scope_n = EXPORT_NFIELDS_ENC (field_scope);
    opt_src = field_option;
    opt_n = EXPORT_NFIELDS_ENC (field_option);
  } else {
    scope_src = field_nf9scope;
    scope_n = EXPORT_NFIELDS_ENC (field_nf9scope);
    opt_src = field_nf9option;
    opt_n = EXPORT_NFIELDS_ENC (field_nf9option);
  }

  for (i = 0; i < scope_n; i++) {
    option_template.tmpl.s[i].ie = htons (scope_src[i].field.ie);
    option_template.tmpl.s[i].length = htons (scope_src[i].field.length);
    option_template.hs[i] = scope_src[i];
  }
  option_template.hs_count = scope_n;
  for (i = 0; i < opt_n; i++) {
    option_template.tmpl.r[i].ie = htons (opt_src[i].field.ie);
    option_template.tmpl.r[i].length = htons (opt_src[i].field.length);
    option_template.hr[i] = opt_src[i];
  }
  option_template.hr_count = opt_n;

  /* scope_speclen/opt_speclen: byte length of the field-specifier
   * lists themselves (4 octets/entry), not of the data they describe. */
  scope_speclen = scope_n * sizeof (struct IPFIX_FIELD_SPECIFIER);
  opt_speclen = opt_n * sizeof (struct IPFIX_FIELD_SPECIFIER);

  option_template.tmpl.h.c.set_id =
    htons (version == 10 ? IPFIX_OPTION_TEMPLATE_SET_ID
                         : NETFLOW9_OPTION_TEMPLATE_SET_ID);
  option_template.tmpl.h.c.length =
    htons (sizeof (option_template.tmpl.h) + scope_speclen + opt_speclen);
  if (version == 10) {
    option_template.tmpl.h.u.i.r.template_id =
      htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    option_template.tmpl.h.u.i.r.count = htons (scope_n + opt_n);
    option_template.tmpl.h.u.i.scope_count = htons (scope_n);
  } else {
    option_template.tmpl.h.u.n.template_id =
      htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    option_template.tmpl.h.u.n.scope_length = htons (scope_speclen);
    option_template.tmpl.h.u.n.option_length = htons (opt_speclen);
  }
  option_template.total_len =
    sizeof (option_template.tmpl.h) + scope_speclen + opt_speclen;
  option_initialized = 1;
}

/**
 * @brief Append the options template set and its data record to a packet.
 *
 * The data record is emitted through export_emit_group_enc() like a standard
 * record.
 *
 * @param packet  Packet buffer.
 * @param offset  Offset to write at; advanced past the appended data.
 * @param version Export version: 9 or 10.
 * @param sp      Send parameters; the option values are taken from sp->param.
 */
static void
ipfix_send_option (u_char *packet, u_int *offset, u_int16_t version,
                   const struct SENDPARAMETER *sp) {
  struct IPFIX_SET_HEADER *c;
  u_int doff;
  u_int scope_speclen, opt_speclen;

  if (!option_initialized)
    ipfix_init_option (version);

  /* Copies template header, s[], and r[] in 3 separate blocks to skip unused
   * tail bytes caused by IPFIX's max-sized field array backing in
   * option_template. */
  scope_speclen =
    option_template.hs_count * sizeof (struct IPFIX_FIELD_SPECIFIER);
  opt_speclen = option_template.hr_count * sizeof (struct IPFIX_FIELD_SPECIFIER);
  memcpy (packet + *offset, &option_template.tmpl.h,
          sizeof (option_template.tmpl.h));
  *offset += sizeof (option_template.tmpl.h);
  memcpy (packet + *offset, option_template.tmpl.s, scope_speclen);
  *offset += scope_speclen;
  memcpy (packet + *offset, option_template.tmpl.r, opt_speclen);
  *offset += opt_speclen;

  c = (struct IPFIX_SET_HEADER *) (packet + *offset);
  doff = sizeof (*c);
  struct EXPORT_CTX ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.sp = sp;
  doff = export_emit_group_enc (option_template.hs, option_template.hs_count,
                                packet + *offset, doff, &ctx);
  doff = export_emit_group_enc (option_template.hr, option_template.hr_count,
                                packet + *offset, doff, &ctx);
  c->set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  c->length = htons (doff);
  *offset += doff;
}

/**
 * @brief Add fields to a template and remember their encoders.
 *
 * Fields that do not fit in the template arrays are dropped.
 *
 * @param tmpl         Template to extend.
 * @param index        Position to start at; advanced by the number of fields
 * added.
 * @param src          Field table with encoders.
 * @param field_number Number of fields to add.
 * @param bi_flag      IPFIX_BIFLAG_ON to add reverse-direction (enterprise)
 * fields.
 * @return Sum of the lengths of the added fields.
 */
static u_int
ipfix_init_template_fields (struct IPFIX_SOFTFLOWD_TEMPLATE_ENCODER *tmpl, u_int *index,
                            const struct EXPORT_FIELD_SPECIFIER_ENCODER *src,
                            u_int field_number, int bi_flag) {
  u_int i, length = 0;
  u_int max_fields = bi_flag ? sizeof (tmpl->t.v) / sizeof (tmpl->t.v[0])
                             : sizeof (tmpl->t.r) / sizeof (tmpl->t.r[0]);
  for (i = 0; i < field_number && *index + i < max_fields; i++) {
    if (bi_flag) {
      tmpl->t.v[*index + i].ie = htons (src[i].field.ie | 0x8000);
      tmpl->t.v[*index + i].length = htons (src[i].field.length);
      tmpl->t.v[*index + i].pen = htonl (REVERSE_PEN);
      tmpl->hbi[*index + i] = src[i];
    } else {
      tmpl->t.r[*index + i].ie = htons (src[i].field.ie);
      tmpl->t.r[*index + i].length = htons (src[i].field.length);
      tmpl->hr[*index + i] = src[i];
    }
    length += src[i].field.length;
  }
  if (bi_flag)
    tmpl->hbi_count = *index + i;
  else
    tmpl->hr_count = *index + i;
  *index += i;
  return length;
}

/**
 * @brief Add the flow start/end time fields chosen by the time format option
 * (-A).
 *
 * @param param   Tracking parameters (time_format).
 * @param tmpl    Template to extend.
 * @param index   Position to start at; advanced.
 * @param version Export version: only IPFIX (10) supports absolute time
 * formats.
 * @return Sum of the lengths of the added fields.
 */
static u_int
ipfix_init_template_time (struct FLOWTRACKPARAMETERS *param,
                          struct IPFIX_SOFTFLOWD_TEMPLATE_ENCODER *tmpl, u_int *index,
                          u_int16_t version) {
  /* Absolute (calendar) timestamps are IPFIX-only
   * NetFlow v9 always uses the relative sysUpTime form. */
  if (version == 10 && param->time_format == 's')
    return ipfix_init_template_fields (tmpl, index, field_timesec, 2,
                                       IPFIX_BIFLAG_OFF);
  if (version == 10 && param->time_format == 'm')
    return ipfix_init_template_fields (tmpl, index, field_timemsec, 2,
                                       IPFIX_BIFLAG_OFF);
  if (version == 10 && param->time_format == 'M')
    return ipfix_init_template_fields (tmpl, index, field_timeusec, 2,
                                       IPFIX_BIFLAG_OFF);
  if (version == 10 && param->time_format == 'n')
    return ipfix_init_template_fields (tmpl, index, field_timensec, 2,
                                       IPFIX_BIFLAG_OFF);
  return ipfix_init_template_fields (tmpl, index, field_timesysup, 2,
                                     IPFIX_BIFLAG_OFF);
}

/**
 * @brief Build one complete template.
 *
 * @param param       Tracking parameters.
 * @param tmpl        Template to build.
 * @param template_id Template id.
 * @param v6_flag     Non-zero for IPv6.
 * @param icmp_flag   Non-zero for the ICMP variant.
 * @param bi_flag     IPFIX_BIFLAG_ON for biflow (reverse fields).
 * @param version     Export version.
 */
static void
ipfix_init_template_unity (struct FLOWTRACKPARAMETERS *param,
                           struct IPFIX_SOFTFLOWD_TEMPLATE_ENCODER *tmpl,
                           u_int template_id, u_int8_t v6_flag,
                           u_int8_t icmp_flag, u_int8_t bi_flag,
                           u_int16_t version) {
  u_int index = 0, bi_index = 0, length = 0;
  memset (tmpl, 0, sizeof (*tmpl));
  tmpl->t.h.c.set_id =
    htons (version == 10 ? IPFIX_TEMPLATE_SET_ID : NETFLOW9_TEMPLATE_SET_ID);
  tmpl->t.h.r.template_id = htons (template_id);

  if (v6_flag)
    length += ipfix_init_template_fields (tmpl, &index, field_v6,
                                          EXPORT_NFIELDS_ENC (field_v6),
                                          IPFIX_BIFLAG_OFF);
  else
    length += ipfix_init_template_fields (tmpl, &index, field_v4,
                                          EXPORT_NFIELDS_ENC (field_v4),
                                          IPFIX_BIFLAG_OFF);
  length += ipfix_init_template_time (param, tmpl, &index, version);
  length += ipfix_init_template_fields (tmpl, &index, field_common,
                                        EXPORT_NFIELDS_ENC (field_common),
                                        IPFIX_BIFLAG_OFF);
  if (icmp_flag) {
    if (v6_flag)
      length += ipfix_init_template_fields (tmpl, &index, field_icmp6,
                                            EXPORT_NFIELDS_ENC (field_icmp6),
                                            IPFIX_BIFLAG_OFF);
    else
      length += ipfix_init_template_fields (tmpl, &index, field_icmp4,
                                            EXPORT_NFIELDS_ENC (field_icmp4),
                                            IPFIX_BIFLAG_OFF);
  } else {
    length += ipfix_init_template_fields (tmpl, &index, field_transport,
                                          EXPORT_NFIELDS_ENC (field_transport),
                                          IPFIX_BIFLAG_OFF);
  }
  if (param->track_level >= TRACK_FULL_VLAN)
    length += ipfix_init_template_fields (tmpl, &index, field_vlan,
                                          EXPORT_NFIELDS_ENC (field_vlan),
                                          IPFIX_BIFLAG_OFF);
  if (param->track_level >= TRACK_FULL_VLAN_ETHER)
    length += ipfix_init_template_fields (tmpl, &index, field_ether,
                                          EXPORT_NFIELDS_ENC (field_ether),
                                          IPFIX_BIFLAG_OFF);
  if (bi_flag && version == 10) {
    length += ipfix_init_template_fields (tmpl, &bi_index, field_bicommon,
                                          EXPORT_NFIELDS_ENC (field_bicommon),
                                          IPFIX_BIFLAG_ON);
    if (icmp_flag) {
      if (v6_flag)
        length += ipfix_init_template_fields (
          tmpl, &bi_index, field_biicmp6,
          EXPORT_NFIELDS_ENC (field_biicmp6), IPFIX_BIFLAG_ON);
      else
        length += ipfix_init_template_fields (
          tmpl, &bi_index, field_biicmp4,
          EXPORT_NFIELDS_ENC (field_biicmp4), IPFIX_BIFLAG_ON);
    } else {
      length += ipfix_init_template_fields (
        tmpl, &bi_index, field_bitransport,
        EXPORT_NFIELDS_ENC (field_bitransport), IPFIX_BIFLAG_ON);
    }
  }
  tmpl->t.bi_count = bi_index;
  tmpl->t.h.r.count = htons (index + bi_index + param->max_num_label);
  tmpl->t.h.c.length =
    htons (sizeof (struct IPFIX_TEMPLATE_SET_HEADER) +
           index * sizeof (struct IPFIX_FIELD_SPECIFIER) +
           bi_index * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) +
           param->max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER));
  tmpl->t.data_len =
    length + param->max_num_label * IPFIX_mplsLabelStackSection_SIZE;
}

/**
 * @brief Build the IPv4, ICMPv4, IPv6 and ICMPv6 templates into templates.
 *
 * @param param   Tracking parameters.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow.
 * @param version Export version: 9 or 10.
 */
static void
ipfix_init_templates (struct FLOWTRACKPARAMETERS *param,
                      u_int8_t bi_flag, u_int16_t version) {
  u_int8_t v6_flag = 0, icmp_flag = 0;
  u_int16_t template_id = 0;
  int i;
  for (i = 0; i < TMPLMAX; i++) {
    switch (i) {
      case TMPLV4:
        v6_flag = 0;
        icmp_flag = 0;
        template_id = IPFIX_SOFTFLOWD_V4_TEMPLATE_ID;
        break;
      case TMPLICMPV4:
        v6_flag = 0;
        icmp_flag = 1;
        template_id = IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID;
        break;
      case TMPLV6:
        v6_flag = 1;
        icmp_flag = 0;
        template_id = IPFIX_SOFTFLOWD_V6_TEMPLATE_ID;
        break;
      case TMPLICMPV6:
        v6_flag = 1;
        icmp_flag = 1;
        template_id = IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID;
        break;
    }
    ipfix_init_template_unity (param, &templates[i], template_id, v6_flag,
                               icmp_flag, bi_flag, version);
  }
}

/**
 * @brief Append a template to a packet, including reverse fields and the MPLS
 * label fields.
 *
 * @param packet        Packet buffer.
 * @param offset        Offset to write at; advanced.
 * @param tmpl          Template to copy.
 * @param bi_flag       Non-zero to append the reverse-direction fields.
 * @param max_num_label Number of MPLS label fields to append.
 */
static void
ipfix_memcpy_template (u_char *packet, u_int *offset,
                       struct IPFIX_SOFTFLOWD_TEMPLATE_ENCODER *tmpl, u_int8_t bi_flag,
                       u_int8_t max_num_label) {
  u_int i, size = ntohs (tmpl->t.h.c.length) -
                  tmpl->t.bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) -
                  max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER);
  memcpy (packet + *offset, &tmpl->t, size);
  *offset += size;
  if (bi_flag) {
    size = tmpl->t.bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER);
    memcpy (packet + *offset, tmpl->t.v, size);
    *offset += size;
  }
  for (i = 0; i < max_num_label; i++) {
    struct IPFIX_FIELD_SPECIFIER *mpls_fs =
      (struct IPFIX_FIELD_SPECIFIER *) &packet[*offset];
    mpls_fs->ie = htons (IPFIX_mplsTopLabelStackSection + i);
    mpls_fs->length = htons (IPFIX_mplsLabelStackSection_SIZE);
    *offset += sizeof (struct IPFIX_FIELD_SPECIFIER);
  }
}

/**
 * @brief Encode the data records of one flow (standard or biflow) using the
 * template field list.
 *
 * Dynamic counterpart of the record loop in send_fixed_flow().
 *
 * @param flow     Flow to encode.
 * @param packet   Output buffer.
 * @param len      Space available in packet.
 * @param sp       Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @param len_used Receives the number of bytes written.
 * @param bi_flag  Non-zero to emit one biflow record instead of one per
 * direction.
 * @param version  Export version.
 * @return Number of records written, or -1 if the buffer is too small.
 */
int
ipfix_flow_to_flowset (const struct FLOW *flow, u_char *packet,
                       u_int len, const struct SENDPARAMETER *sp,
                       u_int *len_used, u_int8_t bi_flag,
                       u_int16_t version) {
  u_int tmplindex = ipfix_flow_to_template_index (flow);
  struct IPFIX_SOFTFLOWD_TEMPLATE_ENCODER *tmpl = &templates[tmplindex];
  u_int offset = 0, nflows = 0, k;
  u_int frecnum = bi_flag ? 1 : 2;
  struct EXPORT_CTX ctx = {.sp = sp, .flow = flow, .i = 0};

  (void) version; /* only used to size frecnum via bi_flag */
  if (len < tmpl->t.data_len * frecnum)
    return (-1);

  for (ctx.i = 0; ctx.i < frecnum; ctx.i++) {
    if (bi_flag == 0 && flow->octets[ctx.i] == 0)
      continue;
    nflows++;
    offset =
      export_emit_group_enc (tmpl->hr, tmpl->hr_count, packet, offset, &ctx);
    if (bi_flag && ctx.i == 0) {
      struct EXPORT_CTX bictx = ctx;
      bictx.i = 1; /* reverse direction */
      offset = export_emit_group_enc (tmpl->hbi, tmpl->hbi_count, packet, offset,
                                      &bictx);
    }
    for (k = 0; k < sp->param->max_num_label; k++) {
      memcpy (&packet[offset], &flow->mplsLabels[k],
              IPFIX_mplsLabelStackSection_SIZE);
      offset += IPFIX_mplsLabelStackSection_SIZE;
    }
  }
  *len_used = offset;
  return (nflows);
}

/**
 * @brief Build the templates and the option record on the first export.
 *
 * @param sp      Send parameters; the tracking parameters are taken from
 * sp->param.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow export.
 * @param version Export version: 9 or 10.
 */
void
ipfix_init_exporter (const struct SENDPARAMETER *sp,
                     u_int8_t bi_flag, u_int16_t version) {
  ipfix_init_templates (sp->param, bi_flag, version);
  ipfix_init_option (version);
}

/**
 * @brief Append the templates and the option record to a packet.
 *
 * @param packet  Packet buffer.
 * @param offset  Offset in the packet to append at; updated.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow export.
 * @param version Export version: 9 or 10.
 * @param sp      Send parameters; the option values are taken from sp->param.
 */
void
ipfix_put_templates (u_char *packet, u_int *offset, u_int8_t bi_flag,
                     u_int16_t version,
                     const struct SENDPARAMETER *sp) {
  u_int i;

  for (i = 0; i < TMPLMAX; i++)
    ipfix_memcpy_template (packet, offset, &templates[i], bi_flag,
                           sp->param->max_num_label);
  ipfix_send_option (packet, offset, version, sp);
}

/**
 * @brief Set ID of the data set that uses a template.
 *
 * @param tmplindex TMPLV4, TMPLICMPV4, TMPLV6 or TMPLICMPV6.
 * @return Template ID in network byte order.
 */
u_int16_t
ipfix_template_set_id (u_int tmplindex) {
  return templates[tmplindex].t.h.r.template_id;
}
