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
 * @file export.h
 * @brief The encoders of the fields and the types shared by the files of the
 *   encoder-based exporter (export.c, export_fixed.c, export_template.c).
 */

#ifndef _EXPORT_H
#define _EXPORT_H

#include "ipfix.h"
#include "softflowd.h"

/** Context for resolving field values: flow, endpoint index, and send
 * parameters. */
struct EXPORT_CTX {
  const struct SENDPARAMETER
    *sp;                   /**< Send parameters (tracking parameters, interface index) */
  const struct FLOW *flow; /**< Flow being encoded */
  u_int i;                 /**< Which endpoint (0/1) is "source" here */
};

/* The encoders are defined in export.c; the field tables name them with
 * DEF_FIELD_ENC (see ipfix_fields.h). */
/**
 * Type of an encoder: write the value of one field of the flow of ctx
 * into dst, length octets.
 */
typedef void
export_encoder_fn (u_char *dst, u_int16_t length,
                   const struct EXPORT_CTX *ctx);
/** Pointer to an encoder. */
typedef export_encoder_fn *export_encoder_t;
/** @cond */
export_encoder_fn
  enc_sourceIPv4Address,
  enc_destinationIPv4Address,
  enc_sourceIPv6Address,
  enc_destinationIPv6Address,
  enc_octetDeltaCount,
  enc_packetDeltaCount,
  enc_ifidx16,
  enc_ifidx32,
  enc_flowDirection,
  enc_flowEndReason,
  enc_sourceTransportPort,
  enc_destinationTransportPort,
  enc_protocolIdentifier,
  enc_tcpControlBits,
  enc_ipVersion,
  enc_ipClassOfService,
  enc_icmpTypeCode,
  enc_vlanId,
  enc_postVlanId,
  enc_sourceMacAddress,
  enc_postDestinationMacAddress,
  enc_flowStartSeconds,
  enc_flowEndSeconds,
  enc_flowStartMilliSeconds,
  enc_flowEndMilliSeconds,
  enc_flowStartMicroSeconds,
  enc_flowEndMicroSeconds,
  enc_flowStartSysUpTime,
  enc_flowEndSysUpTime,
  enc_meteringProcessId,
  enc_systemInitTimeMilliseconds,
  enc_samplingPacketInterval,
  enc_samplingPacketSpace,
  enc_selectorAlgorithm,
  enc_zero,
  enc_exporterAddress,
  enc_originalExporterAddress,
  enc_nf9OptionScopeInterface,
  enc_samplingInterval,
  enc_samplingAlgorithm;
#ifdef ENABLE_IFNAME
export_encoder_fn enc_interfaceName;
#endif
/** @endcond */

/* Per RFC 7011 6.1.9, Micro and Nano IEs share identical NTP 64-bit encoding.
 */
/**
 * Encoder of flowStartNanoSeconds. The micro and nano forms are the same
 * 64-bit NTP encoding (RFC 7011, 6.1.9).
 */
#define enc_flowStartNanoSeconds enc_flowStartMicroSeconds
/**
 * Encoder of flowEndNanoSeconds. The micro and nano forms are the same
 * 64-bit NTP encoding (RFC 7011, 6.1.9).
 */
#define enc_flowEndNanoSeconds enc_flowEndMicroSeconds
/** @brief A field of a template, and the function that encodes its value. */
struct EXPORT_FIELD_SPECIFIER_ENCODER {
  struct IPFIX_FIELD_SPECIFIER field; /**< The field specifier of the template */
  export_encoder_t encoder;           /**< Writes the value of the field */
};

/**
 * Number of the entries of the field table a, an array of struct
 * EXPORT_FIELD_SPECIFIER_ENCODER.
 */
#define EXPORT_NFIELDS_ENC(a) \
  (sizeof (a) / sizeof (struct EXPORT_FIELD_SPECIFIER_ENCODER))

u_int
export_emit_group_enc (const struct EXPORT_FIELD_SPECIFIER_ENCODER *fields,
                       u_int nfields, u_char *packet, u_int offset,
                       const struct EXPORT_CTX *ctx);

#endif /* _EXPORT_H */
