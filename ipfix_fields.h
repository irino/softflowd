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

#ifndef _IPFIX_FIELDS_H
#define _IPFIX_FIELDS_H

/*
 * IPFIX field tables shared by the encoder-based exporter (export.c) and the
 * fixed-format exporter (compat/ipfix.c, COMPAT_EXPORT). Include this header
 * from only those two files. DEF_FIELD_ENC (ie, len, fn) names the encoder fn
 * of each field; the fixed-format exporter does not use it and drops it.
 */

#include "ipfix.h"
#include "psamp.h"

#ifdef COMPAT_EXPORT
#define IPFIX_FIELD_TABLE_TYPE struct IPFIX_FIELD_SPECIFIER
#define DEF_FIELD_ENC(ie, len, fn) {(ie), (len)}
#else
struct EXPORT_CTX;
/* The encoder functions named by DEF_FIELD_ENC below are defined in export.c. */
typedef void
export_encoder_fn (u_char *dst, u_int16_t length,
                   const struct EXPORT_CTX *ctx);
typedef export_encoder_fn *export_encoder_t;
static export_encoder_fn
  enc_sourceIPv4Address,
  enc_destinationIPv4Address,
  enc_sourceIPv6Address,
  enc_destinationIPv6Address,
  enc_octetDeltaCount,
  enc_packetDeltaCount,
  enc_ifidx32,
  enc_flowDirection,
  enc_flowEndReason,
  enc_interfaceName,
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

/* Per RFC 7011 6.1.9, Micro and Nano IEs share identical NTP 64-bit encoding.
 */
#define enc_flowStartNanoSeconds enc_flowStartMicroSeconds
#define enc_flowEndNanoSeconds enc_flowEndMicroSeconds
struct EXPORT_FIELD_SPECIFIER_ENCODER {
  struct IPFIX_FIELD_SPECIFIER field;
  export_encoder_t encoder;
};
#define IPFIX_FIELD_TABLE_TYPE struct EXPORT_FIELD_SPECIFIER_ENCODER
#define DEF_FIELD_ENC(ie, len, fn) {{(ie), (len)}, (fn)}
#endif

/* Field-group descriptors (IPFIX IEs). */
static const IPFIX_FIELD_TABLE_TYPE field_v4[] = {
  DEF_FIELD_ENC (IPFIX_sourceIPv4Address, 4, enc_sourceIPv4Address),
  DEF_FIELD_ENC (IPFIX_destinationIPv4Address, 4, enc_destinationIPv4Address)};

static const IPFIX_FIELD_TABLE_TYPE field_v6[] = {
  DEF_FIELD_ENC (IPFIX_sourceIPv6Address, 16, enc_sourceIPv6Address),
  DEF_FIELD_ENC (IPFIX_destinationIPv6Address, 16,
                 enc_destinationIPv6Address)};

static const IPFIX_FIELD_TABLE_TYPE field_common[] = {
  DEF_FIELD_ENC (IPFIX_octetDeltaCount, 4, enc_octetDeltaCount),
  DEF_FIELD_ENC (IPFIX_packetDeltaCount, 4, enc_packetDeltaCount),
  DEF_FIELD_ENC (IPFIX_ingressInterface, 4, enc_ifidx32),
  DEF_FIELD_ENC (IPFIX_egressInterface, 4, enc_ifidx32),
  DEF_FIELD_ENC (IPFIX_flowDirection, 1, enc_flowDirection),
  DEF_FIELD_ENC (IPFIX_flowEndReason, 1, enc_flowEndReason),
#ifdef ENABLE_IFNAME
  DEF_FIELD_ENC (IPFIX_interfaceName, IFNAMSIZ, enc_interfaceName)
#endif
};

static const IPFIX_FIELD_TABLE_TYPE field_transport[] = {
  DEF_FIELD_ENC (IPFIX_sourceTransportPort, 2, enc_sourceTransportPort),
  DEF_FIELD_ENC (IPFIX_destinationTransportPort, 2,
                 enc_destinationTransportPort),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_tcpControlBits, 1, enc_tcpControlBits),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

static const IPFIX_FIELD_TABLE_TYPE field_icmp4[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv4, 2, enc_icmpTypeCode),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

static const IPFIX_FIELD_TABLE_TYPE field_icmp6[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv6, 2, enc_icmpTypeCode),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

static const IPFIX_FIELD_TABLE_TYPE field_vlan[] = {
  DEF_FIELD_ENC (IPFIX_vlanId, 2, enc_vlanId),
  DEF_FIELD_ENC (IPFIX_postVlanId, 2, enc_postVlanId)};

static const IPFIX_FIELD_TABLE_TYPE field_ether[] = {
  DEF_FIELD_ENC (IPFIX_sourceMacAddress, 6, enc_sourceMacAddress),
  DEF_FIELD_ENC (IPFIX_postDestinationMacAddress, 6,
                 enc_postDestinationMacAddress)};

static const IPFIX_FIELD_TABLE_TYPE field_timesec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartSeconds, 4, enc_flowStartSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndSeconds, 4, enc_flowEndSeconds)};

static const IPFIX_FIELD_TABLE_TYPE field_timemsec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartMilliSeconds, 8, enc_flowStartMilliSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndMilliSeconds, 8, enc_flowEndMilliSeconds)};

static const IPFIX_FIELD_TABLE_TYPE field_timeusec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartMicroSeconds, 8, enc_flowStartMicroSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndMicroSeconds, 8, enc_flowEndMicroSeconds)};

static const IPFIX_FIELD_TABLE_TYPE field_timensec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartNanoSeconds, 8, enc_flowStartNanoSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndNanoSeconds, 8, enc_flowEndNanoSeconds)};

static const IPFIX_FIELD_TABLE_TYPE field_timesysup[] = {
  DEF_FIELD_ENC (IPFIX_flowStartSysUpTime, 4, enc_flowStartSysUpTime),
  DEF_FIELD_ENC (IPFIX_flowEndSysUpTime, 4, enc_flowEndSysUpTime)};

static const IPFIX_FIELD_TABLE_TYPE field_bicommon[] = {
  DEF_FIELD_ENC (IPFIX_octetDeltaCount, 4, enc_octetDeltaCount),
  DEF_FIELD_ENC (IPFIX_packetDeltaCount, 4, enc_packetDeltaCount),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

static const IPFIX_FIELD_TABLE_TYPE field_bitransport[] = {
  DEF_FIELD_ENC (IPFIX_tcpControlBits, 1, enc_tcpControlBits)};

static const IPFIX_FIELD_TABLE_TYPE field_biicmp4[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv4, 2, enc_icmpTypeCode)};

static const IPFIX_FIELD_TABLE_TYPE field_biicmp6[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv6, 2, enc_icmpTypeCode)};

static const IPFIX_FIELD_TABLE_TYPE field_scope[] = {
  DEF_FIELD_ENC (IPFIX_meteringProcessId, 4, enc_meteringProcessId)};

static const IPFIX_FIELD_TABLE_TYPE field_option[] = {
  DEF_FIELD_ENC (IPFIX_systemInitTimeMilliseconds, 8,
                 enc_systemInitTimeMilliseconds),
  DEF_FIELD_ENC (PSAMP_samplingPacketInterval, 4, enc_samplingPacketInterval),
  DEF_FIELD_ENC (PSAMP_samplingPacketSpace, 4, enc_samplingPacketSpace),
  DEF_FIELD_ENC (PSAMP_selectorAlgorithm, 2, enc_selectorAlgorithm),
#ifdef ENABLE_IFNAME
  DEF_FIELD_ENC (IPFIX_interfaceName, IFNAMSIZ, enc_interfaceName),
#else
  DEF_FIELD_ENC (IPFIX_interfaceName, IFNAMSIZ, enc_zero),
#endif
  DEF_FIELD_ENC (IPFIX_exporterIPv4Address, 4, enc_exporterAddress),
  DEF_FIELD_ENC (IPFIX_exporterIPv6Address, 16, enc_exporterAddress),
  DEF_FIELD_ENC (IPFIX_originalExporterIPv4Address, 4,
                 enc_originalExporterAddress),
  DEF_FIELD_ENC (IPFIX_originalExporterIPv6Address, 16,
                 enc_originalExporterAddress)};

static const IPFIX_FIELD_TABLE_TYPE field_nf9scope[] = {DEF_FIELD_ENC (
  IPFIX_OPTION_SCOPE_INTERFACE, 4, enc_nf9OptionScopeInterface)};

static const IPFIX_FIELD_TABLE_TYPE field_nf9option[] = {
  DEF_FIELD_ENC (IPFIX_samplingInterval, 4, enc_samplingInterval),
  DEF_FIELD_ENC (IPFIX_samplingAlgorithm, 1, enc_samplingAlgorithm),
#ifdef ENABLE_IFNAME
  DEF_FIELD_ENC (IPFIX_interfaceName, IFNAMSIZ, enc_interfaceName)
#else
  DEF_FIELD_ENC (IPFIX_interfaceName, IFNAMSIZ, enc_zero)
#endif
};

/* Shared template sized for IPFIX (reused by NetFlow v9).
 * Divided by IPFIX_FIELD_TABLE_TYPE (the actual element type)
 * to avoid over-counting and potential array bounds issues. */
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS \
  (sizeof (field_scope) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS \
  (sizeof (field_option) / sizeof (IPFIX_FIELD_TABLE_TYPE))

#define NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS \
  (sizeof (field_nf9scope) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS \
  (sizeof (field_nf9option) / sizeof (IPFIX_FIELD_TABLE_TYPE))

struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE {
  struct IPFIX_OPTION_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER s[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS];
  struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];
} __packed;

/* Stuff pertaining to the templates that softflowd uses */
#define IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS \
  (sizeof (field_v4) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS \
  (sizeof (field_timesysup) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS \
  (sizeof (field_common) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS \
  (sizeof (field_transport) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS \
  (sizeof (field_icmp4) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS \
  (sizeof (field_vlan) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS \
  (sizeof (field_ether) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS \
  (sizeof (field_bicommon) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS \
  (sizeof (field_bitransport) / sizeof (IPFIX_FIELD_TABLE_TYPE))
#define IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS \
  (sizeof (field_biicmp4) / sizeof (IPFIX_FIELD_TABLE_TYPE))

#define IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS \
  (IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS + IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS)

#define IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS \
  (IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS)

struct IPFIX_SOFTFLOWD_TEMPLATE {
  struct IPFIX_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS];
  struct IPFIX_VENDOR_FIELD_SPECIFIER v[IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS];
  u_int16_t data_len, bi_count;
} __packed;

#endif /* _IPFIX_FIELDS_H */
