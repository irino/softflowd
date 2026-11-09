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
 * @file ipfix_fields.h
 * @brief The tables of the fields of the IPFIX and NetFlow v9 templates, the
 *   layouts of the templates on the wire and the names of the encoders of
 *   the fields. Include it from export.c only.
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

#if COMPAT_EXPORT
/**
 * Type of the entries of the field tables: the field specifier and the
 * encoder of its value.
 */
#define IPFIX_FIELD_TABLE_TYPE struct IPFIX_FIELD_SPECIFIER
/**
 * An entry of a field table: the information element ie, its length len
 * and the encoder fn.
 */
#define DEF_FIELD_ENC(ie, len, fn) {(ie), (len)}
#else
#include "export.h"

/**
 * Type of the entries of the field tables: the field specifier and the
 * encoder of its value.
 */
#define IPFIX_FIELD_TABLE_TYPE struct EXPORT_FIELD_SPECIFIER_ENCODER
/**
 * An entry of a field table: the information element ie, its length len
 * and the encoder fn.
 */
#define DEF_FIELD_ENC(ie, len, fn) {{(ie), (len)}, (fn)}
#endif

/* Field-group descriptors (IPFIX IEs). */
/**
 * Fields of the IPv4 flow template: the source and destination
 * addresses.
 */
static const IPFIX_FIELD_TABLE_TYPE field_v4[] = {
  DEF_FIELD_ENC (IPFIX_sourceIPv4Address, 4, enc_sourceIPv4Address),
  DEF_FIELD_ENC (IPFIX_destinationIPv4Address, 4, enc_destinationIPv4Address)};

/**
 * Fields of the IPv6 flow template: the source and destination
 * addresses.
 */
static const IPFIX_FIELD_TABLE_TYPE field_v6[] = {
  DEF_FIELD_ENC (IPFIX_sourceIPv6Address, 16, enc_sourceIPv6Address),
  DEF_FIELD_ENC (IPFIX_destinationIPv6Address, 16,
                 enc_destinationIPv6Address)};

/**
 * Fields that every flow template has: octets, packets, the interfaces,
 * the direction, the end reason and, with --enable-ifname, the interface
 * name.
 */
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

/**
 * Fields of the flow templates of TCP, UDP and the other protocols:
 * ports, protocol, TCP flags, IP version and type of service.
 */
static const IPFIX_FIELD_TABLE_TYPE field_transport[] = {
  DEF_FIELD_ENC (IPFIX_sourceTransportPort, 2, enc_sourceTransportPort),
  DEF_FIELD_ENC (IPFIX_destinationTransportPort, 2,
                 enc_destinationTransportPort),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_tcpControlBits, 1, enc_tcpControlBits),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

/**
 * Fields of the ICMPv4 flow template: the ICMP type and code, protocol,
 * IP version and type of service.
 */
static const IPFIX_FIELD_TABLE_TYPE field_icmp4[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv4, 2, enc_icmpTypeCode),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

/**
 * Fields of the ICMPv6 flow template: the ICMP type and code, protocol,
 * IP version and type of service.
 */
static const IPFIX_FIELD_TABLE_TYPE field_icmp6[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv6, 2, enc_icmpTypeCode),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

/** Fields of the VLAN IDs, added to a template with -T vlan or deeper. */
static const IPFIX_FIELD_TABLE_TYPE field_vlan[] = {
  DEF_FIELD_ENC (IPFIX_vlanId, 2, enc_vlanId),
  DEF_FIELD_ENC (IPFIX_postVlanId, 2, enc_postVlanId)};

/** Fields of the MAC addresses, added to a template with -T ether. */
static const IPFIX_FIELD_TABLE_TYPE field_ether[] = {
  DEF_FIELD_ENC (IPFIX_sourceMacAddress, 6, enc_sourceMacAddress),
  DEF_FIELD_ENC (IPFIX_postDestinationMacAddress, 6,
                 enc_postDestinationMacAddress)};

/** Fields of the start and end times in seconds. */
static const IPFIX_FIELD_TABLE_TYPE field_timesec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartSeconds, 4, enc_flowStartSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndSeconds, 4, enc_flowEndSeconds)};

/** Fields of the start and end times in milliseconds. */
static const IPFIX_FIELD_TABLE_TYPE field_timemsec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartMilliSeconds, 8, enc_flowStartMilliSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndMilliSeconds, 8, enc_flowEndMilliSeconds)};

/** Fields of the start and end times as NTP timestamps with microseconds. */
static const IPFIX_FIELD_TABLE_TYPE field_timeusec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartMicroSeconds, 8, enc_flowStartMicroSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndMicroSeconds, 8, enc_flowEndMicroSeconds)};

/** Fields of the start and end times as NTP timestamps with nanoseconds. */
static const IPFIX_FIELD_TABLE_TYPE field_timensec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartNanoSeconds, 8, enc_flowStartNanoSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndNanoSeconds, 8, enc_flowEndNanoSeconds)};

/**
 * Fields of the start and end times as milliseconds of the system uptime
 * (NetFlow v9 and the default of IPFIX).
 */
static const IPFIX_FIELD_TABLE_TYPE field_timesysup[] = {
  DEF_FIELD_ENC (IPFIX_flowStartSysUpTime, 4, enc_flowStartSysUpTime),
  DEF_FIELD_ENC (IPFIX_flowEndSysUpTime, 4, enc_flowEndSysUpTime)};

/**
 * Reverse-direction fields that every Biflow template has: octets,
 * packets and type of service.
 */
static const IPFIX_FIELD_TABLE_TYPE field_bicommon[] = {
  DEF_FIELD_ENC (IPFIX_octetDeltaCount, 4, enc_octetDeltaCount),
  DEF_FIELD_ENC (IPFIX_packetDeltaCount, 4, enc_packetDeltaCount),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)};

/** Reverse-direction field of the Biflow templates of TCP: the TCP flags. */
static const IPFIX_FIELD_TABLE_TYPE field_bitransport[] = {
  DEF_FIELD_ENC (IPFIX_tcpControlBits, 1, enc_tcpControlBits)};

/**
 * Reverse-direction field of the Biflow template of ICMPv4: the ICMP
 * type and code.
 */
static const IPFIX_FIELD_TABLE_TYPE field_biicmp4[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv4, 2, enc_icmpTypeCode)};

/**
 * Reverse-direction field of the Biflow template of ICMPv6: the ICMP
 * type and code.
 */
static const IPFIX_FIELD_TABLE_TYPE field_biicmp6[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv6, 2, enc_icmpTypeCode)};

/** Scope field of the options template of IPFIX: the metering process. */
static const IPFIX_FIELD_TABLE_TYPE field_scope[] = {
  DEF_FIELD_ENC (IPFIX_meteringProcessId, 4, enc_meteringProcessId)};

/**
 * Option fields of the options template of IPFIX: the system
 * initialisation time, the sampling, the interface name and the exporter
 * addresses.
 */
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

/** Scope field of the options template of NetFlow v9: the interface. */
static const IPFIX_FIELD_TABLE_TYPE field_nf9scope[] = {DEF_FIELD_ENC (
  IPFIX_OPTION_SCOPE_INTERFACE, 4, enc_nf9OptionScopeInterface)};

/**
 * Option fields of the options template of NetFlow v9: the sampling
 * interval and algorithm and the interface name.
 */
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
/**
 * Number of the scope fields of the options template of IPFIX:
 * field_scope[].
 */
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS \
  (sizeof (field_scope) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the option fields of the options template of IPFIX:
 * field_option[].
 */
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS \
  (sizeof (field_option) / sizeof (IPFIX_FIELD_TABLE_TYPE))

/**
 * Number of the scope fields of the options template of NetFlow v9:
 * field_nf9scope[].
 */
#define NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS \
  (sizeof (field_nf9scope) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the option fields of the options template of NetFlow v9:
 * field_nf9option[].
 */
#define NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS \
  (sizeof (field_nf9option) / sizeof (IPFIX_FIELD_TABLE_TYPE))

/** @brief The options template that softflowd sends, as it is on the wire. */
struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE {
  struct IPFIX_OPTION_TEMPLATE_SET_HEADER h;                                     /**< Set header and options template record header */
  struct IPFIX_FIELD_SPECIFIER s[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS]; /**< Scope fields */
  struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];      /**< Option fields */
} __packed;

/* Stuff pertaining to the templates that softflowd uses */
/**
 * Number of the address fields of a flow template: field_v4[], and as
 * many in field_v6[].
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS \
  (sizeof (field_v4) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the time fields of a flow template: field_timesysup[], and
 * as many in the other time tables.
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS \
  (sizeof (field_timesysup) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/** Number of the fields that every flow template has: field_common[]. */
#define IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS \
  (sizeof (field_common) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the fields of the TCP and UDP flow templates:
 * field_transport[].
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS \
  (sizeof (field_transport) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the fields of the ICMP flow templates: field_icmp4[], and as
 * many in field_icmp6[].
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS \
  (sizeof (field_icmp4) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/** Number of the VLAN fields: field_vlan[]. */
#define IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS \
  (sizeof (field_vlan) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/** Number of the MAC address fields: field_ether[]. */
#define IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS \
  (sizeof (field_ether) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the reverse-direction fields that every Biflow template has:
 * field_bicommon[].
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS \
  (sizeof (field_bicommon) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the reverse-direction fields of the Biflow template of TCP:
 * field_bitransport[].
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS \
  (sizeof (field_bitransport) / sizeof (IPFIX_FIELD_TABLE_TYPE))
/**
 * Number of the reverse-direction fields of the Biflow templates of
 * ICMP: field_biicmp4[], and as many in field_biicmp6[].
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS \
  (sizeof (field_biicmp4) / sizeof (IPFIX_FIELD_TABLE_TYPE))

/**
 * Largest number of the fields of a flow template: the address, time,
 * common, transport, VLAN and MAC address fields.
 */
#define IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS \
  (IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS + IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS)

/** Largest number of the reverse-direction fields of a Biflow template. */
#define IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS \
  (IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS + IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS)

/** @brief A flow template that softflowd sends, as it is on the wire. */
struct IPFIX_SOFTFLOWD_TEMPLATE {
  struct IPFIX_TEMPLATE_SET_HEADER h;                                          /**< Set header and template record header */
  struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS];           /**< Field specifiers of the fields */
  struct IPFIX_VENDOR_FIELD_SPECIFIER v[IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS]; /**< Field specifiers of the reverse-direction fields of biflow; bi_count of them are used */
  u_int16_t data_len;                                                          /**< Length in octets of a data record, MPLS labels included */
  u_int16_t bi_count;                                                          /**< Number of entries of v[] in use */
} __packed;

#endif /* _IPFIX_FIELDS_H */
