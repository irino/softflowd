/*
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

/**
 * @file ipfix.h
 * @brief IPFIX constants and the layouts on the wire: the information element IDs
 *   softflowd uses, the flow end reasons, the headers and the field
 *   specifiers.
 */

#ifndef _IPFIX_H
#define _IPFIX_H

#include "common.h"

/** Set ID of a template set. */
#define IPFIX_TEMPLATE_SET_ID 2
/** Set ID of an options template set. */
#define IPFIX_OPTION_TEMPLATE_SET_ID 3
/**
 * Smallest set ID of a data set. The set ID of a data set is the ID of
 * its template.
 */
#define IPFIX_MIN_RECORD_SET_ID 256
/**
 * The UDP port of IPFIX that IANA registered (the default destination
 * port of -v 10).
 */
#define IPFIX_PORT 4739

/* Option template scope types (same values in NetFlow v9 and IPFIX) */
/** Scope type of an options template: the system. */
#define IPFIX_OPTION_SCOPE_SYSTEM 1
/** Scope type of an options template: an interface. */
#define IPFIX_OPTION_SCOPE_INTERFACE 2
/** Scope type of an options template: a line card. */
#define IPFIX_OPTION_SCOPE_LINECARD 3
/** Scope type of an options template: a cache. */
#define IPFIX_OPTION_SCOPE_CACHE 4
/** Scope type of an options template: a template. */
#define IPFIX_OPTION_SCOPE_TEMPLATE 5

/* Sampling algorithms (same values in NetFlow v9 and IPFIX) */
/** Sampling algorithm: deterministic (every n-th packet). */
#define IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC 1
/** Sampling algorithm: random. */
#define IPFIX_SAMPLING_ALGORITHM_RANDOM 2

/* Flowset record ies the we care about */
/** IPFIX information element octetDeltaCount (IANA ID 1). */
#define IPFIX_octetDeltaCount 1
/** IPFIX information element packetDeltaCount (IANA ID 2). */
#define IPFIX_packetDeltaCount 2
/* ... */
/** IPFIX information element protocolIdentifier (IANA ID 4). */
#define IPFIX_protocolIdentifier 4
/** IPFIX information element ipClassOfService (IANA ID 5). */
#define IPFIX_ipClassOfService 5
/* ... */
/** IPFIX information element tcpControlBits (IANA ID 6). */
#define IPFIX_tcpControlBits 6
/** IPFIX information element sourceTransportPort (IANA ID 7). */
#define IPFIX_sourceTransportPort 7
/** IPFIX information element sourceIPv4Address (IANA ID 8). */
#define IPFIX_sourceIPv4Address 8
/* IEs 9, 15, 16, 17: Express NetFlow v1/v5 layouts for the default
 * encoder-based engine (per IANA). */
/** IPFIX information element sourceIPv4PrefixLength (IANA ID 9). */
#define IPFIX_sourceIPv4PrefixLength 9
/** IPFIX information element ingressInterface (IANA ID 10). */
#define IPFIX_ingressInterface 10
/** IPFIX information element destinationTransportPort (IANA ID 11). */
#define IPFIX_destinationTransportPort 11
/** IPFIX information element destinationIPv4Address (IANA ID 12). */
#define IPFIX_destinationIPv4Address 12
/** IPFIX information element destinationIPv4PrefixLength (IANA ID 13). */
#define IPFIX_destinationIPv4PrefixLength 13
/** IPFIX information element egressInterface (IANA ID 14). */
#define IPFIX_egressInterface 14
/** IPFIX information element ipNextHopIPv4Address (IANA ID 15). */
#define IPFIX_ipNextHopIPv4Address 15
/** IPFIX information element bgpSourceAsNumber (IANA ID 16). */
#define IPFIX_bgpSourceAsNumber 16
/** IPFIX information element bgpDestinationAsNumber (IANA ID 17). */
#define IPFIX_bgpDestinationAsNumber 17
/* ... */
/** IPFIX information element flowEndSysUpTime (IANA ID 21). */
#define IPFIX_flowEndSysUpTime 21
/** IPFIX information element flowStartSysUpTime (IANA ID 22). */
#define IPFIX_flowStartSysUpTime 22
/* ... */
/** IPFIX information element sourceIPv6Address (IANA ID 27). */
#define IPFIX_sourceIPv6Address 27
/** IPFIX information element destinationIPv6Address (IANA ID 28). */
#define IPFIX_destinationIPv6Address 28
/* ... */
/** IPFIX information element icmpTypeCodeIPv4 (IANA ID 32). */
#define IPFIX_icmpTypeCodeIPv4 32
/* ... */
/* Deprecated NetFlow v9 SamplingInterval (superseded by ID 305) */
/** IPFIX information element samplingInterval (IANA ID 34). */
#define IPFIX_samplingInterval 34
/** IPFIX information element samplingAlgorithm (IANA ID 35). */
#define IPFIX_samplingAlgorithm 35
/* ... */
/** IPFIX information element engineType (IANA ID 38). */
#define IPFIX_engineType 38
/** IPFIX information element engineId (IANA ID 39). */
#define IPFIX_engineId 39
/** IPFIX information element exportedMessageTotalCount (IANA ID 41). */
#define IPFIX_exportedMessageTotalCount 41    /* v9 packet sequence */
/** IPFIX information element exportedFlowRecordTotalCount (IANA ID 42). */
#define IPFIX_exportedFlowRecordTotalCount 42 /* v5/IPFIX record sequence */
/* ... */
/** IPFIX information element sourceMacAddress (IANA ID 56). */
#define IPFIX_sourceMacAddress 56
/** IPFIX information element postDestinationMacAddress (IANA ID 57). */
#define IPFIX_postDestinationMacAddress 57
/** IPFIX information element vlanId (IANA ID 58). */
#define IPFIX_vlanId 58
/** IPFIX information element postVlanId (IANA ID 59). */
#define IPFIX_postVlanId 59
/** IPFIX information element ipVersion (IANA ID 60). */
#define IPFIX_ipVersion 60
/** IPFIX information element flowDirection (IANA ID 61). */
#define IPFIX_flowDirection 61
/** IPFIX information element mplsTopLabelStackSection (IANA ID 70). */
#define IPFIX_mplsTopLabelStackSection 70
/* ... */
/** IPFIX information element observationDomainId (IANA ID 149). */
#define IPFIX_observationDomainId 149
/** IPFIX information element interfaceName (IANA ID 82). */
#define IPFIX_interfaceName 82
/* ... */
/** IPFIX information element exportProtocolVersion (IANA ID 214). */
#define IPFIX_exportProtocolVersion 214 /* NetFlow/IPFIX header version */
/** IPFIX information element paddingOctets (IANA ID 210). */
#define IPFIX_paddingOctets 210
/* ... */
/** IPFIX information element exporterIPv4Address (IANA ID 130). */
#define IPFIX_exporterIPv4Address 130
/** IPFIX information element exporterIPv6Address (IANA ID 131). */
#define IPFIX_exporterIPv6Address 131
/* ... */
/** IPFIX information element flowEndReason (IANA ID 136). */
#define IPFIX_flowEndReason 136
/* ... */
/** IPFIX information element icmpTypeCodeIPv6 (IANA ID 139). */
#define IPFIX_icmpTypeCodeIPv6 139
/* ... */
/** IPFIX information element meteringProcessId (IANA ID 143). */
#define IPFIX_meteringProcessId 143
/* ... */
/** IPFIX information element flowStartSeconds (IANA ID 150). */
#define IPFIX_flowStartSeconds 150
/** IPFIX information element flowEndSeconds (IANA ID 151). */
#define IPFIX_flowEndSeconds 151
/** IPFIX information element flowStartMilliSeconds (IANA ID 152). */
#define IPFIX_flowStartMilliSeconds 152
/** IPFIX information element flowEndMilliSeconds (IANA ID 153). */
#define IPFIX_flowEndMilliSeconds 153
/** IPFIX information element flowStartMicroSeconds (IANA ID 154). */
#define IPFIX_flowStartMicroSeconds 154
/** IPFIX information element flowEndMicroSeconds (IANA ID 155). */
#define IPFIX_flowEndMicroSeconds 155
/** IPFIX information element flowStartNanoSeconds (IANA ID 156). */
#define IPFIX_flowStartNanoSeconds 156
/** IPFIX information element flowEndNanoSeconds (IANA ID 157). */
#define IPFIX_flowEndNanoSeconds 157
/* ... */
/** IPFIX information element systemInitTimeMilliseconds (IANA ID 160). */
#define IPFIX_systemInitTimeMilliseconds 160
/* ... */
/** IPFIX information element originalExporterIPv4Address (IANA ID 403). */
#define IPFIX_originalExporterIPv4Address 403
/** IPFIX information element originalExporterIPv6Address (IANA ID 404). */
#define IPFIX_originalExporterIPv6Address 404
/* ... */

// flow end reason for ipfix ie 136
/** Value of flowEndReason: idle timeout. */
#define IPFIX_flowEndReason_idleTimeout 0x01
/** Value of flowEndReason: active timeout. */
#define IPFIX_flowEndReason_activeTimeout 0x02
/** Value of flowEndReason: end of flow detected (a FIN or an RST). */
#define IPFIX_flowEndReason_endOfFlow 0x03
/** Value of flowEndReason: forced end. */
#define IPFIX_flowEndReason_forceEnd 0x04
/** Value of flowEndReason: lack of resources. */
#define IPFIX_flowEndReason_lackOfResource 0x05

// flowDirection for ipfix ie 61
/** Value of flowDirection: ingress flow. */
#define IPFIX_FLOWDIRECTION_INGRESS 0x00
/** Value of flowDirection: egress flow. */
#define IPFIX_FLOWDIRECTION_EGRESS 0x01

/**
 * Length in octets of the part of an MPLS label stack entry that
 * mplsTopLabelStackSection carries: the label, the traffic class and the
 * bottom-of-stack bit.
 */
#define IPFIX_mplsLabelStackSection_SIZE 3

/** @brief IPFIX message header (RFC 7011, 3.1). */
struct IPFIX_HEADER {
  u_int16_t version;               /**< IPFIX version, 10 */
  u_int16_t length;                /**< Length of the message in octets */
  u_int32_t export_time;           /**< Seconds since the epoch */
  u_int32_t sequence_number;       /**< Counter of the data records sent so far */
  u_int32_t observation_domain_id; /**< Identifies the observation domain */
} __packed;
/** @brief Header of a set (RFC 7011, 3.3.2). */
struct IPFIX_SET_HEADER {
  u_int16_t set_id; /**< Kind of the set: 2 for templates, 3 for option templates, 256 and above for data */
  u_int16_t length; /**< Length of the set in octets, header included */
} __packed;
/** @brief Header of a template record (RFC 7011, 3.4.1). */
struct IPFIX_TEMPLATE_RECORD_HEADER {
  u_int16_t template_id; /**< ID of the template */
  u_int16_t count;       /**< Number of fields in the template */
} __packed;
/** @brief Header of a set that holds one template record. */
struct IPFIX_TEMPLATE_SET_HEADER {
  struct IPFIX_SET_HEADER c;             /**< Set header */
  struct IPFIX_TEMPLATE_RECORD_HEADER r; /**< Template record header */
} __packed;

/** @brief Field specifier of a template (RFC 7011, 3.2). */
struct IPFIX_FIELD_SPECIFIER {
  u_int16_t ie;     /**< ID of the information element */
  u_int16_t length; /**< Length of the field in octets */
} __packed;

/** @brief Header of a set that holds one options template record. */
struct IPFIX_OPTION_TEMPLATE_SET_HEADER {
  struct IPFIX_SET_HEADER c; /**< Set header */
  /** The header of the options template record: i is the form of IPFIX and
   * n that of NetFlow v9. */
  union {
    struct {
      struct IPFIX_TEMPLATE_RECORD_HEADER r;
      u_int16_t scope_count;
    } i;
    struct {
      u_int16_t template_id;
      u_int16_t scope_length;
      u_int16_t option_length;
    } n;
  } u;
} __packed;

/** @brief Enterprise-specific field specifier of a template (RFC 7011, 3.2). */
struct IPFIX_VENDOR_FIELD_SPECIFIER {
  u_int16_t ie;     /**< ID of the information element, with the top bit set */
  u_int16_t length; /**< Length of the field in octets */
  u_int32_t pen;    /**< Private enterprise number */
} __packed;
/**
 * Private enterprise number of the reverse information elements of
 * Biflow (RFC 5103).
 */
#define REVERSE_PEN 29305

#endif /* _IPFIX_H */
