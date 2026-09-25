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

#include "common.h"
#include "log.h"
#include "treetype.h"
#include "softflowd.h"
#include "netflow5.h"
#include "netflow9.h"
#include "ipfix.h"
#include "psamp.h"

/*Shared with psamp.c */
int
ipfix_init_fields (struct IPFIX_FIELD_SPECIFIER *dst,
                   u_int *index,
                   const struct IPFIX_FIELD_SPECIFIER *src,
                   u_int field_number) {
  int i, length = 0;
  for (i = 0; i < field_number; i++) {
    dst[*index + i].ie = htons (src[i].ie);
    dst[*index + i].length = htons (src[i].length);
    length += src[i].length;
  }
  *index += field_number;
  return length;
}

void
conv_unix_to_ntp (struct timeval tv, struct ntp_time_t *ntp) {
  if (ntp == NULL)
    return;
  ntp->second = tv.tv_sec + 0x83AA7E80;
  ntp->fraction =
    (uint32_t) ((double) (tv.tv_usec + 1) * (double) (1LL << 32) * 1.0e-6);
}

void
conv_ntp_to_unix (struct ntp_time_t ntp, struct timeval *tv) {
  if (tv == NULL)
    return;
  tv->tv_sec = ntp.second - 0x83AA7E80; // the seconds from Jan 1, 1900 to Jan 1, 1970
  tv->tv_usec =
    (uint32_t) ((double) ntp.fraction * 1.0e6 / (double) (1LL << 32));
}

/* Template/Set IDs and packet-size limit. */
#define IPFIX_SOFTFLOWD_MAX_PACKET_SIZE     1428
#define IPFIX_SOFTFLOWD_V4_TEMPLATE_ID      1024
#define IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID  1025
#define IPFIX_SOFTFLOWD_V6_TEMPLATE_ID      2048
#define IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID  2049
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID  256
#define IPFIX_DEFAULT_TEMPLATE_INTERVAL     16

/* IPFIX flowDirection (IANA IE 61, RFC 7011): Use MAC match (Src=Egress, Dst=Ingress)
 * if configured with ethernet tracking; otherwise fall back to array index i. */
#define IPFIX_FLOWDIRECTION_INGRESS 0x00
#define IPFIX_FLOWDIRECTION_EGRESS  0x01

static u_int8_t
ipfix_flow_direction (const struct FLOW *flow, int i,
                      const struct FLOWTRACKPARAMETERS *param) {
  if (param->direction_mac_set && param->track_level >= TRACK_FULL_VLAN_ETHER) {
    if (memcmp (flow->ethermac[i], param->direction_mac, 6) == 0)
      return (IPFIX_FLOWDIRECTION_EGRESS);
    if (memcmp (flow->ethermac[i ^ 1], param->direction_mac, 6) == 0)
      return (IPFIX_FLOWDIRECTION_INGRESS);
  }
  return ((u_int8_t) i);
}

/* Determines flow template (v4/icmpv4/v6/icmpv6) index;
 * used to select from their TMPLMAX template arrays. */
enum { TMPLV4, TMPLICMPV4, TMPLV6, TMPLICMPV6, TMPLMAX };

static u_int
ipfix_flow_to_template_index (const struct FLOW *flow) {
  if (flow->af == AF_INET)
    return (flow->protocol == IPPROTO_ICMP) ? TMPLICMPV4 : TMPLV4;
  if (flow->af == AF_INET6)
    return (flow->protocol == IPPROTO_ICMPV6) ? TMPLICMPV6 : TMPLV6;
  return TMPLV4;
}


/* Shared field-group descriptors (IPFIX IEs) used both with and without
 * ENABLE_UNIFIED_EXPORT_TYPE_FULL to avoid duplication. */
/* DEF_FIELD_ENC(ie, len, fn): Single macro to define field tables for both
 * with and without ENABLE_UNIFIED_EXPORT_TYPE_FULL without duplicating IE
 * lists. Forward-declares encoder types so the unified expansion can compile. */
#if ENABLE_UNIFIED_EXPORT_TYPE == ENABLE_UNIFIED_EXPORT_TYPE_FULL
struct IPFIX_UNIFIED_CTX;
typedef void (*ipfix_unified_encoder_t) (u_char * dst, u_int16_t length,
                                         const struct IPFIX_UNIFIED_CTX *
                                         ctx);
struct IPFIX_FIELD_SPECIFIER_ENCODER {
  struct IPFIX_FIELD_SPECIFIER field;
  ipfix_unified_encoder_t encoder;
};
/* Forward declarations for 'fn' in DEF_FIELD_ENC (for ENABLE_UNIFIED_EXPORT_TYPE_FULL). */
static void enc_sourceIPv4Address (u_char *, u_int16_t,
                                   const struct IPFIX_UNIFIED_CTX *);
static void enc_destinationIPv4Address (u_char *, u_int16_t,
                                        const struct IPFIX_UNIFIED_CTX *);
static void enc_sourceIPv6Address (u_char *, u_int16_t,
                                   const struct IPFIX_UNIFIED_CTX *);
static void enc_destinationIPv6Address (u_char *, u_int16_t,
                                        const struct IPFIX_UNIFIED_CTX *);
static void enc_sourceTransportPort (u_char *, u_int16_t,
                                     const struct IPFIX_UNIFIED_CTX *);
static void enc_destinationTransportPort (u_char *, u_int16_t,
                                          const struct IPFIX_UNIFIED_CTX *);
static void enc_protocolIdentifier (u_char *, u_int16_t,
                                    const struct IPFIX_UNIFIED_CTX *);
static void enc_tcpControlBits (u_char *, u_int16_t,
                                const struct IPFIX_UNIFIED_CTX *);
static void enc_ipVersion (u_char *, u_int16_t,
                           const struct IPFIX_UNIFIED_CTX *);
static void enc_ipClassOfService (u_char *, u_int16_t,
                                  const struct IPFIX_UNIFIED_CTX *);
static void enc_icmpTypeCode (u_char *, u_int16_t,
                              const struct IPFIX_UNIFIED_CTX *);
static void enc_vlanId (u_char *, u_int16_t,
                        const struct IPFIX_UNIFIED_CTX *);
static void enc_postVlanId (u_char *, u_int16_t,
                            const struct IPFIX_UNIFIED_CTX *);
static void enc_sourceMacAddress (u_char *, u_int16_t,
                                  const struct IPFIX_UNIFIED_CTX *);
static void enc_postDestinationMacAddress (u_char *, u_int16_t,
                                           const struct IPFIX_UNIFIED_CTX *);
static void enc_flowStartSeconds (u_char *, u_int16_t,
                                  const struct IPFIX_UNIFIED_CTX *);
static void enc_flowEndSeconds (u_char *, u_int16_t,
                                const struct IPFIX_UNIFIED_CTX *);
static void enc_flowStartMilliSeconds (u_char *, u_int16_t,
                                       const struct IPFIX_UNIFIED_CTX *);
static void enc_flowEndMilliSeconds (u_char *, u_int16_t,
                                     const struct IPFIX_UNIFIED_CTX *);
static void enc_flowStartMicroSeconds (u_char *, u_int16_t,
                                       const struct IPFIX_UNIFIED_CTX *);
static void enc_flowEndMicroSeconds (u_char *, u_int16_t,
                                     const struct IPFIX_UNIFIED_CTX *);
/* Per RFC 7011 6.1.9, Micro and Nano IEs share identical NTP 64-bit encoding. */
#define enc_flowStartNanoSeconds enc_flowStartMicroSeconds
#define enc_flowEndNanoSeconds enc_flowEndMicroSeconds
static void enc_flowStartSysUpTime (u_char *, u_int16_t,
                                    const struct IPFIX_UNIFIED_CTX *);
static void enc_flowEndSysUpTime (u_char *, u_int16_t,
                                  const struct IPFIX_UNIFIED_CTX *);
static void enc_octetDeltaCount (u_char *, u_int16_t,
                                 const struct IPFIX_UNIFIED_CTX *);
static void enc_packetDeltaCount (u_char *, u_int16_t,
                                  const struct IPFIX_UNIFIED_CTX *);
static void enc_ifidx16 (u_char *, u_int16_t,
                         const struct IPFIX_UNIFIED_CTX *);
static void enc_ifidx32 (u_char *, u_int16_t,
                         const struct IPFIX_UNIFIED_CTX *);
static void enc_flowDirection (u_char *, u_int16_t,
                               const struct IPFIX_UNIFIED_CTX *);
static void enc_flowEndReason (u_char *, u_int16_t,
                               const struct IPFIX_UNIFIED_CTX *);
#ifdef ENABLE_IFNAME
static void enc_interfaceName (u_char *, u_int16_t,
                               const struct IPFIX_UNIFIED_CTX *);
#endif
static void enc_nf9OptionScopeInterface (u_char *, u_int16_t,
                                         const struct IPFIX_UNIFIED_CTX *);
static void enc_zero (u_char *, u_int16_t,
                      const struct IPFIX_UNIFIED_CTX *);
static void enc_meteringProcessId (u_char *, u_int16_t,
                                   const struct IPFIX_UNIFIED_CTX *);
static void enc_systemInitTimeMilliseconds (u_char *, u_int16_t,
                                            const struct IPFIX_UNIFIED_CTX *);
static void enc_samplingPacketInterval (u_char *, u_int16_t,
                                        const struct IPFIX_UNIFIED_CTX *);
static void enc_samplingPacketSpace (u_char *, u_int16_t,
                                     const struct IPFIX_UNIFIED_CTX *);
static void enc_selectorAlgorithm (u_char *, u_int16_t,
                                   const struct IPFIX_UNIFIED_CTX *);
static void enc_exporterAddress (u_char *, u_int16_t,
                                 const struct IPFIX_UNIFIED_CTX *);
static void enc_originalExporterAddress (u_char *, u_int16_t,
                                         const struct IPFIX_UNIFIED_CTX *);
static void enc_samplingInterval (u_char *, u_int16_t,
                                  const struct IPFIX_UNIFIED_CTX *);
static void enc_samplingAlgorithm (u_char *, u_int16_t,
                                   const struct IPFIX_UNIFIED_CTX *);
#define IPFIX_FIELD_TABLE_TYPE struct IPFIX_FIELD_SPECIFIER_ENCODER
#define DEF_FIELD_ENC(ie, len, fn) { { (ie), (len) }, (fn) }
#else
#define IPFIX_FIELD_TABLE_TYPE struct IPFIX_FIELD_SPECIFIER
#define DEF_FIELD_ENC(ie, len, fn) { (ie), (len) }
#endif

/* Shared field-group descriptors (IPFIX IEs) used both with and without
 * ENABLE_UNIFIED_EXPORT_TYPE_FULL to avoid duplication. */
const IPFIX_FIELD_TABLE_TYPE field_v4[] = {
  DEF_FIELD_ENC (IPFIX_sourceIPv4Address, 4, enc_sourceIPv4Address),
  DEF_FIELD_ENC (IPFIX_destinationIPv4Address, 4, enc_destinationIPv4Address)
};

const IPFIX_FIELD_TABLE_TYPE field_v6[] = {
  DEF_FIELD_ENC (IPFIX_sourceIPv6Address, 16, enc_sourceIPv6Address),
  DEF_FIELD_ENC (IPFIX_destinationIPv6Address, 16, enc_destinationIPv6Address)
};

const IPFIX_FIELD_TABLE_TYPE field_common[] = {
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

const IPFIX_FIELD_TABLE_TYPE field_transport[] = {
  DEF_FIELD_ENC (IPFIX_sourceTransportPort, 2, enc_sourceTransportPort),
  DEF_FIELD_ENC (IPFIX_destinationTransportPort, 2,
                 enc_destinationTransportPort),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_tcpControlBits, 1, enc_tcpControlBits),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)
};

const IPFIX_FIELD_TABLE_TYPE field_icmp4[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv4, 2, enc_icmpTypeCode),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)
};

const IPFIX_FIELD_TABLE_TYPE field_icmp6[] = {
  DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv6, 2, enc_icmpTypeCode),
  DEF_FIELD_ENC (IPFIX_protocolIdentifier, 1, enc_protocolIdentifier),
  DEF_FIELD_ENC (IPFIX_ipVersion, 1, enc_ipVersion),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)
};

const IPFIX_FIELD_TABLE_TYPE field_vlan[] = {
  DEF_FIELD_ENC (IPFIX_vlanId, 2, enc_vlanId),
  DEF_FIELD_ENC (IPFIX_postVlanId, 2, enc_postVlanId)
};

const IPFIX_FIELD_TABLE_TYPE field_ether[] = {
  DEF_FIELD_ENC (IPFIX_sourceMacAddress, 6, enc_sourceMacAddress),
  DEF_FIELD_ENC (IPFIX_postDestinationMacAddress, 6,
                 enc_postDestinationMacAddress)
};

const IPFIX_FIELD_TABLE_TYPE field_timesec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartSeconds, 4, enc_flowStartSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndSeconds, 4, enc_flowEndSeconds)
};

const IPFIX_FIELD_TABLE_TYPE field_timemsec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartMilliSeconds, 8, enc_flowStartMilliSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndMilliSeconds, 8, enc_flowEndMilliSeconds)
};

const IPFIX_FIELD_TABLE_TYPE field_timeusec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartMicroSeconds, 8, enc_flowStartMicroSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndMicroSeconds, 8, enc_flowEndMicroSeconds)
};

const IPFIX_FIELD_TABLE_TYPE field_timensec[] = {
  DEF_FIELD_ENC (IPFIX_flowStartNanoSeconds, 8, enc_flowStartNanoSeconds),
  DEF_FIELD_ENC (IPFIX_flowEndNanoSeconds, 8, enc_flowEndNanoSeconds)
};

const IPFIX_FIELD_TABLE_TYPE field_timesysup[] = {
  DEF_FIELD_ENC (IPFIX_flowStartSysUpTime, 4, enc_flowStartSysUpTime),
  DEF_FIELD_ENC (IPFIX_flowEndSysUpTime, 4, enc_flowEndSysUpTime)
};

const IPFIX_FIELD_TABLE_TYPE field_bicommon[] = {
  DEF_FIELD_ENC (IPFIX_octetDeltaCount, 4, enc_octetDeltaCount),
  DEF_FIELD_ENC (IPFIX_packetDeltaCount, 4, enc_packetDeltaCount),
  DEF_FIELD_ENC (IPFIX_ipClassOfService, 1, enc_ipClassOfService)
};

const IPFIX_FIELD_TABLE_TYPE field_bitransport[] =
  { DEF_FIELD_ENC (IPFIX_tcpControlBits, 1, enc_tcpControlBits) };

const IPFIX_FIELD_TABLE_TYPE field_biicmp4[] =
  { DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv4, 2, enc_icmpTypeCode) };

const IPFIX_FIELD_TABLE_TYPE field_biicmp6[] =
  { DEF_FIELD_ENC (IPFIX_icmpTypeCodeIPv6, 2, enc_icmpTypeCode) };

const IPFIX_FIELD_TABLE_TYPE field_scope[] = {
  DEF_FIELD_ENC (IPFIX_meteringProcessId, 4, enc_meteringProcessId)
};

const IPFIX_FIELD_TABLE_TYPE field_option[] = {
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
                 enc_originalExporterAddress)
};

const IPFIX_FIELD_TABLE_TYPE field_nf9scope[] = {
  DEF_FIELD_ENC (NFLOW9_OPTION_SCOPE_INTERFACE, 4, enc_nf9OptionScopeInterface)
};

const IPFIX_FIELD_TABLE_TYPE field_nf9option[] = {
  DEF_FIELD_ENC (NFLOW9_SAMPLING_INTERVAL, 4, enc_samplingInterval),
  DEF_FIELD_ENC (NFLOW9_SAMPLING_ALGORITHM, 1, enc_samplingAlgorithm),
#ifdef ENABLE_IFNAME
  DEF_FIELD_ENC (IPFIX_interfaceName, IFNAMSIZ, enc_interfaceName)
#else
  DEF_FIELD_ENC (IPFIX_interfaceName, IFNAMSIZ, enc_zero)
#endif
};

/* Shared Options Template struct sized for IPFIX (the larger set);
 * NF9 reuses the same layout with fewer slots. */
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS   \
    sizeof(field_scope) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS        \
    sizeof(field_option) / sizeof(struct IPFIX_FIELD_SPECIFIER)

#define NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS  \
    sizeof(field_nf9scope) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS       \
    sizeof(field_nf9option) / sizeof(struct IPFIX_FIELD_SPECIFIER)

struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE {
  struct IPFIX_OPTION_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER
    s[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS];
  struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];
} __packed;

/* ENABLE_UNIFIED_EXPORT_TYPE != FULL (partial or none): Shares IPFIX
 * field tables above, but retains distinct per-version send functions. */
#if ENABLE_UNIFIED_EXPORT_TYPE != ENABLE_UNIFIED_EXPORT_TYPE_FULL

/* Stuff pertaining to the templates that softflowd uses */
#define IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS          \
    sizeof(field_v4) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS        \
    sizeof(field_timesysup) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS      \
    sizeof(field_common) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS   \
    sizeof(field_transport) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS        \
    sizeof(field_icmp4) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS        \
    sizeof(field_vlan) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS       \
    sizeof(field_ether) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS    \
    sizeof(field_bicommon) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS \
    sizeof(field_bitransport) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS      \
    sizeof(field_biicmp4) / sizeof(struct IPFIX_FIELD_SPECIFIER)

#define IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS       \
    IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS +        \
    IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS +      \
    IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS +    \
    IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS + \
    IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS +      \
    IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS

#define IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS    \
    IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS +  \
    IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS

struct IPFIX_SOFTFLOWD_TEMPLATE {
  struct IPFIX_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS];
  struct IPFIX_VENDOR_FIELD_SPECIFIER
    v[IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS];
  u_int16_t data_len, bi_count;
} __packed;

/* softflowd data set */
struct IPFIX_SOFTFLOWD_DATA_COMMON {
  u_int32_t octetDeltaCount, packetDeltaCount;
  u_int32_t ingressInterface, egressInterface;
  u_int8_t flowDirection, flowEndReason;
#ifdef ENABLE_IFNAME
  char interfaceName[IFNAMSIZ];
#endif
} __packed;

struct IPFIX_SOFTFLOWD_DATA_TRANSPORT {
  u_int16_t sourceTransportPort, destinationTransportPort;
  u_int8_t protocolIdentifier, tcpControlBits, ipVersion, ipClassOfService;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_ICMP {
  u_int16_t icmpTypeCode;
  u_int8_t protocolIdentifier, ipVersion, ipClassOfService;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_VLAN {
  u_int16_t vlanId, postVlanId;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_ETHER {
  u_int8_t sourceMacAddress[6], destinationMacAddress[6];
} __packed;

struct IPFIX_SOFTFLOWD_DATA_BICOMMON {
  u_int32_t octetDeltaCount, packetDeltaCount;
  u_int8_t ipClassOfService;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT {
  u_int8_t tcpControlBits;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_BIICMP {
  u_int16_t icmpTypeCode;
} __packed;

union IPFIX_SOFTFLOWD_DATA_TIME {
  struct {
    u_int32_t start;
    u_int32_t end;
  } u32;
  struct {
    u_int64_t start;
    u_int64_t end;
  } u64;
};

struct IPFIX_SOFTFLOWD_DATA_V4ADDR {
  u_int32_t sourceIPv4Address, destinationIPv4Address;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_V6ADDR {
  struct in6_addr sourceIPv6Address, destinationIPv6Address;
} __packed;

struct IPFIX_SOFTFLOWD_OPTION_DATA {
  struct IPFIX_SET_HEADER c;
  u_int32_t scope_pid;
  u_int64_t systemInitTimeMilliseconds;
  u_int32_t samplingInterval;
  u_int32_t samplingSpace;
  u_int16_t samplingAlgorithm;
  char interfaceName[IFNAMSIZ];
  u_int32_t exporterIPv4Address;
  struct in6_addr exporterIPv6Address;
  u_int32_t originalExporterIPv4Address;
  struct in6_addr originalExporterIPv6Address;
} __packed;

struct NFLOW9_SOFTFLOWD_OPTION_DATA {
  struct IPFIX_SET_HEADER c;
  u_int32_t scope_ifidx;
  u_int32_t samplingInterval;
  u_int8_t samplingAlgorithm;
  char interfaceName[IFNAMSIZ];
} __packed;

/* Local data: templates and counters */

/* ... */
#define IPFIX_OPTION_SCOPE_SYSTEM               1
#define IPFIX_OPTION_SCOPE_INTERFACE            2
#define IPFIX_OPTION_SCOPE_LINECARD             3
#define IPFIX_OPTION_SCOPE_CACHE                4
#define IPFIX_OPTION_SCOPE_TEMPLATE             5
/* ... */
#define IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC  1
#define IPFIX_SAMPLING_ALGORITHM_RANDOM         2
/* ... */

// prototype
void memcpy_template (u_char * packet, u_int * offset,
                      struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                      u_int8_t bi_flag, u_int8_t max_num_label);

// variables
static struct IPFIX_SOFTFLOWD_TEMPLATE templates[TMPLMAX];
static struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE option_template;
static struct IPFIX_SOFTFLOWD_OPTION_DATA option_data;
static struct NFLOW9_SOFTFLOWD_OPTION_DATA nf9opt_data;

static int ipfix_pkts_until_template = -1;

static int
ipfix_init_bifields (struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                     u_int *index,
                     const struct IPFIX_FIELD_SPECIFIER *fields,
                     u_int field_number) {
  int i, length = 0;
  for (i = 0; i < field_number; i++) {
    template->v[*index + i].ie = htons (fields[i].ie | 0x8000);
    template->v[*index + i].length = htons (fields[i].length);
    template->v[*index + i].pen = htonl (REVERSE_PEN);
    length += fields[i].length;
  }
  *index += field_number;
  return length;
}

static int
ipfix_init_template_time (struct FLOWTRACKPARAMETERS *param,
                          struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                          u_int *index) {
  int length = 0;
  if (param->time_format == 's') {
    length = ipfix_init_fields (template->r, index,
                                field_timesec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else if (param->time_format == 'm') {
    length = ipfix_init_fields (template->r, index,
                                field_timemsec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else if (param->time_format == 'M') {
    length = ipfix_init_fields (template->r, index,
                                field_timeusec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else if (param->time_format == 'n') {
    length = ipfix_init_fields (template->r, index,
                                field_timensec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else {
    length = ipfix_init_fields (template->r, index,
                                field_timesysup,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  }
  return length;
}

static void
ipfix_init_template_unity (struct FLOWTRACKPARAMETERS *param,
                           struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                           u_int template_id, u_int8_t v6_flag,
                           u_int8_t icmp_flag, u_int8_t bi_flag,
                           u_int16_t version) {
  u_int index = 0, bi_index = 0, length = 0;
  memset (template, 0, sizeof (*template));
  template->h.c.set_id = htons (version == 10 ?
                                IPFIX_TEMPLATE_SET_ID :
                                NFLOW9_TEMPLATE_SET_ID);
  template->h.r.template_id = htons (template_id);
  if (v6_flag) {
    length += ipfix_init_fields (template->r, &index,
                                 field_v6,
                                 IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS);
  } else {
    length += ipfix_init_fields (template->r, &index,
                                 field_v4,
                                 IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS);
  }
  length += ipfix_init_template_time (param, template, &index);
  length += ipfix_init_fields (template->r, &index,
                               field_common,
                               IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS);
  if (icmp_flag) {
    if (v6_flag) {
      length += ipfix_init_fields (template->r, &index,
                                   field_icmp6,
                                   IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS);
    } else {
      length += ipfix_init_fields (template->r, &index,
                                   field_icmp4,
                                   IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS);
    }
  } else {
    length += ipfix_init_fields (template->r, &index,
                                 field_transport,
                                 IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS);
  }
  if (param->track_level >= TRACK_FULL_VLAN) {
    length += ipfix_init_fields (template->r, &index,
                                 field_vlan,
                                 IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS);
  }
  if (param->track_level >= TRACK_FULL_VLAN_ETHER) {
    length += ipfix_init_fields (template->r, &index,
                                 field_ether,
                                 IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS);
  }
  if (bi_flag) {
    length +=
      ipfix_init_bifields (template, &bi_index,
                           field_bicommon,
                           IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS);
    if (icmp_flag) {
      if (v6_flag) {
        length +=
          ipfix_init_bifields (template, &bi_index,
                               field_biicmp6,
                               IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS);
      } else {
        length +=
          ipfix_init_bifields (template, &bi_index,
                               field_biicmp4,
                               IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS);
      }
    } else {
      length +=
        ipfix_init_bifields (template, &bi_index,
                             field_bitransport,
                             IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS);

    }
  }
  template->bi_count = bi_index;
  template->h.r.count = htons (index + bi_index + param->max_num_label);        // mpls
  template->h.c.length =
    htons (sizeof (struct IPFIX_TEMPLATE_SET_HEADER) +
           index * sizeof (struct IPFIX_FIELD_SPECIFIER) +
           bi_index * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) +
           param->max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER));
  template->data_len =
    length + param->max_num_label * IPFIX_mplsLabelStackSection_SIZE;
}

static void
ipfix_init_template (struct FLOWTRACKPARAMETERS *param,
                     u_int8_t bi_flag, u_int16_t version) {
  u_int8_t v6_flag = 0, icmp_flag = 0;
  u_int16_t template_id = 0;
  int i = 0;
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
    ipfix_init_template_unity (param, &templates[i],
                               template_id, v6_flag,
                               icmp_flag, bi_flag, version);
  }
}

static void
nflow9_init_option (u_int16_t ifidx, struct OPTION *option) {
  u_int scope_index = 0, option_index = 0;
  u_int16_t scope_len =
    NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS *
    sizeof (struct IPFIX_FIELD_SPECIFIER);
  u_int16_t opt_len =
    NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS *
    sizeof (struct IPFIX_FIELD_SPECIFIER);

  memset (&option_template, 0, sizeof (option_template));
  option_template.h.c.set_id = htons (NFLOW9_OPTION_TEMPLATE_SET_ID);
  option_template.h.c.length =
    htons (sizeof (option_template.h) + scope_len + opt_len);
  option_template.h.u.n.template_id =
    htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  option_template.h.u.n.scope_length = htons (scope_len);
  option_template.h.u.n.option_length = htons (opt_len);
  ipfix_init_fields (option_template.s, &scope_index,
                     field_nf9scope,
                     NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS);
  ipfix_init_fields (option_template.r, &option_index,
                     field_nf9option,
                     NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS);
  memset (&nf9opt_data, 0, sizeof (nf9opt_data));
  nf9opt_data.c.set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  nf9opt_data.c.length = htons (sizeof (nf9opt_data));
  nf9opt_data.scope_ifidx = htonl (ifidx);
  nf9opt_data.samplingInterval =
    htonl (option->sample > 1 ? option->sample : 1);
  nf9opt_data.samplingAlgorithm = NFLOW9_SAMPLING_ALGORITHM_DETERMINISTIC;
  strncpy (nf9opt_data.interfaceName, option->interfaceName,
           strlen (option->interfaceName) <
           sizeof (nf9opt_data.interfaceName) ?
           strlen (option->interfaceName) :
           sizeof (nf9opt_data.interfaceName));
}

static void
ipfix_init_option (struct timeval *system_boot_time, struct OPTION *option) {
  u_int scope_index = 0, option_index = 0;
  memset (&option_template, 0, sizeof (option_template));
  option_template.h.c.set_id = htons (IPFIX_OPTION_TEMPLATE_SET_ID);
  option_template.h.c.length = htons (sizeof (option_template));
  option_template.h.u.i.r.template_id =
    htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  option_template.h.u.i.r.count =
    htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS +
           IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS);
  option_template.h.u.i.scope_count =
    htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS);

  ipfix_init_fields (option_template.s, &scope_index,
                     field_scope,
                     IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS);
  ipfix_init_fields (option_template.r, &option_index, field_option,
                     IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS);

  memset (&option_data, 0, sizeof (option_data));
  option_data.c.set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  option_data.c.length = htons (sizeof (option_data));
  option_data.scope_pid = htonl ((u_int32_t) option->meteringProcessId);
#if defined(htobe64) || defined(HAVE_DECL_HTOBE64)
  option_data.systemInitTimeMilliseconds =
    htobe64 ((u_int64_t) system_boot_time->tv_sec * 1000 +
             (u_int64_t) system_boot_time->tv_usec / 1000);
#endif
  option_data.samplingAlgorithm = htons (PSAMP_selectorAlgorithm_count);
  option_data.samplingInterval = htonl (1);
  option_data.samplingSpace =
    htonl (option->sample > 0 ? option->sample - 1 : 0);
  strncpy (option_data.interfaceName, option->interfaceName,
           strlen (option->interfaceName) <
           sizeof (option_data.interfaceName) ?
           strlen (option->interfaceName) :
           sizeof (option_data.interfaceName));
  if (option->exporterAddr != NULL) {
    struct addrinfo *rp;
    for (rp = option->exporterAddr; rp != NULL; rp = rp->ai_next) {
      if (rp->ai_family == AF_INET) {
        memcpy (&option_data.exporterIPv4Address,
                &((struct sockaddr_in *) rp->ai_addr)->sin_addr,
                sizeof (option_data.exporterIPv4Address));
        memcpy (&option_data.originalExporterIPv4Address, rp->ai_addr,
                sizeof (option_data.originalExporterIPv4Address));
      } else if (rp->ai_family == AF_INET6) {
        memcpy (&option_data.exporterIPv6Address, rp->ai_addr,
                sizeof (option_data.exporterIPv6Address));
        memcpy (&option_data.originalExporterIPv6Address,
                &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr,
                sizeof (option_data.originalExporterIPv6Address));
      }
    }
  }
}

static int
copy_data_time (union IPFIX_SOFTFLOWD_DATA_TIME *dt,
                const struct FLOW *flow,
                const struct timeval *system_boot_time,
                struct FLOWTRACKPARAMETERS *param) {
  int length = (param->time_format == 'm' || param->time_format == 'M'
                || param->time_format == 'n') ? 16 : 8;
  if (dt == NULL)
    return -1;

  switch (param->time_format) {
    struct ntp_time_t ntptime;
  case 's':
    dt->u32.start = htonl (flow->flow_start.tv_sec);
    dt->u32.end = htonl (flow->flow_last.tv_sec);
    break;
#if defined(htobe64) || defined(HAVE_DECL_HTOBE64)
  case 'm':
    dt->u64.start =
      htobe64 ((u_int64_t) flow->flow_start.tv_sec * 1000 +
               (u_int64_t) flow->flow_start.tv_usec / 1000);
    dt->u64.end =
      htobe64 ((u_int64_t) flow->flow_last.tv_sec * 1000 +
               (u_int64_t) flow->flow_last.tv_usec / 1000);
    break;
  case 'M':
  case 'n':
    conv_unix_to_ntp ((struct timeval) flow->flow_start, &ntptime);
    dt->u64.start =
      htobe64 ((u_int64_t) ntptime.second << 32 | ntptime.fraction);
    conv_unix_to_ntp ((struct timeval) flow->flow_last, &ntptime);
    dt->u64.end =
      htobe64 ((u_int64_t) ntptime.second << 32 | ntptime.fraction);
    break;
#endif
  default:
    dt->u32.start =
      htonl (timeval_sub_ms (&flow->flow_start, system_boot_time));
    dt->u32.end = htonl (timeval_sub_ms (&flow->flow_last, system_boot_time));
    break;
  }
  return length;
}


static int
ipfix_flow_to_flowset (const struct FLOW *flow, u_char *packet,
                       u_int len, u_int16_t ifidx,
                       const struct timeval *system_boot_time,
                       u_int *len_used,
                       struct FLOWTRACKPARAMETERS *param, u_int8_t bi_flag) {
  struct IPFIX_SOFTFLOWD_DATA_V4ADDR *d4[2] = { NULL, NULL };
  struct IPFIX_SOFTFLOWD_DATA_V6ADDR *d6[2] = { NULL, NULL };
  union IPFIX_SOFTFLOWD_DATA_TIME *dt[2] = { NULL, NULL };
  struct IPFIX_SOFTFLOWD_DATA_COMMON *dc[2] = { NULL, NULL };
  struct IPFIX_SOFTFLOWD_DATA_TRANSPORT *dtr[2] = { NULL, NULL };
  struct IPFIX_SOFTFLOWD_DATA_ICMP *di[2] = { NULL, NULL };
  struct IPFIX_SOFTFLOWD_DATA_VLAN *dv[2] = { NULL, NULL };
  struct IPFIX_SOFTFLOWD_DATA_ETHER *de[2] = { NULL, NULL };
  struct IPFIX_SOFTFLOWD_DATA_BICOMMON *dbc = NULL;
  struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT *dbtr = NULL;
  struct IPFIX_SOFTFLOWD_DATA_BIICMP *dbi = NULL;
#ifdef ENABLE_IFNAME
  struct OPTION *option = &param->option;
#endif /* ENABLE_IFNAME */
  u_int freclen = 0, nflows = 0, offset = 0;
  u_int frecnum = bi_flag ? 1 : 2;
  u_int tmplindex = ipfix_flow_to_template_index (flow);
  int i = 0, k = 0;
  freclen = templates[tmplindex].data_len;
  if (len < freclen * frecnum)
    return (-1);

  for (i = 0; i < frecnum; i++) {
    if (bi_flag == 0 && flow->octets[i] == 0)
      continue;
    nflows++;
    if (flow->af == AF_INET) {
      d4[i] = (struct IPFIX_SOFTFLOWD_DATA_V4ADDR *) &packet[offset];
      memcpy (&d4[i]->sourceIPv4Address, &flow->addr[i].v4, 4);
      memcpy (&d4[i]->destinationIPv4Address, &flow->addr[i ^ 1].v4, 4);
      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_V4ADDR);
    } else if (flow->af == AF_INET6) {
      d6[i] = (struct IPFIX_SOFTFLOWD_DATA_V6ADDR *) &packet[offset];
      memcpy (&d6[i]->sourceIPv6Address, &flow->addr[i].v6, 16);
      memcpy (&d6[i]->destinationIPv6Address, &flow->addr[i ^ 1].v6, 16);
      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_V6ADDR);
    }

    dt[i] = (union IPFIX_SOFTFLOWD_DATA_TIME *) &packet[offset];
    offset += copy_data_time (dt[i], flow, system_boot_time, param);

    dc[i] = (struct IPFIX_SOFTFLOWD_DATA_COMMON *) &packet[offset];
    dc[i]->octetDeltaCount = htonl (flow->octets[i]);
    dc[i]->packetDeltaCount = htonl (flow->packets[i]);
    dc[i]->ingressInterface = dc[i]->egressInterface = htonl (ifidx);
    dc[i]->flowDirection = ipfix_flow_direction (flow, i, param);
    dc[i]->flowEndReason = flow->flowEndReason;
#ifdef ENABLE_IFNAME
    strncpy (dc[i]->interfaceName, option->interfaceName,
             strlen (option->interfaceName) <
             sizeof (dc[i]->interfaceName) ?
             strlen (option->interfaceName) : sizeof (dc[i]->interfaceName));
#endif /* ENABLE_IFNAME */
    offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_COMMON);

    if (flow->protocol != IPPROTO_ICMP && flow->protocol != IPPROTO_ICMPV6) {
      dtr[i] = (struct IPFIX_SOFTFLOWD_DATA_TRANSPORT *) &packet[offset];
      dtr[i]->sourceTransportPort = flow->port[i];
      dtr[i]->destinationTransportPort = flow->port[i ^ 1];
      dtr[i]->protocolIdentifier = flow->protocol;
      dtr[i]->tcpControlBits = flow->tcp_flags[i];
      dtr[i]->ipClassOfService = flow->tos[i];
      dtr[i]->ipVersion = (flow->af == AF_INET) ? 4 : 6;
      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_TRANSPORT);
    } else {
      di[i] = (struct IPFIX_SOFTFLOWD_DATA_ICMP *) &packet[offset];
      di[i]->icmpTypeCode = flow->port[i ^ 1];
      di[i]->protocolIdentifier = flow->protocol;
      di[i]->ipClassOfService = flow->tos[i];
      di[i]->ipVersion = (flow->af == AF_INET) ? 4 : 6;
      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_ICMP);
    }
    if (param->track_level >= TRACK_FULL_VLAN) {
      dv[i] = (struct IPFIX_SOFTFLOWD_DATA_VLAN *) &packet[offset];
      dv[i]->vlanId = htons (flow->vlanid[i]);
      dv[i]->postVlanId = htons (flow->vlanid[i ^ 1]);
      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_VLAN);
    }
    if (param->track_level >= TRACK_FULL_VLAN_ETHER) {
      de[i] = (struct IPFIX_SOFTFLOWD_DATA_ETHER *) &packet[offset];
      memcpy (&de[i]->sourceMacAddress, &flow->ethermac[i], 6);
      memcpy (&de[i]->destinationMacAddress, &flow->ethermac[i ^ 1], 6);
      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_ETHER);
    }
    if (bi_flag && i == 0) {
      dbc = (struct IPFIX_SOFTFLOWD_DATA_BICOMMON *) &packet[offset];
      dbc->octetDeltaCount = htonl (flow->octets[1]);
      dbc->packetDeltaCount = htonl (flow->packets[1]);
      dbc->ipClassOfService = flow->tos[1];
      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_BICOMMON);
      if (flow->protocol != IPPROTO_ICMP && flow->protocol != IPPROTO_ICMPV6) {
        dbtr = (struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT *)
          &packet[offset];
        dbtr->tcpControlBits = flow->tcp_flags[1];
        offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT);
      } else {
        dbi = (struct IPFIX_SOFTFLOWD_DATA_BIICMP *)
          &packet[offset];
        dbi->icmpTypeCode = flow->port[1];
        offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_BIICMP);
      }
    }
    for (k = 0; k < param->max_num_label; k++) {
      memcpy (&packet[offset], &flow->mplsLabels[k],
              IPFIX_mplsLabelStackSection_SIZE);
      offset += IPFIX_mplsLabelStackSection_SIZE;
    }
  }
  *len_used = offset;
  return (nflows);
}

static int
valuate_icmp (struct FLOW *flow) {
  if (flow == NULL)
    return -1;
  if (flow->af == AF_INET)
    if (flow->protocol == IPPROTO_ICMP)
      return 1;
    else
      return 0;
  else if (flow->af == AF_INET6)
    if (flow->protocol == IPPROTO_ICMPV6)
      return 1;
    else
      return 0;
  else
    return -1;
  return -1;
}

void
ipfix_resend_template (void) {
  if (ipfix_pkts_until_template > 0)
    ipfix_pkts_until_template = 0;
}

void
memcpy_template (u_char *packet, u_int *offset,
                 struct IPFIX_SOFTFLOWD_TEMPLATE *template, u_int8_t bi_flag,
                 u_int8_t max_num_label) {
  int i = 0;
  int size = ntohs (template->h.c.length) -
    template->bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) -
    max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER);
  memcpy (packet + *offset, template, size);
  *offset += size;
  if (bi_flag) {
    size = template->bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER);
    memcpy (packet + *offset, template->v, size);
    *offset += size;
  }
  // mpls
  for (i = 0; i < max_num_label; i++) {
    struct IPFIX_FIELD_SPECIFIER *mpls_fs =
      (struct IPFIX_FIELD_SPECIFIER *) &packet[*offset];
    mpls_fs->ie = htons (IPFIX_mplsTopLabelStackSection + i);
    mpls_fs->length = htons (IPFIX_mplsLabelStackSection_SIZE);
    *offset += sizeof (struct IPFIX_FIELD_SPECIFIER);
  }
}

/*
 * Given an array of expired flows, send ipfix report packets
 * Returns number of packets sent or -1 on error
 */
static int
send_ipfix_common (struct FLOW **flows, int num_flows,
                   struct NETFLOW_TARGET *target,
                   u_int16_t ifidx, struct FLOWTRACKPARAMETERS *param,
                   int verbose_flag, u_int8_t bi_flag, u_int16_t version) {
  struct IPFIX_HEADER *ipfix;
  struct NFLOW9_HEADER *nf9;
  struct IPFIX_SET_HEADER *dh;
  struct timeval now;
  u_int offset, last_af, i, j, num_packets, inc, last_valid, tmplindex;
  int8_t icmp_flag, last_icmp_flag;
  int r;
  u_int records = 0;
  u_char packet[IPFIX_SOFTFLOWD_MAX_PACKET_SIZE];
  struct timeval *system_boot_time = &param->system_boot_time;
  u_int64_t *flows_exported = &param->flows_exported;
  u_int64_t *records_sent = &param->records_sent;
  struct OPTION *option = &param->option;
  static u_int sequence = 1;

  if (version != 9 && version != 10)
    return (-1);
  if (param->adjust_time)
    now = param->last_packet_time;
  else
    gettimeofday (&now, NULL);

  if (ipfix_pkts_until_template == -1) {
    ipfix_init_template (param, bi_flag, version);
    ipfix_pkts_until_template = 0;
    if (option != NULL) {
      if (version == 10) {
        ipfix_init_option (system_boot_time, option);
      } else {
        nflow9_init_option (ifidx, option);
      }
    }
  }

  last_valid = num_packets = 0;
  for (j = 0; j < num_flows;) {
    memset (packet, 0, sizeof (packet));
    if (version == 10) {
      ipfix = (struct IPFIX_HEADER *) packet;
      ipfix->version = htons (version);
      ipfix->length = 0;        /* Filled as we go, htons at end */
      if (param->adjust_time)
        ipfix->export_time = htonl (now.tv_sec);
      else
        ipfix->export_time = htonl (time (NULL));
      ipfix->od_id = 0;
      offset = sizeof (*ipfix);
    } else if (version == 9) {
      nf9 = (struct NFLOW9_HEADER *) packet;
      nf9->version = htons (version);
      nf9->flows = 0;           /* Filled as we go, htons at end */
      nf9->uptime_ms = htonl (timeval_sub_ms (&now, system_boot_time));
      if (param->adjust_time)
        nf9->export_time = htonl (now.tv_sec);
      else
        nf9->export_time = htonl (time (NULL));
      nf9->od_id = 0;
      offset = sizeof (*nf9);
    }

    /* Refresh template headers if we need to */
    if (ipfix_pkts_until_template <= 0) {
      for (i = 0; i < TMPLMAX; i++) {
        memcpy_template (packet, &offset, &templates[i], bi_flag,
                         param->max_num_label);
      }
      if (option != NULL) {
        u_int16_t opt_tmpl_len = ntohs (option_template.h.c.length);
        memcpy (packet + offset, &option_template, opt_tmpl_len);
        offset += opt_tmpl_len;
        if (version == 10) {
          memcpy (packet + offset, &option_data, sizeof (option_data));
          offset += sizeof (option_data);
        } else if (version == 9) {
          memcpy (packet + offset, &nf9opt_data, sizeof (nf9opt_data));
          offset += sizeof (nf9opt_data);
        }
      }

      ipfix_pkts_until_template = IPFIX_DEFAULT_TEMPLATE_INTERVAL;
      if (target->is_loadbalance && target->num_destinations > 1) {
        if (version == 10) {
          ipfix->length = htons (offset);
          ipfix->sequence =
            htonl ((u_int32_t) (*records_sent & 0x00000000ffffffff));
        } else if (version == 9) {
          nf9->flows = htons (++records);
          nf9->sequence = htonl (sequence++);
        }
        if (send_multi_destinations
            (target->num_destinations, target->destinations, 0, packet,
             offset) < 0)
          return (-1);
        offset = version == 10 ? sizeof (*ipfix) : sizeof (*nf9);       // resest offset
      }
    }

    dh = NULL;
    last_af = 0;
    last_icmp_flag = -1;
    records = 0;
    for (i = 0; i + j < num_flows; i++) {
      icmp_flag = valuate_icmp (flows[i + j]);
      if (dh == NULL || flows[i + j]->af != last_af ||
          icmp_flag != last_icmp_flag) {
        if (dh != NULL) {
          if (offset % 4 != 0) {
            /* Pad to multiple of 4 */
            dh->length += 4 - (offset % 4);
            offset += 4 - (offset % 4);
          }
          /* Finalise last header */
          dh->length = htons (dh->length);
        }
        if (offset + sizeof (*dh) > sizeof (packet)) {
          /* Mark header is finished */
          dh = NULL;
          break;
        }
        dh = (struct IPFIX_SET_HEADER *) (packet + offset);
        tmplindex = ipfix_flow_to_template_index (flows[i + j]);
        dh->set_id = templates[tmplindex].h.r.template_id;
        last_af = flows[i + j]->af;
        last_icmp_flag = icmp_flag;
        last_valid = offset;
        dh->length = sizeof (*dh);      /* Filled as we go */
        offset += sizeof (*dh);
      }
      r = ipfix_flow_to_flowset (flows[i + j],
                                 packet + offset,
                                 sizeof (packet) - offset,
                                 ifidx, system_boot_time,
                                 &inc, param, bi_flag);
      if (r <= 0) {
        /* yank off data header, if we had to go back */
        if (last_valid)
          offset = last_valid;
        break;
      }
      records += (u_int) r;
      offset += inc;
      dh->length += inc;
      last_valid = 0;           /* Don't clobber this header now */
      if (verbose_flag) {
        logit (LOG_DEBUG, "Flow %d/%d: "
               "r %d offset %d ie %04x len %d(0x%04x)",
               r, i, j, offset, dh->set_id, dh->length, dh->length);
      }
    }
    /* Don't finish header if it has already been done */
    if (dh != NULL) {
      if (offset % 4 != 0) {
        /* Pad to multiple of 4 */
        dh->length += 4 - (offset % 4);
        offset += 4 - (offset % 4);
      }
      /* Finalise last header */
      dh->length = htons (dh->length);
    }
    *records_sent += records;
    if (version == 10) {
      ipfix->length = htons (offset);
      ipfix->sequence =
        htonl ((u_int32_t) (*records_sent & 0x00000000ffffffff));
    } else if (version == 9) {
      nf9->flows = htons (records);
      nf9->sequence = htonl (sequence++);
    }

    if (verbose_flag)
      logit (LOG_DEBUG, "Sending flow packet len = %d", offset);
    if (send_multi_destinations
        (target->num_destinations, target->destinations,
         target->is_loadbalance, packet, offset) < 0)
      return (-1);
    num_packets++;
    ipfix_pkts_until_template--;

    j += i;
  }

  *flows_exported += j;
  param->packets_sent += num_packets;
#ifdef ENABLE_PTHREAD
  if (use_thread)
    free (flows);
#endif /* ENABLE_PTHREAD */
  return (num_packets);
}

int
send_nflow9 (struct SENDPARAMETER sp) {
  return send_ipfix_common (sp.flows, sp.num_flows, sp.target, sp.ifidx,
                            sp.param, sp.verbose_flag, 0, 9);
}

int
send_ipfix (struct SENDPARAMETER sp) {
  return send_ipfix_common (sp.flows, sp.num_flows, sp.target, sp.ifidx,
                            sp.param, sp.verbose_flag, 0, 10);
}

int
send_ipfix_bi (struct SENDPARAMETER sp) {
  return send_ipfix_common (sp.flows, sp.num_flows, sp.target, sp.ifidx,
                            sp.param, sp.verbose_flag, 1, 10);
}

#else /* ENABLE_UNIFIED_EXPORT_TYPE == ENABLE_UNIFIED_EXPORT_TYPE_FULL */
/* Unified NetFlow v1/v5/v9/IPFIX exporter (ENABLE_UNIFIED_EXPORT_TYPE_FULL):
 * Consolidates all 4 versions into a single path by treating v1/v5 fields as IPFIX IEs.
 * Active only under --enable-unified-export-type=full (psamp.c remains separate). */

/* Context for resolving field values: flow, endpoint index, and send parameters. */
struct IPFIX_UNIFIED_CTX {
  const struct SENDPARAMETER *sp;
  const struct FLOW *flow;
  u_int i;                      /* which endpoint (0/1) is "source" here */
};

/* Stores host-order 'val' (low 'len' octets) as big-endian at dst.
 * Fast-paths 8/4/2-byte widths via htobe/htonl/htons, falling back to a byte loop. */
static inline void
hton (u_char *dst, u_int64_t val, u_int len) {
  switch (len) {
#if defined(htobe64) || defined(HAVE_DECL_HTOBE64)
  case 8:
    {
      u_int64_t v = htobe64 (val);
      memcpy (dst, &v, 8);
    }
    return;
#endif
  case 4:
    {
      u_int32_t v = htonl ((u_int32_t) val);
      memcpy (dst, &v, 4);
    }
    return;
  case 2:
    {
      u_int16_t v = htons ((u_int16_t) val);
      memcpy (dst, &v, 2);
    }
    return;
  default:
    {
      u_int k;
      for (k = 0; k < len; k++)
        dst[k] = (u_char) (val >> (8 * (len - 1 - k)));
    }
    return;
  }
}

/* Compile-time resolved IE encoder stored directly in field tables.
 * Eliminates runtime lookup/init costs since field lists are static. */
/* Uses compile-time constant 'width' to let the compiler optimize hton()'s
 * switch block down to a single branch on the hot path. */
#define IPFIX_UNIFIED_ENC_HTON(name, val_expr, width) \
static void \
name (u_char *dst, u_int16_t length, const struct IPFIX_UNIFIED_CTX *ctx) { \
  const struct FLOW *flow = ctx->flow; u_int i = ctx->i; \
  (void) flow; (void) i; (void) length; \
  hton (dst, (val_expr), (width)); \
}

/* No length check: field tables statically match each encoder to its exact 'n'
 * (length >= n is always true), allowing unconditional memcpy on the hot path. */
#define IPFIX_UNIFIED_ENC_COPY(name, src_expr, n) \
static void \
name (u_char *dst, u_int16_t length, const struct IPFIX_UNIFIED_CTX *ctx) { \
  const struct FLOW *flow = ctx->flow; u_int i = ctx->i; \
  (void) flow; (void) i; (void) length; \
  memcpy (dst, (src_expr), (n)); \
}

#define IPFIX_UNIFIED_ENC_BYTE(name, val_expr) \
static void \
name (u_char *dst, u_int16_t length, const struct IPFIX_UNIFIED_CTX *ctx) { \
  const struct FLOW *flow = ctx->flow; u_int i = ctx->i; \
  (void) length; (void) flow; (void) i; \
  *dst = (u_char) (val_expr); \
}

/* No-op encoder for NF1/NF5 zero/padding fields. Calling this dummy function
 * directly is faster than testing for a NULL sentinel on the hot path. */
static void
enc_zero (u_char *dst, u_int16_t length, const struct IPFIX_UNIFIED_CTX *ctx) {
  (void) dst;
  (void) length;
  (void) ctx;                   /* no value; buffer already zeroed */
}

IPFIX_UNIFIED_ENC_HTON (enc_octetDeltaCount, flow->octets[i], 4)
IPFIX_UNIFIED_ENC_HTON (enc_packetDeltaCount, flow->packets[i], 4)
IPFIX_UNIFIED_ENC_BYTE (enc_protocolIdentifier, flow->protocol)
IPFIX_UNIFIED_ENC_BYTE (enc_ipClassOfService, flow->tos[i])
IPFIX_UNIFIED_ENC_BYTE (enc_tcpControlBits, flow->tcp_flags[i])
IPFIX_UNIFIED_ENC_COPY (enc_sourceTransportPort, &flow->port[i], 2)
IPFIX_UNIFIED_ENC_COPY (enc_destinationTransportPort, &flow->port[i ^ 1], 2)
IPFIX_UNIFIED_ENC_COPY (enc_icmpTypeCode, &flow->port[i ^ 1], 2)
IPFIX_UNIFIED_ENC_COPY (enc_sourceIPv4Address, &flow->addr[i].v4, 4)
IPFIX_UNIFIED_ENC_COPY (enc_destinationIPv4Address, &flow->addr[i ^ 1].v4, 4)
IPFIX_UNIFIED_ENC_COPY (enc_sourceIPv6Address, &flow->addr[i].v6, 16)
IPFIX_UNIFIED_ENC_COPY (enc_destinationIPv6Address, &flow->addr[i ^ 1].v6, 16)
IPFIX_UNIFIED_ENC_COPY (enc_sourceMacAddress, &flow->ethermac[i], 6)
IPFIX_UNIFIED_ENC_COPY (enc_postDestinationMacAddress, &flow->ethermac[i ^ 1],
                        6)
/* Split into 16-bit and 32-bit encoders so each passes a literal width to hton()
 * for compile-time switch optimization instead of using runtime length. */
IPFIX_UNIFIED_ENC_HTON (enc_ifidx16, ctx->sp->ifidx, 2)   /* NF1/NF5 ingress/egressInterface */
IPFIX_UNIFIED_ENC_HTON (enc_ifidx32, ctx->sp->ifidx, 4)   /* NF9/IPFIX ingress/egressInterface */
IPFIX_UNIFIED_ENC_HTON (enc_flowStartSysUpTime,
                        timeval_sub_ms (&flow->flow_start,
                                      &ctx->sp->param->system_boot_time), 4)
IPFIX_UNIFIED_ENC_HTON (enc_flowEndSysUpTime,
                        timeval_sub_ms (&flow->flow_last,
                                      &ctx->sp->param->system_boot_time), 4)
IPFIX_UNIFIED_ENC_HTON (enc_flowStartSeconds,
                        (u_int32_t) flow->flow_start.tv_sec, 4)
IPFIX_UNIFIED_ENC_HTON (enc_flowEndSeconds,
                        (u_int32_t) flow->flow_last.tv_sec, 4)
IPFIX_UNIFIED_ENC_HTON (enc_flowStartMilliSeconds,
                        (u_int64_t) flow->flow_start.tv_sec * 1000 +
                        (u_int64_t) flow->flow_start.tv_usec / 1000, 8)
IPFIX_UNIFIED_ENC_HTON (enc_flowEndMilliSeconds,
                        (u_int64_t) flow->flow_last.tv_sec * 1000 +
                        (u_int64_t) flow->flow_last.tv_usec / 1000, 8)
IPFIX_UNIFIED_ENC_BYTE (enc_flowEndReason, flow->flowEndReason)

/* Encodes NTP 64-bit timestamps for IPFIX micro/nano (identical encoding). */
static void
enc_flowStartMicroSeconds (u_char *dst, u_int16_t length,
                           const struct IPFIX_UNIFIED_CTX *ctx) {
  struct ntp_time_t ntptime;
  (void) length;
  conv_unix_to_ntp (ctx->flow->flow_start, &ntptime);
  hton (dst, (u_int64_t) ntptime.second << 32 | ntptime.fraction, 8);
}
static void
enc_flowEndMicroSeconds (u_char *dst, u_int16_t length,
                         const struct IPFIX_UNIFIED_CTX *ctx) {
  struct ntp_time_t ntptime;
  (void) length;
  conv_unix_to_ntp (ctx->flow->flow_last, &ntptime);
  hton (dst, (u_int64_t) ntptime.second << 32 | ntptime.fraction, 8);
}

IPFIX_UNIFIED_ENC_HTON (enc_vlanId, ctx->flow->vlanid[ctx->i], 2)
IPFIX_UNIFIED_ENC_HTON (enc_postVlanId, ctx->flow->vlanid[ctx->i ^ 1], 2)
#ifdef ENABLE_IFNAME
static void
enc_interfaceName (u_char *dst, u_int16_t length,
                   const struct IPFIX_UNIFIED_CTX *ctx) {
  size_t n = strlen (ctx->sp->param->option.interfaceName);
  if (n > length)
    n = length;
  memcpy (dst, ctx->sp->param->option.interfaceName, n);
  /* Copies string up to its own length (capped at 'n'), leaving remaining field bytes
   * zeroed by the packet buffer's initial clearance. */
}
#endif /* ENABLE_IFNAME */

IPFIX_UNIFIED_ENC_HTON (enc_nf9OptionScopeInterface, ctx->sp->ifidx, 4)
IPFIX_UNIFIED_ENC_HTON (enc_samplingInterval,
                        ctx->sp->param->option.sample > 1 ?
                        ctx->sp->param->option.sample : 1, length)
IPFIX_UNIFIED_ENC_HTON (enc_systemInitTimeMilliseconds,
                        (u_int64_t) ctx->sp->param->system_boot_time.tv_sec *
                        1000 + (u_int64_t) ctx->sp->param->system_boot_time.tv_usec /
                        1000, 8)
IPFIX_UNIFIED_ENC_HTON (enc_meteringProcessId,
                        (u_int32_t) ctx->sp->param->option.meteringProcessId, 4)
IPFIX_UNIFIED_ENC_HTON (enc_samplingPacketInterval,
                        ctx->sp->param->option.sample > 1 ?
                        ctx->sp->param->option.sample : 1, length)
IPFIX_UNIFIED_ENC_HTON (enc_samplingPacketSpace,
                        ctx->sp->param->option.sample > 0 ?
                        ctx->sp->param->option.sample - 1 : 0, length)
IPFIX_UNIFIED_ENC_HTON (enc_selectorAlgorithm, PSAMP_selectorAlgorithm_count,
                        length)
IPFIX_UNIFIED_ENC_BYTE (enc_samplingAlgorithm,
                        NFLOW9_SAMPLING_ALGORITHM_DETERMINISTIC)

static void
enc_exporterAddress (u_char *dst, u_int16_t length,
                     const struct IPFIX_UNIFIED_CTX *ctx) {
  struct addrinfo *rp;
  for (rp = ctx->sp->param->option.exporterAddr; rp != NULL; rp = rp->ai_next) {
    if (length == 4 && rp->ai_family == AF_INET) {
      memcpy (dst, &((struct sockaddr_in *) rp->ai_addr)->sin_addr, 4);
      return;
    } else if (length == 16 && rp->ai_family == AF_INET6) {
      memcpy (dst, rp->ai_addr, 16);
      return;
    }
  }
}

static void
enc_originalExporterAddress (u_char *dst, u_int16_t length,
                             const struct IPFIX_UNIFIED_CTX *ctx) {
  struct addrinfo *rp;
  for (rp = ctx->sp->param->option.exporterAddr; rp != NULL; rp = rp->ai_next) {
    if (length == 4 && rp->ai_family == AF_INET) {
      memcpy (dst, rp->ai_addr, 4);
      return;
    } else if (length == 16 && rp->ai_family == AF_INET6) {
      memcpy (dst, &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr, 16);
      return;
    }
  }
}

static void
enc_ipVersion (u_char *dst, u_int16_t length,
               const struct IPFIX_UNIFIED_CTX *ctx) {
  (void) length; /* Silence -Wunused-parameter warning */
  *dst = (ctx->flow->af == AF_INET) ? 4 : 6;
}

static void
enc_flowDirection (u_char *dst, u_int16_t length,
                   const struct IPFIX_UNIFIED_CTX *ctx) {
  (void) length; /* Silence -Wunused-parameter warning */
  *dst = ipfix_flow_direction (ctx->flow, ctx->i, ctx->sp->param);
}

/* NetFlow v1/v5 fixed data records: same IEs as field_netflow_v1v5_common[]. */
static const struct IPFIX_FIELD_SPECIFIER_ENCODER
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

static const struct IPFIX_FIELD_SPECIFIER_ENCODER field_netflowv1_tail_enc[] = {
  {{IPFIX_paddingOctets, 2}, enc_zero},
  {{IPFIX_protocolIdentifier, 1}, enc_protocolIdentifier},
  {{IPFIX_ipClassOfService, 1}, enc_ipClassOfService},
  {{IPFIX_tcpControlBits, 1}, enc_tcpControlBits},
  {{IPFIX_paddingOctets, 7}, enc_zero},
};

static const struct IPFIX_FIELD_SPECIFIER_ENCODER field_netflowv5_tail_enc[] = {
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

/* Aliases shared DEF_FIELD_ENC tables to '_enc' names, allowing unified code
 * to reference field specifiers without renaming call sites. */
#define field_v4_enc field_v4
#define field_v6_enc field_v6
#define field_common_enc field_common
#define field_timesysup_enc field_timesysup
#define field_timesec_enc field_timesec
#define field_timemsec_enc field_timemsec
#define field_timeusec_enc field_timeusec
#define field_timensec_enc field_timensec
#define field_transport_enc field_transport
#define field_icmp4_enc field_icmp4
#define field_icmp6_enc field_icmp6
#define field_vlan_enc field_vlan
#define field_ether_enc field_ether
#define field_bicommon_enc field_bicommon
#define field_bitransport_enc field_bitransport
#define field_biicmp4_enc field_biicmp4
#define field_biicmp6_enc field_biicmp6
#define field_scope_enc field_scope
#define field_option_enc field_option
#define field_nf9scope_enc field_nf9scope
#define field_nf9option_enc field_nf9option

#define IPFIX_UNIFIED_NFIELDS(a) (sizeof (a) / sizeof (struct IPFIX_FIELD_SPECIFIER))
#define IPFIX_UNIFIED_NFIELDS_ENC(a) (sizeof (a) / sizeof (struct IPFIX_FIELD_SPECIFIER_ENCODER))

/* Writes packet headers directly per packet using existing structs (NF5/NF9/IPFIX),
 * using the top-level union 'version' member shared across all formats. */
union IPFIX_UNIFIED_HEADER {
  u_int16_t version;
  struct NF5_HEADER nf5;        /* NF1: only the first NF1_HEADER_SIZE octets */
  struct NFLOW9_HEADER nf9;
  struct IPFIX_HEADER ipfix;
};

/* Emits every field of a data-record group by calling each entry's
 * own compile-time-resolved encoder directly -- no lookup. */
static u_int
ipfix_unified_emit_group_enc (const struct IPFIX_FIELD_SPECIFIER_ENCODER
                              *fields, u_int nfields, u_char *packet,
                              u_int offset,
                              const struct IPFIX_UNIFIED_CTX *ctx) {
  u_int i;
  for (i = 0; i < nfields; i++) {
    fields[i].encoder (packet + offset, fields[i].field.length, ctx);
    offset += fields[i].field.length;
  }
  return offset;
}
/* Unconditional loop is faster than per-field NULL checks, which added 0.8%-2.7%
 * instruction overhead in Callgrind measurements due to branch costs. */

/* Builds fixed packet header via union pointer cast, leaving count/length/sequence
 * fields as 0 to be patched in place once the packet is complete. */
static u_int
ipfix_unified_build_header (u_char *packet, u_int16_t version,
                            const struct FLOWTRACKPARAMETERS *param) {
  union IPFIX_UNIFIED_HEADER *h = (union IPFIX_UNIFIED_HEADER *) packet;
  struct timeval now;
  u_int32_t systemInitTimeMilliseconds;

  if (param->adjust_time)
    now = param->last_packet_time;
  else
    gettimeofday (&now, NULL);

  systemInitTimeMilliseconds = timeval_sub_ms (&now, &param->system_boot_time);

  h->version = htons (version);
  switch (version) {
  case 1:
  case 5:
    /* NF1's header is exactly NF5's first NF1_HEADER_SIZE octets (see
     * union IPFIX_UNIFIED_HEADER's comment), so this much is shared. */
    h->nf5.flows = 0;
    h->nf5.uptime_ms = htonl (systemInitTimeMilliseconds);
    h->nf5.time_sec = htonl ((u_int32_t) now.tv_sec);
    h->nf5.time_nanosec =
      htonl ((u_int32_t) now.tv_usec * 1000);
    if (version == 1)
      return NF1_HEADER_SIZE;
    h->nf5.flow_sequence = 0;
    h->nf5.engine_type = 0;
    h->nf5.engine_id = 0;
    if (param->option.sample > 0) {
      u_int16_t sampling_interval_raw = (0x01 << 14) | (param->option.sample & 0x3FFF);
      h->nf5.sampling_interval = htons (sampling_interval_raw);
    } else {
      h->nf5.sampling_interval = 0;
    }
    return sizeof (h->nf5);
  case 9:
    h->nf9.flows = 0;
    h->nf9.uptime_ms = htonl (systemInitTimeMilliseconds);
    h->nf9.export_time = htonl ((u_int32_t) now.tv_sec);
    h->nf9.sequence = 0;
    h->nf9.od_id = 0;
    return sizeof (h->nf9);
  default:                     /* 10 = IPFIX */
    h->ipfix.length = 0;
    h->ipfix.export_time = htonl ((u_int32_t) (param->adjust_time ? now.tv_sec : time (NULL)));
    h->ipfix.sequence = 0;
    h->ipfix.od_id = 0;
    return sizeof (h->ipfix);
  }
}

/* ------------------------------------------------------------------ */
/* NetFlow v1 / v5: fixed (non-templated) export.                      */
/* ------------------------------------------------------------------ */

#define IPFIX_UNIFIED_NF1_MAXFLOWS 24
#define IPFIX_UNIFIED_NF5_MAXFLOWS 30
/* 24 = worst-case (v5) header length: sizeof(struct NF5_HEADER). */
#define IPFIX_UNIFIED_FIXED_MAXPACKET_SIZE (24 + IPFIX_UNIFIED_NF5_MAXFLOWS * 48)

/* Shared engine for NF1/NF5 fixed formats using 48-octet data records,
 * leveraging the same field-list logic as the v9/IPFIX templated exporter. */
static int
send_ipfix_unified_fixed (struct SENDPARAMETER sp, u_int16_t version) {
  struct FLOW **flows = sp.flows;
  int num_flows = sp.num_flows;
  struct FLOWTRACKPARAMETERS *param = sp.param;
  int verbose_flag = sp.verbose_flag;
  u_char packet[IPFIX_UNIFIED_FIXED_MAXPACKET_SIZE];
  const struct IPFIX_FIELD_SPECIFIER_ENCODER *tail_fields =
    (version == 1) ? field_netflowv1_tail_enc : field_netflowv5_tail_enc;
  u_int tail_nfields =
    (version == 1) ? IPFIX_UNIFIED_NFIELDS_ENC (field_netflowv1_tail_enc) :
    IPFIX_UNIFIED_NFIELDS_ENC (field_netflowv5_tail_enc);
  u_int maxflows =
    (version == 1) ? IPFIX_UNIFIED_NF1_MAXFLOWS : IPFIX_UNIFIED_NF5_MAXFLOWS;
  u_int offset, j, i, k, num_packets, flowcount;
  u_int64_t *flows_exported = &param->flows_exported;
  struct IPFIX_UNIFIED_CTX ctx = { .sp = &sp, .flow = NULL, .i = 0 };

  if (version != 1 && version != 5)
    return (-1);

  num_packets = offset = j = flowcount = 0;
  for (i = 0; i < (u_int) num_flows; i++) {
    if (j >= maxflows) {
      if (verbose_flag)
        logit (LOG_DEBUG, "Sending flow packet len = %d", offset);
      param->records_sent += flowcount;
      ((union IPFIX_UNIFIED_HEADER *) packet)->nf5.flows = htons (flowcount);
      if (send_multi_destinations
          (sp.target->num_destinations, sp.target->destinations,
           sp.target->is_loadbalance, packet, offset) < 0)
        return (-1);
      *flows_exported += j;
      j = 0;
      flowcount = 0;
      num_packets++;
    }
    if (j == 0) {
      memset (packet, 0, sizeof (packet));
      offset = ipfix_unified_build_header (packet, version, param);
      if (version == 5)
        ((union IPFIX_UNIFIED_HEADER *) packet)->nf5.flow_sequence =
          htonl ((u_int32_t) * flows_exported);
    }

    /* NetFlow v1/v5 carry IPv4 only, as in the original implementation. */
    if (flows[i]->af != AF_INET)
      continue;

    for (k = 0; k < 2; k++) {
      if (flows[i]->octets[k] == 0)
        continue;
      if (j >= maxflows) {
        /* out of space in this packet; flush and retry this record */
        i--;
        break;
      }
      ctx.flow = flows[i];
      ctx.i = k;
      offset = ipfix_unified_emit_group_enc (field_netflow_v1v5_common_enc,
                                             IPFIX_UNIFIED_NFIELDS_ENC
                                             (field_netflow_v1v5_common_enc),
                                             packet, offset, &ctx);
      offset =
        ipfix_unified_emit_group_enc (tail_fields, tail_nfields, packet,
                                      offset, &ctx);
      j++;
      flowcount++;
    }
  }

  if (j != 0) {
    if (verbose_flag)
      logit (LOG_DEBUG, "Sending flow packet len = %d", offset);
    param->records_sent += flowcount;
    ((union IPFIX_UNIFIED_HEADER *) packet)->nf5.flows = htons (flowcount);
    if (send_multi_destinations
        (sp.target->num_destinations, sp.target->destinations,
         sp.target->is_loadbalance, packet, offset) < 0)
      return (-1);
    *flows_exported += j;
    num_packets++;
  }

  param->packets_sent += num_packets;
#ifdef ENABLE_PTHREAD
  if (use_thread)
    free (sp.flows);
#endif /* ENABLE_PTHREAD */
  return (num_packets);
}

int
send_netflow_v1_unified (struct SENDPARAMETER sp) {
  return send_ipfix_unified_fixed (sp, 1);
}

int
send_netflow_v5_unified (struct SENDPARAMETER sp) {
  return send_ipfix_unified_fixed (sp, 5);
}

/* ------------------------------------------------------------------ */
/* NetFlow v9 / IPFIX: templated export.                                */
/* ------------------------------------------------------------------ */

#define IPFIX_UNIFIED_MAXFIELDS  32
#define IPFIX_UNIFIED_MAXBIFIELDS 8

struct IPFIX_UNIFIED_TEMPLATE {
  struct IPFIX_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER r[IPFIX_UNIFIED_MAXFIELDS];
  struct IPFIX_VENDOR_FIELD_SPECIFIER v[IPFIX_UNIFIED_MAXBIFIELDS];
  struct IPFIX_FIELD_SPECIFIER_ENCODER hr[IPFIX_UNIFIED_MAXFIELDS];     /* per-record encoders */
  u_int hr_count;
  struct IPFIX_FIELD_SPECIFIER_ENCODER hbi[IPFIX_UNIFIED_MAXBIFIELDS];
  u_int hbi_count;
  u_int16_t data_len, bi_count;
};

static struct IPFIX_UNIFIED_TEMPLATE unified_templates[TMPLMAX];
static int unified_pkts_until_template = -1;

/* Emits NFv9/IPFIX Options Templates and Data Records using ipfix_unified_emit_field().
 * Reuses struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE to avoid duplicate padded declarations. */
struct IPFIX_UNIFIED_OPTION_TEMPLATE {
  struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE tmpl;
  /* Host-order copies for the Data Record -- see IPFIX_UNIFIED_TEMPLATE.hr[]. */
  struct IPFIX_FIELD_SPECIFIER_ENCODER
    hs[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS];
  u_int hs_count;
  struct IPFIX_FIELD_SPECIFIER_ENCODER hr[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];
  u_int hr_count;
  u_int16_t total_len;          /* bytes of tmpl.h+s+r actually in use */
};

static struct IPFIX_UNIFIED_OPTION_TEMPLATE unified_option_template;
static int unified_option_initialized = 0;

static void
ipfix_unified_init_option (u_int16_t version) {
  const struct IPFIX_FIELD_SPECIFIER_ENCODER *scope_src, *opt_src;
  u_int scope_n, opt_n, i, scope_speclen, opt_speclen;

  memset (&unified_option_template, 0, sizeof (unified_option_template));
  if (version == 10) {
    scope_src = field_scope_enc;
    scope_n = IPFIX_UNIFIED_NFIELDS_ENC (field_scope_enc);
    opt_src = field_option_enc;
    opt_n = IPFIX_UNIFIED_NFIELDS_ENC (field_option_enc);
  } else {
    scope_src = field_nf9scope_enc;
    scope_n = IPFIX_UNIFIED_NFIELDS_ENC (field_nf9scope_enc);
    opt_src = field_nf9option_enc;
    opt_n = IPFIX_UNIFIED_NFIELDS_ENC (field_nf9option_enc);
  }

  for (i = 0; i < scope_n; i++) {
    unified_option_template.tmpl.s[i].ie = htons (scope_src[i].field.ie);
    unified_option_template.tmpl.s[i].length = htons (scope_src[i].field.length);
    unified_option_template.hs[i] = scope_src[i];
  }
  unified_option_template.hs_count = scope_n;
  for (i = 0; i < opt_n; i++) {
    unified_option_template.tmpl.r[i].ie = htons (opt_src[i].field.ie);
    unified_option_template.tmpl.r[i].length = htons (opt_src[i].field.length);
    unified_option_template.hr[i] = opt_src[i];
  }
  unified_option_template.hr_count = opt_n;

  /* scope_speclen/opt_speclen: byte length of the field-specifier
   * lists themselves (4 octets/entry), not of the data they describe. */
  scope_speclen = scope_n * sizeof (struct IPFIX_FIELD_SPECIFIER);
  opt_speclen = opt_n * sizeof (struct IPFIX_FIELD_SPECIFIER);

  unified_option_template.tmpl.h.c.set_id =
    htons (version == 10 ? IPFIX_OPTION_TEMPLATE_SET_ID :
           NFLOW9_OPTION_TEMPLATE_SET_ID);
  unified_option_template.tmpl.h.c.length =
    htons (sizeof (unified_option_template.tmpl.h) + scope_speclen +
           opt_speclen);
  if (version == 10) {
    unified_option_template.tmpl.h.u.i.r.template_id =
      htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    unified_option_template.tmpl.h.u.i.r.count = htons (scope_n + opt_n);
    unified_option_template.tmpl.h.u.i.scope_count = htons (scope_n);
  } else {
    unified_option_template.tmpl.h.u.n.template_id =
      htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    unified_option_template.tmpl.h.u.n.scope_length = htons (scope_speclen);
    unified_option_template.tmpl.h.u.n.option_length = htons (opt_speclen);
  }
  unified_option_template.total_len =
    sizeof (unified_option_template.tmpl.h) + scope_speclen + opt_speclen;
  unified_option_initialized = 1;
}

/* Appends Options Template Set and Data Record at '*offset', advancing it.
 * Data Records are output via ipfix_unified_emit_field() like standard records. */
static void
ipfix_unified_send_option (u_char *packet, u_int *offset, u_int16_t version,
                           const struct SENDPARAMETER *sp) {
  struct IPFIX_SET_HEADER *c;
  u_int doff;
  u_int scope_speclen, opt_speclen;

  if (!unified_option_initialized)
    ipfix_unified_init_option (version);

  /* Copies template header, s[], and r[] in 3 separate blocks to skip unused tail
   * bytes caused by IPFIX's max-sized field array backing in unified_option_template. */
  scope_speclen =
    unified_option_template.hs_count * sizeof (struct IPFIX_FIELD_SPECIFIER);
  opt_speclen =
    unified_option_template.hr_count * sizeof (struct IPFIX_FIELD_SPECIFIER);
  memcpy (packet + *offset, &unified_option_template.tmpl.h,
          sizeof (unified_option_template.tmpl.h));
  *offset += sizeof (unified_option_template.tmpl.h);
  memcpy (packet + *offset, unified_option_template.tmpl.s, scope_speclen);
  *offset += scope_speclen;
  memcpy (packet + *offset, unified_option_template.tmpl.r, opt_speclen);
  *offset += opt_speclen;

  c = (struct IPFIX_SET_HEADER *) (packet + *offset);
  doff = sizeof (*c);
  struct IPFIX_UNIFIED_CTX ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.sp = sp;
  doff = ipfix_unified_emit_group_enc (unified_option_template.hs,
                                       unified_option_template.hs_count,
                                       packet + *offset, doff, &ctx);
  doff = ipfix_unified_emit_group_enc (unified_option_template.hr,
                                       unified_option_template.hr_count,
                                       packet + *offset, doff, &ctx);
  c->set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  c->length = htons (doff);
  *offset += doff;
}

static u_int
ipfix_unified_init_fields (struct IPFIX_UNIFIED_TEMPLATE *tmpl, u_int *index,
                           const struct IPFIX_FIELD_SPECIFIER_ENCODER *src,
                           u_int field_number) {
  u_int i, length = 0;
  for (i = 0; i < field_number && *index + i < IPFIX_UNIFIED_MAXFIELDS; i++) {
    tmpl->r[*index + i].ie = htons (src[i].field.ie);
    tmpl->r[*index + i].length = htons (src[i].field.length);
    tmpl->hr[*index + i] = src[i];
    length += src[i].field.length;
  }
  tmpl->hr_count = *index + i;
  *index += i;
  return length;
}

static u_int
ipfix_unified_init_bifields (struct IPFIX_UNIFIED_TEMPLATE *tmpl,
                             u_int *index,
                             const struct IPFIX_FIELD_SPECIFIER_ENCODER *src,
                             u_int field_number) {
  u_int i, length = 0;
  for (i = 0; i < field_number && *index + i < IPFIX_UNIFIED_MAXBIFIELDS; i++) {
    tmpl->v[*index + i].ie = htons (src[i].field.ie | 0x8000);
    tmpl->v[*index + i].length = htons (src[i].field.length);
    tmpl->v[*index + i].pen = htonl (REVERSE_PEN);
    tmpl->hbi[*index + i] = src[i];
    length += src[i].field.length;
  }
  tmpl->hbi_count = *index + i;
  *index += i;
  return length;
}

static u_int
ipfix_unified_init_template_time (struct FLOWTRACKPARAMETERS *param,
                                  struct IPFIX_UNIFIED_TEMPLATE *tmpl,
                                  u_int *index, u_int16_t version) {
  /* Absolute (calendar) timestamps are IPFIX-only
   * NetFlow v9 always uses the relative sysUpTime form. */
  if (version == 10 && param->time_format == 's')
    return ipfix_unified_init_fields (tmpl, index, field_timesec_enc, 2);
  if (version == 10 && param->time_format == 'm')
    return ipfix_unified_init_fields (tmpl, index, field_timemsec_enc, 2);
  if (version == 10 && param->time_format == 'M')
    return ipfix_unified_init_fields (tmpl, index, field_timeusec_enc, 2);
  if (version == 10 && param->time_format == 'n')
    return ipfix_unified_init_fields (tmpl, index, field_timensec_enc, 2);
  return ipfix_unified_init_fields (tmpl, index, field_timesysup_enc, 2);
}

static void
ipfix_unified_init_template_unity (struct FLOWTRACKPARAMETERS *param,
                                   struct IPFIX_UNIFIED_TEMPLATE *tmpl,
                                   u_int template_id, u_int8_t v6_flag,
                                   u_int8_t icmp_flag, u_int8_t bi_flag,
                                   u_int16_t version) {
  u_int index = 0, bi_index = 0, length = 0;
  memset (tmpl, 0, sizeof (*tmpl));
  tmpl->h.c.set_id = htons (version == 10 ?
                            IPFIX_TEMPLATE_SET_ID : NFLOW9_TEMPLATE_SET_ID);
  tmpl->h.r.template_id = htons (template_id);

  if (v6_flag)
    length += ipfix_unified_init_fields (tmpl, &index, field_v6_enc,
                                         IPFIX_UNIFIED_NFIELDS_ENC
                                         (field_v6_enc));
  else
    length += ipfix_unified_init_fields (tmpl, &index, field_v4_enc,
                                         IPFIX_UNIFIED_NFIELDS_ENC
                                         (field_v4_enc));
  length += ipfix_unified_init_template_time (param, tmpl, &index, version);
  length += ipfix_unified_init_fields (tmpl, &index, field_common_enc,
                                       IPFIX_UNIFIED_NFIELDS_ENC
                                       (field_common_enc));
  if (icmp_flag) {
    if (v6_flag)
      length += ipfix_unified_init_fields (tmpl, &index, field_icmp6_enc,
                                           IPFIX_UNIFIED_NFIELDS_ENC
                                           (field_icmp6_enc));
    else
      length += ipfix_unified_init_fields (tmpl, &index, field_icmp4_enc,
                                           IPFIX_UNIFIED_NFIELDS_ENC
                                           (field_icmp4_enc));
  } else {
    length += ipfix_unified_init_fields (tmpl, &index, field_transport_enc,
                                         IPFIX_UNIFIED_NFIELDS_ENC
                                         (field_transport_enc));
  }
  if (param->track_level >= TRACK_FULL_VLAN)
    length += ipfix_unified_init_fields (tmpl, &index, field_vlan_enc,
                                         IPFIX_UNIFIED_NFIELDS_ENC
                                         (field_vlan_enc));
  if (param->track_level >= TRACK_FULL_VLAN_ETHER)
    length += ipfix_unified_init_fields (tmpl, &index, field_ether_enc,
                                         IPFIX_UNIFIED_NFIELDS_ENC
                                         (field_ether_enc));
  if (bi_flag && version == 10) {
    length +=
      ipfix_unified_init_bifields (tmpl, &bi_index, field_bicommon_enc,
                                   IPFIX_UNIFIED_NFIELDS_ENC
                                   (field_bicommon_enc));
    if (icmp_flag) {
      if (v6_flag)
        length +=
          ipfix_unified_init_bifields (tmpl, &bi_index, field_biicmp6_enc,
                                       IPFIX_UNIFIED_NFIELDS_ENC
                                       (field_biicmp6_enc));
      else
        length +=
          ipfix_unified_init_bifields (tmpl, &bi_index, field_biicmp4_enc,
                                       IPFIX_UNIFIED_NFIELDS_ENC
                                       (field_biicmp4_enc));
    } else {
      length +=
        ipfix_unified_init_bifields (tmpl, &bi_index, field_bitransport_enc,
                                     IPFIX_UNIFIED_NFIELDS_ENC
                                     (field_bitransport_enc));
    }
  }
  tmpl->bi_count = bi_index;
  tmpl->h.r.count = htons (index + bi_index + param->max_num_label);
  tmpl->h.c.length =
    htons (sizeof (struct IPFIX_TEMPLATE_SET_HEADER) +
           index * sizeof (struct IPFIX_FIELD_SPECIFIER) +
           bi_index * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) +
           param->max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER));
  tmpl->data_len =
    length + param->max_num_label * IPFIX_mplsLabelStackSection_SIZE;
}

static void
ipfix_unified_init_templates (struct FLOWTRACKPARAMETERS *param,
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
    ipfix_unified_init_template_unity (param, &unified_templates[i],
                                       template_id, v6_flag, icmp_flag,
                                       bi_flag, version);
  }
}

/* flow_to_template_index() uses ipfix_flow_to_template_index(). */
static int
ipfix_unified_valuate_icmp (const struct FLOW *flow) {
  if (flow->af == AF_INET)
    return flow->protocol == IPPROTO_ICMP;
  if (flow->af == AF_INET6)
    return flow->protocol == IPPROTO_ICMPV6;
  return 0;
}

/* flowDirection uses ipfix_flow_direction(). */

static void
ipfix_unified_memcpy_template (u_char *packet, u_int *offset,
                               struct IPFIX_UNIFIED_TEMPLATE *tmpl,
                               u_int8_t bi_flag, u_int8_t max_num_label) {
  u_int i, size =
    ntohs (tmpl->h.c.length) -
    tmpl->bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) -
    max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER);
  memcpy (packet + *offset, tmpl, size);
  *offset += size;
  if (bi_flag) {
    size = tmpl->bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER);
    memcpy (packet + *offset, tmpl->v, size);
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

/* Encodes standard or biflow data records using the template's field list;
 * templated counterpart to send_ipfix_unified_fixed()'s record loop. */
static int
ipfix_unified_flow_to_flowset (const struct FLOW *flow, u_char *packet,
                               u_int len, const struct SENDPARAMETER *sp,
                               u_int *len_used,
                               u_int8_t bi_flag, u_int16_t version) {
  u_int tmplindex = ipfix_flow_to_template_index (flow);
  struct IPFIX_UNIFIED_TEMPLATE *tmpl = &unified_templates[tmplindex];
  u_int offset = 0, nflows = 0, k;
  u_int frecnum = bi_flag ? 1 : 2;
  struct IPFIX_UNIFIED_CTX ctx = {  .sp = sp, .flow = flow, .i = 0 };

  (void) version;               /* only used to size frecnum via bi_flag */
  if (len < tmpl->data_len * frecnum)
    return (-1);

  for (ctx.i = 0; ctx.i < frecnum; ctx.i++) {
    if (bi_flag == 0 && flow->octets[ctx.i] == 0)
      continue;
    nflows++;
    offset =
      ipfix_unified_emit_group_enc (tmpl->hr, tmpl->hr_count, packet, offset,
                                    &ctx);
    if (bi_flag && ctx.i == 0) {
      struct IPFIX_UNIFIED_CTX bictx = ctx;
      bictx.i = 1;              /* reverse direction */
      offset =
        ipfix_unified_emit_group_enc (tmpl->hbi, tmpl->hbi_count, packet,
                                      offset, &bictx);
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

void
ipfix_resend_template (void) {
  if (unified_pkts_until_template > 0)
    unified_pkts_until_template = 0;
}

/* Packet-framing loop for NFv9/IPFIX templates, mirroring send_ipfix_common()
 * but emitting records via field lists in ipfix_unified_flow_to_flowset(). */
static int
send_ipfix_unified_templated (struct SENDPARAMETER sp, u_int8_t bi_flag,
                              u_int16_t version) {
  struct FLOW **flows = sp.flows;
  int num_flows = sp.num_flows;
  struct NETFLOW_TARGET *target = sp.target;
  struct FLOWTRACKPARAMETERS *param = sp.param;
  int verbose_flag = sp.verbose_flag;
  struct IPFIX_SET_HEADER *dh;
  union IPFIX_UNIFIED_HEADER *h;
  struct timeval now;
  u_int offset, last_af, i, j, num_packets, inc, last_valid, tmplindex;
  int8_t icmp_flag, last_icmp_flag;
  int r;
  u_int records = 0;
  u_char packet[IPFIX_SOFTFLOWD_MAX_PACKET_SIZE];
  u_int64_t *flows_exported = &param->flows_exported;
  u_int64_t *records_sent = &param->records_sent;
  static u_int sequence = 1;

  if (version != 9 && version != 10)
    return (-1);
  if (param->adjust_time)
    now = param->last_packet_time;
  else
    gettimeofday (&now, NULL);

  if (unified_pkts_until_template == -1) {
    ipfix_unified_init_templates (param, bi_flag, version);
    ipfix_unified_init_option (version);
    unified_pkts_until_template = 0;
  }

  last_valid = num_packets = 0;
  for (j = 0; j < (u_int) num_flows;) {
    memset (packet, 0, sizeof (packet));
    offset = ipfix_unified_build_header (packet, version, param);
    h = (union IPFIX_UNIFIED_HEADER *) packet;

    if (unified_pkts_until_template <= 0) {
      for (i = 0; i < TMPLMAX; i++)
        ipfix_unified_memcpy_template (packet, &offset, &unified_templates[i],
                                       bi_flag, param->max_num_label);
      ipfix_unified_send_option (packet, &offset, version, &sp);
      unified_pkts_until_template = IPFIX_DEFAULT_TEMPLATE_INTERVAL;
      if (target->is_loadbalance && target->num_destinations > 1) {
          /* Template-only packet; NFv9 sets flows count to 1 (preserving
           * 'nf9->flows = htons(++records)' behavior in ipfix.c). */
          if (version == 10) {
          h->ipfix.length = htons (offset);
          h->ipfix.sequence =
            htonl ((u_int32_t) (*records_sent & 0x00000000ffffffff));
        } else {
          h->nf9.flows = htons (1);
          h->nf9.sequence = htonl (sequence++);
        }
        if (send_multi_destinations
            (target->num_destinations, target->destinations, 0, packet,
             offset) < 0)
          return (-1);
        offset = ipfix_unified_build_header (packet, version, param);
      }
    }

    dh = NULL;
    last_af = 0;
    last_icmp_flag = -1;
    records = 0;
    for (i = 0; i + j < (u_int) num_flows; i++) {
      icmp_flag = ipfix_unified_valuate_icmp (flows[i + j]);
      if (dh == NULL || flows[i + j]->af != last_af ||
          icmp_flag != last_icmp_flag) {
        if (dh != NULL) {
          if (offset % 4 != 0) {
            dh->length += 4 - (offset % 4);
            offset += 4 - (offset % 4);
          }
          dh->length = htons (dh->length);
        }
        if (offset + sizeof (*dh) > sizeof (packet)) {
          dh = NULL;
          break;
        }
        dh = (struct IPFIX_SET_HEADER *) (packet + offset);
        tmplindex = ipfix_flow_to_template_index (flows[i + j]);
        dh->set_id = unified_templates[tmplindex].h.r.template_id;
        last_af = flows[i + j]->af;
        last_icmp_flag = icmp_flag;
        last_valid = offset;
        dh->length = sizeof (*dh);
        offset += sizeof (*dh);
      }
      r = ipfix_unified_flow_to_flowset (flows[i + j], packet + offset,
                                         sizeof (packet) - offset, &sp,
                                         &inc, bi_flag, version);
      if (r <= 0) {
        if (last_valid)
          offset = last_valid;
        break;
      }
      records += (u_int) r;
      offset += inc;
      dh->length += inc;
      last_valid = 0;
      if (verbose_flag)
        logit (LOG_DEBUG, "Flow %d/%d: r %d offset %d ie %04x len %d(0x%04x)",
               r, i, j, offset, dh->set_id, dh->length, dh->length);
    }
    if (dh != NULL) {
      if (offset % 4 != 0) {
        dh->length += 4 - (offset % 4);
        offset += 4 - (offset % 4);
      }
      dh->length = htons (dh->length);
    }
    *records_sent += records;
    if (version == 10) {
      h->ipfix.length = htons (offset);
      h->ipfix.sequence =
        htonl ((u_int32_t) (*records_sent & 0x00000000ffffffff));
    } else {
      h->nf9.flows = htons (records);
      h->nf9.sequence = htonl (sequence++);
    }

    if (verbose_flag)
      logit (LOG_DEBUG, "Sending flow packet len = %d", offset);
    if (send_multi_destinations
        (target->num_destinations, target->destinations,
         target->is_loadbalance, packet, offset) < 0)
      return (-1);
    num_packets++;
    unified_pkts_until_template--;

    j += i;
  }

  *flows_exported += j;
  param->packets_sent += num_packets;
#ifdef ENABLE_PTHREAD
  if (use_thread)
    free (flows);
#endif /* ENABLE_PTHREAD */
  return (num_packets);
}

int
send_nflow9_unified (struct SENDPARAMETER sp) {
  return send_ipfix_unified_templated (sp, 0, 9);
}

int
send_ipfix_unified (struct SENDPARAMETER sp) {
  return send_ipfix_unified_templated (sp, 0, 10);
}

int
send_ipfix_bi_unified (struct SENDPARAMETER sp) {
  return send_ipfix_unified_templated (sp, 1, 10);
}

#endif /* ENABLE_UNIFIED_EXPORT_TYPE == ENABLE_UNIFIED_EXPORT_TYPE_FULL */
