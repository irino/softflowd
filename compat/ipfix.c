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
#include "common.h"
#include "log.h"
#include "netflow.h"
#include "psamp.h"
#include "softflowd.h"
#include "treetype.h"

#include "ipfix_fields.h"

/* COMPAT_EXPORT (static or static-separate): Encodes the data records with
 * fixed templates and the static send path. */

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
  } __packed u32;
  struct {
    u_int64_t start;
    u_int64_t end;
  } __packed u64;
} __packed;

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

struct NETFLOW9_SOFTFLOWD_OPTION_DATA {
  struct IPFIX_SET_HEADER c;
  u_int32_t scope_ifidx;
  u_int32_t samplingInterval;
  u_int8_t samplingAlgorithm;
  char interfaceName[IFNAMSIZ];
} __packed;

/* Local data: templates and counters */

// prototype
void
memcpy_template (u_char *packet, u_int *offset,
                 struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                 u_int8_t bi_flag, u_int8_t max_num_label);

// variables
/** Templates indexed by TMPLV4, TMPLICMPV4, TMPLV6 and TMPLICMPV6. */
static struct IPFIX_SOFTFLOWD_TEMPLATE templates[TMPLMAX];
/** IPFIX options template. */
static struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE option_template;
/** IPFIX options data record. */
static struct IPFIX_SOFTFLOWD_OPTION_DATA option_data;
/** NetFlow v9 options data record. */
static struct NETFLOW9_SOFTFLOWD_OPTION_DATA nf9opt_data;

/**
 * @brief Add reverse-direction (enterprise) fields to a template.
 *
 * @param template     Template to extend.
 * @param index        Position to start at; advanced.
 * @param fields       Field table (host byte order).
 * @param field_number Number of fields to add.
 * @return Sum of the lengths of the added fields.
 */
static int
ipfix_init_bifields (struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                     u_int *index,
                     const struct IPFIX_FIELD_SPECIFIER *fields,
                     u_int field_number) {
  int length = 0;
  u_int i;
  for (i = 0; i < field_number; i++) {
    template->v[*index + i].ie = htons (fields[i].ie | 0x8000);
    template->v[*index + i].length = htons (fields[i].length);
    template->v[*index + i].pen = htonl (REVERSE_PEN);
    length += fields[i].length;
  }
  *index += field_number;
  return length;
}

/**
 * @brief Add the flow start/end time fields chosen by the time format option
 * (-A).
 *
 * @param param    Tracking parameters (time_format).
 * @param template Template to extend.
 * @param index    Position to start at; advanced.
 * @return Sum of the lengths of the added fields.
 */
static int
ipfix_init_template_time (struct FLOWTRACKPARAMETERS *param,
                          struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                          u_int *index) {
  int length = 0;
  if (param->time_format == 's') {
    length = ipfix_init_fields (template->r, index, field_timesec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else if (param->time_format == 'm') {
    length = ipfix_init_fields (template->r, index, field_timemsec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else if (param->time_format == 'M') {
    length = ipfix_init_fields (template->r, index, field_timeusec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else if (param->time_format == 'n') {
    length = ipfix_init_fields (template->r, index, field_timensec,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  } else {
    length = ipfix_init_fields (template->r, index, field_timesysup,
                                IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
  }
  return length;
}

/**
 * @brief Build one complete IPFIX/NetFlow v9 template.
 *
 * @param param       Tracking parameters.
 * @param template    Template to build.
 * @param template_id Template id.
 * @param v6_flag     Non-zero for IPv6.
 * @param icmp_flag   Non-zero for the ICMP variant.
 * @param bi_flag     IPFIX_BIFLAG_ON for biflow.
 * @param version     Export version.
 */
static void
ipfix_init_template_unity (struct FLOWTRACKPARAMETERS *param,
                           struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                           u_int template_id, u_int8_t v6_flag,
                           u_int8_t icmp_flag, u_int8_t bi_flag,
                           u_int16_t version) {
  u_int index = 0, bi_index = 0, length = 0;
  memset (template, 0, sizeof (*template));
  template->h.c.set_id =
    htons (version == 10 ? IPFIX_TEMPLATE_SET_ID : NETFLOW9_TEMPLATE_SET_ID);
  template->h.r.template_id = htons (template_id);
  if (v6_flag) {
    length += ipfix_init_fields (template->r, &index, field_v6,
                                 IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS);
  } else {
    length += ipfix_init_fields (template->r, &index, field_v4,
                                 IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS);
  }
  length += ipfix_init_template_time (param, template, &index);
  length += ipfix_init_fields (template->r, &index, field_common,
                               IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS);
  if (icmp_flag) {
    if (v6_flag) {
      length += ipfix_init_fields (template->r, &index, field_icmp6,
                                   IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS);
    } else {
      length += ipfix_init_fields (template->r, &index, field_icmp4,
                                   IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS);
    }
  } else {
    length += ipfix_init_fields (template->r, &index, field_transport,
                                 IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS);
  }
  if (param->track_level >= TRACK_FULL_VLAN) {
    length += ipfix_init_fields (template->r, &index, field_vlan,
                                 IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS);
  }
  if (param->track_level >= TRACK_FULL_VLAN_ETHER) {
    length += ipfix_init_fields (template->r, &index, field_ether,
                                 IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS);
  }
  if (bi_flag) {
    length += ipfix_init_bifields (template, &bi_index, field_bicommon,
                                   IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS);
    if (icmp_flag) {
      if (v6_flag) {
        length += ipfix_init_bifields (template, &bi_index, field_biicmp6,
                                       IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS);
      } else {
        length += ipfix_init_bifields (template, &bi_index, field_biicmp4,
                                       IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS);
      }
    } else {
      length +=
        ipfix_init_bifields (template, &bi_index, field_bitransport,
                             IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS);
    }
  }
  template->bi_count = bi_index;
  template->h.r.count = htons (index + bi_index + param->max_num_label);  // mpls
  template->h.c.length =
    htons (sizeof (struct IPFIX_TEMPLATE_SET_HEADER) +
           index * sizeof (struct IPFIX_FIELD_SPECIFIER) +
           bi_index * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) +
           param->max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER));
  template->data_len =
    length + param->max_num_label *IPFIX_mplsLabelStackSection_SIZE;
}

/**
 * @brief Build the IPv4, ICMPv4, IPv6 and ICMPv6 templates into templates[].
 *
 * @param param   Tracking parameters.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow.
 * @param version Export version: 9 or 10.
 */
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
    ipfix_init_template_unity (param, &templates[i], template_id, v6_flag,
                               icmp_flag, bi_flag, version);
  }
}

/**
 * @brief Build the NetFlow v9 options template and data record (nf9opt_data).
 *
 * @param ifidx  Interface index used as the option scope.
 * @param option Optional information; the sampling interval is taken from here.
 */
static void
nflow9_init_option (u_int16_t ifidx, struct OPTION *option) {
  u_int scope_index = 0, option_index = 0;
  u_int16_t scope_len = NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS *
                        sizeof (struct IPFIX_FIELD_SPECIFIER);
  u_int16_t opt_len = NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS *
                      sizeof (struct IPFIX_FIELD_SPECIFIER);

  memset (&option_template, 0, sizeof (option_template));
  option_template.h.c.set_id = htons (NETFLOW9_OPTION_TEMPLATE_SET_ID);
  option_template.h.c.length =
    htons (sizeof (option_template.h) + scope_len + opt_len);
  option_template.h.u.n.template_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  option_template.h.u.n.scope_length = htons (scope_len);
  option_template.h.u.n.option_length = htons (opt_len);
  ipfix_init_fields (option_template.s, &scope_index, field_nf9scope,
                     NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS);
  ipfix_init_fields (option_template.r, &option_index, field_nf9option,
                     NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS);
  memset (&nf9opt_data, 0, sizeof (nf9opt_data));
  nf9opt_data.c.set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  nf9opt_data.c.length = htons (sizeof (nf9opt_data));
  nf9opt_data.scope_ifidx = htonl (ifidx);
  nf9opt_data.samplingInterval = htonl (option->sample > 1 ? option->sample : 1);
  nf9opt_data.samplingAlgorithm = IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC;
  strlcpy (nf9opt_data.interfaceName, option->interfaceName,
           sizeof (nf9opt_data.interfaceName));
}

/**
 * @brief Build the IPFIX options template and data record.
 *
 * @param system_boot_time Boot time reported in the data record.
 * @param option           Optional information (sampling, process id, interface
 * name, exporter address).
 */
static void
ipfix_init_option (struct timeval *system_boot_time,
                   struct OPTION *option) {
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

  ipfix_init_fields (option_template.s, &scope_index, field_scope,
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
  strlcpy (option_data.interfaceName, option->interfaceName,
           sizeof (option_data.interfaceName));
  if (option->exporterAddr != NULL) {
    struct addrinfo *rp;
    for (rp = option->exporterAddr; rp != NULL; rp = rp->ai_next) {
      if (rp->ai_family == AF_INET) {
        memcpy (&option_data.exporterIPv4Address,
                &((struct sockaddr_in *) rp->ai_addr)->sin_addr,
                sizeof (option_data.exporterIPv4Address));
        memcpy (&option_data.originalExporterIPv4Address,
                &((struct sockaddr_in *) rp->ai_addr)->sin_addr,
                sizeof (option_data.originalExporterIPv4Address));
      } else if (rp->ai_family == AF_INET6) {
        memcpy (&option_data.exporterIPv6Address,
                &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr,
                sizeof (option_data.exporterIPv6Address));
        memcpy (&option_data.originalExporterIPv6Address,
                &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr,
                sizeof (option_data.originalExporterIPv6Address));
      }
    }
  }
}

/**
 * @brief Fill the time part of a data record according to the time format
 * option.
 *
 * @param dt               Record time fields to fill; -1 is returned if NULL.
 * @param flow             Flow whose start and end are stored.
 * @param system_boot_time Base for the relative (sysUpTime) form.
 * @param param            Tracking parameters (time_format).
 * @return Length of the time fields in octets (16 for the 64-bit forms,
 * otherwise 8), or -1 on error.
 */
static int
copy_data_time (union IPFIX_SOFTFLOWD_DATA_TIME *dt,
                const struct FLOW *flow,
                const struct timeval *system_boot_time,
                struct FLOWTRACKPARAMETERS *param) {
  int length = (param->time_format == 'm' || param->time_format == 'M' ||
                param->time_format == 'n')
                 ? 16
                 : 8;
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
      dt->u64.start = htobe64 ((u_int64_t) flow->flow_start.tv_sec * 1000 +
                               (u_int64_t) flow->flow_start.tv_usec / 1000);
      dt->u64.end = htobe64 ((u_int64_t) flow->flow_last.tv_sec * 1000 +
                             (u_int64_t) flow->flow_last.tv_usec / 1000);
      break;
    case 'M':
    case 'n':
      conv_unix_to_ntp ((struct timeval) flow->flow_start, &ntptime);
      dt->u64.start = htobe64 ((u_int64_t) ntptime.second << 32 | ntptime.fraction);
      conv_unix_to_ntp ((struct timeval) flow->flow_last, &ntptime);
      dt->u64.end = htobe64 ((u_int64_t) ntptime.second << 32 | ntptime.fraction);
      break;
#endif
    default:
      dt->u32.start = htonl (timeval_sub_ms (&flow->flow_start, system_boot_time));
      dt->u32.end = htonl (timeval_sub_ms (&flow->flow_last, system_boot_time));
      break;
  }
  return length;
}

/**
 * @brief Encode the data records of one flow (standard or biflow).
 *
 * @param flow     Flow to encode.
 * @param packet   Output buffer.
 * @param len      Space available in packet.
 * @param sp       Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @param len_used Receives the number of bytes written.
 * @param bi_flag  Non-zero to emit one biflow record instead of one per
 * direction.
 * @param version  Export version (not needed by this encoder).
 * @return Number of records written, or -1 on error.
 */
int
ipfix_flow_to_flowset (const struct FLOW *flow, u_char *packet,
                       u_int len, const struct SENDPARAMETER *sp,
                       u_int *len_used, u_int8_t bi_flag,
                       u_int16_t version) {
  u_int16_t ifidx = sp->ifidx;
  struct FLOWTRACKPARAMETERS *param = sp->param;
  const struct timeval *system_boot_time = &param->system_boot_time;
  (void) version;

  struct IPFIX_SOFTFLOWD_DATA_V4ADDR *d4[2] = {NULL, NULL};
  struct IPFIX_SOFTFLOWD_DATA_V6ADDR *d6[2] = {NULL, NULL};
  union IPFIX_SOFTFLOWD_DATA_TIME *dt[2] = {NULL, NULL};
  struct IPFIX_SOFTFLOWD_DATA_COMMON *dc[2] = {NULL, NULL};
  struct IPFIX_SOFTFLOWD_DATA_TRANSPORT *dtr[2] = {NULL, NULL};
  struct IPFIX_SOFTFLOWD_DATA_ICMP *di[2] = {NULL, NULL};
  struct IPFIX_SOFTFLOWD_DATA_VLAN *dv[2] = {NULL, NULL};
  struct IPFIX_SOFTFLOWD_DATA_ETHER *de[2] = {NULL, NULL};
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

  for (i = 0; i < (int) frecnum; i++) {
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
    strlcpy (dc[i]->interfaceName, option->interfaceName,
             sizeof (dc[i]->interfaceName));
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
        dbtr = (struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT *) &packet[offset];
        dbtr->tcpControlBits = flow->tcp_flags[1];
        offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT);
      } else {
        dbi = (struct IPFIX_SOFTFLOWD_DATA_BIICMP *) &packet[offset];
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

/**
 * @brief Append a template to a packet, including reverse fields and the MPLS
 * label fields.
 *
 * @param packet        Packet buffer.
 * @param offset        Offset to write at; advanced.
 * @param template      Template to copy.
 * @param bi_flag       Non-zero to append the reverse-direction fields.
 * @param max_num_label Number of MPLS label fields to append.
 */
void
memcpy_template (u_char *packet, u_int *offset,
                 struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                 u_int8_t bi_flag, u_int8_t max_num_label) {
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
  struct FLOWTRACKPARAMETERS *param = sp->param;

  ipfix_init_template (param, bi_flag, version);
  if (version == 10)
    ipfix_init_option (&param->system_boot_time, &param->option);
  else
    nflow9_init_option (sp->ifidx, &param->option);
}

/**
 * @brief Append the templates and the option record to a packet.
 *
 * @param packet  Packet buffer.
 * @param offset  Offset in the packet to append at; updated.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow export.
 * @param version Export version: 9 or 10.
 * @param sp      Send parameters; the maximum number of labels is taken from
 * sp->param.
 */
void
ipfix_put_templates (u_char *packet, u_int *offset, u_int8_t bi_flag,
                     u_int16_t version,
                     const struct SENDPARAMETER *sp) {
  u_int16_t opt_tmpl_len = ntohs (option_template.h.c.length);
  u_int i;

  for (i = 0; i < TMPLMAX; i++)
    memcpy_template (packet, offset, &templates[i], bi_flag,
                     sp->param->max_num_label);
  memcpy (packet + *offset, &option_template, opt_tmpl_len);
  *offset += opt_tmpl_len;
  if (version == 10) {
    memcpy (packet + *offset, &option_data, sizeof (option_data));
    *offset += sizeof (option_data);
  } else if (version == 9) {
    memcpy (packet + *offset, &nf9opt_data, sizeof (nf9opt_data));
    *offset += sizeof (nf9opt_data);
  }
}

/**
 * @brief Set ID of the data set that uses a template.
 *
 * @param tmplindex TMPLV4, TMPLICMPV4, TMPLV6 or TMPLICMPV6.
 * @return Template ID in network byte order.
 */
u_int16_t
ipfix_template_set_id (u_int tmplindex) {
  return templates[tmplindex].h.r.template_id;
}
