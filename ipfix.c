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

#if defined (HAVE_DECL_HTONLL) && !defined (HAVE_DECL_HTOBE64)
#define htobe64     htonll
#endif
#define JAN_1970    2208988800UL    /* 1970 - 1900 in seconds */

/* IPFIX a.k.a. Netflow v.10 */
struct IPFIX_HEADER
{
    u_int16_t version, length;
    u_int32_t export_time;      /* in seconds */
    u_int32_t sequence, od_id;
} __packed;
struct NFLOW9_HEADER
{
    u_int16_t version, flows;
    u_int32_t uptime_ms;
    u_int32_t export_time;      /* in seconds */
    u_int32_t sequence, od_id;
} __packed;
struct IPFIX_SET_HEADER
{
    u_int16_t set_id, length;
} __packed;
struct IPFIX_TEMPLATE_RECORD_HEADER
{
    u_int16_t template_id, count;
} __packed;
struct IPFIX_TEMPLATE_SET_HEADER
{
    struct IPFIX_SET_HEADER c;
    struct IPFIX_TEMPLATE_RECORD_HEADER r;
} __packed;
struct IPFIX_OPTION_TEMPLATE_SET_HEADER
{
    struct IPFIX_SET_HEADER c;
    union
    {
        struct
        {
            struct IPFIX_TEMPLATE_RECORD_HEADER r;
            u_int16_t scope_count;
        } i;
        struct
        {
            u_int16_t template_id;
            u_int16_t scope_length;
            u_int16_t option_length;
        } n;
    } u;
} __packed;
struct IPFIX_FIELD_SPECIFIER
{
    u_int16_t ie, length;
} __packed;
struct IPFIX_VENDOR_FIELD_SPECIFIER
{
    u_int16_t ie, length;
    u_int32_t pen;
} __packed;
#define REVERSE_PEN 29305

#define NFLOW9_TEMPLATE_SET_ID          0
#define NFLOW9_OPTION_TEMPLATE_SET_ID   1
#define IPFIX_TEMPLATE_SET_ID           2
#define IPFIX_OPTION_TEMPLATE_SET_ID    3
#define IPFIX_MIN_RECORD_SET_ID         256

/* Flowset record ies the we care about */
#define IPFIX_octetDeltaCount           1
#define IPFIX_packetDeltaCount          2
/* ... */
#define IPFIX_protocolIdentifier        4
#define IPFIX_ipClassOfService          5
/* ... */
#define IPFIX_tcpControlBits            6
#define IPFIX_sourceTransportPort       7
#define IPFIX_sourceIPv4Address         8
/* ... */
#define IPFIX_ingressInterface          10
#define IPFIX_destinationTransportPort  11
#define IPFIX_destinationIPv4Address    12
/* ... */
#define IPFIX_egressInterface           14
/* ... */
#define IPFIX_flowEndSysUpTime          21
#define IPFIX_flowStartSysUpTime        22
/* ... */
#define IPFIX_sourceIPv6Address         27
#define IPFIX_destinationIPv6Address    28
/* ... */
#define IPFIX_icmpTypeCodeIPv4          32
/* ... */
#define NFLOW9_SAMPLING_INTERVAL        34
#define NFLOW9_SAMPLING_ALGORITHM       35
/* ... */
#define IPFIX_sourceMacAddress          56
#define IPFIX_postDestinationMacAddress 57
#define IPFIX_vlanId                    58
#define IPFIX_postVlanId                59

#define IPFIX_ipVersion                     60
/* ... */
#define IPFIX_icmpTypeCodeIPv6              139
/* ... */
#define IPFIX_meteringProcessId             143
/* ... */
#define IPFIX_flowStartSeconds              150
#define IPFIX_flowEndSeconds                151
#define IPFIX_flowStartMilliSeconds         152
#define IPFIX_flowEndMilliSeconds           153
#define IPFIX_flowStartMicroSeconds         154
#define IPFIX_flowEndMicroSeconds           155
#define IPFIX_flowStartNanoSeconds          156
#define IPFIX_flowEndNanoSeconds            157
/* ... */
#define IPFIX_systemInitTimeMilliseconds    160
/* ... */
#define PSAMP_selectorAlgorithm             304
#define PSAMP_samplingPacketInterval        305
#define PSAMP_samplingPacketSpace           306

#define PSAMP_selectorAlgorithm_count   1

#define NFLOW9_OPTION_SCOPE_INTERFACE           2
#define NFLOW9_SAMPLING_ALGORITHM_DETERMINISTIC 1

const struct IPFIX_FIELD_SPECIFIER field_v4[] = {
    {IPFIX_sourceIPv4Address, 4},
    {IPFIX_destinationIPv4Address, 4}
};

const struct IPFIX_FIELD_SPECIFIER field_v6[] = {
    {IPFIX_sourceIPv6Address, 16},
    {IPFIX_destinationIPv6Address, 16}
};

const struct IPFIX_FIELD_SPECIFIER field_common[] = {
    {IPFIX_octetDeltaCount, 4},
    {IPFIX_packetDeltaCount, 4},
    {IPFIX_ingressInterface, 4},
    {IPFIX_egressInterface, 4}
};

const struct IPFIX_FIELD_SPECIFIER field_transport[] = {
    {IPFIX_sourceTransportPort, 2},
    {IPFIX_destinationTransportPort, 2},
    {IPFIX_protocolIdentifier, 1},
    {IPFIX_tcpControlBits, 1},
    {IPFIX_ipVersion, 1},
    {IPFIX_ipClassOfService, 1}
};

const struct IPFIX_FIELD_SPECIFIER field_icmp4[] = {
    {IPFIX_icmpTypeCodeIPv4, 2},
    {IPFIX_ipVersion, 1},
    {IPFIX_ipClassOfService, 1}
};

const struct IPFIX_FIELD_SPECIFIER field_icmp6[] = {
    {IPFIX_icmpTypeCodeIPv6, 2},
    {IPFIX_ipVersion, 1},
    {IPFIX_ipClassOfService, 1}
};

const struct IPFIX_FIELD_SPECIFIER field_vlan[] = {
    {IPFIX_vlanId, 2},
    {IPFIX_postVlanId, 2}
};

const struct IPFIX_FIELD_SPECIFIER field_ether[] = {
    {IPFIX_sourceMacAddress, 6},
    {IPFIX_postDestinationMacAddress, 6}
};

const struct IPFIX_FIELD_SPECIFIER field_timesec[] = {
    {IPFIX_flowStartSeconds, 4},
    {IPFIX_flowEndSeconds, 4}
};

const struct IPFIX_FIELD_SPECIFIER field_timemsec[] = {
    {IPFIX_flowStartMilliSeconds, 8},
    {IPFIX_flowEndMilliSeconds, 8}
};

const struct IPFIX_FIELD_SPECIFIER field_timeusec[] = {
    {IPFIX_flowStartMicroSeconds, 8},
    {IPFIX_flowEndMicroSeconds, 8}
};

const struct IPFIX_FIELD_SPECIFIER field_timensec[] = {
    {IPFIX_flowStartNanoSeconds, 8},
    {IPFIX_flowEndNanoSeconds, 8}
};

const struct IPFIX_FIELD_SPECIFIER field_timesysup[] = {
    {IPFIX_flowStartSysUpTime, 4},
    {IPFIX_flowEndSysUpTime, 4}
};

const struct IPFIX_FIELD_SPECIFIER field_bicommon[] = {
    {IPFIX_octetDeltaCount, 4},
    {IPFIX_packetDeltaCount, 4},
    {IPFIX_ipClassOfService, 1}
};

const struct IPFIX_FIELD_SPECIFIER field_bitransport[] =
    { {IPFIX_tcpControlBits, 1} };

const struct IPFIX_FIELD_SPECIFIER field_biicmp4[] =
    { {IPFIX_icmpTypeCodeIPv4, 2} };

const struct IPFIX_FIELD_SPECIFIER field_biicmp6[] =
    { {IPFIX_icmpTypeCodeIPv6, 2} };

const struct IPFIX_FIELD_SPECIFIER field_scope[] =
    { {IPFIX_meteringProcessId, 4} };

const struct IPFIX_FIELD_SPECIFIER field_option[] = {
    {IPFIX_systemInitTimeMilliseconds, 8},
    {PSAMP_samplingPacketInterval, 4},
    {PSAMP_samplingPacketSpace, 4},
    {PSAMP_selectorAlgorithm, 2}
};

const struct IPFIX_FIELD_SPECIFIER field_nf9scope[] =
    { {NFLOW9_OPTION_SCOPE_INTERFACE, 4} };

const struct IPFIX_FIELD_SPECIFIER field_nf9option[] = {
    {NFLOW9_SAMPLING_INTERVAL, 4},
    {NFLOW9_SAMPLING_ALGORITHM, 1}
};

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
//#define IPFIX_SOFTFLOWD_TEMPLATE_VENDORRECORDS        5
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

struct IPFIX_SOFTFLOWD_TEMPLATE
{
    struct IPFIX_TEMPLATE_SET_HEADER h;
    struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS];
    struct IPFIX_VENDOR_FIELD_SPECIFIER
        v[IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS];
    u_int16_t data_len, bi_count;
} __packed;

#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS   \
    sizeof(field_scope) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS        \
    sizeof(field_option) / sizeof(struct IPFIX_FIELD_SPECIFIER)

#define NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS  \
    sizeof(field_nf9scope) / sizeof(struct IPFIX_FIELD_SPECIFIER)
#define NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS       \
    sizeof(field_nf9option) / sizeof(struct IPFIX_FIELD_SPECIFIER)


struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE
{
    struct IPFIX_OPTION_TEMPLATE_SET_HEADER h;
    struct IPFIX_FIELD_SPECIFIER
        s[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS];
    struct IPFIX_FIELD_SPECIFIER r[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];
} __packed;

/* softflowd data set */
struct IPFIX_SOFTFLOWD_DATA_COMMON
{
    u_int32_t octetDeltaCount, packetDeltaCount;
    u_int32_t ingressInterface, egressInterface;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_TRANSPORT
{
    u_int16_t sourceTransportPort, destinationTransportPort;
    u_int8_t protocolIdentifier, tcpControlBits, ipVersion, ipClassOfService;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_ICMP
{
    u_int16_t icmpTypeCode;
    u_int8_t ipVersion, ipClassOfService;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_VLAN
{
    u_int16_t vlanId, postVlanId;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_ETHER
{
    u_int8_t sourceMacAddress[6], destinationMacAddress[6];
} __packed;

struct IPFIX_SOFTFLOWD_DATA_BICOMMON
{
    u_int32_t octetDeltaCount, packetDeltaCount;
    u_int8_t ipClassOfService;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT
{
    u_int8_t tcpControlBits;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_BIICMP
{
    u_int16_t icmpTypeCode;
} __packed;

union IPFIX_SOFTFLOWD_DATA_TIME
{
    struct
    {
        u_int32_t start;
        u_int32_t end;
    } u32;
    struct
    {
        u_int64_t start;
        u_int64_t end;
    } u64;
};

struct IPFIX_SOFTFLOWD_DATA_V4ADDR
{
    u_int32_t sourceIPv4Address, destinationIPv4Address;
} __packed;

struct IPFIX_SOFTFLOWD_DATA_V6ADDR
{
    struct in6_addr sourceIPv6Address, destinationIPv6Address;
} __packed;

struct IPFIX_SOFTFLOWD_OPTION_DATA
{
    struct IPFIX_SET_HEADER c;
    u_int32_t scope_pid;
    u_int64_t systemInitTimeMilliseconds;
    u_int32_t samplingInterval;
    u_int32_t samplingSpace;
    u_int16_t samplingAlgorithm;
} __packed;

struct NFLOW9_SOFTFLOWD_OPTION_DATA
{
    struct IPFIX_SET_HEADER c;
    u_int32_t scope_ifidx;
    u_int32_t samplingInterval;
    u_int8_t samplingAlgorithm;
} __packed;

/* Local data: templates and counters */
#define IPFIX_SOFTFLOWD_MAX_PACKET_SIZE     1428
#define IPFIX_SOFTFLOWD_V4_TEMPLATE_ID      1024
#define IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID  1025
#define IPFIX_SOFTFLOWD_V6_TEMPLATE_ID      2048
#define IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID  2049
#define IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID  256

#define IPFIX_DEFAULT_TEMPLATE_INTERVAL 16

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

enum
{ TMPLV4, TMPLICMPV4, TMPLV6, TMPLICMPV6, TMPLMAX };
static struct IPFIX_SOFTFLOWD_TEMPLATE template[TMPLMAX];
static struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE option_template;
static struct IPFIX_SOFTFLOWD_OPTION_DATA option_data;
static struct NFLOW9_SOFTFLOWD_OPTION_DATA nf9opt_data;

static int ipfix_pkts_until_template = -1;

static int
ipfix_init_fields (struct IPFIX_FIELD_SPECIFIER *dst,
                   u_int * index,
                   const struct IPFIX_FIELD_SPECIFIER *src,
                   u_int field_number)
{
    int length = 0;
    for (int i = 0; i < field_number; i++)
      {
          dst[*index + i].ie = htons (src[i].ie);
          dst[*index + i].length = htons (src[i].length);
          length += src[i].length;
      }
    *index += field_number;
    return length;
}

static int
ipfix_init_bifields (struct IPFIX_SOFTFLOWD_TEMPLATE *template,
                     u_int * index,
                     const struct IPFIX_FIELD_SPECIFIER *fields,
                     u_int field_number)
{
    int length = 0;
    for (int i = 0; i < field_number; i++)
      {
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
                          u_int * index)
{
    int length = 0;
    if (param->time_format == 's')
      {
          length = ipfix_init_fields (template->r, index,
                                      field_timesec,
                                      IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
      }
    else if (param->time_format == 'm')
      {
          length = ipfix_init_fields (template->r, index,
                                      field_timemsec,
                                      IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
      }
    else if (param->time_format == 'M')
      {
          length = ipfix_init_fields (template->r, index,
                                      field_timeusec,
                                      IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
      }
    else if (param->time_format == 'n')
      {
          length = ipfix_init_fields (template->r, index,
                                      field_timensec,
                                      IPFIX_SOFTFLOWD_TEMPLATE_TIMERECORDS);
      }
    else
      {
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
                           u_int16_t version)
{
    u_int index = 0, bi_index = 0, length = 0;
    bzero (template, sizeof (*template));
    template->h.c.set_id = htons (version == 10 ?
                                  IPFIX_TEMPLATE_SET_ID :
                                  NFLOW9_TEMPLATE_SET_ID);
    template->h.r.template_id = htons (template_id);
    if (v6_flag)
      {
          length += ipfix_init_fields (template->r, &index,
                                       field_v6,
                                       IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS);
      }
    else
      {
          length += ipfix_init_fields (template->r, &index,
                                       field_v4,
                                       IPFIX_SOFTFLOWD_TEMPLATE_IPRECORDS);
      }
    length += ipfix_init_template_time (param, template, &index);
    length += ipfix_init_fields (template->r, &index,
                                 field_common,
                                 IPFIX_SOFTFLOWD_TEMPLATE_COMMONRECORDS);
    if (icmp_flag)
      {
          if (v6_flag)
            {
                length += ipfix_init_fields (template->r, &index,
                                             field_icmp6,
                                             IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS);
            }
          else
            {
                length += ipfix_init_fields (template->r, &index,
                                             field_icmp4,
                                             IPFIX_SOFTFLOWD_TEMPLATE_ICMPRECORDS);
            }
      }
    else
      {
          length += ipfix_init_fields (template->r, &index,
                                       field_transport,
                                       IPFIX_SOFTFLOWD_TEMPLATE_TRANSPORTRECORDS);
      }
    if (param->track_level >= TRACK_FULL_VLAN)
      {
          length += ipfix_init_fields (template->r, &index,
                                       field_vlan,
                                       IPFIX_SOFTFLOWD_TEMPLATE_VLANRECORDS);
      }
    if (param->track_level >= TRACK_FULL_VLAN_ETHER)
      {
          length += ipfix_init_fields (template->r, &index,
                                       field_ether,
                                       IPFIX_SOFTFLOWD_TEMPLATE_ETHERRECORDS);
      }
    if (bi_flag)
      {
          length +=
              ipfix_init_bifields (template, &bi_index,
                                   field_bicommon,
                                   IPFIX_SOFTFLOWD_TEMPLATE_BICOMMONRECORDS);
          if (icmp_flag)
            {
                if (v6_flag)
                  {
                      length +=
                          ipfix_init_bifields (template, &bi_index,
                                               field_biicmp6,
                                               IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS);
                  }
                else
                  {
                      length +=
                          ipfix_init_bifields (template, &bi_index,
                                               field_biicmp4,
                                               IPFIX_SOFTFLOWD_TEMPLATE_BIICMPRECORDS);
                  }
            }
          else
            {
                length +=
                    ipfix_init_bifields (template, &bi_index,
                                         field_bitransport,
                                         IPFIX_SOFTFLOWD_TEMPLATE_BITRANSPORTRECORDS);

            }
      }
    template->bi_count = bi_index;
    template->h.r.count = htons (index + bi_index);
    template->h.c.length =
        htons (sizeof (struct IPFIX_TEMPLATE_SET_HEADER) +
               index * sizeof (struct IPFIX_FIELD_SPECIFIER) +
               bi_index * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER));
    template->data_len = length;
}

static void
ipfix_init_template (struct FLOWTRACKPARAMETERS *param,
                     u_int8_t bi_flag, u_int16_t version)
{
    u_int8_t v6_flag = 0, icmp_flag = 0;
    u_int16_t template_id = 0;
    for (int i = 0; i < TMPLMAX; i++)
      {
          switch (i)
            {
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
          ipfix_init_template_unity (param, &template[i],
                                     template_id, v6_flag,
                                     icmp_flag, bi_flag, version);
      }
}

static void
nflow9_init_option (u_int16_t ifidx, struct OPTION *option)
{
    u_int scope_index = 0, option_index = 0;
    u_int16_t scope_len =
        NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS *
        sizeof (struct IPFIX_FIELD_SPECIFIER);
    u_int16_t opt_len =
        NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS *
        sizeof (struct IPFIX_FIELD_SPECIFIER);

    bzero (&option_template, sizeof (option_template));
    option_template.h.c.set_id = htons (NFLOW9_OPTION_TEMPLATE_SET_ID);
    option_template.h.c.length =
        htons (sizeof (option_template.h) + scope_len + opt_len);
    option_template.h.u.n.template_id
        = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    option_template.h.u.n.scope_length = htons (scope_len);
    option_template.h.u.n.option_length = htons (opt_len);
    ipfix_init_fields (option_template.s, &scope_index,
                       field_nf9scope,
                       NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS);
    ipfix_init_fields (option_template.r, &option_index,
                       field_nf9option,
                       NFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS);
    bzero (&nf9opt_data, sizeof (nf9opt_data));
    nf9opt_data.c.set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    nf9opt_data.c.length = htons (sizeof (nf9opt_data));
    nf9opt_data.scope_ifidx = htonl (ifidx);
    nf9opt_data.samplingInterval =
        htonl (option->sample > 1 ? option->sample : 1);
    nf9opt_data.samplingAlgorithm = NFLOW9_SAMPLING_ALGORITHM_DETERMINISTIC;
}

static void
ipfix_init_option (struct timeval *system_boot_time, struct OPTION *option)
{
    u_int scope_index = 0, option_index = 0;
    bzero (&option_template, sizeof (option_template));
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

    bzero (&option_data, sizeof (option_data));
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
}

static int
copy_data_time (union IPFIX_SOFTFLOWD_DATA_TIME *dt,
                const struct FLOW *flow,
                const struct timeval *system_boot_time,
                struct FLOWTRACKPARAMETERS *param)
{
    int length = (param->time_format == 'm' || param->time_format == 'M'
                  || param->time_format == 'n') ? 16 : 8;
    if (dt == NULL)
        return -1;

    if (param->time_format == 's')
      {
          dt->u32.start = htonl (flow->flow_start.tv_sec);
          dt->u32.end = htonl (flow->flow_last.tv_sec);
      }
#if defined(htobe64) || defined(HAVE_DECL_HTOBE64)
    else if (param->time_format == 'm')
      {                         /* milliseconds */
          dt->u64.start =
              htobe64 ((u_int64_t) flow->flow_start.tv_sec * 1000 +
                       (u_int64_t) flow->flow_start.tv_usec / 1000);
          dt->u64.end =
              htobe64 ((u_int64_t) flow->flow_last.tv_sec * 1000 +
                       (u_int64_t) flow->flow_last.tv_usec / 1000);
      }
    else if (param->time_format == 'M')
      {                         /* microseconds */
          dt->u64.start =
              htobe64 (((u_int64_t) flow->flow_start.tv_sec +
                        JAN_1970) << 32 | (u_int32_t) (((u_int64_t) flow->
                                                        flow_start.
                                                        tv_usec << 32) /
                                                       1e6));
          dt->u64.end =
              htobe64 (((u_int64_t) flow->flow_last.tv_sec +
                        JAN_1970) << 32 | (u_int32_t) (((u_int64_t) flow->
                                                        flow_last.
                                                        tv_usec << 32) /
                                                       1e6));
      }
    else if (param->time_format == 'n')
      {                         /* nanoseconds */
          dt->u64.start =
              htobe64 (((u_int64_t) flow->flow_start.tv_sec +
                        JAN_1970) << 32 | (u_int32_t) (((u_int64_t) flow->
                                                        flow_start.
                                                        tv_usec << 32) /
                                                       1e9));
          dt->u64.end =
              htobe64 (((u_int64_t) flow->flow_last.tv_sec +
                        JAN_1970) << 32 | (u_int32_t) (((u_int64_t) flow->
                                                        flow_last.
                                                        tv_usec << 32) /
                                                       1e9));
      }
#endif
    else
      {
          dt->u32.start =
              htonl (timeval_sub_ms (&flow->flow_start, system_boot_time));
          dt->u32.end =
              htonl (timeval_sub_ms (&flow->flow_last, system_boot_time));
      }
    return length;
}

static u_int
ipfix_flow_to_template_index (const struct FLOW *flow)
{
    u_int index = 0;
    if (flow->af == AF_INET)
      {
          index = (flow->protocol == IPPROTO_ICMP) ? TMPLICMPV4 : TMPLV4;
      }
    else if (flow->af == AF_INET6)
      {
          index = (flow->protocol == IPPROTO_ICMPV6) ? TMPLICMPV6 : TMPLV6;
      }
    return index;
}

static int
ipfix_flow_to_flowset (const struct FLOW *flow, u_char * packet,
                       u_int len, u_int16_t ifidx,
                       const struct timeval *system_boot_time,
                       u_int * len_used,
                       struct FLOWTRACKPARAMETERS *param, u_int8_t bi_flag)
{
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

    u_int freclen = 0, nflows = 0, offset = 0;
    u_int frecnum = bi_flag ? 1 : 2;
    u_int tmplindex = ipfix_flow_to_template_index (flow);
    freclen = template[tmplindex].data_len;
    if (len < freclen * frecnum)
        return (-1);

    for (int i = 0; i < frecnum; i++)
      {
          if (bi_flag == 0 && flow->octets[i] == 0)
              continue;
          nflows++;
          if (flow->af == AF_INET)
            {
                d4[i] =
                    (struct IPFIX_SOFTFLOWD_DATA_V4ADDR *) &packet[offset];
                memcpy (&d4[i]->sourceIPv4Address, &flow->addr[i].v4, 4);
                memcpy (&d4[i]->destinationIPv4Address,
                        &flow->addr[i ^ 1].v4, 4);
                offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_V4ADDR);
            }
          else if (flow->af == AF_INET6)
            {
                d6[i] =
                    (struct IPFIX_SOFTFLOWD_DATA_V6ADDR *) &packet[offset];
                memcpy (&d6[i]->sourceIPv6Address, &flow->addr[i].v6, 16);
                memcpy (&d6[i]->destinationIPv6Address,
                        &flow->addr[i ^ 1].v6, 16);
                offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_V6ADDR);
            }

          dt[i] = (union IPFIX_SOFTFLOWD_DATA_TIME *) &packet[offset];
          offset += copy_data_time (dt[i], flow, system_boot_time, param);

          dc[i] = (struct IPFIX_SOFTFLOWD_DATA_COMMON *) &packet[offset];
          dc[i]->octetDeltaCount = htonl (flow->octets[i]);
          dc[i]->packetDeltaCount = htonl (flow->packets[i]);
          dc[i]->ingressInterface = dc[i]->egressInterface = htonl (ifidx);
          offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_COMMON);

          if (flow->protocol != IPPROTO_ICMP
              && flow->protocol != IPPROTO_ICMPV6)
            {
                dtr[i] =
                    (struct IPFIX_SOFTFLOWD_DATA_TRANSPORT *) &packet[offset];
                dtr[i]->sourceTransportPort = flow->port[i];
                dtr[i]->destinationTransportPort = flow->port[i ^ 1];
                dtr[i]->protocolIdentifier = flow->protocol;
                dtr[i]->tcpControlBits = flow->tcp_flags[i];
                dtr[i]->ipClassOfService = flow->tos[i];
                dtr[i]->ipVersion = (flow->af == AF_INET) ? 4 : 6;
                offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_TRANSPORT);
            }
          else
            {
                di[i] = (struct IPFIX_SOFTFLOWD_DATA_ICMP *) &packet[offset];
                di[i]->icmpTypeCode = flow->port[i ^ 1];
                di[i]->ipClassOfService = flow->tos[i];
                di[i]->ipVersion = (flow->af == AF_INET) ? 4 : 6;
                offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_ICMP);
            }
          if (param->track_level >= TRACK_FULL_VLAN)
            {
                dv[i] = (struct IPFIX_SOFTFLOWD_DATA_VLAN *) &packet[offset];
                dv[i]->vlanId = flow->vlanid[i];
                dv[i]->postVlanId = flow->vlanid[i ^ 1];
                offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_VLAN);
            }
          if (param->track_level >= TRACK_FULL_VLAN_ETHER)
            {
                de[i] = (struct IPFIX_SOFTFLOWD_DATA_ETHER *) &packet[offset];
                memcpy (&de[i]->sourceMacAddress, &flow->ethermac[i], 6);
                memcpy (&de[i]->destinationMacAddress,
                        &flow->ethermac[i ^ 1], 6);
                offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_ETHER);
            }
          if (bi_flag && i == 0)
            {
                dbc =
                    (struct IPFIX_SOFTFLOWD_DATA_BICOMMON *) &packet[offset];
                dbc->octetDeltaCount = htonl (flow->octets[1]);
                dbc->packetDeltaCount = htonl (flow->packets[1]);
                dbc->ipClassOfService = flow->tos[1];
                offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_BICOMMON);
                if (flow->protocol != IPPROTO_ICMP
                    && flow->protocol != IPPROTO_ICMPV6)
                  {
                      dbtr =
                          (struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT *)
                          &packet[offset];
                      dbtr->tcpControlBits = flow->tcp_flags[1];
                      offset +=
                          sizeof (struct IPFIX_SOFTFLOWD_DATA_BITRANSPORT);
                  }
                else
                  {
                      dbi =
                          (struct IPFIX_SOFTFLOWD_DATA_BIICMP *)
                          &packet[offset];
                      dbi->icmpTypeCode = flow->port[1];
                      offset += sizeof (struct IPFIX_SOFTFLOWD_DATA_BIICMP);
                  }
            }
      }
    *len_used = offset;
    return (nflows);
}

static int
valuate_icmp (struct FLOW *flow)
{
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
    return -1;
}

void
ipfix_resend_template (void)
{
    if (ipfix_pkts_until_template > 0)
        ipfix_pkts_until_template = 0;
}

void
memcpy_template (u_char * packet, u_int * offset,
                 struct IPFIX_SOFTFLOWD_TEMPLATE *template, u_int8_t bi_flag)
{
    int size = ntohs (template->h.c.length) -
        template->bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER);
    memcpy (packet + *offset, template, size);
    *offset += size;
    if (bi_flag)
      {
          size =
              template->bi_count *
              sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER);
          memcpy (packet + *offset, template->v, size);
          *offset += size;
      }
}

/*
 * Given an array of expired flows, send ipfix report packets
 * Returns number of packets sent or -1 on error
 */
static int
send_ipfix_common (struct FLOW **flows, int num_flows,
                   int nfsock, u_int16_t ifidx,
                   struct FLOWTRACKPARAMETERS *param,
                   int verbose_flag, u_int8_t bi_flag, u_int16_t version)
{
    struct IPFIX_HEADER *ipfix;
    struct NFLOW9_HEADER *nf9;
    struct IPFIX_SET_HEADER *dh;
    struct timeval now;
    u_int offset, last_af, i, j, num_packets, inc, last_valid;
    int8_t icmp_flag, last_icmp_flag;
    socklen_t errsz;
    int err, r;
    u_int records;
    u_char packet[IPFIX_SOFTFLOWD_MAX_PACKET_SIZE];
    struct timeval *system_boot_time = &param->system_boot_time;
    u_int64_t *flows_exported = &param->flows_exported;
    u_int64_t *records_sent = &param->records_sent;
    struct OPTION *option = &param->option;
    u_int tmplindex = 0;

    gettimeofday (&now, NULL);

    if (ipfix_pkts_until_template == -1)
      {
          ipfix_init_template (param, bi_flag, version);
          ipfix_pkts_until_template = 0;
          if (option != NULL)
            {
                if (version == 10)
                  {
                      ipfix_init_option (system_boot_time, option);
                  }
                else
                  {
                      nflow9_init_option (ifidx, option);
                  }
            }
      }

    last_valid = num_packets = 0;
    for (j = 0; j < num_flows;)
      {
          bzero (packet, sizeof (packet));
          if (version == 10)
            {
                ipfix = (struct IPFIX_HEADER *) packet;
                ipfix->version = htons (version);
                ipfix->length = 0;  /* Filled as we go, htons at end */
                ipfix->export_time = htonl (time (NULL));
                ipfix->od_id = 0;
                offset = sizeof (*ipfix);
            }
          else if (version == 9)
            {
                nf9 = (struct NFLOW9_HEADER *) packet;
                nf9->version = htons (version);
                nf9->flows = 0; /* Filled as we go, htons at end */
                nf9->uptime_ms =
                    htonl (timeval_sub_ms (&now, system_boot_time));

                nf9->export_time = htonl (time (NULL));
                nf9->od_id = 0;
                offset = sizeof (*nf9);
            }

          /* Refresh template headers if we need to */
          if (ipfix_pkts_until_template <= 0)
            {
                for (int i = 0; i < TMPLMAX; i++)
                  {
                      memcpy_template (packet, &offset,
                                       &template[i], bi_flag);
                  }
                if (option != NULL)
                  {
                      u_int16_t opt_tmpl_len =
                          ntohs (option_template.h.c.length);
                      memcpy (packet + offset, &option_template,
                              opt_tmpl_len);
                      offset += opt_tmpl_len;
                      if (version == 10)
                        {
                            memcpy (packet + offset, &option_data,
                                    sizeof (option_data));
                            offset += sizeof (option_data);
                        }
                      else if (version == 9)
                        {
                            memcpy (packet + offset, &nf9opt_data,
                                    sizeof (nf9opt_data));
                            offset += sizeof (nf9opt_data);
                        }
                  }

                ipfix_pkts_until_template = IPFIX_DEFAULT_TEMPLATE_INTERVAL;
            }

          dh = NULL;
          last_af = 0;
          last_icmp_flag = -1;
          records = 0;
          for (i = 0; i + j < num_flows; i++)
            {
                icmp_flag = valuate_icmp (flows[i + j]);
                if (dh == NULL || flows[i + j]->af != last_af ||
                    icmp_flag != last_icmp_flag)
                  {
                      if (dh != NULL)
                        {
                            if (offset % 4 != 0)
                              {
                                  /* Pad to multiple of 4 */
                                  dh->length += 4 - (offset % 4);
                                  offset += 4 - (offset % 4);
                              }
                            /* Finalise last header */
                            dh->length = htons (dh->length);
                        }
                      if (offset + sizeof (*dh) > sizeof (packet))
                        {
                            /* Mark header is finished */
                            dh = NULL;
                            break;
                        }
                      dh = (struct IPFIX_SET_HEADER *) (packet + offset);
                      tmplindex = ipfix_flow_to_template_index (flows[i + j]);
                      dh->set_id = template[tmplindex].h.r.template_id;
                      last_af = flows[i + j]->af;
                      last_icmp_flag = icmp_flag;
                      last_valid = offset;
                      dh->length = sizeof (*dh);    /* Filled as we go */
                      offset += sizeof (*dh);
                  }
                r = ipfix_flow_to_flowset (flows[i + j],
                                           packet + offset,
                                           sizeof (packet) - offset,
                                           ifidx, system_boot_time,
                                           &inc, param, bi_flag);
                if (r <= 0)
                  {
                      /* yank off data header, if we had to go back */
                      if (last_valid)
                          offset = last_valid;
                      break;
                  }
                records += (u_int) r;
                offset += inc;
                dh->length += inc;
                last_valid = 0; /* Don't clobber this header now */
                if (verbose_flag)
                  {
                      logit (LOG_DEBUG, "Flow %d/%d: "
                             "r %d offset %d ie %04x len %d(0x%04x)",
                             r, i, j, offset,
                             dh->set_id, dh->length, dh->length);
                  }
            }
          /* Don't finish header if it has already been done */
          if (dh != NULL)
            {
                if (offset % 4 != 0)
                  {
                      /* Pad to multiple of 4 */
                      dh->length += 4 - (offset % 4);
                      offset += 4 - (offset % 4);
                  }
                /* Finalise last header */
                dh->length = htons (dh->length);
            }
          ipfix->length = htons (offset);
          *records_sent += records;
          ipfix->sequence =
              htonl ((u_int32_t) (*records_sent & 0x00000000ffffffff));

          if (verbose_flag)
              logit (LOG_DEBUG, "Sending flow packet len = %d", offset);
          errsz = sizeof (err);
          /* Clear ICMP errors */
          getsockopt (nfsock, SOL_SOCKET, SO_ERROR, &err, &errsz);
          if (send (nfsock, packet, (size_t) offset, 0) == -1)
              return (-1);
          num_packets++;
          ipfix_pkts_until_template--;

          j += i;
      }

    *flows_exported += j;
    return (num_packets);
}

int
send_nflow9 (struct FLOW **flows, int num_flows, int nfsock,
             u_int16_t ifidx, struct FLOWTRACKPARAMETERS *param,
             int verbose_flag)
{
    return send_ipfix_common (flows, num_flows, nfsock, ifidx,
                              param, verbose_flag, 0, 9);
}

int
send_ipfix (struct FLOW **flows, int num_flows, int nfsock,
            u_int16_t ifidx, struct FLOWTRACKPARAMETERS *param,
            int verbose_flag)
{
    return send_ipfix_common (flows, num_flows, nfsock, ifidx,
                              param, verbose_flag, 0, 10);
}

int
send_ipfix_bi (struct FLOW **flows, int num_flows, int nfsock,
               u_int16_t ifidx,
               struct FLOWTRACKPARAMETERS *param, int verbose_flag)
{
    return send_ipfix_common (flows, num_flows, nfsock, ifidx,
                              param, verbose_flag, 1, 10);
}
