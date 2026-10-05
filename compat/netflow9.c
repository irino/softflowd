/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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
#include "netflow.h"
#include "ipfix.h"

/* Legacy (--enable-export-merge=none) NetFlow v9 exporter limits */
#define NETFLOW9_SOFTFLOWD_MAX_PACKET_SIZE                   512
#define NETFLOW9_SOFTFLOWD_TEMPLATE_NRECORDS                 16
#define NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS     1
#define NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS          2

/* NetFlow v9: stuff pertaining to the templates that softflowd uses */
struct NETFLOW9_SOFTFLOWD_TEMPLATE {
  struct IPFIX_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER r[NETFLOW9_SOFTFLOWD_TEMPLATE_NRECORDS];
} __packed;

struct NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE {
  struct IPFIX_OPTION_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER
    s[NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS];
  struct IPFIX_FIELD_SPECIFIER
    r[NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];
} __packed;

/* softflowd data flowset types */
struct NETFLOW9_SOFTFLOWD_DATA_COMMON {
  u_int32_t flowEndSysUpTime, flowStartSysUpTime;
  u_int32_t octetDeltaCount, packetDeltaCount;
  u_int32_t ingressInterface, egressInterface;
  u_int16_t sourceTransportPort, destinationTransportPort;
  u_int8_t protocolIdentifier, tcpControlBits, ipVersion, ipClassOfService;
  /* icmpTypeCodeIPv4 (IE 32) is used for IPv6 flows too, as in older releases */
  u_int16_t icmpTypeCodeIPv4, vlanId;
} __packed;

struct NETFLOW9_SOFTFLOWD_DATA_V4 {
  u_int32_t sourceIPv4Address, destinationIPv4Address;
  struct NETFLOW9_SOFTFLOWD_DATA_COMMON c;
} __packed;

struct NETFLOW9_SOFTFLOWD_DATA_V6 {
  u_int8_t sourceIPv6Address[16], destinationIPv6Address[16];
  struct NETFLOW9_SOFTFLOWD_DATA_COMMON c;
} __packed;

struct NETFLOW9_SOFTFLOWD_OPTION_DATA {
  struct IPFIX_SET_HEADER c;
  u_int32_t scope_ifidx;
  u_int32_t samplingInterval;
  u_int8_t samplingAlgorithm;
  u_int8_t padding[3];
} __packed;

/* Local data: templates and counters */


/** IPv4 data template. */
static struct NETFLOW9_SOFTFLOWD_TEMPLATE v4_template;
/** IPv6 data template. */
static struct NETFLOW9_SOFTFLOWD_TEMPLATE v6_template;
/** Options template. */
static struct NETFLOW9_SOFTFLOWD_OPTION_TEMPLATE option_template;
/** Options data record. */
static struct NETFLOW9_SOFTFLOWD_OPTION_DATA option_data;
/** Packets until templates are sent again: -1 = not built yet, 0 or less = send with the next packet. */
static int nf9_pkts_until_template = -1;

/**
 * @brief Build the IPv4 and IPv6 NetFlow v9 template flowsets (v4_template, v6_template).
 */
static void
nf9_init_template (void) {
  memset (&v4_template, 0, sizeof (v4_template));
  v4_template.h.c.set_id = htons (NETFLOW9_TEMPLATE_SET_ID);
  v4_template.h.c.length = htons (sizeof (v4_template));
  v4_template.h.r.template_id = htons (IPFIX_SOFTFLOWD_V4_TEMPLATE_ID);
  v4_template.h.r.count = htons (NETFLOW9_SOFTFLOWD_TEMPLATE_NRECORDS);
  v4_template.r[0].ie = htons (IPFIX_sourceIPv4Address);
  v4_template.r[0].length = htons (4);
  v4_template.r[1].ie = htons (IPFIX_destinationIPv4Address);
  v4_template.r[1].length = htons (4);
  v4_template.r[2].ie = htons (IPFIX_flowEndSysUpTime);
  v4_template.r[2].length = htons (4);
  v4_template.r[3].ie = htons (IPFIX_flowStartSysUpTime);
  v4_template.r[3].length = htons (4);
  v4_template.r[4].ie = htons (IPFIX_octetDeltaCount);
  v4_template.r[4].length = htons (4);
  v4_template.r[5].ie = htons (IPFIX_packetDeltaCount);
  v4_template.r[5].length = htons (4);
  v4_template.r[6].ie = htons (IPFIX_ingressInterface);
  v4_template.r[6].length = htons (4);
  v4_template.r[7].ie = htons (IPFIX_egressInterface);
  v4_template.r[7].length = htons (4);
  v4_template.r[8].ie = htons (IPFIX_sourceTransportPort);
  v4_template.r[8].length = htons (2);
  v4_template.r[9].ie = htons (IPFIX_destinationTransportPort);
  v4_template.r[9].length = htons (2);
  v4_template.r[10].ie = htons (IPFIX_protocolIdentifier);
  v4_template.r[10].length = htons (1);
  v4_template.r[11].ie = htons (IPFIX_tcpControlBits);
  v4_template.r[11].length = htons (1);
  v4_template.r[12].ie = htons (IPFIX_ipVersion);
  v4_template.r[12].length = htons (1);
  v4_template.r[13].ie = htons (IPFIX_ipClassOfService);
  v4_template.r[13].length = htons (1);
  v4_template.r[14].ie = htons (IPFIX_icmpTypeCodeIPv4);
  v4_template.r[14].length = htons (2);
  v4_template.r[15].ie = htons (IPFIX_vlanId);
  v4_template.r[15].length = htons (2);
  memset (&v6_template, 0, sizeof (v6_template));
  v6_template.h.c.set_id = htons (NETFLOW9_TEMPLATE_SET_ID);
  v6_template.h.c.length = htons (sizeof (v6_template));
  v6_template.h.r.template_id = htons (IPFIX_SOFTFLOWD_V6_TEMPLATE_ID);
  v6_template.h.r.count = htons (NETFLOW9_SOFTFLOWD_TEMPLATE_NRECORDS);
  v6_template.r[0].ie = htons (IPFIX_sourceIPv6Address);
  v6_template.r[0].length = htons (16);
  v6_template.r[1].ie = htons (IPFIX_destinationIPv6Address);
  v6_template.r[1].length = htons (16);
  v6_template.r[2].ie = htons (IPFIX_flowEndSysUpTime);
  v6_template.r[2].length = htons (4);
  v6_template.r[3].ie = htons (IPFIX_flowStartSysUpTime);
  v6_template.r[3].length = htons (4);
  v6_template.r[4].ie = htons (IPFIX_octetDeltaCount);
  v6_template.r[4].length = htons (4);
  v6_template.r[5].ie = htons (IPFIX_packetDeltaCount);
  v6_template.r[5].length = htons (4);
  v6_template.r[6].ie = htons (IPFIX_ingressInterface);
  v6_template.r[6].length = htons (4);
  v6_template.r[7].ie = htons (IPFIX_egressInterface);
  v6_template.r[7].length = htons (4);
  v6_template.r[8].ie = htons (IPFIX_sourceTransportPort);
  v6_template.r[8].length = htons (2);
  v6_template.r[9].ie = htons (IPFIX_destinationTransportPort);
  v6_template.r[9].length = htons (2);
  v6_template.r[10].ie = htons (IPFIX_protocolIdentifier);
  v6_template.r[10].length = htons (1);
  v6_template.r[11].ie = htons (IPFIX_tcpControlBits);
  v6_template.r[11].length = htons (1);
  v6_template.r[12].ie = htons (IPFIX_ipVersion);
  v6_template.r[12].length = htons (1);
  v6_template.r[13].ie = htons (IPFIX_ipClassOfService);
  v6_template.r[13].length = htons (1);
  /* legacy: IE 32 is kept for ICMPv6 too (byte-compatible with older releases) */
  v6_template.r[14].ie = htons (IPFIX_icmpTypeCodeIPv4);
  v6_template.r[14].length = htons (2);
  v6_template.r[15].ie = htons (IPFIX_vlanId);
  v6_template.r[15].length = htons (2);
}

/**
 * @brief Build the NetFlow v9 options template and options data record.
 *
 * @param ifidx  Interface index used as the option scope.
 * @param option Optional information; the sampling interval is taken from here.
 */
static void
nf9_init_option (u_int16_t ifidx, struct OPTION *option) {
  memset (&option_template, 0, sizeof (option_template));
  option_template.h.c.set_id = htons (NETFLOW9_OPTION_TEMPLATE_SET_ID);
  option_template.h.c.length = htons (sizeof (option_template));
  option_template.h.u.n.template_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  option_template.h.u.n.scope_length = htons (sizeof (option_template.s));
  option_template.h.u.n.option_length = htons (sizeof (option_template.r));
  option_template.s[0].ie = htons (IPFIX_OPTION_SCOPE_INTERFACE);
  option_template.s[0].length = htons (sizeof (option_data.scope_ifidx));
  option_template.r[0].ie = htons (IPFIX_samplingInterval);
  option_template.r[0].length =
    htons (sizeof (option_data.samplingInterval));
  option_template.r[1].ie = htons (IPFIX_samplingAlgorithm);
  option_template.r[1].length =
    htons (sizeof (option_data.samplingAlgorithm));

  memset (&option_data, 0, sizeof (option_data));
  option_data.c.set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  option_data.c.length = htons (sizeof (option_data));
  option_data.scope_ifidx = htonl (ifidx);
  option_data.samplingInterval = htonl (option->sample);
  option_data.samplingAlgorithm = IPFIX_SAMPLING_ALGORITHM_DETERMINISTIC;
}

/**
 * @brief Encode the records of one flow (one per direction that has traffic) into a data flowset.
 *
 * @param flow             Flow to encode.
 * @param packet           Output buffer.
 * @param len              Space available in packet.
 * @param ifidx            Interface index to put into the records.
 * @param system_boot_time Base for start/end times.
 * @param len_used         Receives the number of bytes written.
 * @return Number of records written, or -1 if the buffer is too small or the address family is unsupported.
 */
static int
nf_flow_to_flowset (const struct FLOW *flow, u_char * packet, u_int len,
                    u_int16_t ifidx, const struct timeval *system_boot_time,
                    u_int * len_used) {
  union {
    struct NETFLOW9_SOFTFLOWD_DATA_V4 d4;
    struct NETFLOW9_SOFTFLOWD_DATA_V6 d6;
  } d[2];
  struct NETFLOW9_SOFTFLOWD_DATA_COMMON *dc[2];
  u_int freclen, ret_len, nflows;

  memset (d, 0, sizeof (d));
  *len_used = nflows = ret_len = 0;
  switch (flow->af) {
  case AF_INET:
    freclen = sizeof (struct NETFLOW9_SOFTFLOWD_DATA_V4);
    memcpy (&d[0].d4.sourceIPv4Address, &flow->addr[0].v4, 4);
    memcpy (&d[0].d4.destinationIPv4Address, &flow->addr[1].v4, 4);
    memcpy (&d[1].d4.sourceIPv4Address, &flow->addr[1].v4, 4);
    memcpy (&d[1].d4.destinationIPv4Address, &flow->addr[0].v4, 4);
    dc[0] = &d[0].d4.c;
    dc[1] = &d[1].d4.c;
    dc[0]->ipVersion = dc[1]->ipVersion = 4;
    break;
  case AF_INET6:
    freclen = sizeof (struct NETFLOW9_SOFTFLOWD_DATA_V6);
    memcpy (&d[0].d6.sourceIPv6Address, &flow->addr[0].v6, 16);
    memcpy (&d[0].d6.destinationIPv6Address, &flow->addr[1].v6, 16);
    memcpy (&d[1].d6.sourceIPv6Address, &flow->addr[1].v6, 16);
    memcpy (&d[1].d6.destinationIPv6Address, &flow->addr[0].v6, 16);
    dc[0] = &d[0].d6.c;
    dc[1] = &d[1].d6.c;
    dc[0]->ipVersion = dc[1]->ipVersion = 6;
    break;
  default:
    return (-1);
  }

  dc[0]->flowStartSysUpTime = dc[1]->flowStartSysUpTime =
    htonl (timeval_sub_ms (&flow->flow_start, system_boot_time));
  dc[0]->flowEndSysUpTime = dc[1]->flowEndSysUpTime =
    htonl (timeval_sub_ms (&flow->flow_last, system_boot_time));
  dc[0]->octetDeltaCount = htonl (flow->octets[0]);
  dc[1]->octetDeltaCount = htonl (flow->octets[1]);
  dc[0]->packetDeltaCount = htonl (flow->packets[0]);
  dc[1]->packetDeltaCount = htonl (flow->packets[1]);
  dc[0]->ingressInterface = dc[0]->egressInterface = htonl (ifidx);
  dc[1]->ingressInterface = dc[1]->egressInterface = htonl (ifidx);
  dc[0]->sourceTransportPort = dc[1]->destinationTransportPort = flow->port[0];
  dc[1]->sourceTransportPort = dc[0]->destinationTransportPort = flow->port[1];
  dc[0]->protocolIdentifier = dc[1]->protocolIdentifier = flow->protocol;
  dc[0]->tcpControlBits = flow->tcp_flags[0];
  dc[1]->tcpControlBits = flow->tcp_flags[1];
  dc[0]->ipClassOfService = flow->tos[0];
  dc[1]->ipClassOfService = flow->tos[1];
  if (flow->protocol == IPPROTO_ICMP || flow->protocol == IPPROTO_ICMPV6) {
    dc[0]->icmpTypeCodeIPv4 = dc[0]->destinationTransportPort;
    dc[1]->icmpTypeCodeIPv4 = dc[1]->destinationTransportPort;
  }
  dc[0]->vlanId = dc[1]->vlanId = htons (flow->vlanid[0]);
  if (flow->octets[0] > 0) {
    if (ret_len + freclen > len)
      return (-1);
    memcpy (packet + ret_len, &d[0], freclen);
    ret_len += freclen;
    nflows++;
  }
  if (flow->octets[1] > 0) {
    if (ret_len + freclen > len)
      return (-1);
    memcpy (packet + ret_len, &d[1], freclen);
    ret_len += freclen;
    nflows++;
  }

  *len_used = ret_len;
  return (nflows);
}

/*
 * Given an array of expired flows, send netflow v9 report packets
 * Returns number of packets sent or -1 on error
 */
#if EXPORT_MERGE == EXPORT_MERGE_NONE
/**
 * @brief Send expired flows as NetFlow v9 export packets (legacy exporter, --enable-export-merge=none).
 *
 * @param sp Send parameters: flows to export, target destinations, interface index, tracking parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_netflow_v9 (struct SENDPARAMETER sp) {
  struct FLOW **flows = sp.flows;
  int num_flows = sp.num_flows;
  u_int16_t ifidx = sp.ifidx;
  struct FLOWTRACKPARAMETERS *param = sp.param;
  int verbose_flag = sp.verbose_flag;
  struct NETFLOW9_HEADER *nf9;
  struct IPFIX_SET_HEADER *dh;
  struct timeval now;
  u_int offset, last_af, i, j, num_packets, inc, last_valid;
  int r;
  u_char packet[NETFLOW9_SOFTFLOWD_MAX_PACKET_SIZE];
  struct timeval *system_boot_time = &param->system_boot_time;
  u_int64_t *flows_exported = &param->flows_exported;
  u_int64_t *packets_sent = &param->packets_sent;
  struct OPTION *option = &param->option;

  SET_EXPORT_NOW (now, param);

  if (nf9_pkts_until_template == -1) {
    nf9_init_template ();
    nf9_pkts_until_template = 0;
    if (option != NULL && option->sample > 1) {
      nf9_init_option (ifidx, option);
    }
  }

  last_valid = num_packets = 0;
  for (j = 0; j < (u_int) num_flows;) {
    memset (packet, 0, sizeof (packet));
    nf9 = (struct NETFLOW9_HEADER *) packet;

    nf9->version = htons (9);
    nf9->flows = 0;             /* Filled as we go, htons at end */
    nf9->sysUpTime = htonl (timeval_sub_ms (&now, system_boot_time));
    nf9->export_time = htonl ((u_int32_t) now.tv_sec);
    nf9->observation_domain_id = 0;
    offset = sizeof (*nf9);

    /* Refresh template headers if we need to */
    if (nf9_pkts_until_template <= 0) {
      memcpy (packet + offset, &v4_template, sizeof (v4_template));
      offset += sizeof (v4_template);
      nf9->flows++;
      memcpy (packet + offset, &v6_template, sizeof (v6_template));
      offset += sizeof (v6_template);
      nf9->flows++;
      if (option != NULL && option->sample > 1) {
        memcpy (packet + offset, &option_template, sizeof (option_template));
        offset += sizeof (option_template);
        nf9->flows++;
        memcpy (packet + offset, &option_data, sizeof (option_data));
        offset += sizeof (option_data);
        nf9->flows++;
      }

      nf9_pkts_until_template = IPFIX_DEFAULT_TEMPLATE_INTERVAL;
    }

    dh = NULL;
    last_af = 0;
    for (i = 0; i + j < (u_int) num_flows; i++) {
      if (dh == NULL || (u_int) flows[i + j]->af != last_af) {
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
        dh = (struct IPFIX_SET_HEADER *)
          (packet + offset);
        dh->set_id =
          (flows[i + j]->af == AF_INET) ?
          v4_template.h.r.template_id : v6_template.h.r.template_id;
        last_af = flows[i + j]->af;
        last_valid = offset;
        dh->length = sizeof (*dh);    /* Filled as we go */
        offset += sizeof (*dh);
      }

      r = nf_flow_to_flowset (flows[i + j], packet + offset,
                              sizeof (packet) - offset, ifidx,
                              system_boot_time, &inc);
      if (r <= 0) {
        /* yank off data header, if we had to go back */
        if (last_valid)
          offset = last_valid;
        break;
      }
      offset += inc;
      dh->length += inc;
      nf9->flows += r;
      last_valid = 0;           /* Don't clobber this header now */
      if (verbose_flag) {
        logit (LOG_DEBUG, "Flow %d/%d: "
               "r %d offset %d type %04x len %d(0x%04x) "
               "flows %d", r, i, j, offset,
               dh->set_id, dh->length, dh->length, nf9->flows);
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
    param->records_sent += nf9->flows;
    nf9->flows = htons (nf9->flows);
    nf9->sequence_number = htonl ((u_int32_t)
                           ((*packets_sent + num_packets +
                             1) & 0x00000000ffffffff));

    if (send_multi_destinations
        (sp.target->num_destinations, sp.target->destinations,
         sp.target->is_loadbalance, packet, offset, verbose_flag) < 0)
      return (-1);
    num_packets++;
    nf9_pkts_until_template--;

    j += i;
  }

  *flows_exported += j;
  param->packets_sent += num_packets;
#ifdef ENABLE_PTHREAD
  if (use_thread)
    free (sp.flows);
#endif /* ENABLE_PTHREAD */
  return (num_packets);
}
#endif /* EXPORT_MERGE == EXPORT_MERGE_NONE */

/**
 * @brief Request that the templates be sent again with the next export packet.
 */
void
netflow9_resend_template (void) {
  if (nf9_pkts_until_template > 0)
    nf9_pkts_until_template = 0;
}
