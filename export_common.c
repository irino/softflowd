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

#include "export_common.h"
#include "ipfix.h"
#include "common.h"
#include "log.h"
#include "netflow.h"
#include "psamp.h"
#include "softflowd.h"
#include "treetype.h"

/**
 * @brief Fill field specifiers of a template from a field table (also used by
 * psamp.c).
 *
 * @param dst          Template field specifier array to fill.
 * @param index        Position in dst to start at; advanced by field_number.
 * @param src          Field table (host byte order).
 * @param field_number Number of fields to copy.
 * @return Sum of the lengths of the copied fields.
 */
int
ipfix_init_fields (struct IPFIX_FIELD_SPECIFIER *dst, u_int *index,
                   const struct IPFIX_FIELD_SPECIFIER *src,
                   u_int field_number) {
  int length = 0;
  u_int i;
  for (i = 0; i < field_number; i++) {
    dst[*index + i].ie = htons (src[i].ie);
    dst[*index + i].length = htons (src[i].length);
    length += src[i].length;
  }
  *index += field_number;
  return length;
}

/**
 * @brief Convert a Unix time to a 64-bit NTP timestamp.
 *
 * @param tv  Unix time.
 * @param ntp Receives the NTP seconds and fraction; nothing is done if NULL.
 */
void
conv_unix_to_ntp (struct timeval tv, struct ntp_time_t *ntp) {
  if (ntp == NULL)
    return;
  ntp->second = tv.tv_sec + 0x83AA7E80;
  ntp->fraction =
    (uint32_t) ((double) (tv.tv_usec + 1) * (double) (1LL << 32) * 1.0e-6);
}

/**
 * @brief Convert a 64-bit NTP timestamp to a Unix time.
 *
 * @param ntp NTP timestamp.
 * @param tv  Receives the Unix time; nothing is done if NULL.
 */
void
conv_ntp_to_unix (struct ntp_time_t ntp, struct timeval *tv) {
  if (tv == NULL)
    return;
  tv->tv_sec =
    ntp.second - 0x83AA7E80;  // the seconds from Jan 1, 1900 to Jan 1, 1970
  tv->tv_usec = (uint32_t) ((double) ntp.fraction * 1.0e6 / (double) (1LL << 32));
}

/**
 * @brief Value of the IPFIX flowDirection element (IANA IE 61, RFC 7011).
 *
 * Without a direction MAC and ethernet tracking the endpoint index i is
 * returned instead.
 *
 * @param flow  Flow.
 * @param i     Endpoint index (0 or 1) of the record being encoded.
 * @param param Tracking parameters holding the direction MAC.
 * @return IPFIX_FLOWDIRECTION_EGRESS if the source MAC of endpoint i matches
 * the direction MAC, IPFIX_FLOWDIRECTION_INGRESS if its destination MAC does.
 */
u_int8_t
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

/**
 * @brief Select which of the TMPLMAX templates a flow uses (IPv4, ICMPv4, IPv6
 * or ICMPv6).
 *
 * @param flow Flow.
 * @return TMPLV4, TMPLICMPV4, TMPLV6 or TMPLICMPV6.
 */
u_int
ipfix_flow_to_template_index (const struct FLOW *flow) {
  if (flow->af == AF_INET)
    return (flow->protocol == IPPROTO_ICMP) ? TMPLICMPV4 : TMPLV4;
  if (flow->af == AF_INET6)
    return (flow->protocol == IPPROTO_ICMPV6) ? TMPLICMPV6 : TMPLV6;
  return TMPLV4;
}

/**
 * @brief Write the packet header for the given export version at the start of
 * the packet.
 *
 * Count, length and sequence fields are left 0 and patched in place once the
 * packet is complete.
 *
 * @param packet  Packet buffer.
 * @param version Export version: 1, 5, 9 or 10.
 * @param param   Tracking parameters (export time, boot time).
 * @return Size of the header in bytes.
 */
u_int
export_build_flow_header (u_char *packet, u_int16_t version,
                          const struct FLOWTRACKPARAMETERS *param) {
  struct timeval now;
  u_int32_t sysUpTime;

  SET_EXPORT_NOW (now, param);

  sysUpTime = timeval_sub_ms (&now, &param->system_boot_time);

  switch (version) {
    case 1:
    case 5: {
      /* The NetFlow v1 header is exactly the first NETFLOW1_HEADER_SIZE octets of
     * the v5 one, so v1 copies only that much. The members that are not set are
     * 0. */
      struct NETFLOW5_HEADER hdr = {
        .version = htons (version),
        .sysUpTime = htonl (sysUpTime),
        .export_time = htonl ((u_int32_t) now.tv_sec),
        .export_time_nanoseconds = htonl ((u_int32_t) now.tv_usec * 1000),
        .sampling_interval =
          param->option.sample > 0
            ? htons ((0x01 << 14) | (param->option.sample & 0x3FFF))
            : 0,
      };
      u_int len = (version == 1) ? NETFLOW1_HEADER_SIZE : sizeof (hdr);
      memcpy (packet, &hdr, len);
      return len;
    }
    case 9: {
      struct NETFLOW9_HEADER hdr = {
        .version = htons (version),
        .sysUpTime = htonl (sysUpTime),
        .export_time = htonl ((u_int32_t) now.tv_sec),
      };
      memcpy (packet, &hdr, sizeof (hdr));
      return sizeof (hdr);
    }
    default: { /* 10 = IPFIX */
      struct IPFIX_HEADER hdr = {
        .version = htons (version),
        .export_time = htonl ((u_int32_t) now.tv_sec),
      };
      memcpy (packet, &hdr, sizeof (hdr));
      return sizeof (hdr);
    }
  }
}

/** Packets until templates are sent again: -1 = not built yet, 0 or less = send
 * with the next packet, reset to IPFIX_DEFAULT_TEMPLATE_INTERVAL after sending.
 */
static int ipfix_pkts_until_template = -1;

/**
 * @brief Request that the templates be sent again with the next export packet.
 */
void
ipfix_resend_template (void) {
  if (ipfix_pkts_until_template > 0)
    ipfix_pkts_until_template = 0;
}

/**
 * @brief Tell whether a flow is ICMP (ICMPv4 for IPv4, ICMPv6 for IPv6).
 *
 * @param flow Flow.
 * @return 1 if the flow is ICMP, 0 otherwise.
 */
static int
valuate_icmp (const struct FLOW *flow) {
  if (flow->af == AF_INET)
    return flow->protocol == IPPROTO_ICMP;
  if (flow->af == AF_INET6)
    return flow->protocol == IPPROTO_ICMPV6;
  return 0;
}

/**
 * @brief Send flows as NetFlow v9 or IPFIX packets.
 *
 * Packet-framing loop that exports NetFlow v9 and IPFIX. Templates and the options record are sent first and
 * then every IPFIX_DEFAULT_TEMPLATE_INTERVAL packets; the records come from
 * ipfix_flow_to_flowset(), which builds them dynamically from the template
 * field lists.
 *
 * @param sp      Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow export.
 * @param version Export version: 9 or 10.
 * @return Number of packets sent, or -1 on error.
 */
static int
send_ipfix_flows (struct SENDPARAMETER sp, u_int8_t bi_flag,
                  u_int16_t version) {
  struct FLOW **flows = sp.flows;
  int num_flows = sp.num_flows;
  struct NETFLOW_TARGET *target = sp.target;
  struct FLOWTRACKPARAMETERS *param = sp.param;
  int verbose_flag = sp.verbose_flag;
  struct IPFIX_SET_HEADER *dh;
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

  if (ipfix_pkts_until_template == -1) {
    ipfix_init_exporter (&sp, bi_flag, version);
    ipfix_pkts_until_template = 0;
  }

  last_valid = num_packets = 0;
  for (j = 0; j < (u_int) num_flows;) {
    memset (packet, 0, sizeof (packet));
    offset = export_build_flow_header (packet, version, param);

    if (ipfix_pkts_until_template <= 0) {
      ipfix_put_templates (packet, &offset, bi_flag, version, &sp);
      ipfix_pkts_until_template = IPFIX_DEFAULT_TEMPLATE_INTERVAL;
      if (target->is_loadbalance && target->num_destinations > 1) {
        /* Template-only packet; NFv9 sets flows count to 1 (preserving
         * 'nf9->flows = htons(++records)' behavior in ipfix.c). */
        if (version == 10) {
          MEMCPY (packet + offsetof (struct IPFIX_HEADER, length),
                  &(u_int16_t) {htons (offset)}, u_int16_t);
          MEMCPY (packet + offsetof (struct IPFIX_HEADER, sequence_number),
                  &(u_int32_t) {htonl ((u_int32_t) (*records_sent &
                                                    0x00000000ffffffff))},
                  u_int32_t);
        } else {
          MEMCPY (packet + offsetof (struct NETFLOW9_HEADER, flows),
                  &(u_int16_t) {htons (1)}, u_int16_t);
          MEMCPY (packet + offsetof (struct NETFLOW9_HEADER, sequence_number),
                  &(u_int32_t) {htonl (sequence++)}, u_int32_t);
        }
        if (send_multi_destinations (target->num_destinations,
                                     target->destinations, 0, packet, offset,
                                     verbose_flag) < 0)
          return (-1);
        offset = export_build_flow_header (packet, version, param);
      }
    }

    dh = NULL;
    last_af = 0;
    last_icmp_flag = -1;
    records = 0;
    for (i = 0; i + j < (u_int) num_flows; i++) {
      icmp_flag = valuate_icmp (flows[i + j]);
      if (dh == NULL || (u_int) flows[i + j]->af != last_af ||
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
        dh->set_id = ipfix_template_set_id (tmplindex);
        last_af = flows[i + j]->af;
        last_icmp_flag = icmp_flag;
        last_valid = offset;
        dh->length = sizeof (*dh);
        offset += sizeof (*dh);
      }
      r = ipfix_flow_to_flowset (flows[i + j], packet + offset,
                                 sizeof (packet) - offset, &sp, &inc, bi_flag,
                                 version);
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
        logit (LOG_DEBUG, "Flow %d/%d: r %d offset %d ie %04x len %d(0x%04x)", r,
               i, j, offset, dh->set_id, dh->length, dh->length);
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
      MEMCPY (packet + offsetof (struct IPFIX_HEADER, length),
              &(u_int16_t) {htons (offset)}, u_int16_t);
      MEMCPY (packet + offsetof (struct IPFIX_HEADER, sequence_number),
              &(u_int32_t) {htonl ((u_int32_t) (*records_sent &
                                                0x00000000ffffffff))},
              u_int32_t);
    } else {
      MEMCPY (packet + offsetof (struct NETFLOW9_HEADER, flows),
              &(u_int16_t) {htons (records)}, u_int16_t);
      MEMCPY (packet + offsetof (struct NETFLOW9_HEADER, sequence_number),
              &(u_int32_t) {htonl (sequence++)}, u_int32_t);
    }

    if (send_multi_destinations (target->num_destinations, target->destinations,
                                 target->is_loadbalance, packet, offset,
                                 verbose_flag) < 0)
      return (-1);
    num_packets++;
    ipfix_pkts_until_template--;

    j += i;
  }

  *flows_exported += j;
  param->packets_sent += num_packets;
  return (num_packets);
}
#if COMPAT_EXPORT != COMPAT_EXPORT_STATIC_SEPARATE
/**
 * @brief Send expired flows as NetFlow v9 packets.
 *
 * Not defined for --enable-compat-export=static-separate, where
 * compat/netflow9.c does this.
 *
 *
 * @param sp Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_netflow_v9 (struct SENDPARAMETER sp) {
  return send_ipfix_flows (sp, 0, 9);
}
#endif /* COMPAT_EXPORT != COMPAT_EXPORT_STATIC_SEPARATE */

/**
 * @brief Send expired flows as IPFIX packets.
 *
 * @param sp Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_ipfix (struct SENDPARAMETER sp) {
  return send_ipfix_flows (sp, 0, 10);
}

/**
 * @brief Send expired flows as IPFIX biflow packets.
 *
 * @param sp Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @return Number of packets sent, or -1 on error.
 */
int
send_ipfix_bi (struct SENDPARAMETER sp) {
  return send_ipfix_flows (sp, 1, 10);
}
