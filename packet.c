/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
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

/**
 * @file packet.c
 * @brief Packet parsing: decode the datalink, IP and transport headers of a
 *   captured packet into a flow record and add it to the flow table.
 *   This file was split from softflowd.c.
 */

#include "softflowd.h"
#include "packet.h"
#include "expire.h"
#include "flow.h"
#include "format.h"
#include "globals.h"
#include "ipfix.h"
#include "log.h"
#include <netinet/icmp6.h>
#include <netinet/in.h>
#ifdef LINUX
#ifdef HAVE_LINUX_DCCP_H
#include <linux/dccp.h> /* struct dccp_hdr */
#endif
#endif /* LINUX */

/** @brief Describes a datalink header and how to extract v4/v6 frames from it */
struct DATALINK {
  int dlt;           /**< BPF datalink type */
  int skiplen;       /**< Number of bytes to skip datalink header */
  int ft_off;        /**< Datalink frametype offset */
  int ft_len;        /**< Datalink frametype length */
  int ft_is_be;      /**< Set if frametype is big-endian */
  u_int32_t ft_mask; /**< Mask applied to frametype */
  u_int32_t ft_v4;   /**< IPv4 frametype */
  u_int32_t ft_v6;   /**< IPv6 frametype */
};

/* Datalink types that we know about */
/**
 * The datalink types that softflowd reads, and where the headers are in
 * each.
 */
static const struct DATALINK lt[] = {
  {DLT_EN10MB, 14, 12, 2, 1, 0xffffffff, 0x0800, 0x86dd},
  {DLT_PPP, 5, 3, 2, 1, 0xffffffff, 0x0021, 0x0057},
#ifdef DLT_LINUX_SLL
  {DLT_LINUX_SLL, 16, 14, 2, 1, 0xffffffff, 0x0800, 0x86dd},
#endif
  {DLT_RAW, 0, 0, 1, 1, 0x000000f0, 0x0040, 0x0060},
  {DLT_NULL, 4, 0, 4, 0, 0xffffffff, AF_INET, AF_INET6},
#ifdef DLT_LOOP
  {DLT_LOOP, 4, 0, 4, 1, 0xffffffff, AF_INET, AF_INET6},
#endif
#ifdef DLT_PFLOG
  {DLT_PFLOG, 48, 1, 1, 0, 0x000000ff, AF_INET, AF_INET6},
#endif
  {-1, -1, -1, -1, -1, 0x00000000, 0xffff, 0xffff},
};

/** Offset just past a member of a struct, i.e. the bytes needed to read it. */
#define MEMBER_END(type, member) \
  (offsetof (type, member) + sizeof (((type *) 0)->member))

/** Bytes of a header that must be present: all of it if "full", else up to
 * and including its member "last". */
#define HDR_MIN_LEN(full, type, last) \
  ((full) ? sizeof (type) : MEMBER_END (type, last))

/**
 * @brief Fill in the transport-layer (TCP/UDP/SCTP/DCCP/ICMP/ICMPv6) parts of a
 * flow record.
 *
 * ICMP type and code are encoded into the destination port, like Cisco routers
 * do.
 *
 * @param flow             Flow record to fill.
 * @param pkt              Start of the transport header.
 * @param caplen           Bytes available at pkt.
 * @param protocol         IP protocol number.
 * @param ndx              Endpoint index (0 or 1) of the packet source.
 * @param full_l4hdr_check Non-zero to require the whole transport header.
 */
static void
transport_to_flowrec (struct FLOW *flow, const u_int8_t *pkt,
                      const size_t caplen, int protocol, int ndx,
                      int full_l4hdr_check) {
  size_t min_len;

  /*
   * Ports are stored per direction: slot "ndx" is the source side and
   * slot "ndx ^ 1" the destination side.  ndx is chosen by the caller
   * from the order of the IP addresses, so both directions of a flow
   * land in the same record.  Limitation: if source and destination
   * addresses are equal, both directions get ndx 0 and are not merged.
   */
  switch (protocol) {
    case IPPROTO_TCP:
      /* ports and flags */
      min_len = HDR_MIN_LEN (full_l4hdr_check, struct tcphdr, th_flags);
      break;
    case IPPROTO_UDP:
      min_len = HDR_MIN_LEN (full_l4hdr_check, struct udphdr, uh_dport);
      break;
#ifdef IPPROTO_DCCP
    case IPPROTO_DCCP:
#ifdef HAVE_LINUX_DCCP_H
      min_len = HDR_MIN_LEN (full_l4hdr_check, struct dccp_hdr, dccph_dport);
#else
      min_len = MEMBER_END (struct udphdr, uh_dport);
#endif /* HAVE_LINUX_DCCP_H */
      break;
#endif
#ifdef IPPROTO_SCTP
    case IPPROTO_SCTP: /* no header struct available: ports only */
      min_len = MEMBER_END (struct udphdr, uh_dport);
      break;
#endif
    case IPPROTO_ICMP:
      /* type and code */
      min_len = HDR_MIN_LEN (full_l4hdr_check, struct icmp, icmp_code);
      break;
    case IPPROTO_ICMPV6:
      /* type and code */
      min_len = HDR_MIN_LEN (full_l4hdr_check, struct icmp6_hdr, icmp6_code);
      break;
    default:
      return;
  }
  if (caplen < min_len)
    return;

  if (protocol == IPPROTO_TCP)
    flow->tcp_flags[ndx] |= pkt[offsetof (struct tcphdr, th_flags)];

  if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
    /* Encode ICMP type * 256 + code into the destination port, like Cisco */
    /* ICMP header also serves ICMPv6: both start with type and code */
    flow->port[ndx] = 0;
    flow->port[ndx ^ 1] =
      htons ((pkt[offsetof (struct icmp, icmp_type)] << 8) |
             pkt[offsetof (struct icmp, icmp_code)]);
  } else {
    /* UDP header also serves TCP, SCTP, DCCP:
     * all start with the source destination ports */
    /* ports are copied as they are on the wire */
    MEMCPY (&flow->port[ndx], pkt + offsetof (struct udphdr, uh_sport),
            flow->port[ndx]);
    MEMCPY (&flow->port[ndx ^ 1], pkt + offsetof (struct udphdr, uh_dport),
            flow->port[ndx ^ 1]);
  }
}

/**
 * @brief Convert an IPv4 packet to a partial flow record (used for comparison).
 *
 * @param flow     Flow record to fill.
 * @param pkt      Start of the IP header.
 * @param caplen   Bytes available at pkt.
 * @param isfrag   Set to 1 if the packet is a fragment.
 * @param isfirst  Set to 1 if it is the first fragment or not fragmented.
 * @param ndx      Set to the endpoint index (0 or 1) of the packet source in
 * canonical order.
 * @param track_lv Tracking level (TRACK_*).
 * @return IP header size in bytes, or a negative value on error (runt packet or
 * wrong IP version).
 */
/* The head is not shared through MEMCPY: the default works on a copy of the
 * header (ip.), the legacy one on a pointer into the packet (ip->). */
static int
ipv4_to_flowrec (struct FLOW *flow, const u_int8_t *pkt,
                 size_t caplen, int *isfrag, int *isfirst, int *ndx,
                 int track_lv) {
#ifndef ENABLE_DIRECT_COPIES /* default: aligned copies via memcpy */
  struct ip iph;
  const struct ip *ip = &iph;
  if (flow == NULL || pkt == NULL || isfrag == NULL || isfirst == NULL ||
      ndx == NULL || caplen < sizeof (iph))
    return (-1); /* Runt packet */
  memcpy (&iph, pkt, sizeof (iph));
  if (caplen < ip->ip_hl * 4 || ip->ip_v != 4)
    return (-1); /* Runt packet or Unsupported IP version */
#else            /* ENABLE_DIRECT_COPIES: legacy direct pointer casting */
  const struct ip *ip = (const struct ip *) pkt;
  if (flow == NULL || ip == NULL || isfrag == NULL || isfirst == NULL ||
      ndx == NULL || caplen < 20 || caplen < ip->ip_hl * 4 || ip->ip_v != 4)
    return (-1); /* Runt packet or Unsupported IP version */
#endif

  /* Prepare to store flow in canonical format */
  *ndx = memcmp (&ip->ip_src, &ip->ip_dst, sizeof (ip->ip_src)) > 0 ? 1 : 0;
  flow->addr[*ndx].v4 = ip->ip_src;
  flow->addr[*ndx ^ 1].v4 = ip->ip_dst;
  flow->protocol = track_lv >= TRACK_IP_PROTO ? ip->ip_p : 0;
  flow->tos[*ndx] = track_lv >= TRACK_FULL ? ip->ip_tos : 0;
  *isfrag = (ntohs (ip->ip_off) & (IP_OFFMASK | IP_MF)) ? 1 : 0;
  *isfirst = (ntohs (ip->ip_off) & IP_OFFMASK) == 0 ? 1 : 0;
  return (ip->ip_hl * 4);
}

/**
 * @brief Convert an IPv6 packet to a partial flow record (used for comparison).
 *
 * @param flow     Flow record to fill.
 * @param pkt      Start of the IPv6 header.
 * @param caplen   Bytes available at pkt.
 * @param isfrag   Set to 1 if the packet is a fragment.
 * @param isfirst  Set to 1 if it is the first fragment or not fragmented.
 * @param ndx      Set to the endpoint index (0 or 1) of the packet source in
 * canonical order.
 * @param track_lv Tracking level (TRACK_*).
 * @return Size of the IPv6 and extension headers in bytes, or a negative value
 * on error.
 */
/* The head is not shared through MEMCPY: the default works on a copy of the
 * header (ip6.), the legacy one on a pointer into the packet (ip6->). */
static int
ipv6_to_flowrec (struct FLOW *flow, const u_int8_t *pkt,
                 size_t caplen, int *isfrag, int *isfirst, int *ndx,
                 int track_lv) {
#ifndef ENABLE_DIRECT_COPIES /* default: aligned copies via memcpy */
  struct ip6_hdr ip6h;
  const struct ip6_hdr *ip6 = &ip6h;
  const struct ip6_ext *eh6;
  struct ip6_frag fh6;
#else /* ENABLE_DIRECT_COPIES: legacy direct pointer casting */
  const struct ip6_hdr *ip6 = (const struct ip6_hdr *) pkt;
  const struct ip6_ext *eh6;
  struct ip6_frag fh6;
#endif
  int nxt, size, remain;
#ifndef ENABLE_DIRECT_COPIES /* default: aligned copies via memcpy */
  if (flow == NULL || pkt == NULL || isfrag == NULL || isfirst == NULL ||
      ndx == NULL || caplen < sizeof (ip6h))
    return (-1); /* Runt packet */
  memcpy (&ip6h, pkt, sizeof (ip6h));
  if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
    return (-1); /* Unsupported IP version */
#else            /* ENABLE_DIRECT_COPIES: legacy direct pointer casting */
  if (flow == NULL || ip6 == NULL || isfrag == NULL || isfirst == NULL ||
      ndx == NULL || caplen < sizeof (*ip6) ||
      (ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
    return (-1); /* Runt packet or Unsupported IP version */
#endif

  *ndx = memcmp (&ip6->ip6_src, &ip6->ip6_dst, sizeof (ip6->ip6_src)) > 0 ? 1 : 0;
  flow->ip6_flowlabel[*ndx] = ip6->ip6_flow & IPV6_FLOWLABEL_MASK;
  flow->addr[*ndx].v6 = ip6->ip6_src;
  flow->addr[*ndx ^ 1].v6 = ip6->ip6_dst;

  *isfrag = 0;
  *isfirst = 1;
  nxt = ip6->ip6_nxt;
  size = sizeof (*ip6);

  /* Now loop through headers, looking for transport header */
  for (;;) {
    remain = caplen - size;
    eh6 = (const struct ip6_ext *) (pkt + size);
    if (nxt == IPPROTO_HOPOPTS || nxt == IPPROTO_ROUTING ||
        nxt == IPPROTO_DSTOPTS) {
      if (remain < (int) sizeof (*eh6))
        return (size); /* Runt */
      int eh6size = (eh6->ip6e_len + 1) << 3;
      if (remain < eh6size)
        return (size); /* Runt */
      nxt = eh6->ip6e_nxt;
      size += eh6size;
    } else if (nxt == IPPROTO_FRAGMENT) {
      *isfrag = 1;
      if (remain < (int) sizeof (fh6))
        return (size); /* Runt */
      MEMCPY (&fh6, eh6, fh6);
      if ((fh6.ip6f_offlg & IP6F_OFF_MASK) != 0)
        *isfirst = 0;
      nxt = fh6.ip6f_nxt;
      size += sizeof (fh6);
    } else
      break;
  }
  flow->protocol = track_lv >= TRACK_IP_PROTO ? nxt : 0;
  flow->tos[*ndx] = track_lv >= TRACK_FULL
                      ? (ntohl (ip6->ip6_flow) & 0x0ff00000) >> 20
                      : 0;
  return size;
}

/**
 * @brief Record the source and destination MAC addresses of an Ethernet frame
 * in a flow.
 *
 * @param flow  Flow record to fill.
 * @param ether Ethernet header; nothing is done if NULL.
 * @param ndx   Endpoint index of the frame source; nothing is done if negative.
 */
static void
ether_to_flowrec (struct FLOW *flow,
                  const struct ether_header *ether, int ndx) {
  if (ndx < 0 || ether == NULL)
    return;
  memcpy (flow->ethermac[ndx], ether->ether_shost, ETH_ALEN);
  memcpy (flow->ethermac[ndx ^ 1], ether->ether_dhost, ETH_ALEN);
  return;
}

/**
 * @brief Put the two directions of a flow record the other way round.
 *
 * Everything that is kept for each of the two endpoints changes places.
 */
static void
flow_swap_directions (struct FLOW *flow) {
  struct FLOW saved = *flow;
  int i;

  for (i = 0; i < 2; i++) {
    flow->octets[i] = saved.octets[i ^ 1];
    flow->packets[i] = saved.packets[i ^ 1];
    flow->ip6_flowlabel[i] = saved.ip6_flowlabel[i ^ 1];
    flow->addr[i] = saved.addr[i ^ 1];
    flow->port[i] = saved.port[i ^ 1];
    flow->tcp_flags[i] = saved.tcp_flags[i ^ 1];
    flow->tos[i] = saved.tos[i ^ 1];
    flow->vlanid[i] = saved.vlanid[i ^ 1];
    memcpy (flow->ethermac[i], saved.ethermac[i ^ 1], sizeof (flow->ethermac[i]));
  }
}

/**
 * @brief Main per-packet processing function.
 *
 * Takes a packet provided by libpcap and finds a matching flow, creating one if
 * none exists. Also marks flows for fast expiry, based on flow or packet
 * attributes; the actual expiry is performed elsewhere.
 *
 * @param cb_ctxt       Callback context (flow tracking state, target, link
 * type).
 * @param phdr          libpcap packet header.
 * @param frame         Start of the frame.
 * @param datalink_size Bytes of link-layer header to skip.
 * @param af            Address family of the IP packet.
 * @param vlanid        VLAN id of the frame, or 0.
 * @param num_label     Number of MPLS labels found.
 * @return PP_OK, PP_BAD_PACKET or PP_MALLOC_FAIL.
 */
int
process_packet (struct CB_CTXT *cb_ctxt,
                const struct pcap_pkthdr *phdr, const u_char *frame,
                int datalink_size, int af, u_int16_t vlanid,
                u_int8_t num_label) {
  struct FLOW tmp, *flow;
  u_int32_t idx;
  struct FLOWTRACK *ft = cb_ctxt->ft;
  const u_int32_t caplen = phdr->caplen - datalink_size;
  int frag = 0, first = 1, ndx = -1, i = 0, size = -1;
  const u_int8_t *pkt = frame + datalink_size + num_label * 4;
  /* Convert the IP packet to a flow identity */
  memset (&tmp, 0, sizeof (tmp));
  if (af == AF_INET) {
    size = ipv4_to_flowrec (&tmp, pkt, caplen, &frag, &first, &ndx,
                            ft->param.track_level);
  } else if (af == AF_INET6) {
    size = ipv6_to_flowrec (&tmp, pkt, caplen, &frag, &first, &ndx,
                            ft->param.track_level);
  }
  if ((af != AF_INET && af != AF_INET6) || ndx < 0 ||
      size == -1) { /* bad packet */
    ft->param.bad_packets++;
    return (PP_BAD_PACKET);
  }
  /* good packet */
  tmp.af = af;
  tmp.octets[ndx] = phdr->len - datalink_size;
  tmp.packets[ndx] = 1;

  if (frag)
    ft->param.frag_packets++;
  if (first && ft->param.track_level >= TRACK_IP_PROTO_PORT)
    transport_to_flowrec (&tmp, pkt + size, caplen - size, tmp.protocol, ndx,
                          ft->param.full_l4hdr_check);
  if (ft->param.track_level >= TRACK_FULL_VLAN)
    tmp.vlanid[ndx] = vlanid;
  if (ft->param.track_level >= TRACK_FULL_VLAN_ETHER &&
      cb_ctxt->linktype == DLT_EN10MB)
    ether_to_flowrec (&tmp, (const struct ether_header *) frame, ndx);

  /*
   * RFC 5103: the packets of the two directions of a flow belong to one
   * Biflow, also when the address is the same at both ends (a conversation
   * on a loopback interface, for one). The endpoints are put in canonical
   * order by the address, and by the port where the addresses are the same,
   * the lower first, so that the two directions find the same flow.
   */
  if (ndx == 0 &&
      memcmp (&tmp.addr[0], &tmp.addr[1], sizeof (tmp.addr[0])) == 0 &&
      ntohs (tmp.port[0]) > ntohs (tmp.port[1])) {
    flow_swap_directions (&tmp);
    ndx = 1;
  }

  tmp.mplsLabelStackDepth = num_label < 10 ? num_label : 10;
  for (i = 0; i < num_label && i < 10; i++) {
    MEMCPY (&tmp.mplsLabels[i],
            frame + datalink_size + i * sizeof (tmp.mplsLabels[i]),
            tmp.mplsLabels[i]);
  }

  /* If a matching flow does not exist, create and insert one */
  idx = flow_index (ft, &tmp);
  if ((flow = flow_table_find (ft, &tmp, idx)) == NULL) {
    /* Allocate and fill in the flow */
    if ((flow = flow_get (ft)) == NULL) {
      logit (LOG_ERR, "process_packet: flow_get failed", sizeof (*flow));
      return (PP_MALLOC_FAIL);
    }
    memcpy (flow, &tmp, sizeof (*flow));
    PCAP_TS_TO_TIMEVAL (flow->flow_start, phdr->ts);
    flow->flow_seq = ft->param.next_flow_seq++;
    flow_table_insert (ft, flow, idx);

    /* Allocate and fill in the associated expiry event */
    if ((flow->expiry = expiry_get (ft)) == NULL) {
      logit (LOG_ERR, "process_packet: expiry_get failed",
             sizeof (*flow->expiry));
      return (PP_MALLOC_FAIL);
    }
    flow->expiry->flow = flow;
    /* Must be non-zero (0 means expire immediately) */
    flow->expiry->expires_at = 1;
    flow->expiry->reason = R_GENERAL;
    flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;
    EXPIRY_INSERT (EXPIRIES, &ft->expiries, flow->expiry);

    ft->param.num_flows++;
    if (verbose_flag)
      logit (LOG_DEBUG, "ADD FLOW %s", format_flow_brief (flow));
  } else {
    /* Update flow statistics */
    flow->packets[0] += tmp.packets[0];
    flow->octets[0] += tmp.octets[0];
    flow->tcp_flags[0] |= tmp.tcp_flags[0];
    flow->packets[1] += tmp.packets[1];
    flow->octets[1] += tmp.octets[1];
    flow->tcp_flags[1] |= tmp.tcp_flags[1];
  }

  PCAP_TS_TO_TIMEVAL (flow->flow_last, phdr->ts);

  if (flow->expiry->expires_at != 0)
    flow_update_expiry (ft, flow);

  return (PP_OK);
}

/**
 * @brief Work out how many bytes of link-layer header to skip.
 *
 * If pkt is given, also checks whether it is a packet we are interested in
 * (IPv4 or IPv6).
 *
 * @param linktype  libpcap data link type.
 * @param pkt       Packet to inspect, or NULL to only check that the link type
 * is supported.
 * @param caplen    Bytes available at pkt.
 * @param af        Receives the address family (IPv4 or IPv6) of the payload.
 * @param vlanid    Receives the VLAN id, if any.
 * @param num_label Receives the number of MPLS labels, if any.
 * @return Number of bytes to skip, or -1 if the packet should be skipped
 * entirely.
 */
int
datalink_check (int linktype, const u_int8_t *pkt, u_int32_t caplen,
                int *af, u_int16_t *vlanid, u_int8_t *num_label) {
  int i, j;
  u_int32_t frametype;
  int vlan_size = 0;

  static const struct DATALINK *dl = NULL;

  /* Try to cache last used linktype */
  if (dl == NULL || dl->dlt != linktype) {
    for (i = 0; lt[i].dlt != linktype && lt[i].dlt != -1; i++)
      ;
    dl = &lt[i];
  }
  if (dl->dlt == -1 || pkt == NULL)
    return (dl->dlt);
  if (caplen <= (u_int32_t) dl->skiplen)
    return (-1);

  /* Suck out the frametype */
  frametype = 0;

  /* Processing 802.1Q vlan in ethernet */
  if (linktype == DLT_EN10MB) {
    for (j = 0; j < dl->ft_len; j++) {
      frametype <<= 8;
      frametype |= pkt[j + dl->ft_off];
    }
    frametype &= dl->ft_mask;
    if (frametype == ETHERTYPE_VLAN) {
      for (j = 0; j < 2; j++) {
        *vlanid <<= 8;
        *vlanid |= pkt[j + dl->skiplen];
      }
      /* Mask out the PCP and DEI values, leaving just the VID. */
      *vlanid &= 0xFFF;
      vlan_size = 4;
    }
  }
  frametype = 0;

  if (dl->ft_is_be) {
    for (j = 0; j < dl->ft_len; j++) {
      frametype <<= 8;
      frametype |= pkt[j + dl->ft_off + vlan_size];
    }
  } else {
    for (j = dl->ft_len - 1; j >= 0; j--) {
      frametype <<= 8;
      frametype |= pkt[j + dl->ft_off + vlan_size];
    }
  }
  frametype &= dl->ft_mask;

  if (frametype == dl->ft_v4)
    *af = AF_INET;
  else if (frametype == dl->ft_v6)
    *af = AF_INET6;
  else if (frametype == ETH_P_MPLS_UC && num_label != NULL) {
    u_int32_t shim = 0;
    u_int8_t ip_version = 0;
    do {
      MEMCPY (&shim,
              pkt + dl->skiplen + vlan_size + *num_label * sizeof (shim),
              shim);
      *num_label += 1;
    } while (!((ntohl (shim) & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT));
    ip_version = (pkt[dl->skiplen + vlan_size + *num_label * 4] & 0xf0) >> 4;
    if (ip_version == 4)
      *af = AF_INET;
    else if (ip_version == 6)
      *af = AF_INET6;
    else
      return (-1);
  } else
    return (-1);

  return (dl->skiplen + vlan_size);
}
