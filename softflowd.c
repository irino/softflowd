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

/*
 * This is software implementation of Cisco's NetFlow(tm) traffic       
 * reporting system. It operates by listening (via libpcap) on a        
 * promiscuous interface and tracking traffic flows.                    
 *
 * Traffic flows are recorded by source/destination/protocol
 * IP address or, in the case of TCP and UDP, by
 * src_addr:src_port/dest_addr:dest_port/protocol
 *
 * Flows expire automatically after a period of inactivity (default: 1
 * hour) They may also be evicted (in order of age) in situations where
 * there are more flows than slots available.
 *
 * Netflow compatible packets are sent to a specified target host upon
 * flow expiry.
 *
 * As this implementation watches traffic promiscuously, it is likely to
 * place significant load on hosts or gateways on which it is installed.
 */

#include "common.h"
#include "sys-tree.h"
#include "convtime.h"
#include "softflowd.h"
#include "treetype.h"
#include "freelist.h"
#include "log.h"
#include "netflow9.h"
#include "ipfix.h"
#include "psamp.h"
#include <pcap.h>
#ifdef LINUX
#include <net/if.h>
#endif /* LINUX */

#define IPFIX_PORT 4739

/* Global variables */
static int verbose_flag = 0;    /* Debugging flag */
static u_int16_t if_index = 0;  /* "manual" interface index */
static int track_level;
static int snaplen = 0;
#ifdef ENABLE_PTHREAD
pthread_mutex_t read_mutex;
pthread_cond_t read_cond;
int use_thread;
u_char packet_data[1500];
struct pcap_pkthdr packet_header;
struct FLOW *send_expired_flows;
#endif /* ENABLE_PTHREAD */

/* Signal handler flags */
static volatile sig_atomic_t graceful_shutdown_request = 0;

/* Describes a datalink header and how to extract v4/v6 frames from it */
struct DATALINK {
  int dlt;                      /* BPF datalink type */
  int skiplen;                  /* Number of bytes to skip datalink header */
  int ft_off;                   /* Datalink frametype offset */
  int ft_len;                   /* Datalink frametype length */
  int ft_is_be;                 /* Set if frametype is big-endian */
  u_int32_t ft_mask;            /* Mask applied to frametype */
  u_int32_t ft_v4;              /* IPv4 frametype */
  u_int32_t ft_v6;              /* IPv6 frametype */
};

/* Datalink types that we know about */
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

/* Netflow send functions */
typedef int (netflow_send_func_t) (struct SENDPARAMETER);

struct NETFLOW_SENDER {
  int version;
  netflow_send_func_t *func;
  netflow_send_func_t *bidir_func;
  int v6_capable;
};

/* Array of NetFlow export function that we know of. NB. nf[0] is default */
static const struct NETFLOW_SENDER nf[] = {
  {5, send_netflow_v5, NULL, 0},
  {1, send_netflow_v1, NULL, 0},
#ifdef ENABLE_LEGACY
  {9, send_netflow_v9, NULL, 1},
#else /* ENABLE_LEGACY */
  {9, send_nflow9, NULL, 1},
#endif /* ENABLE_LEGACY */
  {NF_VERSION_IPFIX, send_ipfix, send_ipfix_bi, 1},
#ifdef ENABLE_NTOPNG
  {SOFTFLOWD_NF_VERSION_NTOPNG, send_ntopng, NULL, 1},
#endif
};

static const struct NETFLOW_SENDER *
lookup_netflow_sender (int version) {
  int i, r;
  for (i = 0, r = version; i < sizeof (nf) / sizeof (struct NETFLOW_SENDER);
       i++) {
    if (nf[i].version == r)
      return &nf[i];
  }
  return NULL;
}

/* Signal handlers */
static void
sighand_graceful_shutdown (int signum) {
  graceful_shutdown_request = signum;
}

static void
sighand_other (int signum) {
  /* XXX: this may not be completely safe */
  logit (LOG_WARNING, "Exiting immediately on unexpected signal %d", signum);
  _exit (0);
}

/*
 * This is the flow comparison function.
 */
static int
flow_compare (struct FLOW *a, struct FLOW *b) {
  /* Be careful to avoid signed vs unsigned issues here */
  int r, i;
  if (track_level == TRACK_FULL_VLAN || track_level == TRACK_FULL_VLAN_ETHER) {
    if (a->vlanid[0] != b->vlanid[0])
      return (a->vlanid[0] > b->vlanid[0] ? 1 : -1);

    if (a->vlanid[1] != b->vlanid[1])
      return (a->vlanid[1] > b->vlanid[1] ? 1 : -1);
  }

  if (track_level == TRACK_FULL_VLAN_ETHER) {
    if ((r = memcmp (&a->ethermac[0], &b->ethermac[0], 6)) != 0)
      return (r > 0 ? 1 : -1);

    if ((r = memcmp (&a->ethermac[1], &b->ethermac[1], 6)) != 0)
      return (r > 0 ? 1 : -1);
  }

  if (a->af != b->af)
    return (a->af > b->af ? 1 : -1);

  if ((r = memcmp (&a->addr[0], &b->addr[0], sizeof (a->addr[0]))) != 0)
    return (r > 0 ? 1 : -1);

  if ((r = memcmp (&a->addr[1], &b->addr[1], sizeof (a->addr[1]))) != 0)
    return (r > 0 ? 1 : -1);

#ifdef notyet
  if (a->ip6_flowlabel[0] != 0 && b->ip6_flowlabel[0] != 0 &&
      a->ip6_flowlabel[0] != b->ip6_flowlabel[0])
    return (a->ip6_flowlabel[0] > b->ip6_flowlabel[0] ? 1 : -1);

  if (a->ip6_flowlabel[1] != 0 && b->ip6_flowlabel[1] != 0 &&
      a->ip6_flowlabel[1] != b->ip6_flowlabel[1])
    return (a->ip6_flowlabel[1] > b->ip6_flowlabel[1] ? 1 : -1);
#endif

  if (a->protocol != b->protocol)
    return (a->protocol > b->protocol ? 1 : -1);

  if (a->port[0] != b->port[0])
    return (ntohs (a->port[0]) > ntohs (b->port[0]) ? 1 : -1);

  if (a->port[1] != b->port[1])
    return (ntohs (a->port[1]) > ntohs (b->port[1]) ? 1 : -1);

  if (a->mplsLabelStackDepth != b->mplsLabelStackDepth)
    return (a->mplsLabelStackDepth > b->mplsLabelStackDepth ? 1 : -1);
  for (i = 0; i < a->mplsLabelStackDepth; i++) {
    if (a->mplsLabels[i] != b->mplsLabels[i])
      return (a->mplsLabels[i] > b->mplsLabels[i] ? 1 : -1);
  }

  return (0);
}

/* Generate functions for flow tree */
FLOW_PROTOTYPE (FLOWS, FLOW, trp, flow_compare);
FLOW_GENERATE (FLOWS, FLOW, trp, flow_compare);

/*
 * This is the expiry comparison function.
 */
static int
expiry_compare (struct EXPIRY *a, struct EXPIRY *b) {
  if (a->expires_at != b->expires_at)
    return (a->expires_at > b->expires_at ? 1 : -1);

  /* Make expiry entries unique by comparing flow sequence */
  if (a->flow->flow_seq != b->flow->flow_seq)
    return (a->flow->flow_seq > b->flow->flow_seq ? 1 : -1);

  return (0);
}

/* Generate functions for flow tree */
EXPIRY_PROTOTYPE (EXPIRIES, EXPIRY, trp, expiry_compare);
EXPIRY_GENERATE (EXPIRIES, EXPIRY, trp, expiry_compare);

static struct FLOW *
flow_get (struct FLOWTRACK *ft) {
  return freelist_get (&ft->flow_freelist);
}

static void
flow_put (struct FLOWTRACK *ft, struct FLOW *flow) {
  return freelist_put (&ft->flow_freelist, flow);
}

static struct EXPIRY *
expiry_get (struct FLOWTRACK *ft) {
  return freelist_get (&ft->expiry_freelist);
}

static void
expiry_put (struct FLOWTRACK *ft, struct EXPIRY *expiry) {
  return freelist_put (&ft->expiry_freelist, expiry);
}

#if 0
/* Dump a packet */
static void
dump_packet (const u_int8_t * p, int len) {
  char buf[1024], tmp[3];
  int i;

  for (*buf = '\0', i = 0; i < len; i++) {
    snprintf (tmp, sizeof (tmp), "%02x%s", p[i], i % 2 ? " " : "");
    if (strlcat (buf, tmp, sizeof (buf) - 4) >= sizeof (buf) - 4) {
      strlcat (buf, "...", sizeof (buf));
      break;
    }
  }
  logit (LOG_INFO, "packet len %d: %s", len, buf);
}
#endif

/* Format a time in an ISOish format */
static const char *
format_time (time_t t) {
  struct tm *tm;
  static char buf[32];

  tm = gmtime (&t);
  strftime (buf, sizeof (buf), "%Y-%m-%dT%H:%M:%S", tm);

  return (buf);

}

static const char *
format_ethermac (uint8_t ethermac[6]) {
  static char buf[1024];
  snprintf (buf, sizeof (buf), "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            ethermac[0], ethermac[1], ethermac[2], ethermac[3],
            ethermac[4], ethermac[5]);
  return buf;
}

/* Format a flow in a verbose and ugly way */
static const char *
format_flow (struct FLOW *flow) {
  char addr1[64], addr2[64], start_time[32], fin_time[32];
  static char buf[4096];

  inet_ntop (flow->af, &flow->addr[0], addr1, sizeof (addr1));
  inet_ntop (flow->af, &flow->addr[1], addr2, sizeof (addr2));

  snprintf (start_time, sizeof (start_time), "%s",
            format_time (flow->flow_start.tv_sec));
  snprintf (fin_time, sizeof (fin_time), "%s",
            format_time (flow->flow_last.tv_sec));

  snprintf (buf, sizeof (buf),
            "seq:%" PRIu64 " [%s]:%hu <> [%s]:%hu proto:%u "
            "octets>:%u packets>:%u octets<:%u packets<:%u "
            "start:%s.%03lld finish:%s.%03lld tcp>:%02x tcp<:%02x "
            "flowlabel>:%08x flowlabel<:%08x "
            "vlan>:%u vlan<:%u ether:%s <> %s", flow->flow_seq, addr1,
            ntohs (flow->port[0]), addr2, ntohs (flow->port[1]),
            (int) flow->protocol, flow->octets[0], flow->packets[0],
            flow->octets[1], flow->packets[1], start_time,
            (long long) ((flow->flow_start.tv_usec + 500) / 1000), fin_time,
            (long long) ((flow->flow_last.tv_usec + 500) / 1000),
            flow->tcp_flags[0], flow->tcp_flags[1], flow->ip6_flowlabel[0],
            flow->ip6_flowlabel[1], flow->vlanid[0], flow->vlanid[1],
            format_ethermac (flow->ethermac[0]),
            format_ethermac (flow->ethermac[1]));

  return (buf);
}

/* Format a flow in a brief way */
static const char *
format_flow_brief (struct FLOW *flow) {
  char addr1[64], addr2[64];
  static char buf[4096];

  inet_ntop (flow->af, &flow->addr[0], addr1, sizeof (addr1));
  inet_ntop (flow->af, &flow->addr[1], addr2, sizeof (addr2));

  snprintf (buf, sizeof (buf),
            "seq:%" PRIu64 " [%s]:%hu <> [%s]:%hu proto:%u "
            "vlan>:%u vlan<:%u  ether:%s <> %s ",
            flow->flow_seq,
            addr1, ntohs (flow->port[0]), addr2, ntohs (flow->port[1]),
            (int) flow->protocol, flow->vlanid[0], flow->vlanid[1],
            format_ethermac (flow->ethermac[0]),
            format_ethermac (flow->ethermac[1]));

  return (buf);
}

/* Fill in transport-layer (tcp/udp) portions of flow record */
static int
transport_to_flowrec (struct FLOW *flow, const u_int8_t * pkt,
                      const size_t caplen, int isfrag, int protocol, int ndx) 
{
  const struct tcphdr *tcp = (const struct tcphdr *) pkt;
  const struct udphdr *udp = (const struct udphdr *) pkt;
  const struct icmp *icmp = (const struct icmp *) pkt;

  /*
   * XXX to keep flow in proper canonical format, it may be necessary to
   * swap the array slots based on the order of the port numbers does
   * this matter in practice??? I don't think so - return flows will
   * always match, because of their symmetrical addr/ports
   */

  switch (protocol) {
  case IPPROTO_TCP:
    /* Check for runt packet, but don't error out on short frags */
    if (caplen < sizeof (*tcp))
      return (isfrag ? 0 : 1);
    flow->port[ndx] = tcp->th_sport;
    flow->port[ndx ^ 1] = tcp->th_dport;
    flow->tcp_flags[ndx] |= tcp->th_flags;
    break;
  case IPPROTO_UDP:
    /* Check for runt packet, but don't error out on short frags */
    if (caplen < sizeof (*udp))
      return (isfrag ? 0 : 1);
    flow->port[ndx] = udp->uh_sport;
    flow->port[ndx ^ 1] = udp->uh_dport;
    break;
  case IPPROTO_ICMP:
  case IPPROTO_ICMPV6:
    /*
     * Encode ICMP type * 256 + code into dest port like
     * Cisco routers
     */
    flow->port[ndx] = 0;
    flow->port[ndx ^ 1] = htons (icmp->icmp_type * 256 + icmp->icmp_code);
    break;
  }
  return (0);
}

static int
make_ndx_ipv4 (const struct ip *ip, size_t caplen) {
  if (caplen < 20 || caplen < ip->ip_hl * 4)
    return (-1);                /* Runt packet */
  if (ip->ip_v != 4)
    return (-1);                /* Unsupported IP version */

  /* Prepare to store flow in canonical format */
  return (memcmp (&ip->ip_src, &ip->ip_dst, sizeof (ip->ip_src)) > 0 ? 1 : 0);
}

/* Convert a IPv4 packet to a partial flow record (used for comparison) */
static int
ipv4_to_flowrec (struct FLOW *flow, const u_int8_t * pkt, size_t caplen,
                 size_t len, int *isfrag, int af, int ndx) {
  const struct ip *ip = (const struct ip *) pkt;
  //int ndx = make_ndx_ipv4 (ip, caplen);
  if (ndx < 0)
    return (-1);

  flow->af = af;
  flow->addr[ndx].v4 = ip->ip_src;
  flow->addr[ndx ^ 1].v4 = ip->ip_dst;
  flow->protocol = ip->ip_p;
  flow->octets[ndx] = len;
  flow->packets[ndx] = 1;
  flow->tos[ndx] = ip->ip_tos;

  *isfrag = (ntohs (ip->ip_off) & (IP_OFFMASK | IP_MF)) ? 1 : 0;

  /* Don't try to examine higher level headers if not first fragment */
  if (*isfrag && (ntohs (ip->ip_off) & IP_OFFMASK) != 0)
    return (0);

  return (transport_to_flowrec (flow, pkt + (ip->ip_hl * 4),
                                caplen - (ip->ip_hl * 4), *isfrag, ip->ip_p,
                                ndx));
}

static int
make_ndx_ipv6 (const struct ip6_hdr *ip6, size_t caplen) {
  if (caplen < sizeof (*ip6))
    return (-1);                /* Runt packet */

  if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
    return (-1);                /* Unsupported IPv6 version */

  /* Prepare to store flow in canonical format */
  return (memcmp (&ip6->ip6_src, &ip6->ip6_dst,
                  sizeof (ip6->ip6_src)) > 0 ? 1 : 0);
}

/* Convert a IPv6 packet to a partial flow record (used for comparison) */
static int
ipv6_to_flowrec (struct FLOW *flow, const u_int8_t * pkt, size_t caplen,
                 size_t len, int *isfrag, int af, int ndx) {
  const struct ip6_hdr *ip6 = (const struct ip6_hdr *) pkt;
  const struct ip6_ext *eh6;
  const struct ip6_frag *fh6;
  int nxt;

  if (ndx < 0)
    return (-1);

  flow->af = af;
  flow->ip6_flowlabel[ndx] = ip6->ip6_flow & IPV6_FLOWLABEL_MASK;
  flow->addr[ndx].v6 = ip6->ip6_src;
  flow->addr[ndx ^ 1].v6 = ip6->ip6_dst;
  flow->octets[ndx] = len;
  flow->packets[ndx] = 1;
  flow->tos[ndx] = (ntohl (ip6->ip6_flow) & ntohl (0x0ff00000)) >> 20;

  *isfrag = 0;
  nxt = ip6->ip6_nxt;
  pkt += sizeof (*ip6);
  caplen -= sizeof (*ip6);

  /* Now loop through headers, looking for transport header */
  for (;;) {
    eh6 = (const struct ip6_ext *) pkt;
    if (nxt == IPPROTO_HOPOPTS ||
        nxt == IPPROTO_ROUTING || nxt == IPPROTO_DSTOPTS) {
      if (caplen < sizeof (*eh6) || caplen < (eh6->ip6e_len + 1) << 3)
        return (1);             /* Runt */
      nxt = eh6->ip6e_nxt;
      pkt += (eh6->ip6e_len + 1) << 3;
      caplen -= (eh6->ip6e_len + 1) << 3;
    } else if (nxt == IPPROTO_FRAGMENT) {
      *isfrag = 1;
      fh6 = (const struct ip6_frag *) eh6;
      if (caplen < sizeof (*fh6))
        return (1);             /* Runt */
      /*
       * Don't try to examine higher level headers if 
       * not first fragment
       */
      if ((fh6->ip6f_offlg & IP6F_OFF_MASK) != 0)
        return (0);
      nxt = fh6->ip6f_nxt;
      pkt += sizeof (*fh6);
      caplen -= sizeof (*fh6);
    } else
      break;
  }
  flow->protocol = nxt;

  return (transport_to_flowrec (flow, pkt, caplen, *isfrag, nxt, ndx));
}

static int
vlan_to_flowrec (struct FLOW *flow, u_int16_t vlanid, int ndx) {
  if (ndx < 0)
    return (-1);
  return (flow->vlanid[ndx] = vlanid);

}

static int
ether_to_flowrec (struct FLOW *flow, struct ether_header *ether, int ndx) {
  if (ndx < 0)
    return (-1);
  if (ether == NULL)
    return (-1);
  memcpy (flow->ethermac[ndx], ether->ether_shost, ETH_ALEN);
  memcpy (flow->ethermac[ndx ^ 1], ether->ether_dhost, ETH_ALEN);
  return (1);
}

static void
flow_update_expiry (struct FLOWTRACK *ft, struct FLOW *flow) {
  EXPIRY_REMOVE (EXPIRIES, &ft->expiries, flow->expiry);

  /* Flows over 2 GiB traffic */
  if (flow->octets[0] > (1U << 31) || flow->octets[1] > (1U << 31)) {
    flow->expiry->expires_at = 0;
    flow->expiry->reason = R_OVERBYTES;
    flow->flowEndReason = IPFIX_flowEndReason_lackOfResource;
    goto out;
  }

  /* Flows over maximum life seconds */
  if (ft->param.maximum_lifetime != 0 &&
      flow->flow_last.tv_sec - flow->flow_start.tv_sec >
      ft->param.maximum_lifetime) {
    flow->expiry->expires_at = 0;
    flow->expiry->reason = R_MAXLIFE;
    flow->flowEndReason = IPFIX_flowEndReason_activeTimeout;
    goto out;
  }

  if (flow->protocol == IPPROTO_TCP) {
    /* Reset TCP flows */
    if (ft->param.tcp_rst_timeout != 0 &&
        ((flow->tcp_flags[0] & TH_RST) || (flow->tcp_flags[1] & TH_RST))) {
      flow->expiry->expires_at = flow->flow_last.tv_sec +
        ft->param.tcp_rst_timeout;
      flow->expiry->reason = R_TCP_RST;
      flow->flowEndReason = IPFIX_flowEndReason_endOfFlow;
      goto out;
    }
    /* Finished TCP flows */
    if (ft->param.tcp_fin_timeout != 0 &&
        ((flow->tcp_flags[0] & TH_FIN) && (flow->tcp_flags[1] & TH_FIN))) {
      flow->expiry->expires_at = flow->flow_last.tv_sec +
        ft->param.tcp_fin_timeout;
      flow->expiry->reason = R_TCP_FIN;
      flow->flowEndReason = IPFIX_flowEndReason_endOfFlow;
      goto out;
    }

    /* TCP flows */
    if (ft->param.tcp_timeout != 0) {
      flow->expiry->expires_at = flow->flow_last.tv_sec +
        ft->param.tcp_timeout;
      flow->expiry->reason = R_TCP;
      flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;
      goto out;
    }
  }

  if (ft->param.udp_timeout != 0 && flow->protocol == IPPROTO_UDP) {
    /* UDP flows */
    flow->expiry->expires_at = flow->flow_last.tv_sec + ft->param.udp_timeout;
    flow->expiry->reason = R_UDP;
    flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;
    goto out;
  }

  if (ft->param.icmp_timeout != 0 &&
      ((flow->af == AF_INET && flow->protocol == IPPROTO_ICMP) ||
       ((flow->af == AF_INET6 && flow->protocol == IPPROTO_ICMPV6)))) {
    /* ICMP flows */
    flow->expiry->expires_at = flow->flow_last.tv_sec +
      ft->param.icmp_timeout;
    flow->expiry->reason = R_ICMP;
    flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;
    goto out;
  }

  /* Everything else */
  flow->expiry->expires_at = flow->flow_last.tv_sec +
    ft->param.general_timeout;
  flow->expiry->reason = R_GENERAL;
  flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;

out:
  if (ft->param.maximum_lifetime != 0 && flow->expiry->expires_at != 0) {
    flow->expiry->expires_at = MIN (flow->expiry->expires_at,
                                    flow->flow_start.tv_sec +
                                    ft->param.maximum_lifetime);
  }

  EXPIRY_INSERT (EXPIRIES, &ft->expiries, flow->expiry);
}


/* Return values from process_packet */
#define PP_OK		0
#define PP_BAD_PACKET	-2
#define PP_MALLOC_FAIL	-3

/*
 * Main per-packet processing function. Take a packet (provided by 
 * libpcap) and attempt to find a matching flow. If no such flow exists, 
 * then create one. 
 *
 * Also marks flows for fast expiry, based on flow or packet attributes
 * (the actual expiry is performed elsewhere)
 */
static int
process_packet (struct FLOWTRACK *ft, const u_int8_t * frame_data, int af,
                const u_int32_t caplen, const u_int32_t len,
                struct ether_header *ether, u_int16_t vlanid,
                const struct timeval *received_time, u_int8_t num_label) {
  struct FLOW tmp, *flow;
  int frag, ndx, i;
  const u_int8_t *pkt = frame_data + num_label * 4;
  /* Convert the IP packet to a flow identity */
  memset (&tmp, 0, sizeof (tmp));
  switch (af) {
  case AF_INET:
    ndx = make_ndx_ipv4 ((const struct ip *) pkt, caplen);
    if (ipv4_to_flowrec (&tmp, pkt, caplen, len, &frag, af, ndx) == -1)
      goto bad;
    break;
  case AF_INET6:
    ndx = make_ndx_ipv6 ((const struct ip6_hdr *) pkt, caplen);
    if (ipv6_to_flowrec (&tmp, pkt, caplen, len, &frag, af, ndx) == -1)
      goto bad;
    break;
  default:
  bad:
    ft->param.bad_packets++;
    return (PP_BAD_PACKET);
  }

  if (frag)
    ft->param.frag_packets++;

  /* Zero out bits of the flow that aren't relevant to tracking level */
  switch (ft->param.track_level) {
  case TRACK_IP_ONLY:
    tmp.protocol = 0;
    /* FALLTHROUGH */
  case TRACK_IP_PROTO:
    tmp.port[0] = tmp.port[1] = 0;
    tmp.tcp_flags[0] = tmp.tcp_flags[1] = 0;
    /* FALLTHROUGH */
  case TRACK_FULL:
    tmp.vlanid[0] = tmp.vlanid[1] = 0;
    break;
  case TRACK_FULL_VLAN_ETHER:
    ether_to_flowrec (&tmp, ether, ndx);
    /* FALLTHROUGH */
  case TRACK_FULL_VLAN:
    vlan_to_flowrec (&tmp, vlanid, ndx);
    break;
  }

  tmp.mplsLabelStackDepth = num_label;
  for (i = 0; i < num_label && i < 10; i++) {
    tmp.mplsLabels[i] = *(((u_int32_t *) frame_data) + i);
  }

  /* If a matching flow does not exist, create and insert one */
  if ((flow = FLOW_FIND (FLOWS, &ft->flows, &tmp)) == NULL) {
    /* Allocate and fill in the flow */
    if ((flow = flow_get (ft)) == NULL) {
      logit (LOG_ERR, "process_packet: flow_get failed", sizeof (*flow));
      return (PP_MALLOC_FAIL);
    }
    memcpy (flow, &tmp, sizeof (*flow));
    memcpy (&flow->flow_start, received_time, sizeof (flow->flow_start));
    flow->flow_seq = ft->param.next_flow_seq++;
    FLOW_INSERT (FLOWS, &ft->flows, flow);

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

  memcpy (&flow->flow_last, received_time, sizeof (flow->flow_last));

  if (flow->expiry->expires_at != 0)
    flow_update_expiry (ft, flow);

  return (PP_OK);
}

/*
 * Subtract two timevals. Returns (t1 - t2) in milliseconds.
 */
u_int32_t
timeval_sub_ms (const struct timeval *t1, const struct timeval *t2) {
  struct timeval res;

  res.tv_sec = t1->tv_sec - t2->tv_sec;
  res.tv_usec = t1->tv_usec - t2->tv_usec;
  if (res.tv_usec < 0) {
    res.tv_usec += 1000000L;
    res.tv_sec--;
  }
  return ((u_int32_t) res.tv_sec * 1000 + (u_int32_t) res.tv_usec / 1000);
}

int
send_multi_destinations (int num_destinations,
                         struct DESTINATION *destinations,
                         u_int8_t is_loadbalance, u_int8_t * packet,
                         int size) {
  struct DESTINATION *dest;
  int i, err;
  socklen_t errsz;
  static u_int64_t sent = 0;
  for (i = 0; i < num_destinations; i++) {
    if (!is_loadbalance || (is_loadbalance && (sent % num_destinations == i))) {
      dest = &destinations[i];
      errsz = sizeof (err);
      getsockopt (dest->sock, SOL_SOCKET, SO_ERROR, &err, &errsz);      // Clear ICMP errors
      if (send (dest->sock, packet, (size_t) size, 0) == -1)
        return (-1);
    }
  }
  sent++;
  return is_loadbalance ? 1 : i;
}

static void
update_statistic (struct STATISTIC *s, double new, double n) {
  if (n == 1.0) {
    s->min = s->mean = s->max = new;
    return;
  }

  s->min = MIN (s->min, new);
  s->max = MAX (s->max, new);

  s->mean = s->mean + ((new - s->mean) / n);
}

/* Update global statistics */
static void
update_statistics (struct FLOWTRACK *ft, struct FLOW *flow) {
  double tmp;
  static double n = 1.0;

  ft->param.flows_expired++;
  ft->param.flows_pp[flow->protocol % 256]++;

  tmp = (double) flow->flow_last.tv_sec +
    ((double) flow->flow_last.tv_usec / 1000000.0);
  tmp -= (double) flow->flow_start.tv_sec +
    ((double) flow->flow_start.tv_usec / 1000000.0);
  if (tmp < 0.0)
    tmp = 0.0;

  update_statistic (&ft->param.duration, tmp, n);
  update_statistic (&ft->param.duration_pp[flow->protocol], tmp,
                    (double) ft->param.flows_pp[flow->protocol % 256]);

  tmp = flow->octets[0] + flow->octets[1];
  update_statistic (&ft->param.octets, tmp, n);
  ft->param.octets_pp[flow->protocol % 256] += tmp;

  tmp = flow->packets[0] + flow->packets[1];
  update_statistic (&ft->param.packets, tmp, n);
  ft->param.packets_pp[flow->protocol % 256] += tmp;

  n++;
}

static void
update_expiry_stats (struct FLOWTRACK *ft, struct EXPIRY *e) {
  switch (e->reason) {
  case R_GENERAL:
    ft->param.expired_general++;
    break;
  case R_TCP:
    ft->param.expired_tcp++;
    break;
  case R_TCP_RST:
    ft->param.expired_tcp_rst++;
    break;
  case R_TCP_FIN:
    ft->param.expired_tcp_fin++;
    break;
  case R_UDP:
    ft->param.expired_udp++;
    break;
  case R_ICMP:
    ft->param.expired_icmp++;
    break;
  case R_MAXLIFE:
    ft->param.expired_maxlife++;
    break;
  case R_OVERBYTES:
    ft->param.expired_overbytes++;
    break;
  case R_OVERFLOWS:
    ft->param.expired_maxflows++;
    break;
  case R_FLUSH:
    ft->param.expired_flush++;
    break;
  }
}

/* How long before the next expiry event in millisecond */
static int
next_expire (struct FLOWTRACK *ft) {
  struct EXPIRY *expiry;
  struct timeval now;
  u_int32_t expires_at, ret, fudge;

  if (ft->param.adjust_time)
    now = ft->param.last_packet_time;
  else
    gettimeofday (&now, NULL);

  if ((expiry = EXPIRY_MIN (EXPIRIES, &ft->expiries)) == NULL)
    return (-1);                /* indefinite */

  expires_at = expiry->expires_at;

  /* Don't cluster urgent expiries */
  if (expires_at == 0 && (expiry->reason == R_OVERBYTES ||
                          expiry->reason == R_OVERFLOWS
                          || expiry->reason == R_FLUSH))
    return (0);                 /* Now */

  /* Cluster expiries by expiry_interval */
  if (ft->param.expiry_interval > 1) {
    if ((fudge = expires_at % ft->param.expiry_interval) > 0)
      expires_at += ft->param.expiry_interval - fudge;
  }

  if (expires_at < now.tv_sec)
    return (0);                 /* Now */

  ret = 999 + (expires_at - now.tv_sec) * 1000;
  return (ret);
}

/*
 * Scan the tree of expiry events and process expired flows. If zap_all
 * is set, then forcibly expire all flows.
 */
#define CE_EXPIRE_NORMAL	0       /* Normal expiry processing */
#define CE_EXPIRE_ALL		-1      /* Expire all flows immediately */
#define CE_EXPIRE_FORCED	1       /* Only expire force-expired flows */
static int
check_expired (struct FLOWTRACK *ft, struct NETFLOW_TARGET *target, int ex) {
  struct FLOW **expired_flows, **oldexp;
  int num_expired, i, r;
  struct timeval now;

  struct EXPIRY *expiry, *nexpiry;

  if (ft->param.adjust_time)
    now = ft->param.last_packet_time;
  else
    gettimeofday (&now, NULL);

  r = 0;
  num_expired = 0;
  expired_flows = NULL;

  if (verbose_flag)
    logit (LOG_DEBUG, "Starting expiry scan: mode %d", ex);

  for (expiry = EXPIRY_MIN (EXPIRIES, &ft->expiries);
       expiry != NULL; expiry = nexpiry) {
    nexpiry = EXPIRY_NEXT (EXPIRIES, &ft->expiries, expiry);
    if ((expiry->expires_at == 0) || (ex == CE_EXPIRE_ALL) ||
        (ex != CE_EXPIRE_FORCED && (expiry->expires_at < now.tv_sec))) {
      /* Flow has expired */
      if (ft->param.maximum_lifetime != 0 &&
          expiry->flow->flow_last.tv_sec -
          expiry->flow->flow_start.tv_sec >= ft->param.maximum_lifetime)
        expiry->reason = R_MAXLIFE;

      if (verbose_flag)
        logit (LOG_DEBUG,
               "Queuing flow seq:%" PRIu64 " (%p) for expiry "
               "reason %d", expiry->flow->flow_seq,
               expiry->flow, expiry->reason);

      /* Add to array of expired flows */
      oldexp = expired_flows;
      expired_flows = realloc (expired_flows,
                               sizeof (*expired_flows) * (num_expired + 1));
      /* Don't fatal on realloc failures */
      if (expired_flows == NULL)
        expired_flows = oldexp;
      else {
        expired_flows[num_expired] = expiry->flow;
        num_expired++;
      }

      if (ex == CE_EXPIRE_ALL)
        expiry->reason = R_FLUSH;

      update_expiry_stats (ft, expiry);

      /* Remove from flow tree, destroy expiry event */
      FLOW_REMOVE (FLOWS, &ft->flows, expiry->flow);
      EXPIRY_REMOVE (EXPIRIES, &ft->expiries, expiry);
      expiry->flow->expiry = NULL;
      expiry_put (ft, expiry);

      ft->param.num_flows--;
    }
  }

  if (verbose_flag)
    logit (LOG_DEBUG, "Finished scan %d flow(s) to be evicted", num_expired);

  /* Processing for expired flows */
  if (num_expired > 0) {
    if (target != NULL) {
      struct SENDPARAMETER sp =
        { expired_flows, num_expired, target, if_index, &ft->param,
        verbose_flag
      };
      netflow_send_func_t *func =
        ft->param.bidirection ==
        1 ? target->dialect->bidir_func : target->dialect->func;
      if (func == NULL) {
        func = target->dialect->func;
      }
#ifdef ENABLE_PTHREAD
      if (use_thread) {
        pthread_t write_thread = 0;
        sp.flows = calloc (num_expired, sizeof (struct FLOW));
        memcpy (sp.flows, expired_flows, sizeof (struct FLOW) * num_expired);
        if (pthread_create (&write_thread, NULL, (void *) func, (void *) &sp)
            < 0) {
          perror ("pthread_create error");
          exit (1);
        }
        if (pthread_detach (write_thread) != 0) {
          perror ("pthread_detach error");
          exit (1);
        }
        r = 1;
      } else
#endif /* ENABLE_PTHREAD */
        r = func (sp);
      if (verbose_flag)
        logit (LOG_DEBUG, "sent %d netflow packets", r);
      if (r <= 0)
        ft->param.flows_dropped += num_expired * 2;     /* XXX what if r < num_expired * 2 ? */
    }
    for (i = 0; i < num_expired; i++) {
      if (verbose_flag) {
        logit (LOG_DEBUG, "EXPIRED: %s (%p)",
               format_flow (expired_flows[i]), expired_flows[i]);
      }
      update_statistics (ft, expired_flows[i]);
      flow_put (ft, expired_flows[i]);
    }

    free (expired_flows);
  }
  if (ft->param.boot_time_reinit != 0) {
    if (now.tv_sec - ft->param.system_boot_time.tv_sec >
        ft->param.boot_time_reinit) {
      ft->param.system_boot_time = now;
    }
  }

  return (r == -1 ? -1 : num_expired);
}

/*
 * Force expiry of num_to_expire flows (e.g. when flow table overfull) 
 */
static void
force_expire (struct FLOWTRACK *ft, u_int32_t num_to_expire) {
  struct EXPIRY *expiry, **expiryv;
  int i;

  /* XXX move all overflow processing here (maybe) */
  if (verbose_flag)
    logit (LOG_INFO, "Forcing expiry of %d flows", num_to_expire);

  /*
   * Do this in two steps, as it is dangerous to change a key on 
   * a tree entry without first removing it and then re-adding it.
   * It is even worse when this has to be done during a FOREACH :)
   * To get around this, we make a list of expired flows and _then_ 
   * alter them 
   */

  if ((expiryv = calloc (num_to_expire, sizeof (*expiryv))) == NULL) {
    /*
     * On malloc failure, expire ALL flows. I assume that 
     * setting all the keys in a tree to the same value is 
     * safe.
     */
    logit (LOG_ERR, "Out of memory while expiring flows - "
           "all flows expired");
    EXPIRY_FOREACH (expiry, EXPIRIES, &ft->expiries) {
      expiry->expires_at = 0;
      expiry->reason = R_OVERFLOWS;
      ft->param.flows_force_expired++;
    }
    return;
  }

  /* Make the list of flows to expire */
  i = 0;
  EXPIRY_FOREACH (expiry, EXPIRIES, &ft->expiries) {
    if (i >= num_to_expire)
      break;
    expiryv[i++] = expiry;
  }
  if (i < num_to_expire) {
    logit (LOG_ERR, "Needed to expire %d flows, "
           "but only %d active", num_to_expire, i);
    num_to_expire = i;
  }

  for (i = 0; i < num_to_expire; i++) {
    EXPIRY_REMOVE (EXPIRIES, &ft->expiries, expiryv[i]);
    expiryv[i]->expires_at = 0;
    expiryv[i]->reason = R_OVERFLOWS;
    EXPIRY_INSERT (EXPIRIES, &ft->expiries, expiryv[i]);
  }
  ft->param.flows_force_expired += num_to_expire;
  free (expiryv);
  /* XXX - this is overcomplicated, perhaps use a separate queue */
}

/* Delete all flows that we know about without processing */
static int
delete_all_flows (struct FLOWTRACK *ft) {
  struct FLOW *flow, *nflow;
  int i;

  i = 0;
  for (flow = FLOW_MIN (FLOWS, &ft->flows); flow != NULL; flow = nflow) {
    nflow = FLOW_NEXT (FLOWS, &ft->flows, flow);
    FLOW_REMOVE (FLOWS, &ft->flows, flow);

    EXPIRY_REMOVE (EXPIRIES, &ft->expiries, flow->expiry);
    expiry_put (ft, flow->expiry);

    ft->param.num_flows--;
    flow_put (ft, flow);
    i++;
  }

  return (i);
}

/*
 * Log our current status. 
 * Includes summary counters and (in verbose mode) the list of current flows
 * and the tree of expiry events.
 */
static int
statistics (struct FLOWTRACK *ft, FILE * out, pcap_t * pcap) {
  int i;
  struct protoent *pe;
  char proto[32];
  struct pcap_stat ps;

  fprintf (out, "Number of active flows: %d\n", ft->param.num_flows);
  fprintf (out, "Packets processed: %" PRIu64 "\n", ft->param.total_packets);
  if (ft->param.non_sampled_packets)
    fprintf (out, "Packets non-sampled: %" PRIu64 "\n",
             ft->param.non_sampled_packets);
  fprintf (out, "Fragments: %" PRIu64 "\n", ft->param.frag_packets);
  fprintf (out,
           "Ignored packets: %" PRIu64 " (%" PRIu64 " non-IP, %" PRIu64
           " too short)\n", ft->param.non_ip_packets + ft->param.bad_packets,
           ft->param.non_ip_packets, ft->param.bad_packets);
  fprintf (out, "Flows expired: %" PRIu64 " (%" PRIu64 " forced)\n",
           ft->param.flows_expired, ft->param.flows_force_expired);
  fprintf (out,
           "Flows exported: %" PRIu64 " (%" PRIu64 " records) in %" PRIu64
           " packets (%" PRIu64 " failures)\n", ft->param.flows_exported,
           ft->param.records_sent, ft->param.packets_sent,
           ft->param.flows_dropped);

  if (pcap_stats (pcap, &ps) == 0) {
    fprintf (out, "Packets received by libpcap: %lu\n",
             (unsigned long) ps.ps_recv);
    fprintf (out, "Packets dropped by libpcap: %lu\n",
             (unsigned long) ps.ps_drop);
    fprintf (out, "Packets dropped by interface: %lu\n",
             (unsigned long) ps.ps_ifdrop);
  }

  fprintf (out, "\n");

  if (ft->param.flows_expired != 0) {
    fprintf (out,
             "Expired flow statistics:  minimum       average       maximum\n");
    fprintf (out, "  Flow bytes:        %12.0f  %12.0f  %12.0f\n",
             ft->param.octets.min, ft->param.octets.mean,
             ft->param.octets.max);
    fprintf (out, "  Flow packets:      %12.0f  %12.0f  %12.0f\n",
             ft->param.packets.min, ft->param.packets.mean,
             ft->param.packets.max);
    fprintf (out, "  Duration:          %12.2fs %12.2fs %12.2fs\n",
             ft->param.duration.min, ft->param.duration.mean,
             ft->param.duration.max);

    fprintf (out, "\n");
    fprintf (out, "Expired flow reasons:\n");
    fprintf (out, "       tcp = %9" PRIu64 "   tcp.rst = %9" PRIu64 "   "
             "tcp.fin = %9" PRIu64 "\n", ft->param.expired_tcp,
             ft->param.expired_tcp_rst, ft->param.expired_tcp_fin);
    fprintf (out,
             "       udp = %9" PRIu64 "      icmp = %9" PRIu64 "   "
             "general = %9" PRIu64 "\n", ft->param.expired_udp,
             ft->param.expired_icmp, ft->param.expired_general);
    fprintf (out, "   maxlife = %9" PRIu64 "\n", ft->param.expired_maxlife);
    fprintf (out, "over 2 GiB = %9" PRIu64 "\n", ft->param.expired_overbytes);
    fprintf (out, "  maxflows = %9" PRIu64 "\n", ft->param.expired_maxflows);
    fprintf (out, "   flushed = %9" PRIu64 "\n", ft->param.expired_flush);

    fprintf (out, "\n");

    fprintf (out, "Per-protocol statistics:     Octets      "
             "Packets   Avg Life    Max Life\n");
    for (i = 0; i < 256; i++) {
      if (ft->param.packets_pp[i]) {
        pe = getprotobynumber (i);
        snprintf (proto, sizeof (proto), "%s (%d)",
                  pe != NULL ? pe->p_name : "Unknown", i);
        fprintf (out, "  %17s: %14" PRIu64 " %12" PRIu64 "   %8.2fs "
                 "%10.2fs\n", proto,
                 ft->param.octets_pp[i],
                 ft->param.packets_pp[i],
                 ft->param.duration_pp[i].mean, ft->param.duration_pp[i].max);
      }
    }
  }

  return (0);
}

static void
dump_flows (struct FLOWTRACK *ft, FILE * out) {
  struct EXPIRY *expiry;
  time_t now;

  now = time (NULL);

  EXPIRY_FOREACH (expiry, EXPIRIES, &ft->expiries) {
    fprintf (out, "ACTIVE %s\n", format_flow (expiry->flow));
    if ((long int) expiry->expires_at - now < 0) {
      fprintf (out,
               "EXPIRY EVENT for flow %" PRIu64 " now%s\n",
               expiry->flow->flow_seq,
               expiry->expires_at == 0 ? " (FORCED)" : "");
    } else {
      fprintf (out,
               "EXPIRY EVENT for flow %" PRIu64 " in %lld seconds\n",
               expiry->flow->flow_seq, (long long) expiry->expires_at - now);
    }
    fprintf (out, "\n");
  }
}

/*
 * Figure out how many bytes to skip from front of packet to get past 
 * datalink headers. If pkt is specified, also check whether determine
 * whether or not it is one that we are interested in (IPv4 or IPv6 for now)
 *
 * Returns number of bytes to skip or -1 to indicate that entire 
 * packet should be skipped
 */
static int
datalink_check (int linktype, const u_int8_t * pkt, u_int32_t caplen, int *af,
                struct ether_header **ether, u_int16_t * vlanid,
                u_int8_t * num_label) {
  int i, j;
  u_int32_t frametype;
  int vlan_size = 0;

  static const struct DATALINK *dl = NULL;

  /* Try to cache last used linktype */
  if (dl == NULL || dl->dlt != linktype) {
    for (i = 0; lt[i].dlt != linktype && lt[i].dlt != -1; i++);
    dl = &lt[i];
  }
  if (dl->dlt == -1 || pkt == NULL)
    return (dl->dlt);
  if (caplen <= dl->skiplen)
    return (-1);

  /* Suck out the frametype */
  frametype = 0;

  /* Processing 802.1Q vlan in ethernet */
  if (linktype == DLT_EN10MB) {
    if (ether != NULL)
      *ether = (struct ether_header *) pkt;
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
      /* 
       * Mask out the PCP and DEI values,
       * leaving just the VID.
       */
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
      shim = *((u_int32_t *) (pkt + dl->skiplen + vlan_size) + *num_label);
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

/*
 * Per-packet callback function from libpcap. Pass the packet (if it is IP)
 * sans datalink headers to process_packet.
 */
void
flow_cb (u_char * user_data, const struct pcap_pkthdr *phdr,
         const u_char * pkt) {
  int s, af = 0;
  struct CB_CTXT *cb_ctxt = (struct CB_CTXT *) user_data;
  struct timeval tv;
  u_int16_t vlanid = 0;
  struct ether_header *ether = NULL;
  u_char *mpls_hdr = NULL;
  u_int8_t num_label = 0;

  if (cb_ctxt->ft->param.total_packets == 0) {
    if (cb_ctxt->ft->param.adjust_time) {
      cb_ctxt->ft->param.system_boot_time = phdr->ts;
    }
  }

  if (cb_ctxt->ft->param.option.sample &&
      (cb_ctxt->ft->param.total_packets +
       cb_ctxt->ft->param.non_sampled_packets) %
      cb_ctxt->ft->param.option.sample > 0) {
    cb_ctxt->ft->param.non_sampled_packets++;
    return;
  }
  cb_ctxt->ft->param.total_packets++;
  if (cb_ctxt->ft->param.is_psamp) {
    send_psamp (pkt, phdr->caplen, phdr->ts, cb_ctxt->target,
                cb_ctxt->ft->param.total_packets);
    return;
  }

  s = datalink_check (cb_ctxt->linktype, pkt, phdr->caplen, &af, &ether,
                      &vlanid, &num_label);
  if (s < 0 || (!cb_ctxt->want_v6 && af == AF_INET6)) {
    cb_ctxt->ft->param.non_ip_packets++;
    cb_ctxt->ft->param.total_packets--;
  } else {
    tv.tv_sec = phdr->ts.tv_sec;
    tv.tv_usec = phdr->ts.tv_usec;
    if (process_packet (cb_ctxt->ft, pkt + s, af, phdr->caplen - s,
                        phdr->len - s, ether, vlanid, &tv,
                        num_label) == PP_MALLOC_FAIL)
      cb_ctxt->fatal = 1;
  }
  if (cb_ctxt->ft->param.adjust_time)
    cb_ctxt->ft->param.last_packet_time = phdr->ts;
}

#ifdef ENABLE_PTHREAD
static void
pcap_memcpy (u_char * user_data, const struct pcap_pkthdr *phdr,
             const u_char * pkt) {
  pthread_mutex_lock (&read_mutex);
  memcpy (&packet_header, phdr, sizeof (struct pcap_pkthdr));
  memcpy (&packet_data, pkt, sizeof (packet_data));
  pthread_mutex_unlock (&read_mutex);
  pthread_cond_signal (&read_cond);
}

void *
process_packet_loop (void *arg) {
  while (!graceful_shutdown_request) {
    pthread_mutex_lock (&read_mutex);
    pthread_cond_wait (&read_cond, &read_mutex);
    if (graceful_shutdown_request)
      break;
    flow_cb ((u_char *) arg, &packet_header, (u_char *) & packet_data);
    pthread_mutex_unlock (&read_mutex);
  }
}
#endif /* ENABLE_PTHREAD */

static void
print_timeouts (struct FLOWTRACK *ft, FILE * out) {
  fprintf (out, "           TCP timeout: %ds\n", ft->param.tcp_timeout);
  fprintf (out, "  TCP post-RST timeout: %ds\n", ft->param.tcp_rst_timeout);
  fprintf (out, "  TCP post-FIN timeout: %ds\n", ft->param.tcp_fin_timeout);
  fprintf (out, "           UDP timeout: %ds\n", ft->param.udp_timeout);
  fprintf (out, "          ICMP timeout: %ds\n", ft->param.icmp_timeout);
  fprintf (out, "       General timeout: %ds\n", ft->param.general_timeout);
  fprintf (out, "      Maximum lifetime: %ds\n", ft->param.maximum_lifetime);
  fprintf (out, "       Expiry interval: %ds\n", ft->param.expiry_interval);
}

static int
accept_control (int lsock, struct NETFLOW_TARGET *target,
                struct FLOWTRACK *ft, pcap_t * pcap, int *exit_request,
                int *stop_collection_flag) {
  char buf[64], *p;
  FILE *ctlf;
  int fd, ret;

  if ((fd = accept (lsock, NULL, NULL)) == -1) {
    logit (LOG_ERR, "ctl accept: %s - exiting", strerror (errno));
    return (-1);
  }
  if ((ctlf = fdopen (fd, "r+")) == NULL) {
    logit (LOG_ERR, "fdopen: %s - exiting\n", strerror (errno));
    close (fd);
    return (-1);
  }
  setlinebuf (ctlf);

  if (fgets (buf, sizeof (buf), ctlf) == NULL) {
    logit (LOG_ERR, "Control socket yielded no data");
    return (0);
  }
  if ((p = strchr (buf, '\n')) != NULL)
    *p = '\0';

  if (verbose_flag)
    logit (LOG_DEBUG, "Control socket \"%s\"", buf);

  /* XXX - use dispatch table */
  ret = -1;
  if (strcmp (buf, "help") == 0) {
    fprintf (ctlf, "Valid control words are:\n");
    fprintf (ctlf, "\tdebug+ debug- delete-all dump-flows exit "
             "expire-all\n");
    fprintf (ctlf, "\tshutdown start-gather statistics stop-gather "
             "timeouts\n");
    fprintf (ctlf, "\tsend-template\n");
    ret = 0;
  } else if (strcmp (buf, "shutdown") == 0) {
    fprintf (ctlf, "softflowd[%u]: Shutting down gracefully...\n",
             (unsigned int) getpid ());
    graceful_shutdown_request = 1;
    ret = 1;
  } else if (strcmp (buf, "exit") == 0) {
    fprintf (ctlf, "softflowd[%u]: Exiting now...\n",
             (unsigned int) getpid ());
    *exit_request = 1;
    ret = 1;
  } else if (strcmp (buf, "expire-all") == 0) {
#ifdef ENABLE_LEGACY
    netflow9_resend_template ();
#else /* ENABLE_LEGACY */
    ipfix_resend_template ();
#endif /* ENABLE_LEGACY */
    fprintf (ctlf, "softflowd[%u]: Expired %d flows.\n",
             (unsigned int) getpid (), check_expired (ft, target,
                                                      CE_EXPIRE_ALL));
    ret = 0;
  } else if (strcmp (buf, "send-template") == 0) {
#ifdef ENABLE_LEGACY
    netflow9_resend_template ();
#else /* ENABLE_LEGACY */
    ipfix_resend_template ();
#endif /* ENABLE_LEGACY */
    fprintf (ctlf, "softflowd[%u]: Template will be sent at "
             "next flow export\n", (unsigned int) getpid ());
    ret = 0;
  } else if (strcmp (buf, "delete-all") == 0) {
    fprintf (ctlf, "softflowd[%u]: Deleted %d flows.\n",
             (unsigned int) getpid (), delete_all_flows (ft));
    ret = 0;
  } else if (strcmp (buf, "statistics") == 0) {
    fprintf (ctlf, "softflowd[%u]: Accumulated statistics "
             "since %s UTC:\n", (unsigned int) getpid (),
             format_time (ft->param.system_boot_time.tv_sec));
    statistics (ft, ctlf, pcap);
    ret = 0;
  } else if (strcmp (buf, "debug+") == 0) {
    fprintf (ctlf, "softflowd[%u]: Debug level increased.\n",
             (unsigned int) getpid ());
    verbose_flag = 1;
    ret = 0;
  } else if (strcmp (buf, "debug-") == 0) {
    fprintf (ctlf, "softflowd[%u]: Debug level decreased.\n",
             (unsigned int) getpid ());
    verbose_flag = 0;
    ret = 0;
  } else if (strcmp (buf, "stop-gather") == 0) {
    fprintf (ctlf, "softflowd[%u]: Data collection stopped.\n",
             (unsigned int) getpid ());
    *stop_collection_flag = 1;
    ret = 0;
  } else if (strcmp (buf, "start-gather") == 0) {
    fprintf (ctlf, "softflowd[%u]: Data collection resumed.\n",
             (unsigned int) getpid ());
    *stop_collection_flag = 0;
    ret = 0;
  } else if (strcmp (buf, "dump-flows") == 0) {
    fprintf (ctlf, "softflowd[%u]: Dumping flow data:\n",
             (unsigned int) getpid ());
    dump_flows (ft, ctlf);
    ret = 0;
  } else if (strcmp (buf, "timeouts") == 0) {
    fprintf (ctlf, "softflowd[%u]: Printing timeouts:\n",
             (unsigned int) getpid ());
    print_timeouts (ft, ctlf);
    ret = 0;
  } else {
    fprintf (ctlf, "Unknown control command \"%s\"\n", buf);
    ret = 0;
  }

  fclose (ctlf);
  close (fd);

  return (ret);
}

static int
recvsock (uint16_t portnumber) {
  struct sockaddr_in addr;
  int rsock = socket (AF_INET, SOCK_DGRAM, 0);
  if (rsock < 0) {
    perror ("socket");
    return rsock;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons (portnumber);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind (rsock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    perror ("bind");
    return -1;
  };
  return rsock;
}

#ifdef LINUX
static void
bind_device (int sock, char *ifname) {
  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
  if (setsockopt
      (sock, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
    perror ("SO_BINDTODEVICE failed");
  }
}
#endif /* LINUX */

static int
connsock (struct sockaddr_storage *addr, socklen_t len, int hoplimit,
          int protocol) {
  int s;
  unsigned int h6;
  unsigned char h4;
  struct sockaddr_in *in4 = (struct sockaddr_in *) addr;
  struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) addr;

  if ((s =
       socket (addr->ss_family,
               protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
               protocol)) == -1) {
    fprintf (stderr, "socket() error: %s\n", strerror (errno));
    exit (1);
  }
  if (connect (s, (struct sockaddr *) addr, len) == -1) {
    fprintf (stderr, "connect() error: %s\n", strerror (errno));
    exit (1);
  }

  switch (addr->ss_family) {
  case AF_INET:
    /* Default to link-local TTL for multicast addresses */
    if (hoplimit == -1 && IN_MULTICAST (in4->sin_addr.s_addr))
      hoplimit = 1;
    if (hoplimit == -1)
      break;
    h4 = hoplimit;
    if (setsockopt (s, IPPROTO_IP, IP_MULTICAST_TTL, &h4, sizeof (h4)) == -1) {
      fprintf (stderr, "setsockopt(IP_MULTICAST_TTL, "
               "%u): %s\n", h4, strerror (errno));
      exit (1);
    }
    break;
  case AF_INET6:
    /* Default to link-local hoplimit for multicast addresses */
    if (hoplimit == -1 && IN6_IS_ADDR_MULTICAST (&in6->sin6_addr))
      hoplimit = 1;
    if (hoplimit == -1)
      break;
    h6 = hoplimit;
    if (setsockopt (s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                    &h6, sizeof (h6)) == -1) {
      fprintf (stderr, "setsockopt(IPV6_MULTICAST_HOPS, %u): "
               "%s\n", h6, strerror (errno));
      exit (1);
    }
  }

  return (s);
}

static int
unix_listener (const char *path) {
  struct sockaddr_un addr;
  socklen_t addrlen;
  int s;

  memset (&addr, '\0', sizeof (addr));
  addr.sun_family = AF_UNIX;

  if (strlcpy (addr.sun_path, path, sizeof (addr.sun_path)) >=
      sizeof (addr.sun_path)) {
    fprintf (stderr, "control socket path too long\n");
    exit (1);
  }

  addr.sun_path[sizeof (addr.sun_path) - 1] = '\0';

  addrlen = offsetof (struct sockaddr_un, sun_path) + strlen (path) + 1;
#ifdef SOCK_HAS_LEN
  addr.sun_len = addrlen;
#endif

  if ((s = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
    fprintf (stderr, "unix domain socket() error: %s\n", strerror (errno));
    exit (1);
  }
  unlink (path);
  if (bind (s, (struct sockaddr *) &addr, addrlen) == -1) {
    fprintf (stderr, "unix domain bind(\"%s\") error: %s\n",
             addr.sun_path, strerror (errno));
    exit (1);
  }
  if (listen (s, 64) == -1) {
    fprintf (stderr, "unix domain listen() error: %s\n", strerror (errno));
    exit (1);
  }

  return (s);
}

static void
setup_packet_capture (struct pcap **pcap, int *linktype,
                      char *dev, char *capfile, char *bpf_prog, int need_v6,
                      int promisc, int buffer_size_override) {
  char ebuf[PCAP_ERRBUF_SIZE];
  struct bpf_program prog_c;
  u_int32_t bpf_mask, bpf_net;
  int res;

  /* Open pcap */
  if (dev != NULL) {
    if (!snaplen)
      snaplen = need_v6 ? LIBPCAP_SNAPLEN_V6 : LIBPCAP_SNAPLEN_V4;
    if ((*pcap = pcap_create (dev, ebuf)) == NULL) {
      fprintf (stderr, "pcap_create: %s\n", ebuf);
      exit (1);
    }
    if ((res = pcap_set_snaplen (*pcap, snaplen)) != 0) {
      fprintf (stderr, "pcap_set_snaplen: %s\n", pcap_geterr (*pcap));
      exit (1);
    }
    if ((res = pcap_set_promisc (*pcap, promisc)) != 0) {
      fprintf (stderr, "pcap_set_promisc: %s\n", pcap_geterr (*pcap));
      exit (1);
    }
    if ((res = pcap_set_timeout (*pcap, 0)) != 0) {
      fprintf (stderr, "pcap_set_timeout: %s\n", pcap_geterr (*pcap));
      exit (1);
    }
    if (buffer_size_override > 0)
      if ((res = pcap_set_buffer_size (*pcap, buffer_size_override)) != 0) {
        fprintf (stderr, "pcap_set_buffer_size: %s\n", pcap_geterr (*pcap));
        exit (1);
      }
    if (pcap_lookupnet (dev, &bpf_net, &bpf_mask, ebuf) == -1)
      bpf_net = bpf_mask = 0;
    if ((res = pcap_activate (*pcap)) != 0) {
      fprintf (stderr, "pcap_activate: %s\n", pcap_geterr (*pcap));
      exit (1);
    }
  } else {
    if ((*pcap = pcap_open_offline (capfile, ebuf)) == NULL) {
      fprintf (stderr, "pcap_open_offline(%s): %s\n", capfile, ebuf);
      exit (1);
    }
    bpf_net = bpf_mask = 0;
  }
  *linktype = pcap_datalink (*pcap);
  if (datalink_check (*linktype, NULL, 0, NULL, NULL, NULL, NULL) == -1) {
    fprintf (stderr, "Unsupported datalink type %d\n", *linktype);
    exit (1);
  }
  /* Attach BPF filter, if specified */
  if (bpf_prog != NULL) {
    if (pcap_compile (*pcap, &prog_c, bpf_prog, 1, bpf_mask) == -1) {
      fprintf (stderr, "pcap_compile(\"%s\"): %s\n",
               bpf_prog, pcap_geterr (*pcap));
      exit (1);
    }
    if (pcap_setfilter (*pcap, &prog_c) == -1) {
      fprintf (stderr, "pcap_setfilter: %s\n", pcap_geterr (*pcap));
      exit (1);
    }
  }
#ifdef BIOCLOCK
  /*
   * If we are reading from an device (not a file), then 
   * lock the underlying BPF device to prevent changes in the 
   * unprivileged child
   */
  if (dev != NULL && ioctl (pcap_fileno (*pcap), BIOCLOCK) < 0) {
    fprintf (stderr, "ioctl(BIOCLOCK) failed: %s\n", strerror (errno));
    exit (1);
  }
#endif
}

static void
init_flowtrack (struct FLOWTRACK *ft) {
  /* Set up flow-tracking structure */
  memset (ft, '\0', sizeof (*ft));
  ft->param.next_flow_seq = 1;
  FLOW_INIT (&ft->flows);
  EXPIRY_INIT (&ft->expiries);

  freelist_init (&ft->flow_freelist, sizeof (struct FLOW));
  freelist_init (&ft->expiry_freelist, sizeof (struct EXPIRY));

  ft->param.max_flows = DEFAULT_MAX_FLOWS;

  track_level = ft->param.track_level = TRACK_FULL;

  ft->param.tcp_timeout = DEFAULT_TCP_TIMEOUT;
  ft->param.tcp_rst_timeout = DEFAULT_TCP_RST_TIMEOUT;
  ft->param.tcp_fin_timeout = DEFAULT_TCP_FIN_TIMEOUT;
  ft->param.udp_timeout = DEFAULT_UDP_TIMEOUT;
  ft->param.icmp_timeout = DEFAULT_ICMP_TIMEOUT;
  ft->param.general_timeout = DEFAULT_GENERAL_TIMEOUT;
  ft->param.maximum_lifetime = DEFAULT_MAXIMUM_LIFETIME;
  ft->param.expiry_interval = DEFAULT_EXPIRY_INTERVAL;
}

static char *
argv_join (int argc, char **argv) {
  int i;
  size_t ret_len;
  char *ret;

  ret_len = 0;
  ret = NULL;
  for (i = 0; i < argc; i++) {
    ret_len += strlen (argv[i]);
    if ((ret = realloc (ret, ret_len + 2)) == NULL) {
      fprintf (stderr, "Memory allocation failed.\n");
      exit (1);
    }
    if (i == 0)
      ret[0] = '\0';
    else {
      ret_len++;                /* Make room for ' ' */
      strlcat (ret, " ", ret_len + 1);
    }

    strlcat (ret, argv[i], ret_len + 1);
  }

  return (ret);
}

/* Display commandline usage information */
static void
usage (void) {
  fprintf (stderr,
           "Usage: %s [options] [bpf_program]\n"
           "This is %s version %s. Valid commandline options:\n"
           "  -i [idx:]interface      Specify interface to listen on\n"
           "  -r pcap_file            Specify packet capture file to read\n"
           "  -t timeout=time         Specify named timeout\n"
           "  -m max_flows            Specify maximum number of flows to track (default %d)\n"
           "  -n host:port            Send Cisco NetFlow(tm)-compatible packets to host:port\n"
           "  -p pidfile              Record pid in specified file\n"
           "                          (default: %s)\n"
           "  -c socketfile           Location of control socket\n"
           "                          (default: %s)\n"
           "  -v 1|5|9|10|psamp       NetFlow export packet version\n"
           "                          10 means IPFIX and psamp means PSAMP (packet sampling)\n"
#ifdef ENABLE_NTOPNG
           "     ntopng               ntopng means direct injection to NTOPNG (if supported).\n"
#endif
           "  -L hoplimit             Set TTL/hoplimit for export datagrams\n"
           "  -T full|port|proto|ip|  Set flow tracking level (default: full)\n"
           "     vlan                 (\"vlan\" tracking means \"full\" tracking with vlanid)\n"
           "     ether                (\"ether\" tracking means \"vlan\" tracking with ether header)\n"
           "  -6                      Track IPv6 flows, regardless of whether selected \n"
           "                          NetFlow export protocol supports it\n"
           "  -d                      Don't daemonise (run in foreground)\n"
           "  -D                      Debug mode: foreground + verbosity + track v6 flows\n"
           "  -P udp|tcp|sctp         Specify transport layer protocol for exporting packets\n"
           "  -A sec|milli|micro|nano Specify absolute time format form exporting records\n"
           "  -s sampling_rate        Specify periodical sampling rate (denominator)\n"
           "  -B bytes                Libpcap buffer size in bytes\n"
           "  -b                      Bidirectional mode in IPFIX (-b work with -v 10)\n"
           "  -a                      Adjusting time for reading pcap file (-a work with -r)\n"
           "  -C capture_length       Specify length for packet capture (snaplen)\n"
           "  -l                      Load balancing mode for multiple destinations\n"
           "  -R receive_port         Specify port number for PSAMP receive mode\n"
#ifdef ENABLE_PTHREAD
           "  -M                      Enable multithread\n"
#endif /* ENABLE_PTHREAD */
           "  -N                      Disable promiscuous mode\n"
#ifdef LINUX
           "  -S send_interface_name  Specify send interface name\n"
#endif /* LINUX */
           "  -x                      Specify number of MPLS labels\n"
           "  -I                      Specify seconds for reinitialize boot time\n"
           "  -h                      Display this help\n"
           "\n"
           "Valid timeout names and default values:\n"
           "  tcp     (default %6d)"
           "  tcp.rst (default %6d)"
           "  tcp.fin (default %6d)\n"
           "  udp     (default %6d)"
           "  icmp    (default %6d)"
           "  general (default %6d)\n"
           "  maxlife (default %6d)"
           "  expint  (default %6d)\n"
           "\n",
           PROGNAME, PROGNAME, PROGVER, DEFAULT_MAX_FLOWS, DEFAULT_PIDFILE,
           DEFAULT_CTLSOCK,
           DEFAULT_TCP_TIMEOUT, DEFAULT_TCP_RST_TIMEOUT,
           DEFAULT_TCP_FIN_TIMEOUT, DEFAULT_UDP_TIMEOUT, DEFAULT_ICMP_TIMEOUT,
           DEFAULT_GENERAL_TIMEOUT, DEFAULT_MAXIMUM_LIFETIME,
           DEFAULT_EXPIRY_INTERVAL);
}

static void
set_timeout (struct FLOWTRACK *ft, const char *to_spec) {
  char *name, *value;
  int timeout;

  if ((name = strdup (to_spec)) == NULL) {
    fprintf (stderr, "Out of memory\n");
    exit (1);
  }
  if ((value = strchr (name, '=')) == NULL || *(++value) == '\0') {
    fprintf (stderr, "Invalid -t option \"%s\".\n", name);
    usage ();
    exit (1);
  }
  *(value - 1) = '\0';
  timeout = convtime (value);
  if (timeout < 0) {
    fprintf (stderr, "Invalid -t timeout.\n");
    usage ();
    exit (1);
  }
  if (strcmp (name, "tcp") == 0)
    ft->param.tcp_timeout = timeout;
  else if (strcmp (name, "tcp.rst") == 0)
    ft->param.tcp_rst_timeout = timeout;
  else if (strcmp (name, "tcp.fin") == 0)
    ft->param.tcp_fin_timeout = timeout;
  else if (strcmp (name, "udp") == 0)
    ft->param.udp_timeout = timeout;
  else if (strcmp (name, "icmp") == 0)
    ft->param.icmp_timeout = timeout;
  else if (strcmp (name, "general") == 0)
    ft->param.general_timeout = timeout;
  else if (strcmp (name, "maxlife") == 0)
    ft->param.maximum_lifetime = timeout;
  else if (strcmp (name, "expint") == 0)
    ft->param.expiry_interval = timeout;
  else {
    fprintf (stderr, "Invalid -t name.\n");
    usage ();
    exit (1);
  }

  if (ft->param.general_timeout == 0) {
    fprintf (stderr, "\"general\" flow timeout must be "
             "greater than zero\n");
    exit (1);
  }

  free (name);
}

static void
parse_hostport (const char *s, struct sockaddr *addr, socklen_t * len) {
  char *orig, *host, *port;
  struct addrinfo hints, *res;
  int herr;

  if ((host = orig = strdup (s)) == NULL) {
    fprintf (stderr, "Out of memory\n");
    exit (1);
  }
  if ((port = strrchr (host, ':')) == NULL ||
      *(++port) == '\0' || *host == '\0') {
    fprintf (stderr, "Invalid -n argument.\n");
    usage ();
    exit (1);
  }
  *(port - 1) = '\0';

  /* Accept [host]:port for numeric IPv6 addresses */
  if (*host == '[' && *(port - 2) == ']') {
    host++;
    *(port - 2) = '\0';
  }

  memset (&hints, '\0', sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  if ((herr = getaddrinfo (host, port, &hints, &res)) == -1) {
    fprintf (stderr, "Address lookup failed: %s\n", gai_strerror (herr));
    exit (1);
  }
  if (res == NULL || res->ai_addr == NULL) {
    fprintf (stderr, "No addresses found for [%s]:%s\n", host, port);
    exit (1);
  }
  if (res->ai_addrlen > *len) {
    fprintf (stderr, "Address too long\n");
    exit (1);
  }
  memcpy (addr, res->ai_addr, res->ai_addrlen);
  free (orig);
  *len = res->ai_addrlen;
}

static int
parse_hostports (const char *s, struct DESTINATION *dest, int max_dest) {
  int i = 0;
  char *hostport;
  for (hostport = strsep ((char **) &s, ",");
       hostport != NULL && i < max_dest;
       hostport = strsep ((char **) &s, ",")) {
    dest[i].sslen = sizeof (dest[i].ss);
    parse_hostport (hostport, (struct sockaddr *) &dest[i].ss,
                    &dest[i].sslen);
    i++;
  }
  return i;
}

/* 
 * Drop privileges and chroot, will exit on failure
 */
static void
drop_privs (void) {
  struct passwd *pw;

  if ((pw = getpwnam (PRIVDROP_USER)) == NULL) {
    logit (LOG_ERR, "Unable to find unprivileged user \"%s\"", PRIVDROP_USER);
    exit (1);
  }
  if (chdir (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, strerror (errno));
    exit (1);
  }
  if (chroot (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chroot to directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, strerror (errno));
    exit (1);
  }
  if (chdir ("/") != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot root: %s", strerror (errno));
    exit (1);
  }
  if (setgroups (1, &pw->pw_gid) != 0) {
    logit (LOG_ERR, "Couldn't setgroups (%u): %s",
           (unsigned int) pw->pw_gid, strerror (errno));
    exit (1);
  }
#if defined(HAVE_SETRESGID)
  if (setresgid (pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
#elif defined(HAVE_SETREGID)
  if (setregid (pw->pw_gid, pw->pw_gid) == -1)
#else
  if (setegid (pw->pw_gid) == -1 || setgid (pw->pw_gid) == -1)
#endif
  {
    logit (LOG_ERR, "Couldn't set gid (%u): %s",
           (unsigned int) pw->pw_gid, strerror (errno));
    exit (1);
  }
#if defined(HAVE_SETRESUID)
  if (setresuid (pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
#elif defined(HAVE_SETREUID)
  if (setreuid (pw->pw_uid, pw->pw_uid) == -1)
#else
  if (seteuid (pw->pw_uid) == -1 || setuid (pw->pw_uid) == -1)
#endif
  {
    logit (LOG_ERR, "Couldn't set uid (%u): %s",
           (unsigned int) pw->pw_uid, strerror (errno));
    exit (1);
  }
}

int
main (int argc, char **argv) {
  char *dev, *capfile, *bpf_prog;
  const char *pidfile_path, *ctlsock_path;
  extern char *optarg;
  extern int optind;
  int ch, dontfork_flag, linktype, ctlsock, err, always_v6, r, dest_idx;
  int stop_collection_flag, exit_request, hoplimit;
  pcap_t *pcap = NULL;
  struct FLOWTRACK flowtrack;
  struct NETFLOW_TARGET target;
  struct CB_CTXT cb_ctxt;
  struct pollfd pl[2];
  struct DESTINATION *dest;
  int pcap_override_buffer_size = 0;
  int protocol = IPPROTO_UDP;
  int version = 0;
  int rsock = 0, recvport = IPFIX_PORT, recvloop = 0;
#ifdef LINUX
  char *send_ifname;
#endif /* LINUX */
#ifdef ENABLE_PTHREAD
  int use_thread = 0;
  pthread_t read_thread = 0;

  pthread_mutex_init (&read_mutex, NULL);
  pthread_cond_init (&read_cond, NULL);
#endif /* ENABLE_PTHREAD */
  int use_promisc = 1;
  long int boot_time_reinit_sec = 0;
  char *timeunit;

  closefrom (STDERR_FILENO + 1);

  init_flowtrack (&flowtrack);

  memset (&target, '\0', sizeof (target));
  target.dialect = &nf[0];
  hoplimit = -1;
  bpf_prog = NULL;
  ctlsock = -1;
  dev = capfile = NULL;
  pidfile_path = DEFAULT_PIDFILE;
  ctlsock_path = DEFAULT_CTLSOCK;
  dontfork_flag = 0;
  always_v6 = 0;

  while ((ch =
          getopt (argc, argv,
                  "6hdDL:T:i:r:f:t:n:m:p:c:v:s:P:A:B:baC:lR:MNS:x:I:")) !=
         -1) {
    switch (ch) {
    case '6':
      always_v6 = 1;
      break;
    case 'h':
      usage ();
      return (0);
    case 'D':
      verbose_flag = 1;
      always_v6 = 1;
      /* FALLTHROUGH */
    case 'd':
      dontfork_flag = 1;
      break;
    case 'i':
      if (capfile != NULL || dev != NULL) {
        fprintf (stderr, "Packet source already " "specified.\n\n");
        usage ();
        exit (1);
      }
#if defined(HAVE_STRSEP)
      dev = strsep (&optarg, ":");
#else /* defined(HAVE_STRSEP) */
      dev = strtok (optarg, ":");
#endif /* defined(HAVE_STRSEP) */
      if (optarg != NULL) {
        if (strlen (dev) > 0) {
          if_index = (u_int16_t) atoi (dev);
        }
        dev = optarg;
      }
      if (strlen (dev) == 0) {
        fprintf (stderr, "Wrong interface is specified.\n\n");
        usage ();
        exit (1);
      }
      if (verbose_flag)
        fprintf (stderr, "Using %s (idx: %d)\n", dev, if_index);
      strncpy (flowtrack.param.option.interfaceName, dev,
               strlen (dev) <
               sizeof (flowtrack.param.option.interfaceName) ?
               strlen (dev) : sizeof (flowtrack.param.option.interfaceName));
      break;
    case 'r':
      if (capfile != NULL || dev != NULL) {
        fprintf (stderr, "Packet source already " "specified.\n\n");
        usage ();
        exit (1);
      }
      capfile = optarg;
      dontfork_flag = 1;
      ctlsock_path = NULL;
      strncpy (flowtrack.param.option.interfaceName, capfile,
               strlen (capfile) <
               sizeof (flowtrack.param.option.interfaceName) ?
               strlen (capfile) :
               sizeof (flowtrack.param.option.interfaceName));
      break;
    case 't':
      /* Will exit on failure */
      set_timeout (&flowtrack, optarg);
      break;
    case 'T':
      if (strcasecmp (optarg, "full") == 0)
        flowtrack.param.track_level = TRACK_FULL;
      else if (strcasecmp (optarg, "port") == 0)
        flowtrack.param.track_level = TRACK_IP_PROTO_PORT;
      else if (strcasecmp (optarg, "proto") == 0)
        flowtrack.param.track_level = TRACK_IP_PROTO;
      else if (strcasecmp (optarg, "ip") == 0)
        flowtrack.param.track_level = TRACK_IP_ONLY;
      else if (strcasecmp (optarg, "vlan") == 0)
        flowtrack.param.track_level = TRACK_FULL_VLAN;
      else if (strcasecmp (optarg, "ether") == 0)
        flowtrack.param.track_level = TRACK_FULL_VLAN_ETHER;

      else {
        fprintf (stderr, "Unknown flow tracking " "level\n");
        usage ();
        exit (1);
      }
      track_level = flowtrack.param.track_level;
      break;
    case 'L':
      hoplimit = atoi (optarg);
      if (hoplimit < 0 || hoplimit > 255) {
        fprintf (stderr, "Invalid hop limit\n\n");
        usage ();
        exit (1);
      }
      break;
    case 'm':
      if ((flowtrack.param.max_flows = atoi (optarg)) < 0) {
        fprintf (stderr, "Invalid maximum flows\n\n");
        usage ();
        exit (1);
      }
      break;
    case 'n':
      /* Will exit on failure */
      target.num_destinations =
        parse_hostports (optarg, target.destinations,
                         SOFTFLOWD_MAX_DESTINATIONS);
      break;
    case 'p':
      pidfile_path = optarg;
      break;
    case 'c':
      if (strcmp (optarg, "none") == 0)
        ctlsock_path = NULL;
      else
        ctlsock_path = optarg;
      break;
    case 'v':
      if (!strncmp (optarg, "psamp", sizeof ("psamp"))) {
        flowtrack.param.is_psamp = 1;
        break;
      }
#ifdef ENABLE_NTOPNG
      if (!strncmp (optarg, SOFTFLOWD_NF_VERSION_NTOPNG_STRING,
                    sizeof (SOFTFLOWD_NF_VERSION_NTOPNG_STRING))) {
        version = SOFTFLOWD_NF_VERSION_NTOPNG;
      }
#endif /* ENABLE_NTOPNG */
      version = version ? version : atoi (optarg);
      target.dialect = lookup_netflow_sender (version);
      if (target.dialect == NULL) {
        fprintf (stderr, "Invalid NetFlow version\n");
        exit (1);
      }
      break;
    case 's':
      flowtrack.param.option.sample = atoi (optarg);
      if (flowtrack.param.option.sample < 2) {
        flowtrack.param.option.sample = 0;
      }
      break;
    case 'B':
      pcap_override_buffer_size = atoi (optarg);
      break;
    case 'P':
      if (strcasecmp (optarg, "udp") == 0)
        protocol = IPPROTO_UDP;
      else if (strcasecmp (optarg, "tcp") == 0)
        protocol = IPPROTO_TCP;
#ifdef IPPROTO_SCTP
      else if (strcasecmp (optarg, "sctp") == 0)
        protocol = IPPROTO_SCTP;
#endif
      else {
        fprintf (stderr, "Unknown transport layer protocol" "\n");
        usage ();
        exit (1);
      }
      break;
    case 'A':
      if (strcasecmp (optarg, "sec") == 0)
        flowtrack.param.time_format = 's';
      else if (strcasecmp (optarg, "milli") == 0)
        flowtrack.param.time_format = 'm';
      else if (strcasecmp (optarg, "micro") == 0)
        flowtrack.param.time_format = 'M';
      else if (strcasecmp (optarg, "nano") == 0)
        flowtrack.param.time_format = 'n';
      else {
        fprintf (stderr, "Unknown time format" "\n");
        usage ();
        exit (1);
      }
      break;
    case 'b':
      flowtrack.param.bidirection = 1;
      break;
    case 'a':
      flowtrack.param.adjust_time = 1;
      break;
    case 'C':                  /* Capture Length */
      snaplen = atoi (optarg);
      break;
    case 'l':                  // load balancing
      target.is_loadbalance = 1;
      break;
    case 'R':
      recvport = atoi (optarg);
      if (recvport < 0 && recvport > 65535)
        recvport = IPFIX_PORT;
      rsock = recvsock ((uint16_t) recvport);
      break;
    case 'M':
#ifdef ENABLE_PTHREAD
      use_thread = 1;
#endif /* ENABLE_PTHREAD */
      break;
    case 'N':
      use_promisc = 0;
      break;
#ifdef LINUX
    case 'S':
      send_ifname = optarg;
      break;
#endif /* LINUX */
    case 'x':
      flowtrack.param.max_num_label = atoi (optarg);
      if (flowtrack.param.max_num_label < 0
          || flowtrack.param.max_num_label > 10) {
        fprintf (stderr, "Invalid number of MPLS label\n\n");
        usage ();
        exit (1);
      }
      break;
    case 'I':
      boot_time_reinit_sec = strtol (optarg, &timeunit, 10);
      if ((errno == ERANGE
           && (boot_time_reinit_sec == LONG_MAX
               || boot_time_reinit_sec == LONG_MIN))
          || (errno != 0 && boot_time_reinit_sec == 0)) {
        perror ("strtol");
        usage ();
        exit (EXIT_FAILURE);
      }
      if (timeunit == optarg) {
        fprintf (stderr, "No digits were found in boot_time_reinit\n");
        usage ();
        exit (EXIT_FAILURE);
      }
      if (*timeunit == 'd' || *timeunit == 'D') {       /* days */
        if (boot_time_reinit_sec > BOOTTIME_MAX_DAY) {
          boot_time_reinit_sec = BOOTTIME_MAX_DAY;
        }
        boot_time_reinit_sec *= (24 * 60 * 60); /* convert to seconds */
      } else if (*timeunit == 'h' || *timeunit == 'H') {        /* hours */
        if (boot_time_reinit_sec > BOOTTIME_MAX_HOUR) {
          boot_time_reinit_sec = BOOTTIME_MAX_HOUR;
        }
        boot_time_reinit_sec *= (60 * 60);      /* convert to seconds */
      } else if (*timeunit == 'm' || *timeunit == 'M') {        /* minutes */
        if (boot_time_reinit_sec > BOOTTIME_MAX_MIN) {
          boot_time_reinit_sec = BOOTTIME_MAX_MIN;
        }
        boot_time_reinit_sec *= 60;     /* convert to seconds */
      } else {
        if (boot_time_reinit_sec > BOOTTIME_MAX_SEC) {  /* seconds */
          boot_time_reinit_sec = BOOTTIME_MAX_SEC;
        }
      }
      if (verbose_flag) {
        fprintf (stderr, "boot_time_reinit is %ld seconds.\n",
                 boot_time_reinit_sec);
      }
      break;
    default:
      fprintf (stderr, "Invalid commandline option.\n");
      usage ();
      exit (1);
    }
  }

  if (capfile == NULL && dev == NULL && rsock <= 0) {
    fprintf (stderr, "-i, -r or -R option not specified.\n");
    usage ();
    exit (1);
  }

  /* join remaining arguments (if any) into bpf program */
  bpf_prog = argv_join (argc - optind, argv + optind);

  /* Will exit on failure */
  if (capfile != NULL || dev != NULL)
    setup_packet_capture (&pcap, &linktype, dev, capfile, bpf_prog,
                          target.dialect->v6_capable || always_v6,
                          use_promisc, pcap_override_buffer_size);
  else if (rsock > 0)
    linktype = 1;               //LINKTYPE_ETHERNET

  /* Netflow send socket */
  for (dest_idx = 0; dest_idx < target.num_destinations; dest_idx++) {
    dest = &target.destinations[dest_idx];
    if (dest->ss.ss_family != 0) {
      if ((err = getnameinfo ((struct sockaddr *) &dest->ss, dest->sslen,
                              dest->hostname, sizeof (dest->hostname),
                              dest->servname, sizeof (dest->servname),
                              NI_NUMERICHOST | NI_NUMERICSERV)) == -1) {
        fprintf (stderr, "getnameinfo: %d\n", err);
        exit (1);
      }
#ifdef ENABLE_NTOPNG
      if (target.dialect->version == SOFTFLOWD_NF_VERSION_NTOPNG) {
        int rc = connect_ntopng (dest->hostname, dest->servname, &dest->zmq);

        if (rc) {
          fprintf (stderr,
                   "Could not create ZeroMQ socket for %s:%s: (%d) %s\n",
                   dest->hostname, dest->servname, rc, strerror (rc));
          exit (1);
        }
      } else
#endif
        dest->sock = connsock (&dest->ss, dest->sslen, hoplimit, protocol);
#ifdef LINUX
      if (dest->sock > 0 && send_ifname != NULL) {
        bind_device (dest->sock, send_ifname);
      }
#endif /* LINUX */
    }
  }

  /* Control socket */
  if (ctlsock_path != NULL)
    ctlsock = unix_listener (ctlsock_path);     /* Will exit on fail */

  if (dontfork_flag) {
    loginit (PROGNAME, 1);
  } else {
    FILE *pidfile;

    r = daemon (0, 0);
    loginit (PROGNAME, 0);

    if ((pidfile = fopen (pidfile_path, "r")) != NULL) {
      int pid;
      if (fscanf (pidfile, "%u", &pid) == EOF) {
        //fscanf error
        if (ferror (pidfile)) {
          perror ("fscanf");
        }
      }
      fclose (pidfile);

      /* Check if the pid exists */
      int pidfree = (kill (pid, 0) && errno == ESRCH);
      if (!pidfree) {
        fprintf (stderr, "Already running under pid %u\n", pid);
        exit (1);
      }
    }
    if ((pidfile = fopen (pidfile_path, "w")) == NULL) {
      fprintf (stderr, "Couldn't open pidfile %s: %s\n",
               pidfile_path, strerror (errno));
      exit (1);
    }
    fprintf (pidfile, "%u\n", (unsigned int) getpid ());
    fclose (pidfile);

    signal (SIGINT, sighand_graceful_shutdown);
    signal (SIGTERM, sighand_graceful_shutdown);
    signal (SIGSEGV, sighand_other);

    setprotoent (1);
    drop_privs ();
  }

  logit (LOG_NOTICE, "%s v%s starting data collection", PROGNAME, PROGVER);
  for (dest_idx = 0; dest_idx < target.num_destinations; dest_idx++) {
    dest = &target.destinations[dest_idx];
    if (dest->ss.ss_family != 0) {
      logit (LOG_NOTICE, "Exporting flows from %s to [%s]:%s",
             flowtrack.param.option.interfaceName,
             dest->hostname, dest->servname);
    }
  }
  flowtrack.param.option.meteringProcessId = getpid ();
  flowtrack.param.boot_time_reinit = boot_time_reinit_sec;

  /* Main processing loop */
  gettimeofday (&flowtrack.param.system_boot_time, NULL);
  stop_collection_flag = 0;
  memset (&cb_ctxt, '\0', sizeof (cb_ctxt));
  cb_ctxt.ft = &flowtrack;
  cb_ctxt.target = &target;
  cb_ctxt.linktype = linktype;
  cb_ctxt.want_v6 = target.dialect->v6_capable || always_v6;
#ifdef ENABLE_PTHREAD
  if (use_thread) {
    if (pthread_create
        (&read_thread, NULL, process_packet_loop, (void *) &cb_ctxt) < 0) {
      perror ("pthread_create error");
      exit (1);
    }
  }
#endif /* ENABLE_PTHREAD */
  for (r = 0; graceful_shutdown_request == 0; r = 0) {
    /*
     * Silly libpcap's timeout function doesn't work, so we
     * do it here (only if we are reading live)
     */
    if (capfile == NULL && (dev != NULL || rsock > 0)) {        //online
      memset (pl, '\0', sizeof (pl));

      /* This can only be set via the control socket */
      if (!stop_collection_flag && dev != NULL) {
        pl[0].events = POLLIN | POLLERR | POLLHUP;
        pl[0].fd = pcap_fileno (pcap);
      } else if (!stop_collection_flag && rsock > 0) {
        pl[0].fd = rsock;
        pl[0].events = POLLIN | POLLERR | POLLHUP;
      }
      if (ctlsock != -1) {
        pl[1].fd = ctlsock;
        pl[1].events = POLLIN | POLLERR | POLLHUP;
      }

      r = poll (pl, (ctlsock == -1) ? 1 : 2, next_expire (&flowtrack));
      if (r == -1 && errno != EINTR) {
        logit (LOG_ERR, "Exiting on poll: %s", strerror (errno));
        break;
      }
    }

    /* Accept connection on control socket if present */
    if (ctlsock != -1 && pl[1].revents != 0) {
      if (accept_control (ctlsock, &target, &flowtrack, pcap,
                          &exit_request, &stop_collection_flag) != 0)
        break;
    }

    /* If we have data, run it through libpcap */
    if (!stop_collection_flag && (capfile != NULL || pl[0].revents != 0)) {
      if (capfile != NULL || dev != NULL) {
#ifdef ENABLE_PTHREAD
        if (use_thread)
          r =
            pcap_dispatch (pcap, flowtrack.param.max_flows, pcap_memcpy,
                           NULL);
        else
#endif /* ENABLE_PTHREAD */
          r = pcap_dispatch (pcap, flowtrack.param.max_flows, flow_cb,
                             (void *) &cb_ctxt);
        if (r == -1) {
          logit (LOG_ERR, "Exiting on pcap_dispatch: %s", pcap_geterr (pcap));
          break;
        } else if (r == 0 && capfile != NULL) {
          logit (LOG_NOTICE, "Shutting down after " "pcap EOF");
          graceful_shutdown_request = 1;
          break;
        }
      } else if (rsock > 0) {
        for (recvloop = 0;
             recvloop < flowtrack.param.max_flows && pl[0].revents != 0;
             recvloop++) {
          r = recv_psamp (rsock, &cb_ctxt);
          if (r == -1) {
            logit (LOG_ERR, "recv_psamp error");
            break;
          }
          if (recvloop + 1 == flowtrack.param.max_flows) {
            r = poll (pl, 1, next_expire (&flowtrack));
            if (r == -1 && errno != EINTR) {
              logit (LOG_ERR, "Exiting on poll: %s", strerror (errno));
              break;
            }
          }
        }
      }
    }
    r = 0;

    /* Fatal error from per-packet functions */
    if (cb_ctxt.fatal) {
      logit (LOG_WARNING, "Fatal error - exiting immediately");
      break;
    }

    /*
     * Expiry processing happens every recheck_rate seconds
     * or whenever we have exceeded the maximum number of active 
     * flows
     */
    if (flowtrack.param.num_flows > flowtrack.param.max_flows ||
        next_expire (&flowtrack) == 0) {
    expiry_check:
      /*
       * If we are reading from a capture file, we never
       * expire flows based on time - instead we only 
       * expire flows when the flow table is full. 
       */
      if (check_expired (&flowtrack, &target,
                         capfile == NULL ? CE_EXPIRE_NORMAL :
                         CE_EXPIRE_FORCED) < 0)
        logit (LOG_WARNING, "Unable to export flows");

      /*
       * If we are over max_flows, force-expire the oldest 
       * out first and immediately reprocess to evict them
       */
      if (flowtrack.param.num_flows > flowtrack.param.max_flows) {
        force_expire (&flowtrack,
                      flowtrack.param.num_flows - flowtrack.param.max_flows);
        goto expiry_check;
      }
    }
  }

  /* Flags set by signal handlers or control socket */
  if (graceful_shutdown_request) {
    logit (LOG_WARNING, "Shutting down on user request");
    check_expired (&flowtrack, &target, CE_EXPIRE_ALL);
  } else if (exit_request)
    logit (LOG_WARNING, "Exiting immediately on user request");
  else
    logit (LOG_ERR, "Exiting immediately on internal error");

  if (capfile != NULL && dontfork_flag)
    statistics (&flowtrack, stdout, pcap);

#ifdef ENABLE_PTHREAD
  if (use_thread) {
    pthread_cond_signal (&read_cond);
    pthread_join (read_thread, NULL);
  }
#endif /* ENABLE_PTHREAD */

  pcap_close (pcap);

  for (dest_idx = 0; dest_idx < target.num_destinations; dest_idx++) {
    dest = &target.destinations[dest_idx];
    if (dest->sock != -1)
      close (dest->sock);
  }

  unlink (pidfile_path);
  if (ctlsock_path != NULL)
    unlink (ctlsock_path);

  if (rsock > 0)
    close (rsock);

  return (r == 0 ? 0 : 1);
}
