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

/* $Id$ */

/*
 * This is software implementation of Cisco's NetFlow(tm) traffic 
 * reporting system. It operates by listening (via libpcap) on a 
 * promiscuous interface and tracking traffic flows. 
 *
 * Traffic flows are recorded by source/destination/protocol IP address or, in the
 * case of TCP and UDP, by src_addr:src_port/dest_addr:dest_port/protocol
 *
 * Flows expire automatically after a period of inactivity (default: 1 hour)
 * They may also be evicted (in order of age) in situations where there are 
 * more flows than slots available.
 *
 * Netflow version 1 compatible packets are sent to a specified target 
 * host upon flow expiry.
 *
 * As this implementation watches traffic promiscuously, it is likely to 
 * place significant load on hosts or gateways on which it is installed.
 */

#include "common.h"
#include "convtime.h"

#include "sys-tree.h"

#include <pcap.h>

/* Global variables */
static int verbose_flag = 0;		/* Debugging flag */

/* Signal handler flags */
static int graceful_shutdown_request = 0;	

/* "System boot" time, for SysUptime */
static struct timeval system_boot_time;

/*
 * Capture length for libpcap: Must fit the link layer header, plus 
 * a maximally sized ip header and most of a TCP header
 */
#define LIBPCAP_SNAPLEN		96

/*
 * Timeouts
 */
#define DEFAULT_TCP_TIMEOUT		3600
#define DEFAULT_TCP_RST_TIMEOUT		120
#define DEFAULT_TCP_FIN_TIMEOUT		300
#define DEFAULT_UDP_TIMEOUT		300
#define DEFAULT_GENERAL_TIMEOUT		3600
#define DEFAULT_MAXIMUM_LIFETIME	(3600*24*7)

/*
 * How many seconds to wait for pcap data before doing housekeeping
 */
#define EXPIRY_WAIT	8

/*
 * How many seconds to wait in poll
 */
#define POLL_WAIT	((EXPIRY_WAIT * 1000) / 2)

/*
 * Default maximum number of flow to track simultaneously 
 * 8192 corresponds to just under 1Mb of flow data
 */
#define DEFAULT_MAX_FLOWS	8192

/* Store a couple of statistics, maybe more in the future */
struct STATISTIC {
	double min, mean, max;
};

/*
 * This structure is the root of the flow tracking system.
 * It holds the root of the tree of active flows and the head of the
 * tree of expiry events. It also collects miscellaneous statistics
 */
struct FLOWTRACK {
	/* The flows and their expiry events */
	RB_HEAD(FLOWS, FLOW) flows;		/* Top of flow tree */
	RB_HEAD(EXPIRIES, EXPIRY) expiries;	/* Top of expiries tree */

	unsigned int num_flows;			/* # of active flows */
	u_int64_t next_flow_seq;		/* Next flow ID */
	
	/* Flow timeouts */
	int tcp_timeout;			/* Open TCP connections */
	int tcp_rst_timeout;			/* TCP flows after RST */
	int tcp_fin_timeout;			/* TCP flows after bidi FIN */
	int udp_timeout;			/* UDP flows */
	int general_timeout;			/* Everything else */
	int maximum_lifetime;			/* Maximum life for flows */

	/* Statistics */
	u_int64_t total_packets;		/* # of good packets */
	u_int64_t non_ip_packets;		/* # of not-IP packets */
	u_int64_t bad_packets;			/* # of bad packets */
	u_int64_t flows_expired;		/* # expired */
	u_int64_t flows_exported;		/* # of flows sent */
	u_int64_t flows_dropped;		/* # of flows dropped */
	u_int64_t flows_force_expired;		/* # of flows forced out */
	u_int64_t packets_sent;			/* # netflow packets sent */
	struct STATISTIC duration;		/* Flow duration */
	struct STATISTIC octets;		/* Bytes (bidir) */
	struct STATISTIC packets;		/* Packets (bidir) */

	/* Per protocol statistics */
	u_int64_t flows_pp[256];
	u_int64_t octets_pp[256];
	u_int64_t packets_pp[256];
	struct STATISTIC duration_pp[256];

	/* Timeout statistics */
	u_int64_t expired_general;
	u_int64_t expired_tcp;
	u_int64_t expired_tcp_rst;
	u_int64_t expired_tcp_fin;
	u_int64_t expired_udp;
	u_int64_t expired_maxlife;
	u_int64_t expired_overbytes;
	u_int64_t expired_maxflows;
	u_int64_t expired_flush;
};

/*
 * This structure is an entry in the tree of flows that we are 
 * currently tracking. 
 *
 * Because flows are matched _bi-directionally_, they must be stored in
 * a canonical format: the numerically lowest address and port number must
 * be stored in the first address and port array slot respectively.
 */
struct FLOW {
	/* Housekeeping */
	struct EXPIRY *expiry;			/* Pointer to expiry record */
	RB_ENTRY(FLOW) trp;			/* Tree pointer */

	/* Per-flow statistics (all in _host_ byte order) */
	u_int64_t flow_seq;			/* Flow ID */
	struct timeval flow_start;		/* Time of creation */
	struct timeval flow_last;		/* Time of last traffic */

	/* Per-endpoint statistics (all in _host_ byte order) */
	u_int32_t octets[2];			/* Octets so far */
	u_int32_t packets[2];			/* Packets so far */

	/* Flow identity (all are in _network_ byte order) */
	u_int32_t addr[2];			/* Endpoint addresses */
	u_int16_t port[2];			/* Endpoint ports */
	u_int8_t tcp_flags[2];			/* Cumulative OR of flags */
	u_int8_t protocol;			/* Protocol */
};

/*
 * This is an entry in the tree of expiry events. The tree is used to 
 * avoid traversion the whole tree of active flows looking for ones to
 * expire. "expires_at" is the time at which the flow should be discarded,
 * or zero if it is scheduled for immediate disposal. 
 *
 * When a flow which hasn't been scheduled for immediate expiry registers 
 * traffic, it is deleted from its current position in the tree and 
 * re-inserted (subject to its updated timeout).
 *
 * Expiry scans operate by starting at the head of the tree and expiring
 * each entry with expires_at < now
 * 
 */
struct EXPIRY {
	RB_ENTRY(EXPIRY) trp;			/* Tree pointer */
	struct FLOW *flow;			/* pointer to flow */

	u_int32_t expires_at;			/* time_t */
	enum { 
		R_GENERAL, R_TCP, R_TCP_RST, R_TCP_FIN, R_UDP, 
		R_MAXLIFE, R_OVERBYTES, R_OVERFLOWS, R_FLUSH
	} reason;
};

/* Context for libpcap callback functions */
struct CB_CTXT {
	struct FLOWTRACK *ft;
	int linktype;
	int fatal;
};

/*
 * This is the Cisco Netflow(tm) version 1 packet format
 * Based on:
 * http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm
 */
struct NF1_HEADER {
	u_int16_t version, flows;
	u_int32_t uptime_ms, time_sec, time_nanosec;
};
struct NF1_FLOW {
	u_int32_t src_ip, dest_ip, nexthop_ip;
	u_int16_t if_index_in, if_index_out;
	u_int32_t flow_packets, flow_octets;
	u_int32_t flow_start, flow_finish;
	u_int16_t src_port, dest_port;
	u_int16_t pad1;
	u_int8_t protocol, tos, tcp_flags;
	u_int8_t pad2, pad3, pad4;
	u_int32_t reserved1;
#if 0
 	u_int8_t reserved2; /* XXX: no longer used */
#endif
};
/* Maximum of 24 flows per packet */
#define NF1_MAXFLOWS		24
#define NF1_MAXPACKET_SIZE	(sizeof(struct NF1_HEADER) + \
				 (NF1_MAXFLOWS * sizeof(struct NF1_FLOW)))

/* Signal handlers */
static void sighand_graceful_shutdown(int signum)
{
	graceful_shutdown_request = signum;
}

static void sighand_other(int signum)
{
	/* XXX: this may not be completely safe */
	syslog(LOG_WARNING, "Exiting immediately on unexpected signal %d", signum);
	_exit(0);
}

/*
 * This is the flow comparison function.
 */
static inline int
flow_compare(struct FLOW *a, struct FLOW *b)
{
	/* Be careful to avoid signed vs unsigned issues here */

	if (a->addr[0] != b->addr[0])
		return (ntohl(a->addr[0]) > ntohl(b->addr[0]) ? 1 : -1);

	if (a->addr[1] != b->addr[1])
		return (ntohl(a->addr[1]) > ntohl(b->addr[1]) ? 1 : -1);

	if (a->protocol != b->protocol)
		return (a->protocol > b->protocol ? 1 : -1);

	if (a->port[0] != b->port[0])
		return (ntohs(a->port[0]) > ntohs(b->port[0]) ? 1 : -1);

	if (a->port[1] != b->port[1])
		return (ntohs(a->port[1]) > ntohs(b->port[1]) ? 1 : -1);

	return (0);
}

/* Generate functions for flow tree */
RB_PROTOTYPE(FLOWS, FLOW, trp, flow_compare);
RB_GENERATE(FLOWS, FLOW, trp, flow_compare);

/*
 * This is the expiry comparison function.
 */
static inline int
expiry_compare(struct EXPIRY *a, struct EXPIRY *b)
{
	if (a->expires_at != b->expires_at)
		return (a->expires_at > b->expires_at ? 1 : -1);

	/* Make expiry entries unique by comparing flow sequence */
	if (a->flow->flow_seq != b->flow->flow_seq)
		return (a->flow->flow_seq > b->flow->flow_seq ? 1 : -1);

	return (0);
}

/* Generate functions for flow tree */
RB_PROTOTYPE(EXPIRIES, EXPIRY, trp, expiry_compare);
RB_GENERATE(EXPIRIES, EXPIRY, trp, expiry_compare);

/* Format a time in an ISOish format */
static const char *
format_time(time_t t)
{
	struct tm *tm;
	static char buf[20];

	tm = localtime(&t);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

	return (buf);

}

/* Format a flow in a verbose and ugly way */
static const char *
format_flow(struct FLOW *flow)
{
	struct in_addr i;
	char addr1[16], addr2[16], stime[20], ftime[20];
	static char buf[1024];

	i.s_addr = flow->addr[0];
	snprintf(addr1, sizeof(addr1), "%s", inet_ntoa(i));

	i.s_addr = flow->addr[1];
	snprintf(addr2, sizeof(addr2), "%s", inet_ntoa(i));

	snprintf(stime, sizeof(ftime), "%s", 
	    format_time(flow->flow_start.tv_sec));
	snprintf(ftime, sizeof(ftime), "%s", 
	    format_time(flow->flow_last.tv_sec));

	snprintf(buf, sizeof(buf), 
	    "seq:%llu %s:%hu <> %s:%hu proto:%u octets>:%u packets>:%u octets<:%u packets<:%u start:%s.%03ld finish:%s.%03ld tcp>:%02x tcp<:%02x",
	    flow->flow_seq,
	    addr1, ntohs(flow->port[0]), addr2, ntohs(flow->port[1]),
	    (int)flow->protocol, 
	    flow->octets[0], flow->packets[0], 
	    flow->octets[1], flow->packets[1], 
	    stime, (flow->flow_start.tv_usec + 500) / 1000, 
	    ftime, (flow->flow_start.tv_usec + 500) / 1000,
	    flow->tcp_flags[0], flow->tcp_flags[1]);

	return (buf);
}

/* Format a flow in a brief way */
static const char *
format_flow_brief(struct FLOW *flow)
{
	struct in_addr i;
	char addr1[16], addr2[16];
	static char buf[1024];

	i.s_addr = flow->addr[0];
	snprintf(addr1, sizeof(addr1), "%s", inet_ntoa(i));

	i.s_addr = flow->addr[1];
	snprintf(addr2, sizeof(addr2), "%s", inet_ntoa(i));

	snprintf(buf, sizeof(buf), 
	    "seq:%llu %s:%hu <> %s:%hu proto:%u",
	    flow->flow_seq,
	    addr1, ntohs(flow->port[0]), addr2, ntohs(flow->port[1]),
	    (int)flow->protocol);

	return (buf);
}

/* Convert a packet to a partial flow record (used for comparison) */
static int
packet_to_flowrec(struct FLOW *flow, const u_int8_t *pkt, 
    const size_t caplen, const size_t len)
{
	const struct ip *ip = (const struct ip *)pkt;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	int ndx;

	if (caplen < 20 || caplen < ip->ip_hl * 4)
		return (-1);	/* Runt packet */
	if (ip->ip_v != 4)
		return (-1);	/* Unsupported IP version */
	
	memset(flow, '\0', sizeof(*flow));

	/* Prepare to store flow in canonical format */
	ndx = ntohl(ip->ip_src.s_addr) > ntohl(ip->ip_dst.s_addr) ? 1 : 0;
	
	flow->addr[ndx] = ip->ip_src.s_addr;
	flow->addr[ndx ^ 1] = ip->ip_dst.s_addr;
	flow->protocol = ip->ip_p;
	flow->octets[ndx] = len;
	flow->packets[ndx] = 1;

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		tcp = (const struct tcphdr *)(pkt + (ip->ip_hl * 4));

		if (caplen - (ip->ip_hl * 4) < sizeof(*tcp)) /* Runt packet */
			return (-1);
		flow->port[ndx] = tcp->th_sport;
		flow->port[ndx ^ 1] = tcp->th_dport;
		flow->tcp_flags[ndx] |= tcp->th_flags;
		break;
	case IPPROTO_UDP:
		udp = (const struct udphdr *)(pkt + (ip->ip_hl * 4));

		if (caplen - (ip->ip_hl * 4) < sizeof(*udp)) /* Runt packet */
			return (-1);
		flow->port[ndx] = udp->uh_sport;
		flow->port[ndx ^ 1] = udp->uh_dport;
		break;
	}
	
	return (0);
}

static void
flow_update_expiry(struct FLOWTRACK *ft, struct FLOW *flow)
{
	/* Flows over 2Gb traffic */
	if (flow->octets[0] > (1U << 31) || flow->octets[1] > (1U << 31)) {
		flow->expiry->expires_at = 0;
		flow->expiry->reason = R_OVERBYTES;
		return;
	}
	
	/* Flows over maximum life seconds */
	if (ft->maximum_lifetime != 0 && 
	    flow->flow_last.tv_sec - flow->flow_start.tv_sec > 
	    ft->maximum_lifetime) {
		flow->expiry->expires_at = 0;
		flow->expiry->reason = R_MAXLIFE;
		return;
	}
	
	if (flow->protocol == IPPROTO_TCP) {
		/* Reset TCP flows */
		if ((flow->tcp_flags[0] & TH_RST) ||
		    (flow->tcp_flags[1] & TH_RST)) {
			flow->expiry->expires_at = flow->flow_last.tv_sec + 
			    ft->tcp_rst_timeout;
			flow->expiry->reason = R_TCP_RST;
			return;
		}
		/* Finished TCP flows */
		if ((flow->tcp_flags[0] & TH_FIN) &&
		    (flow->tcp_flags[1] & TH_FIN)) {
			flow->expiry->expires_at = flow->flow_last.tv_sec + 
			    ft->tcp_fin_timeout;
			flow->expiry->reason = R_TCP_FIN;
			return;
		}

		/* TCP flows */
		flow->expiry->expires_at = flow->flow_last.tv_sec + 
		    ft->tcp_timeout;
		flow->expiry->reason = R_TCP;
		return;
	}

	if (flow->protocol == IPPROTO_UDP) {
		/* UDP flows */
		flow->expiry->expires_at = flow->flow_last.tv_sec + 
		    ft->udp_timeout;
		flow->expiry->reason = R_UDP;
		return;
	}

	/* Everything else */
	flow->expiry->expires_at = flow->flow_last.tv_sec + 
	    ft->general_timeout;
	flow->expiry->reason = R_GENERAL;
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
process_packet(struct FLOWTRACK *ft, const u_int8_t *pkt, 
    const u_int32_t caplen, const u_int32_t len, 
    const struct timeval *received_time)
{
	struct FLOW tmp, *flow;

	ft->total_packets++;

	/* Convert the IP packet to a flow identity */
	if (packet_to_flowrec(&tmp, pkt, caplen, len) == -1) {
		ft->bad_packets++;
		return (PP_BAD_PACKET);
	}

	/* If a matching flow does not exist, create and insert one */
	if ((flow = RB_FIND(FLOWS, &ft->flows, &tmp)) == NULL) {
		/* Allocate and fill in the flow */
		if ((flow = malloc(sizeof(*flow))) == NULL)
			return (PP_MALLOC_FAIL);
		memcpy(flow, &tmp, sizeof(*flow));
		memcpy(&flow->flow_start, received_time,
		    sizeof(flow->flow_start));
		flow->flow_seq = ft->next_flow_seq++;
		RB_INSERT(FLOWS, &ft->flows, flow);

		/* Allocate and fill in the associated expiry event */
		if ((flow->expiry = malloc(sizeof(*flow->expiry))) == NULL)
			return (PP_MALLOC_FAIL);
		flow->expiry->flow = flow;
		/* Must be non-zero (0 means expire immediately) */
		flow->expiry->expires_at = 1;
		flow->expiry->reason = R_GENERAL;

		ft->num_flows++;
		if (verbose_flag)
			syslog(LOG_DEBUG, "ADD FLOW %s", format_flow_brief(flow));
	} else {
		/*
		 * If an entry is scheduled for immediate expiry, then 
		 * don't bother moving it from the head of the list
		 */
		if (flow->expiry->expires_at != 0) {
#if 0
			syslog(LOG_DEBUG, "Removing expiry %p", flow->expiry);
#endif
			RB_REMOVE(EXPIRIES, &ft->expiries, flow->expiry);
		}
	
		/* Update flow statistics */
		flow->packets[0] += tmp.packets[0];
		flow->octets[0] += tmp.octets[0];
		flow->tcp_flags[0] |= tmp.tcp_flags[0];
		flow->packets[1] += tmp.packets[1];
		flow->octets[1] += tmp.octets[1];
		flow->tcp_flags[1] |= tmp.tcp_flags[1];
	}
	
	memcpy(&flow->flow_last, received_time, sizeof(flow->flow_last));

	if (flow->expiry->expires_at != 0) {
		flow_update_expiry(ft, flow);
		RB_INSERT(EXPIRIES, &ft->expiries, flow->expiry);
	}

	return (PP_OK);
}

/*
 * Subtract two timevals. Returns (t1 - t2) in milliseconds.
 */
static u_int32_t
timeval_sub_ms(struct timeval *t1, struct timeval *t2)
{
	struct timeval res;

	res.tv_sec = t1->tv_sec - t2->tv_sec;
	res.tv_usec = t1->tv_usec - t2->tv_usec;
	if (res.tv_usec < 0) {
		res.tv_usec += 1000000L;
		res.tv_sec--;
	}
	return ((u_int32_t)res.tv_sec * 1000 + (u_int32_t)res.tv_usec / 1000);
}

/*
 * Given an array of expired flows, send netflow v1 report packets
 * Returns number of packets sent or -1 on error
 */
static int
send_netflow_v1(struct FLOW **flows, int num_flows, int nfsock)
{
	struct timeval now;
	u_int32_t uptime_ms;
	u_int8_t packet[NF1_MAXPACKET_SIZE];	/* Maximum allowed packet size (24 flows) */
	struct NF1_HEADER *hdr = NULL;
	struct NF1_FLOW *flw = NULL;
	int i, j, offset, num_packets;
	
	gettimeofday(&now, NULL);
	uptime_ms = timeval_sub_ms(&now, &system_boot_time);

	hdr = (struct NF1_HEADER *)packet;
	for(num_packets = offset = j = i = 0; i < num_flows; i++) {
		if (j >= NF1_MAXFLOWS - 1) {
			if (verbose_flag)
				syslog(LOG_DEBUG, "Sending flow packet len = %d", offset);
			hdr->flows = htons(hdr->flows);
			if (send(nfsock, packet, (size_t)offset, 0) == -1)
				return (-1);
			j = 0;
			num_packets++;
		}
		if (j == 0) {
#if 0
			if (verbose_flag)
				syslog(LOG_DEBUG, "Starting on new flow packet");
#endif
			memset(&packet, '\0', sizeof(packet));
			hdr->version = htons(1);
			hdr->flows = 0; /* Filled in as we go */
			hdr->uptime_ms = htonl(uptime_ms);
			hdr->time_sec = htonl(now.tv_sec);
			hdr->time_nanosec = htonl(now.tv_usec * 1000);
			offset = sizeof(*hdr);
		}		
		flw = (struct NF1_FLOW *)(packet + offset);
		
		if (flows[i]->octets[0] > 0) {
#if 0
			if (verbose_flag)
				syslog(LOG_DEBUG, "Flow %d of %d 0>1", i, num_flows);
#endif
			flw->src_ip = flows[i]->addr[0];
			flw->dest_ip = flows[i]->addr[1];
			flw->src_port = flows[i]->port[0];
			flw->dest_port = flows[i]->port[1];
			flw->flow_packets = htonl(flows[i]->packets[0]);
			flw->flow_octets = htonl(flows[i]->octets[0]);
			flw->flow_start = htonl(timeval_sub_ms(&flows[i]->flow_start, &system_boot_time));
			flw->flow_finish = htonl(timeval_sub_ms(&flows[i]->flow_last, &system_boot_time));
			flw->protocol = flows[i]->protocol;
			flw->tcp_flags = flows[i]->tcp_flags[0];
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF1_FLOW *)(packet + offset);

		if (flows[i]->octets[1] > 0) {
#if 0
			if (verbose_flag)
				syslog(LOG_DEBUG, "Flow %d of %d 1<0", i, num_flows);
#endif
			flw->src_ip = flows[i]->addr[1];
			flw->dest_ip = flows[i]->addr[0];
			flw->src_port = flows[i]->port[1];
			flw->dest_port = flows[i]->port[0];
			flw->flow_packets = htonl(flows[i]->packets[1]);
			flw->flow_octets = htonl(flows[i]->octets[1]);
			flw->flow_start = htonl(timeval_sub_ms(&flows[i]->flow_start, &system_boot_time));
			flw->flow_finish = htonl(timeval_sub_ms(&flows[i]->flow_last, &system_boot_time));
			flw->protocol = flows[i]->protocol;
			flw->tcp_flags = flows[i]->tcp_flags[1];
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
	}

	/* Send any leftovers */
	if (j != 0) {
		if (verbose_flag)
			syslog(LOG_DEBUG, "Sending flow packet len = %d", offset);
		hdr->flows = htons(hdr->flows);
		if (send(nfsock, packet, (size_t)offset, 0) == -1)
			return (-1);
		num_packets++;
	}

	return (num_packets);
}

static void
update_statistic(struct STATISTIC *s, double new, double n)
{
	if (n == 1.0) {
		s->min = s->mean = s->max = new;
		return;
	}

	s->min = MIN(s->min, new);
	s->max = MAX(s->max, new);

	/*
	 * XXX I think this method of calculating the a new mean from an 
	 * existing mean is correct but I don't have my stats book handy
	 *
	 * I use this instead of "Mnew = ((Mold * n - 1) + S) / n" to 
	 * avoid accumulating fp rounding errors. Maybe I'm misguided :)
	 */
	s->mean = s->mean + ((new - s->mean) / n);
}


/* Update global statistics */
static void
update_statistics(struct FLOWTRACK *ft, struct FLOW *flow)
{
	double tmp;
	static double n = 1.0;

	ft->flows_expired++;
	ft->flows_pp[flow->protocol % 256]++;

	tmp = (double)flow->flow_last.tv_sec +
	    ((double)flow->flow_last.tv_usec / 1000000.0);
	tmp -= (double)flow->flow_start.tv_sec +
	    ((double)flow->flow_start.tv_usec / 1000000.0);
	if (tmp < 0.0)
		tmp = 0.0;

	update_statistic(&ft->duration, tmp, n);
	update_statistic(&ft->duration_pp[flow->protocol], tmp, 
	    (double)ft->flows_pp[flow->protocol % 256]);

	tmp = flow->octets[0] + flow->octets[1];
	update_statistic(&ft->octets, tmp, n);
	ft->octets_pp[flow->protocol % 256] += tmp;

	tmp = flow->packets[0] + flow->packets[1];
	update_statistic(&ft->packets, tmp, n);
	ft->packets_pp[flow->protocol % 256] += tmp;

	n++;
}

static void 
update_expiry_stats(struct FLOWTRACK *ft, struct EXPIRY *e)
{
	switch (e->reason) {
	case R_GENERAL:
		ft->expired_general++;
		break;
	case R_TCP:
		ft->expired_tcp++;
		break;
	case R_TCP_RST:
		ft->expired_tcp_rst++;
		break;
	case R_TCP_FIN:
		ft->expired_tcp_fin++;
		break;
	case R_UDP:
		ft->expired_udp++;
		break;
	case R_MAXLIFE:
		ft->expired_maxlife++;
		break;
	case R_OVERBYTES:
		ft->expired_overbytes++;
		break;
	case R_OVERFLOWS:
		ft->expired_maxflows++;
		break;
	case R_FLUSH:
		ft->expired_flush++;
		break;
	}	
}

/*
 * Scan the tree of expiry events and process expired flows. If zap_all
 * is set, then forcibly expire all flows.
 */
#define CE_EXPIRE_NORMAL	0  /* Normal expiry processing */
#define CE_EXPIRE_ALL		-1 /* Expire all flows immediately */
#define CE_EXPIRE_FORCED	1  /* Only expire force-expired flows */
static int
check_expired(struct FLOWTRACK *ft, int nfsock, int ex)
{
	struct FLOW **expired_flows;
	int num_expired, i, r;
	struct timeval now;

	struct EXPIRY *expiry, *nexpiry;

	gettimeofday(&now, NULL);
	r = 0;
	num_expired = 0;
	expired_flows = NULL;

	if (verbose_flag)
		syslog(LOG_DEBUG, "Starting expiry scan: mode %d", ex);

	for(expiry = RB_MIN(EXPIRIES, &ft->expiries); expiry != NULL; expiry = nexpiry) {
		nexpiry = RB_NEXT(EXPIRIES, &ft->expiries, expiry);
		if ((expiry->expires_at == 0) || (ex == CE_EXPIRE_ALL) || 
		    (ex != CE_EXPIRE_FORCED &&
		    (expiry->expires_at < now.tv_sec))) {
			/* Flow has expired */
			if (verbose_flag)
				syslog(LOG_DEBUG, "Queuing flow seq:%llu (%p) for expiry",
				   expiry->flow->flow_seq, expiry->flow);

			/* Add to array of expired flows */
			expired_flows = realloc(expired_flows,
			    sizeof(*expired_flows) * (num_expired + 1));
			expired_flows[num_expired] = expiry->flow;
			num_expired++;

			if (ex == CE_EXPIRE_ALL)
				expiry->reason = R_FLUSH;

			update_expiry_stats(ft, expiry);

			/* Remove from flow tree, destroy expiry event */
			RB_REMOVE(FLOWS, &ft->flows, expiry->flow);
			RB_REMOVE(EXPIRIES, &ft->expiries, expiry);
			expiry->flow->expiry = NULL;
			free(expiry);

			ft->num_flows--;
		}
	}

	if (verbose_flag)
		syslog(LOG_DEBUG, "Finished scan %d flow(s) to be evicted", num_expired);
	
	/* Processing for expired flows */
	if (num_expired > 0) {
		if (nfsock != -1) {
			r = send_netflow_v1(expired_flows, num_expired, nfsock);
			if (verbose_flag)
				syslog(LOG_DEBUG, "sent %d netflow packets", r);
			if (r > 0) {
				ft->flows_exported += num_expired * 2;
				ft->packets_sent += r;
			} else {
				ft->flows_dropped += num_expired * 2;
			}
		}
		for (i = 0; i < num_expired; i++) {
			if (verbose_flag) {
				syslog(LOG_DEBUG, "EXPIRED: %s (%p)", 
				    format_flow(expired_flows[i]),
				    expired_flows[i]);
			}
			update_statistics(ft, expired_flows[i]);

			free(expired_flows[i]);
		}
	
		free(expired_flows);
	}

	return (r == -1 ? -1 : num_expired);
}

/*
 * Force expiry of num_to_expire flows (e.g. when flow table overfull) 
 */
static void
force_expire(struct FLOWTRACK *ft, u_int32_t num_to_expire)
{
	struct EXPIRY *expiry;

	/* XXX move all overflow processing here (maybe) */
	if (verbose_flag)
		syslog(LOG_INFO, "Forcing expiry of %d flows",
		    num_to_expire);

	RB_FOREACH(expiry, EXPIRIES, &ft->expiries) {
		if (num_to_expire-- <= 0)
			break;
		expiry->expires_at = 0;
		expiry->reason = R_OVERFLOWS;
		ft->flows_force_expired++;
	}
}

/* Delete all flows that we know about without processing */
static int
delete_all_flows(struct FLOWTRACK *ft)
{
	struct FLOW *flow, *nflow;
	int i;
	
	i = 0;
	for(flow = RB_MIN(FLOWS, &ft->flows); flow != NULL; flow = nflow) {
		nflow = RB_NEXT(FLOWS, &ft->flows, flow);
		RB_REMOVE(FLOWS, &ft->flows, flow);
		
		RB_REMOVE(EXPIRIES, &ft->expiries, flow->expiry);
		free(flow->expiry);

		ft->num_flows--;
		free(flow);
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
statistics(struct FLOWTRACK *ft, FILE *out)
{
	int i;
	struct protoent *pe;
	char proto[32];

	fprintf(out, "Number of active flows: %d\n", ft->num_flows);
	fprintf(out, "Packets processed: %llu\n", ft->total_packets);
	fprintf(out, "Ignored packets: %llu (%llu non-IP, %llu too short)\n",
	    ft->non_ip_packets + ft->bad_packets, ft->non_ip_packets, ft->bad_packets);
	fprintf(out, "Flows expired: %llu (%llu forced)\n", 
	    ft->flows_expired, ft->flows_force_expired);
	fprintf(out, "Flows exported: %llu in %llu packets (%llu failures)\n",
	    ft->flows_exported, ft->packets_sent, ft->flows_dropped);

	fprintf(out, "\n");

	if (ft->flows_expired != 0) {
		fprintf(out, "Expired flow statistics:  minimum       average       maximum\n");
		fprintf(out, "  Flow bytes:        %12.0f  %12.0f  %12.0f\n", 
		    ft->octets.min, ft->octets.mean, ft->octets.max);
		fprintf(out, "  Flow packets:      %12.0f  %12.0f  %12.0f\n", 
		    ft->packets.min, ft->packets.mean, ft->packets.max);
		fprintf(out, "  Duration:          %12.2fs %12.2fs %12.2fs\n", 
		    ft->duration.min, ft->duration.mean, ft->duration.max);

		fprintf(out, "\n");
		fprintf(out, "Expired flow reasons:\n");
		fprintf(out, "       tcp = %9llu   tcp.rst = %9llu   tcp.fin = %9llu\n", 
		    ft->expired_tcp, ft->expired_tcp_rst, ft->expired_tcp_fin);
		fprintf(out, "       udp = %9llu   general = %9llu   maxlife = %9llu\n",
		    ft->expired_udp, ft->expired_general, ft->expired_maxlife);
		fprintf(out, "  over 2Gb = %9llu\n", ft->expired_overbytes);
		fprintf(out, "  maxflows = %9llu\n", ft->expired_maxflows);
		fprintf(out, "   flushed = %9llu\n", ft->expired_flush);

		fprintf(out, "\n");

		fprintf(out, "Per-protocol statistics:     Octets      Packets   Avg Life    Max Life\n");
		setprotoent(1);
		for(i = 0; i < 256; i++) {
			if (ft->packets_pp[i]) {
				pe = getprotobynumber(i);
				snprintf(proto, sizeof(proto), "%s (%d)", 
				    pe != NULL ? pe->p_name : "Unknown", i);
				fprintf(out, 
				    "  %17s: %14llu %12llu   %8.2fs %10.2fs\n",
				    proto,
				    ft->octets_pp[i], 
				    ft->packets_pp[i],
				    ft->duration_pp[i].mean,
				    ft->duration_pp[i].max);
			}
		}
		endprotoent();
	}

#if 0
	fprintf(out, "RB_EMPTY: %d\n", RB_EMPTY(&ft->flows));
	fprintf(out, "TAILQ_EMPTY: %d\n", TAILQ_EMPTY(&ft->expiries));
#endif

	return (0);
}

static void
dump_flows(struct FLOWTRACK *ft, FILE *out)
{
	struct EXPIRY *expiry;
	time_t now;

	now = time(NULL);

	RB_FOREACH(expiry, EXPIRIES, &ft->expiries) {
		fprintf(out, "ACTIVE %s\n", format_flow(expiry->flow));
		if ((long int) expiry->expires_at - now < 0) {
			fprintf(out, 
			    "EXPIRY EVENT for flow %llu now%s\n",
			    expiry->flow->flow_seq, 
			    expiry->expires_at == 0 ? " (FORCED)": "");
		} else {
			fprintf(out, 
			    "EXPIRY EVENT for flow %llu in %ld seconds\n",
			    expiry->flow->flow_seq, 
			    (long int) expiry->expires_at - now);
		}
		fprintf(out, "\n");
	}
}

/*
 * Figure out how many bytes to skip from front of packet to get past 
 * datalink headers. If pkt is specified, also check whether it is an 
 * IP packet. 
 *
 * Returns number of bytes to skip or -1 to indicate that entire 
 * packet should be skipped
 */
static int 
datalink_skip(int linktype, const u_int8_t *pkt, u_int32_t caplen)
{
	int skiplen;

	/* Figure out how many bytes to skip */
	switch(linktype) {
		case DLT_EN10MB:
			skiplen = 6+6+2;
			break;
		case DLT_PPP:
			skiplen = 5;
			break;
		case DLT_RAW:
			skiplen = 0;
			break;
#ifdef DLT_LOOP
		case DLT_LOOP:
#endif
		case DLT_NULL:
			skiplen = 4;
			break;
		default:
			skiplen = -1;
			break;
	}
	
	if (pkt == NULL || skiplen <= 0)
		return (skiplen);
	
	if (caplen <= skiplen)
		return (-1);
	
	/* Test the supplied packet to determine if it is IP */	
	switch(linktype) {
		case DLT_EN10MB:
			if (ntohs(*(const u_int16_t*)(pkt + 12)) != 0x0800)
				skiplen = -1;
			break;
		case DLT_PPP:
			/* XXX: untested */
			if (ntohs(*(const u_int16_t*)(pkt + 3)) != 0x21)
				skiplen = -1;
			break;
		case DLT_NULL:
			/* XXX: untested */
			if (*(const u_int32_t*)pkt != AF_INET)
				skiplen = -1;
			break;
#ifdef DLT_LOOP
		case DLT_LOOP:
#endif
			if (ntohl(*(const u_int32_t*)pkt) != AF_INET)
				skiplen = -1;
			break;
		case DLT_RAW:
			/* XXX: untested */
			break;
		default:
			skiplen = -1;
			break;
	}
	
	return (skiplen);
}

/*
 * Per-packet callback function from libpcap. Pass the packet (if it is IP)
 * sans datalink headers to process_packet.
 */
static void
flow_cb(u_char *user_data, const struct pcap_pkthdr* phdr, 
    const u_char *pkt)
{
	int s;
	struct CB_CTXT *cb_ctxt = (struct CB_CTXT *)user_data;
	
	if ((s = datalink_skip(cb_ctxt->linktype, pkt, phdr->caplen)) == -1) {
		cb_ctxt->ft->non_ip_packets++;
	} else {
		if (process_packet(cb_ctxt->ft, pkt + s, 
		    phdr->caplen - s, phdr->len - s, 
		    (const struct timeval *)&phdr->ts) == PP_MALLOC_FAIL)
			cb_ctxt->fatal = 1;
	}
}

static void
print_timeouts(struct FLOWTRACK *ft, FILE *out)
{
	fprintf(out, "           TCP timeout: %ds\n", ft->tcp_timeout);
	fprintf(out, "  TCP post-RST timeout: %ds\n", ft->tcp_rst_timeout);
	fprintf(out, "  TCP post-FIN timeout: %ds\n", ft->tcp_fin_timeout);
	fprintf(out, "           UDP timeout: %ds\n", ft->udp_timeout);
	fprintf(out, "       General timeout: %ds\n", ft->general_timeout);
	fprintf(out, "      Maximum lifetime: %ds\n", ft->maximum_lifetime);
}

static int
accept_control(int lsock, int nfsock, struct FLOWTRACK *ft,
    int *exit_request, int *stop_collection_flag)
{
	unsigned char buf[64], *p;
	FILE *ctlf;
	int fd, ret;

	if ((fd = accept(lsock, NULL, NULL)) == -1) {
		syslog(LOG_ERR, "ctl accept: %s - exiting",
		    strerror(errno));
		return(-1);
	}
	if ((ctlf = fdopen(fd, "r+")) == NULL) {
		syslog(LOG_ERR, "fdopen: %s - exiting\n",
		    strerror(errno));
		close(fd);
		return (-1);
	}
	setlinebuf(ctlf);

	if (fgets(buf, sizeof(buf), ctlf) == NULL) {
		syslog(LOG_ERR, "Control socket yielded no data");
		return (0);
	}
	if ((p = strchr(buf, '\n')) != NULL)
		*p = '\0';
	
	if (verbose_flag)
		syslog(LOG_DEBUG, "Control socket \"%s\"", buf);

	/* XXX - use dispatch table */
	ret = -1;
	if (strcmp(buf, "shutdown") == 0) {
		fprintf(ctlf, "softflowd[%u]: Shutting down gracefully...\n", getpid());
		graceful_shutdown_request = 1;
		ret = 1;
	} else if (strcmp(buf, "exit") == 0) {
		fprintf(ctlf, "softflowd[%u]: Exiting now...\n", getpid());
		*exit_request = 1;
		ret = 1;
	} else if (strcmp(buf, "expire-all") == 0) {
		fprintf(ctlf, "softflowd[%u]: Expired %d flows.\n", getpid(), 
		    check_expired(ft, nfsock, CE_EXPIRE_ALL));
		ret = 0;
	} else if (strcmp(buf, "delete-all") == 0) {
		fprintf(ctlf, "softflowd[%u]: Deleted %d flows.\n", getpid(), 
		    delete_all_flows(ft));
		ret = 0;
	} else if (strcmp(buf, "statistics") == 0) {
		fprintf(ctlf, "softflowd[%u]: Accumulated statistics:\n", 
		    getpid());
		statistics(ft, ctlf);
		ret = 0;
	} else if (strcmp(buf, "debug+") == 0) {
		fprintf(ctlf, "softflowd[%u]: Debug level increased.\n",
		    getpid());
		verbose_flag = 1;
		ret = 0;
	} else if (strcmp(buf, "debug-") == 0) {
		fprintf(ctlf, "softflowd[%u]: Debug level decreased.\n",
		    getpid());
		verbose_flag = 0;
		ret = 0;
	} else if (strcmp(buf, "stop-gather") == 0) {
		fprintf(ctlf, "softflowd[%u]: Data collection stopped.\n",
		    getpid());
		*stop_collection_flag = 1;
		ret = 0;
	} else if (strcmp(buf, "start-gather") == 0) {
		fprintf(ctlf, "softflowd[%u]: Data collection resumed.\n",
		    getpid());
		*stop_collection_flag = 0;
		ret = 0;
	} else if (strcmp(buf, "dump-flows") == 0) {
		fprintf(ctlf, "softflowd[%u]: Dumping flow data:\n",
		    getpid());
		dump_flows(ft, ctlf);
		ret = 0;
	} else if (strcmp(buf, "timeouts") == 0) {
		fprintf(ctlf, "softflowd[%u]: Printing timeouts:\n",
		    getpid());
		print_timeouts(ft, ctlf);
		ret = 0;
	} else {
		fprintf(ctlf, "Unknown control commmand \"%s\"\n", buf);
		ret = 0;
	}

	fclose(ctlf);
	close(fd);
	
	return (ret);
}

static int
connsock(struct sockaddr_in *addr)
{
	int s;

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket() error: %s\n", 
		    strerror(errno));
		exit(1);
	}
	if (connect(s, (struct sockaddr*)addr, sizeof(*addr)) == -1) {
		fprintf(stderr, "connect() error: %s\n",
		    strerror(errno));
		exit(1);
	}

	return(s);
}

static int 
unix_listener(const char *path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int s;

	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
	
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
#ifdef SOCK_HAS_LEN 
	addr.sun_len = addrlen;
#endif

	if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "unix domain socket() error: %s\n", 
		    strerror(errno));
		exit(1);
	}
	unlink(path);
	if (bind(s, (struct sockaddr*)&addr, addrlen) == -1) {
		fprintf(stderr, "unix domain bind(\"%s\") error: %s\n",
		    addr.sun_path, strerror(errno));
		exit(1);
	}
	if (listen(s, 64) == -1) {
		fprintf(stderr, "unix domain listen() error: %s\n",
		    strerror(errno));
		exit(1);
	}
	
	return (s);
}

static void
setup_packet_capture(struct pcap **pcap, int *linktype, 
    char *dev, char *capfile, char *bpf_prog)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	struct bpf_program prog_c;
	u_int32_t bpf_mask, bpf_net;

	/* Open pcap */
	if (dev != NULL) {
		if ((*pcap = pcap_open_live(dev, LIBPCAP_SNAPLEN, 
		    1, 0, ebuf)) == NULL) {
			fprintf(stderr, "pcap_open_live: %s\n", ebuf);
			exit(1);
		}
		if (pcap_lookupnet(dev, &bpf_net, &bpf_mask, ebuf) == -1)
			bpf_net = bpf_mask = 0;
	} else {
		if ((*pcap = pcap_open_offline(capfile, ebuf)) == NULL) {
			fprintf(stderr, "pcap_open_offline(%s): %s\n", 
			    capfile, ebuf);
			exit(1);
		}
		bpf_net = bpf_mask = 0;
	}
	*linktype = pcap_datalink(*pcap);
	if (datalink_skip(*linktype, NULL, 0) == -1) {
		fprintf(stderr, "Unsupported datalink type %d\n", *linktype);
		exit(1);
	}
	/* Attach BPF filter, if specified */
	if (bpf_prog != NULL) {
		if (pcap_compile(*pcap, &prog_c, bpf_prog, 1, bpf_mask) == -1) {
			fprintf(stderr, "pcap_compile(\"%s\"): %s\n", 
			    bpf_prog, pcap_geterr(*pcap));
			exit(1);
		}
		if (pcap_setfilter(*pcap, &prog_c) == -1) {
			fprintf(stderr, "pcap_setfilter: %s\n", 
			    pcap_geterr(*pcap));
			exit(1);
		}
	}
}

static void
init_flowtrack(struct FLOWTRACK *ft)
{
	/* Set up flow-tracking structure */
	memset(ft, '\0', sizeof(*ft));
	ft->next_flow_seq = 1;
	RB_INIT(&ft->flows);
	RB_INIT(&ft->expiries);
	
	ft->tcp_timeout = DEFAULT_TCP_TIMEOUT;
	ft->tcp_rst_timeout = DEFAULT_TCP_RST_TIMEOUT;
	ft->tcp_fin_timeout = DEFAULT_TCP_FIN_TIMEOUT;
	ft->udp_timeout = DEFAULT_UDP_TIMEOUT;
	ft->general_timeout = DEFAULT_GENERAL_TIMEOUT;
	ft->maximum_lifetime = DEFAULT_MAXIMUM_LIFETIME;
}

static char *
argv_join(int argc, char **argv)
{
	int i;
	size_t ret_len;
	char *ret;

	ret_len = 0;
	ret = NULL;
	for (i = 0; i < argc; i++) {
		ret_len += strlen(argv[i]);
		if (i != 0)
			ret_len++; /* Make room for ' ' */
		if ((ret = realloc(ret, ret_len + 1)) == NULL) {
			fprintf(stderr, "Memory allocation failed.\n");
			exit(1);
		}
		if (i == 0)
			ret[0] = '\0';
		else
			strncat(ret, " ", ret_len + 1);
			
		strncat(ret, argv[i], ret_len + 1);
	}

	return (ret);
}

/* Display commandline usage information */
static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options] [bpf_program]\n", PROGNAME);
	fprintf(stderr, "This is %s version %s. Valid commandline options:\n", PROGNAME, PROGVER);
	fprintf(stderr, "  -i interface    Specify interface to listen on\n");
	fprintf(stderr, "  -r pcap_file    Specify packet capture file to read\n");
	fprintf(stderr, "  -t timeout=time Specify named timeout\n");
	fprintf(stderr, "  -m max_flows    Specify maximum number of flows to track (default %d)\n", DEFAULT_MAX_FLOWS);
	fprintf(stderr, "  -n host:port    Send Cisco NetFlow(tm)-compatible packets to host:port\n");
	fprintf(stderr, "  -p pidfile      Record pid in specified file (default: %s)\n", DEFAULT_PIDFILE);
	fprintf(stderr, "  -c pidfile      Location of control socket (default: %s)\n", DEFAULT_CTLSOCK);
	fprintf(stderr, "  -d              Don't daemonise\n");
	fprintf(stderr, "  -D              Debug mode: don't daemonise + verbosity\n");
	fprintf(stderr, "  -h              Display this help\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Valid timeout names and default values:\n");
	fprintf(stderr, "  tcp     (default %d)", DEFAULT_TCP_TIMEOUT);
	fprintf(stderr, "  tcp.rst (default %d) ", DEFAULT_TCP_RST_TIMEOUT);
	fprintf(stderr, "  tcp.fin (default %d)\n", DEFAULT_TCP_FIN_TIMEOUT);
	fprintf(stderr, "  udp     (default %d) ", DEFAULT_UDP_TIMEOUT);
	fprintf(stderr, "  general (default %d)", DEFAULT_GENERAL_TIMEOUT);
	fprintf(stderr, "  maxlife (default %d)\n", DEFAULT_MAXIMUM_LIFETIME);
	fprintf(stderr, "\n");
}

static void
set_timeout(struct FLOWTRACK *ft, const char *to_spec)
{
	char *name, *value;
	int timeout;

	if ((name = strdup(to_spec)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	if ((value = strchr(name, '=')) == NULL ||
	    *(++value) == '\0') {
		fprintf(stderr, "Invalid -t option \"%s\".\n", name);
		usage();
		exit(1);
	}
	*(value - 1) = '\0';
	timeout = convtime(value);
	if (timeout <= 0) {
		fprintf(stderr, "Invalid -t timeout.\n");
		usage();
		exit(1);
	}
	if (strcmp(name, "tcp") == 0)
		ft->tcp_timeout = timeout;
	else if (strcmp(name, "tcp.rst") == 0)
		ft->tcp_rst_timeout = timeout;
	else if (strcmp(name, "tcp.fin") == 0)
		ft->tcp_fin_timeout = timeout;
	else if (strcmp(name, "udp") == 0)
		ft->udp_timeout = timeout;
	else if (strcmp(name, "general") == 0)
		ft->general_timeout = timeout;
	else if (strcmp(name, "maxlife") == 0)
		ft->maximum_lifetime = timeout;
	else {
		fprintf(stderr, "Invalid -t name.\n");
		usage();
		exit(1);
	}

	free(name);
}

static void
parse_hostport(const char *s, struct sockaddr_in *addr)
{
	char *host, *port;

	if ((host = strdup(s)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	if ((port = strchr(host, ':')) == NULL || *(++port) == '\0') {
		fprintf(stderr, "Invalid -n option.\n");
		usage();
		exit(1);
	}
	*(port - 1) = '\0';
	addr->sin_family = AF_INET;
	addr->sin_port = atoi(port);
	if (addr->sin_port <= 0 || addr->sin_port >= 65536) {
		fprintf(stderr, "Invalid -n port.\n");
		usage();
		exit(1);
	}
	addr->sin_port = htons(addr->sin_port);
	if (inet_aton(host, &addr->sin_addr) == 0) {
		fprintf(stderr, "Invalid -n host.\n");
		usage();
		exit(1);
	}
	free(host);
}

int
main(int argc, char **argv)
{
	char *dev, *capfile, *bpf_prog;
	const char *pidfile_path, *ctlsock_path;
	extern char *optarg;
	extern int optind;
	int ch, dontfork_flag, linktype, nfsock, ctlsock, r;
	int max_flows, stop_collection_flag, exit_request;
	pcap_t *pcap = NULL;
	struct FLOWTRACK flowtrack;
	struct sockaddr_in dest;
	time_t next_expiry_check;
	
	memset(&dest, '\0', sizeof(dest));
#ifdef SOCK_HAS_LEN 
	dest.sin_len = sizeof(dest);
#endif

	init_flowtrack(&flowtrack);

	bpf_prog = NULL;
	nfsock = ctlsock = -1;
	dev = capfile = NULL;
	max_flows = DEFAULT_MAX_FLOWS;
	pidfile_path = DEFAULT_PIDFILE;
	ctlsock_path = DEFAULT_CTLSOCK;
	dontfork_flag = 0;
	while ((ch = getopt(argc, argv, "hdDi:r:f:t:n:m:p:c:")) != -1) {
		switch (ch) {
		case 'h':
			usage();
			return (0);
		case 'D':
			verbose_flag = 1;
			/* FALLTHROUGH */
		case 'd':
			dontfork_flag = 1;
			break;
		case 'i':
			if (capfile != NULL || dev != NULL) {
				fprintf(stderr, "Packet source already specified.\n\n");
				usage();
				exit(1);
			}
			dev = optarg;
			break;
		case 'r':
			if (capfile != NULL || dev != NULL) {
				fprintf(stderr, "Packet source already specified.\n\n");
				usage();
				exit(1);
			}
			capfile = optarg;
			dontfork_flag = 1;
			ctlsock_path = NULL;
			break;
		case 't':
			/* Will exit on failure */
			set_timeout(&flowtrack, optarg); 
			break;
		case 'm':
			if ((max_flows = atoi(optarg)) < 0) {
				fprintf(stderr, "Invalid maximum flows\n\n");
				usage();
				exit(1);
			}
			break;
		case 'n':
			/* Will exit on failure */
			parse_hostport(optarg, &dest);
			break;
		case 'p':
			pidfile_path = optarg;
			break;
		case 'c':
			if (strcmp(optarg, "none") == 0)
				ctlsock_path = NULL;
			else
				ctlsock_path = optarg;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	if (capfile == NULL && dev == NULL) {
		fprintf(stderr, "-i or -r option not specified.\n");
		usage();
		exit(1);
	}
	
	/* join remaining arguments (if any) into bpf program */
	bpf_prog = argv_join(argc - optind, argv + optind);

	/* Will exit on failure */
	setup_packet_capture(&pcap, &linktype, dev, capfile, bpf_prog);
	
	/* Netflow send socket */
	if (dest.sin_family != 0)
		nfsock = connsock(&dest); /* Will exit on fail */
	
	/* Control socket */
	if (ctlsock_path != NULL)
		ctlsock = unix_listener(ctlsock_path); /* Will exit on fail */
	
	if (dontfork_flag) {
		openlog(PROGNAME, LOG_PID|LOG_PERROR, LOG_DAEMON);
	} else {	
		FILE *pidfile;

		daemon(0, 0);
		openlog(PROGNAME, LOG_PID, LOG_DAEMON);

		if ((pidfile = fopen(pidfile_path, "w")) == NULL) {
			fprintf(stderr, "Couldn't open pidfile %s: %s\n",
			    pidfile_path, strerror(errno));
			exit(1);
		}
		fprintf(pidfile, "%u\n", getpid());
		fclose(pidfile);

		signal(SIGINT, sighand_graceful_shutdown);
		signal(SIGTERM, sighand_graceful_shutdown);
		signal(SIGSEGV, sighand_other);
	}

	syslog(LOG_NOTICE, "%s v%s starting data collection", PROGNAME, PROGVER);

	/* Main processing loop */
	gettimeofday(&system_boot_time, NULL);
	stop_collection_flag = 0;
	next_expiry_check = time(NULL) + EXPIRY_WAIT;
	for(;;) {
		struct CB_CTXT cb_ctxt = {&flowtrack, linktype};
		struct pollfd pl[2];

		/*
		 * Silly libpcap's timeout function doesn't work, so we
		 * do it here (only if we are reading live)
		 */
		r = 0;
		if (capfile == NULL) {
			memset(pl, '\0', sizeof(pl));

			/* This can only be set via the control socket */
			if (!stop_collection_flag) {
				pl[0].events = POLLIN|POLLERR|POLLHUP;
				pl[0].fd = pcap_fileno(pcap);
			}
			if (ctlsock != -1) {
				pl[1].fd = ctlsock;
				pl[1].events = POLLIN|POLLERR|POLLHUP;
			}

			r = poll(pl, (ctlsock == -1) ? 1 : 2, POLL_WAIT);
			if (r == -1 && errno != EINTR) {
				syslog(LOG_ERR, "Exiting on poll: %s", 
				    strerror(errno));
				break;
			}
		}

		/* Accept connection on control socket if present */
		if (ctlsock != -1 && pl[1].revents != 0) {
			if (accept_control(ctlsock, nfsock, &flowtrack, 
			    &exit_request, &stop_collection_flag) != 0)
				break;
		}

		/* If we have data, run it through libpcap */
		if (!stop_collection_flag && 
		    (capfile != NULL || pl[0].revents != 0)) {
			r = pcap_dispatch(pcap, max_flows, flow_cb, (void*)&cb_ctxt);
			if (r == -1) {
				syslog(LOG_ERR, "Exiting on pcap_dispatch: %s", 
				    pcap_geterr(pcap));
				break;
			} else if (r == 0) {
				syslog(LOG_NOTICE, "Shutting down after pcap EOF");
				graceful_shutdown_request = 1;
				break;
			}
		}
		r = 0;

		/* Fatal error from per-packet functions */
		if (cb_ctxt.fatal) {
			syslog(LOG_WARNING, "Fatal error - exiting immediately");
			break;
		}

		/*
		 * Expiry processing happens every recheck_rate seconds
		 * or whenever we have exceeded the maximum number of active 
		 * flows
		 */
		if (flowtrack.num_flows > max_flows || 
		    next_expiry_check <= time(NULL)) {
expiry_check:
			/*
			 * If we are reading from a capture file, we never
			 * expire flows based on time - instead we only 
			 * expire flows when the flow table is full. 
			 */
			if (check_expired(&flowtrack, nfsock, 
			    capfile == NULL ? CE_EXPIRE_NORMAL : CE_EXPIRE_FORCED) < 0)
				syslog(LOG_WARNING, "Unable to export flows");
	
			/*
			 * If we are over max_flows, force-expire the oldest 
			 * out first and immediately reprocess to evict them
			 */
			if (flowtrack.num_flows > max_flows) {
				force_expire(&flowtrack, flowtrack.num_flows - max_flows);
				goto expiry_check;
			}
			next_expiry_check = time(NULL) + EXPIRY_WAIT;
		}
	}

	/* Flags set by signal handlers or control socket */
	if (graceful_shutdown_request) {
		syslog(LOG_WARNING, "Shutting down on user request");
		check_expired(&flowtrack, nfsock, CE_EXPIRE_ALL);
	} else if (exit_request)
		syslog(LOG_WARNING, "Exiting immediately on user request");
	else
		syslog(LOG_ERR, "Exiting immediately on internal error");
		
	if (capfile != NULL && dontfork_flag)
		statistics(&flowtrack, stdout);

	pcap_close(pcap);
	
	if (nfsock != -1)
		close(nfsock);

	unlink(pidfile_path);
	if (ctlsock_path != NULL)
		unlink(ctlsock_path);
	
	exit(r == 0 ? 0 : 1);
}
