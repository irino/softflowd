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

/* XXX - TODO:
 * - Properly fast-expire closed TCP sessions
 * - Flow exporter sends flow records for flows with 0 octets/packets
 * - IPv6 support (I don't think netflow supports it yet)
 * - maybe make expiries a tree keyed by expires_at, so we can have 
 *   different expiry rates for TCP and UDP connections
 *    - e.g. heuristics to fast-expire udp transaction traffic like dns
 */

#define _BSD_SOURCE /* Needed for BSD-style struct ip,tcp,udp on Linux */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/bpf.h>

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#if defined(__OpenBSD__)
# include <sys/tree.h>
# include <sys/queue.h>
#else
# include "sys-tree.h"
# include "sys-queue.h"
#endif

#include <pcap.h>

/* Global variables */
static int verbose_flag = 0;		/* Debugging flag */

/* Signal handler flags */
static int graceful_shutdown_request = 0;	
static int exit_request = 0;
static int purge_flows = 0;
static int delete_flows = 0;
static int dump_stats = 0;

/* The name of the program */
#define PROGNAME		"softflowd"

/* The name of the program */
#define PROGVER			"0.1"

/* Default pidfile */
#define DEFAULT_PIDFILE		"/var/run/" PROGNAME ".pid"

/*
 * Capture length for libpcap: Must fit a maximally sized ip header 
 * and the first four bytes of a TCP/UDP header (source and 
 * destination port numbers)
 */
#define LIBPCAP_SNAPLEN		80

/*
 * Default timeout: Quiescent flows which have not seen traffic for 
 * this many seconds will be expired
 */
#define DEFAULT_TIMEOUT 	3600

/*
 * How many seconds to wait for pcap data before doing housekeeping
 */
#define MAINLOOP_TIMEOUT	8

/*
 * Default maximum number of flow to track simultaneously 
 * 8192 corresponds to just under 1Mb of flow data
 */
#define DEFAULT_MAX_FLOWS	8192

#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif

/*
 * This structure is the root of the flow tracking system.
 * It holds the root of the tree of active flows and the head of the
 * queue of expiry events. It also collects miscellaneous statistics
 */
struct FLOWTRACK {
	unsigned int num_flows;			/* # of active flows */
	u_int64_t next_flow_seq;		/* Next flow ID */
	u_int64_t total_packets;		/* # of good packets */
	u_int64_t non_ip_packets;		/* # of not-IP packets */
	u_int64_t bad_packets;			/* # of bad packets */
	u_int64_t flows_exported;		/* # of flows sent */
	u_int64_t flows_dropped;		/* # of flows dropped */
	u_int64_t flows_force_expired;		/* # of flows forced out */
	double max_dur, min_dur, mean_dur;	/* flow duration */
	double max_bytes, min_bytes, mean_bytes;/* flow bytes (both ways) */
	double max_pkts, min_pkts, mean_pkts;	/* flow packets (both ways) */
	RB_HEAD(FLOWS, FLOW) flows;		/* Top of flow tree */
	TAILQ_HEAD(EXPIRIES, EXPIRY) expiries;	/* Top of expiries queue */
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
	RB_ENTRY(FLOW) next;			/* Tree pointer */

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
 * This is an entry in the queue of expiry events. The queue is used to 
 * avoid traversion the whole tree of active flows looking for ones to
 * expire. "expires_at" is the time at which the flow should be discarded,
 * or zero if it is scheduled for immediate disposal. 
 *
 * When a flow which hasn't been scheduled for immediate expiry registers 
 * traffic, it is deleted from its current position in the queue and 
 * appended to the end.
 *
 * Expiry scans operate by starting at the head of the queue and expiring
 * each entry with expires_at < now
 * 
 */
struct EXPIRY {
	TAILQ_ENTRY(EXPIRY) next;		/* Queue pointer */

	u_int32_t expires_at;			/* time_t */
	struct FLOW *flow;			/* pointer to flow */
};

/* Context for libpcap callback functions */
struct CB_CTXT {
	struct FLOWTRACK *ft;
	int timeout;
	int linktype;
	int fatal;
};

/*
 * This is the Cisco Netflow(tm) version 1 packet format
 * Based on:
 * http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm
 */
struct NETFLOW_HEADER_V1 {
	u_int16_t version, flows;
	u_int32_t uptime_ms, time_sec, time_nanosec;
};
struct NETFLOW_FLOW_V1 {
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


/* Signal handlers */
static void sighand_graceful_shutdown(int signum)
{
	graceful_shutdown_request = signum;
}

static void sighand_exit(int signum)
{
	exit_request = 1;
}

static void sighand_purge(int signum)
{
	purge_flows = 1;
	signal(signum, sighand_purge);
}

static void sighand_delete(int signum)
{
	delete_flows = 1;
	signal(signum, sighand_delete);
}

static void sighand_dump_stats(int signum)
{
	dump_stats = 1;
	signal(signum, sighand_dump_stats);
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
	int n;

	n = ntohl(a->addr[0]) - ntohl(b->addr[0]);
	if (n != 0)
		return (n);

	n = ntohl(a->addr[1]) - ntohl(b->addr[1]);
	if (n != 0)
		return (n);

	n = a->protocol - b->protocol;
	if (n != 0)
		return (n);
	
	n = ntohs(a->port[0]) - ntohs(b->port[0]);
	if (n != 0)
		return (n);

	n = ntohs(a->port[1]) - ntohs(b->port[1]);
	if (n != 0)
		return (n);

	return (0);
}

/* Generate functions for flow tree */
RB_PROTOTYPE(FLOWS, FLOW, next, flow_compare);
RB_GENERATE(FLOWS, FLOW, next, flow_compare);

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
    const struct timeval *received_time, int timeout)
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

		ft->num_flows++;
		if (verbose_flag)
			syslog(LOG_DEBUG, "ADD FLOW %s", format_flow_brief(flow));
	} else {
		/*
		 * If an entry is scheduled for immediate expiry, then 
		 * don't bother moving it from the head of the list
		 */
		if (flow->expiry->expires_at != 0)
			TAILQ_REMOVE(&ft->expiries, flow->expiry, next);

		/* Update flow statistics */
		flow->packets[0] += tmp.packets[0];
		flow->octets[0] += tmp.octets[0];
		flow->tcp_flags[0] |= tmp.tcp_flags[0];
		flow->packets[1] += tmp.packets[1];
		flow->octets[1] += tmp.octets[1];
		flow->tcp_flags[1] |= tmp.tcp_flags[1];
	}
	
	memcpy(&flow->flow_last, received_time, sizeof(flow->flow_last));

	/*
	 * Here we do fast-expiry of certain flows.
	 *
	 * The current use is a bit of a kludge: avoid octet counter 
	 * overflow by expiring flows early which are halfway toward 
	 * overflow  (2Gb of traffic). If the real traffic flow continues, 
	 * the flow entry will be immediately added again anyway.
	 *
	 * Later we can use a similar mechanism for fast-expiring 
	 * closed TCP sessions
	 */
	if (flow->expiry->expires_at != 0) {
		if (flow->octets[0] > (1U << 31) || 
		    flow->octets[1] > (1U << 31)) {
			flow->expiry->expires_at = 0;
			TAILQ_INSERT_HEAD(&ft->expiries, flow->expiry, next);
		} else {
			flow->expiry->expires_at = flow->flow_last.tv_sec + 
			    timeout;
			TAILQ_INSERT_TAIL(&ft->expiries, flow->expiry, next);
		}
	}

	return (PP_OK);
}

/* Given an array of expired flows, send netflow v1 report packets */
static int
send_netflow_v1(struct FLOW **flows, int num_flows, int nfsock)
{
	struct timeval now;
	u_int8_t packet[1152];	/* Maximum allowed packet size (24 flows) */
	struct NETFLOW_HEADER_V1 *hdr = NULL;
	struct NETFLOW_FLOW_V1 *flw = NULL;
	int i, j, offset;
	
	gettimeofday(&now, NULL);

	for(offset = j = i = 0; i < num_flows; i++) {
		if (j == 0 || j >= 23) {
			if (j != 0) {
				hdr->flows = htons(hdr->flows);
				if (send(nfsock, packet, 
				    (size_t)offset, 0) == -1)
					return (-1);
			}
			memset(&packet, '\0', sizeof(packet));
			hdr = (struct NETFLOW_HEADER_V1 *)packet;
			hdr->version = htons(1);
			hdr->flows = 0; /* Filled in as we go */
			hdr->uptime_ms = 0;
			hdr->time_sec = htonl(now.tv_sec);
			hdr->time_nanosec = htonl(now.tv_usec * 1000);
			offset = sizeof(*hdr);
			j = 0;
		}		
		flw = (struct NETFLOW_FLOW_V1 *)(packet + offset);
		
		if (flows[i]->octets[0] > 0) {
			flw->src_ip = flows[i]->addr[0];
			flw->dest_ip = flows[i]->addr[1];
			flw->src_port = flows[i]->port[0];
			flw->dest_port = flows[i]->port[1];
			flw->flow_packets = htonl(flows[i]->packets[0]);
			flw->flow_octets = htonl(flows[i]->octets[0]);
			flw->flow_start = htonl(flows[i]->flow_start.tv_sec);
			flw->flow_finish = htonl(flows[i]->flow_last.tv_sec);
			flw->protocol = flows[i]->protocol;
			flw->tcp_flags = flows[i]->tcp_flags[0];
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NETFLOW_FLOW_V1 *)(packet + offset);

		if (flows[i]->octets[1] > 0) {
			flw->src_ip = flows[i]->addr[1];
			flw->dest_ip = flows[i]->addr[0];
			flw->src_port = flows[i]->port[1];
			flw->dest_port = flows[i]->port[0];
			flw->flow_packets = htonl(flows[i]->packets[1]);
			flw->flow_octets = htonl(flows[i]->octets[1]);
			flw->flow_start = htonl(flows[i]->flow_start.tv_sec);
			flw->flow_finish = htonl(flows[i]->flow_last.tv_sec);
			flw->protocol = flows[i]->protocol;
			flw->tcp_flags = flows[i]->tcp_flags[1];
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
	}

	return (0);
}

static double 
update_mean(double mean, double new_sample, double n)
{
	/*
	 * XXX I think this method of calculating the a new mean from an 
	 * existing mean is correct but I don't have my stats book handy
	 *
	 * I use this instead of "Mnew = ((Mold * n - 1) + S) / n" to 
	 * avoid accumulating fp rounding errors. Maybe I'm misguided :)
	 */
	return (mean + ((new_sample - mean) / n));
}

/* Update global statistics */
static void
update_statistics(struct FLOWTRACK *ft, struct FLOW *flow)
{
	double tmp;
	static double n = 1.0;

	tmp = (double)flow->flow_last.tv_sec +
	    ((double)flow->flow_last.tv_usec / 1000000.0);
	tmp -= (double)flow->flow_start.tv_sec +
	    ((double)flow->flow_start.tv_usec / 1000000.0);

	if (n == 1.0) {
		ft->min_dur = ft->mean_dur = ft->max_dur = tmp;
	} else {
		ft->mean_dur = update_mean(ft->mean_dur, tmp, n);
		ft->min_dur = MIN(ft->min_dur, tmp);
		ft->max_dur = MAX(ft->max_dur, tmp);
	}

	tmp = flow->octets[0] + flow->octets[1];
	if (n == 1.0) {
		ft->min_bytes = ft->mean_bytes = ft->max_bytes = tmp;
	} else {
		ft->mean_bytes = update_mean(ft->mean_bytes, tmp, n);
		ft->min_bytes = MIN(ft->min_bytes, tmp);
		ft->max_bytes = MAX(ft->max_bytes, tmp);
	}

	tmp = flow->packets[0] + flow->packets[1];
	if (n == 1.0) {
		ft->min_pkts = ft->mean_pkts = ft->max_pkts = tmp;
	} else {
		ft->mean_pkts = update_mean(ft->mean_pkts, tmp, n);
		ft->min_pkts = MIN(ft->min_pkts, tmp);
		ft->max_pkts = MAX(ft->max_pkts, tmp);
	}
	n++;
}

/*
 * Scan the queue of expiry events and process expired flows. If zap_all
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

	if (verbose)
		syslog(LOG_DEBUG, "Starting expiry scan: mode %d", ex);

	for (expiry = TAILQ_FIRST(&ft->expiries); expiry != NULL; expiry = nexpiry) {
		nexpiry = TAILQ_NEXT(expiry, next);
		if ((expiry->expires_at == 0) || (ex == CE_EXPIRE_ALL) || 
		    (ex != CE_EXPIRE_FORCED &&
		    (expiry->expires_at < now.tv_sec))) {
			if (verbose_flag)
				syslog(LOG_DEBUG, "Queuing flow seq:%llu (%p) for expiry",
				   expiry->flow->flow_seq, expiry->flow);

			/* Flow has expired */
			RB_REMOVE(FLOWS, &ft->flows, expiry->flow);
			TAILQ_REMOVE(&ft->expiries, expiry, next);

			ft->num_flows--;

			/* Add to array of expired flows */

			expired_flows = realloc(expired_flows,
			    sizeof(*expired_flows) * (num_expired + 1));
			expired_flows[num_expired] = expiry->flow;
			num_expired++;
			
			expiry->flow->expiry = NULL;
			free(expiry);
		}
	}

	if (verbose)
		syslog(LOG_DEBUG, "Finished scan %d flow to be evicted", ex);
	
	/* Processing for expired flows */
	if (num_expired > 0) {
		r = send_netflow_v1(expired_flows, num_expired, nfsock);
		for (i = 0; i < num_expired; i++) {
			if (verbose_flag)
				syslog(LOG_DEBUG, "EXPIRED: %s (%p)", 
				    format_flow(expired_flows[i]),
				    expired_flows[i]);
			
			update_statistics(ft, expired_flows[i]);

			free(expired_flows[i]);
		}
	
		if (r == 0)
			ft->flows_exported += num_expired * 2;
		else
			ft->flows_dropped += num_expired * 2;

		free(expired_flows);
	}

	return (r);
}

/*
 * Force expiry of num_to_expire flows (e.g. when flow table overfull) 
 */
static void
force_expire(struct FLOWTRACK *ft, u_int32_t num_to_expire)
{
	struct EXPIRY *expiry;

	if (verbose_flag)
		syslog(LOG_INFO, "Forcing expiry of %d flows",
		    num_to_expire);

	TAILQ_FOREACH(expiry, &ft->expiries, next) {
		if (num_to_expire-- <= 0)
			break;
		expiry->expires_at = 0;
		ft->flows_force_expired++;
	}
}

/* Delete all flows that we know about without processing */
static int
delete_all_flows(struct FLOWTRACK *ft)
{
	struct FLOW *flow, *nflow;

	for(flow = RB_MIN(FLOWS, &ft->flows); flow != NULL; flow = nflow) {
		nflow = RB_NEXT(FLOWS, &ft->flows, flow);
		RB_REMOVE(FLOWS, &ft->flows, flow);
		
		TAILQ_REMOVE(&ft->expiries, flow->expiry, next);
		free(flow->expiry);

		ft->num_flows--;
		free(flow);
	}
	
	return (0);
}

/*
 * Log our current status. 
 * Includes summary counters and (in verbose mode) the list of current flows
 * and the queue of expiry events.
 */
static int
log_stats(struct FLOWTRACK *ft)
{
	struct FLOW *flow;
	struct EXPIRY *expiry;
	time_t now;
	
	now = time(NULL);

	syslog(LOG_INFO, "Number of active flows: %d", ft->num_flows);
	syslog(LOG_INFO, "Total packets processed: %llu", ft->total_packets);
	syslog(LOG_INFO, "Ignored non-ip packets: %llu", ft->non_ip_packets);
	syslog(LOG_INFO, "Ignored illegible packets: %llu", ft->bad_packets);
	syslog(LOG_INFO, "Total flows exported: %llu", ft->flows_exported);
	syslog(LOG_INFO, "Flow export packets dropped: %llu", ft->flows_dropped);
	syslog(LOG_INFO, "Flows forcibly expired: %llu", ft->flows_force_expired);

	syslog(LOG_INFO, "Flow duration: %0.2f / %0.2f / %0.2f (min / mean / max)", 
	    ft->min_dur, ft->mean_dur, ft->max_dur);
	syslog(LOG_INFO, "Flow bytes: %0.2f / %0.2f / %0.2f (min / mean / max)", 
	    ft->min_bytes, ft->mean_bytes, ft->max_bytes);
	syslog(LOG_INFO, "Flow packets: %0.2f / %0.2f / %0.2f (min / mean / max)", 
	    ft->min_pkts, ft->mean_pkts, ft->max_pkts);


#if 0
	syslog(LOG_INFO, "RB_EMPTY: %d", RB_EMPTY(&ft->flows));
	syslog(LOG_INFO, "TAILQ_EMPTY: %d", TAILQ_EMPTY(&ft->expiries));
#endif

	if (verbose_flag) {
		RB_FOREACH(flow, FLOWS, &ft->flows)
			syslog(LOG_DEBUG, "ACTIVE %s", format_flow(flow));
		TAILQ_FOREACH(expiry, &ft->expiries, next) {
			syslog(LOG_DEBUG, 
			    "EXPIRY EVENT for flow %llu in %ld seconds",
			    expiry->flow->flow_seq, 
			    (long int) expiry->expires_at - now);
		}
	}

	return (0);
}

/* Display commandline usage information */
static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n", PROGNAME);
	fprintf(stderr, "This is %s version %s. Valid commandline options:\n", PROGNAME, PROGVER);
	fprintf(stderr, "  -i interface  Specify interface to listen on\n");
	fprintf(stderr, "  -r pcap_file  Specify packet capture file to read\n");
	fprintf(stderr, "  -t timeout    Quiescent flow expiry timeout in seconds (default %d)\n", DEFAULT_TIMEOUT);
	fprintf(stderr, "  -m max_flows  Specify maximum number of flows to track (default %d)\n", DEFAULT_MAX_FLOWS);
	fprintf(stderr, "  -n host:port  Send Cisco NetFlow(tm)-compatible packets to host:port\n");
	fprintf(stderr, "  -d            Don't daemonise\n");
	fprintf(stderr, "  -D            Debug mode: don't daemonise + verbosity\n");
	fprintf(stderr, "  -h            Display this help\n");
	fprintf(stderr, "\n");
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
		case DLT_LOOP:
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
		case DLT_LOOP:
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
		    (const struct timeval *)&phdr->ts, 
		    cb_ctxt->timeout) == PP_MALLOC_FAIL)
			cb_ctxt->fatal = 1;
	}
}

int
main(int argc, char **argv)
{
	char *dev, *capfile, *hostport, *value;
	const char *pidfile_path;
	char ebuf[PCAP_ERRBUF_SIZE];
	extern char *optarg;
	int ch, timeout, dontfork_flag, r, linktype, sock, max_flows;
	pcap_t *pcap = NULL;
	struct sockaddr_in target;
	struct FLOWTRACK flowtrack;
	time_t next_expiry_check;
	FILE *pidfile;
	
	memset(&target, '\0', sizeof(target));
	/* XXX: this check probably isn't sufficient for all systems */
#ifndef __GNU_LIBRARY__ 
	target.sin_len = sizeof(target);
#endif

	dev = capfile = NULL;
	timeout = DEFAULT_TIMEOUT;
	max_flows = DEFAULT_MAX_FLOWS;
	pidfile_path = DEFAULT_PIDFILE;
	dontfork_flag = 0;
	while ((ch = getopt(argc, argv, "hdDi:r:t:n:m:p:")) != -1) {
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
			break;
		case 't':
			if ((timeout = atoi(optarg)) < 0) {
				fprintf(stderr, "Invalid timeout\n\n");
				usage();
				exit(1);
			}
			break;
		case 'm':
			if ((max_flows = atoi(optarg)) < 0) {
				fprintf(stderr, "Invalid maximum flows\n\n");
				usage();
				exit(1);
			}
			break;
		case 'n':
			if ((hostport = strdup(optarg)) == NULL) {
				fprintf(stderr, "Out of memory\n");
				exit(1);
			}
			if ((value = strchr(hostport, ':')) == NULL ||
			    *(++value) == '\0') {
				fprintf(stderr, "Invalid -n option.\n");
				usage();
				exit(1);
			}
			*(value - 1) = '\0';
			target.sin_family = AF_INET;
			target.sin_port = atoi(value);
			if (target.sin_port <= 0 || target.sin_port >= 65536) {
				fprintf(stderr, "Invalid -n port.\n");
				usage();
				exit(1);
			}
			target.sin_port = htons(target.sin_port);
			if (inet_aton(hostport, &target.sin_addr) == 0) {
				fprintf(stderr, "Invalid -n host.\n");
				usage();
				exit(1);
			}
			free(hostport);
			break;
		case 'p':
			pidfile_path = optarg;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	if (target.sin_family == 0) {
		fprintf(stderr, "-n option not specified.\n");
		usage();
		exit(1);
	}

	if (capfile == NULL && dev == NULL) {
		fprintf(stderr, "-i or -r option not specified.\n");
		usage();
		exit(1);
	}

	/* Set up flow-tracking structure */
	memset(&flowtrack, '\0', sizeof(flowtrack));
	flowtrack.next_flow_seq = 1;
	RB_INIT(&flowtrack.flows);
	TAILQ_INIT(&flowtrack.expiries);

	/* Open pcap */
	if (dev != NULL) {
		if ((pcap = pcap_open_live(dev, LIBPCAP_SNAPLEN, 
		    1, 0, ebuf)) == NULL) {
			fprintf(stderr, "pcap_open_live: %s\n", ebuf);
			exit(1);
		}
	} else {
		if ((pcap = pcap_open_offline(capfile, ebuf)) == NULL) {
			fprintf(stderr, "pcap_open_offline(%s): %s\n", capfile, 
			    ebuf);
			exit(1);
		}
	}
	linktype = pcap_datalink(pcap);
	if (datalink_skip(linktype, NULL, 0) == -1) {
		fprintf(stderr, "Unsupported datalink type %d\n", linktype);
		exit(1);
	}

	/* Netflow send socket */
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket() error: %s\n", strerror(errno));
		exit(1);
	}
	if (connect(sock, (struct sockaddr *)&target, sizeof(target)) == -1) {
		fprintf(stderr, "connect() error: %s\n", strerror(errno));
		exit(1);
	}
	
	if (dontfork_flag) {
		openlog(PROGNAME, LOG_PID|LOG_PERROR, LOG_DAEMON);
	} else {	
		daemon(0, 0);
		openlog(PROGNAME, LOG_PID, LOG_DAEMON);
		if ((pidfile = fopen(pidfile_path, "w")) == NULL) {
			fprintf(stderr, "Couldn't open pidfile %s: %s\n",
			    pidfile_path, strerror(errno));
			exit(1);
		}
		fprintf(pidfile, "%u", getpid());
		fclose(pidfile);
	}

	signal(SIGINT, sighand_graceful_shutdown);
	signal(SIGTERM, sighand_exit);
	signal(SIGHUP, sighand_purge);
	signal(SIGUSR1, sighand_delete);
	signal(SIGUSR2, sighand_dump_stats);
	/* Only catch SEGV when daemonised */
	if (!dontfork_flag)
		signal(SIGSEGV, sighand_other);

	syslog(LOG_NOTICE, "%s v%s starting data collection", PROGNAME, PROGVER);

	/* Main processing loop */
	next_expiry_check = time(NULL) + MAINLOOP_TIMEOUT;
	for(;;) {
		struct CB_CTXT cb_ctxt = {&flowtrack, timeout, linktype};
		struct pollfd pl[1];

		/*
		 * Silly libpcap's timeout function doesn't work, so we
		 * do it here (only if we are reading live)
		 */
		r = 0;
		if (capfile == NULL) { 
			pl[0].fd = pcap_fileno(pcap);
			pl[0].events = POLLIN|POLLERR|POLLHUP;
			pl[0].revents = 0;
			r = poll(pl, 1, MAINLOOP_TIMEOUT * 1000);
			if (r == -1 && errno != EINTR) {
				syslog(LOG_ERR, "Exiting on poll: %s", 
				    strerror(errno));
				break;
			}
		}

		/* If we have data, run it through libpcap */
		if (capfile != NULL || r > 0) {
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

		/* Flags set by signal handlers */
		if (graceful_shutdown_request) {
			syslog(LOG_WARNING, "Shutting down on user request");
			break;
		}
		if (exit_request) {
			syslog(LOG_WARNING, "Exiting immediately on user request");
			break;
		}
		if (purge_flows) {
			syslog(LOG_NOTICE, "Purging flows on user request");
			purge_flows = 0;
			check_expired(&flowtrack, sock, CE_EXPIRE_ALL);
		}
		if (delete_flows) {
			syslog(LOG_NOTICE, "Deleting all flows on user request");
			delete_flows = 0;
			delete_all_flows(&flowtrack);
		}
		if (dump_stats) {
			syslog(LOG_INFO, "Dumping statistics");
			dump_stats = 0;
			log_stats(&flowtrack);
		}

		/*
		 * Expiry processing happens every MAINLOOP_TIMEOUT seconds
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
			if (check_expired(&flowtrack, sock, 
			    capfile == NULL ? CE_EXPIRE_NORMAL : CE_EXPIRE_FORCED) != 0)
				syslog(LOG_WARNING, "Unable to export flows");
	
			/*
			 * If we are over max_flows, force-expire the oldest 
			 * out first and immediately reprocess to evict them
			 */
			if (flowtrack.num_flows > max_flows) {
				force_expire(&flowtrack, flowtrack.num_flows - max_flows);
				goto expiry_check;
			}
			next_expiry_check = time(NULL) + MAINLOOP_TIMEOUT;
		}
	}

	if (graceful_shutdown_request)
		check_expired(&flowtrack, sock, CE_EXPIRE_ALL);

	pcap_close(pcap);
	close(sock);

	log_stats(&flowtrack);
	
	exit(r == 0 ? 0 : 1);
}
