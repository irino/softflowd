/*
 * Copyright (c) 2002 Damien Miller.  All rights reserved.
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
 * @file softflowd.h
 * @brief The structures and constants that the parts of softflowd share: the
 *   flow, the parameters of the flow table, the export targets and the
 *   prototypes of the senders.
 */

#ifndef _SOFTFLOWD_H
#define _SOFTFLOWD_H
#include "common.h"
#ifdef HAVE_BSD_SYS_TREE_H
#include <bsd/sys/tree.h>
#else
#include "compat/bsd/sys-tree.h"
#endif
#include "freelist.h"
#include "treetype.h"
#include <pcap.h>
#ifdef ENABLE_PTHREAD
#include <pthread.h>
extern int use_thread;
#endif /* ENABLE_PTHREAD */
#ifdef ENABLE_NTOPNG
#include <zmq.h>
// The version field in NetFow and IPFIX headers is 16 bits unsiged int.
// If the version number is over 0x7fff0000, it is unique number in softflowd.
/**
 * Version number that selects the export to ntopng (-v ntopng). It is
 * above the 16 bits of the version field of NetFlow, so that it never
 * collides with a real version.
 */
#define SOFTFLOWD_NF_VERSION_NTOPNG (0x7fff0001)
/** The name of the export to ntopng as -v takes it. */
#define SOFTFLOWD_NF_VERSION_NTOPNG_STRING "ntopng"
#ifdef ENABLE_NTOPNG_JSON
#define SOFTFLOWD_NF_VERSION_NTOPNG_JSON (0x7fff0002)
#define SOFTFLOWD_NF_VERSION_NTOPNG_JSON_STRING "ntopng-json"
#endif /* ENABLE_NTOPNG_JSON */
/** @brief The ZeroMQ context and the socket of a connection to ntopng. */
struct ZMQ {
  void *context; /**< The ZeroMQ context */
  void *socket;  /**< The ZeroMQ socket */
};
#endif /* ENABLE_NTOPNG */

/* User to setuid to and directory to chroot to when we drop privs */
#ifndef PRIVDROP_USER
/** User that the daemon changes to when it drops its privileges. */
#define PRIVDROP_USER "nobody"
#endif

#ifndef PRIVDROP_CHROOT_DIR
/**
 * Directory that the daemon changes the root to when it drops its
 * privileges.
 */
#define PRIVDROP_CHROOT_DIR "/var/empty"
#endif
/*
 * Capture length for libpcap: Must fit the link layer header, plus
 * a maximally sized ip/ipv6 header and most of a TCP header
 */
/**
 * Capture length of libpcap for IPv4. It must fit the link layer header,
 * an IP header of maximum size and most of a TCP header.
 */
#define LIBPCAP_SNAPLEN_V4 96
/**
 * Capture length of libpcap for IPv6. It must fit the link layer header,
 * an IPv6 header of maximum size and most of a TCP header.
 */
#define LIBPCAP_SNAPLEN_V6 160

/*
 * Timeouts
 */
/** Default timeout in seconds of an open TCP connection (-t tcp). */
#define DEFAULT_TCP_TIMEOUT 3600
/**
 * Default timeout in seconds of a TCP connection after an RST from one
 * or both endpoints (-t tcp.rst).
 */
#define DEFAULT_TCP_RST_TIMEOUT 120
/**
 * Default timeout in seconds of a TCP connection after a FIN from both
 * endpoints (-t tcp.fin).
 */
#define DEFAULT_TCP_FIN_TIMEOUT 300
/** Default timeout in seconds of a UDP flow (-t udp). */
#define DEFAULT_UDP_TIMEOUT 300
/** Default timeout in seconds of an ICMP flow (-t icmp). */
#define DEFAULT_ICMP_TIMEOUT 300
/**
 * Default general timeout in seconds, applied to all traffic unless
 * another timeout overrides it (-t general).
 */
#define DEFAULT_GENERAL_TIMEOUT 3600
/** Default maximum lifetime in seconds of a flow (-t maxlife): 7 days. */
#define DEFAULT_MAXIMUM_LIFETIME (3600 * 24 * 7)
/**
 * Default interval in seconds between the scans for the flows to expire
 * (-t expint).
 */
#define DEFAULT_EXPIRY_INTERVAL 60

/*
 * Default maximum number of flow to track simultaneously
 * 8192 corresponds to just under 1Mb of flow data
 */
/** Default maximum number of flows tracked at a time (-m). */
#define DEFAULT_MAX_FLOWS 8192

/** Version number of IPFIX in the message header. */
#define NF_VERSION_IPFIX 10

/** Store a couple of statistics, maybe more in the future */
struct STATISTIC {
  double min;  /**< Smallest sample */
  double mean; /**< Running mean */
  double max;  /**< Largest sample */
};

/** Flow tracking levels */
enum {
  TRACK_IP_ONLY,        /* src/dst tuple */
  TRACK_IP_PROTO,       /* src/dst/proto 3-tuple */
  TRACK_IP_PROTO_PORT,  /* src/dst/addr/port/proto 5-tuple */
  TRACK_FULL,           /* src/dst/addr/port/proto/tos 6-tuple */
  TRACK_FULL_VLAN,      /* src/dst/addr/port/proto/tos/vlanid 7-tuple */
  TRACK_FULL_VLAN_ETHER /* src/dst/addr/port/proto/tos/vlanid/src-mac/dst-mac
                           9-tuple */
};

/** Largest number of export destinations. */
#define SOFTFLOWD_MAX_DESTINATIONS 16

/* Copy tv_sec and tv_usec individually to support platforms where
 * pcap_pkthdr.ts is a struct bpf_timeval (e.g. OpenBSD). */
/**
 * Copy the time stamp src of a pcap packet header to the struct timeval
 * dst, member by member.
 */
#define PCAP_TS_TO_TIMEVAL(dst, src) \
  do {                               \
    (dst).tv_sec = (src).tv_sec;     \
    (dst).tv_usec = (src).tv_usec;   \
  } while (0)

/** printf format of an Ethernet address, to be used with FORMAT_ETHERMAC. */
#define PRI_ETHERMAC "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
/**
 * The six octets of the Ethernet address em, as the arguments of
 * PRI_ETHERMAC.
 */
#define FORMAT_ETHERMAC(em) em[0], em[1], em[2], em[3], em[4], em[5]

/* Return values from process_packet */
/** Result of process_packet (): the packet was processed. */
#define PP_OK 0
/** Result of process_packet (): the packet is bad or too short. */
#define PP_BAD_PACKET -2
/** Result of process_packet (): memory for a flow could not be allocated. */
#define PP_MALLOC_FAIL -3

/* check_expired() modes */
/** Mode of check_expired (): normal expiry processing. */
#define CE_EXPIRE_NORMAL 0 /* Normal expiry processing */
/** Mode of check_expired (): expire all the flows at once. */
#define CE_EXPIRE_ALL -1   /* Expire all flows immediately */
/**
 * Mode of check_expired (): expire only the flows that are marked for
 * forced expiry.
 */
#define CE_EXPIRE_FORCED 1 /* Only expire force-expired flows */

/**
 * Largest interval of -I in days: what fits in the 32 bits of the
 * milliseconds of sysUpTime.
 */
#define BOOTTIME_MAX_DAY 49
/** Largest interval of -I in hours. */
#define BOOTTIME_MAX_HOUR 1193
/** Largest interval of -I in minutes. */
#define BOOTTIME_MAX_MIN 71582
/** Largest interval of -I in seconds. */
#define BOOTTIME_MAX_SEC 4294944

/**
 * This structure contains optional information carried by Option Data
 * Record.
 */
struct OPTION {
  uint32_t sample;              /**< Sampling rate (-s); 1 in every "sample" packets */
  pid_t meteringProcessId;      /**< Process id of softflowd, sent as
                                   meteringProcessId */
  char interfaceName[IFNAMSIZ]; /**< Capture interface name, sent as
                                   interfaceName */
  struct addrinfo
    *exporterAddr; /**< Exporter address(es) sent in the option record */
};

/** Why a flow is expired; also indexes FLOWTRACKPARAMETERS.expired[]. */
enum EXPIRY_REASON {
  R_GENERAL,   /**< General timeout */
  R_TCP,       /**< TCP timeout */
  R_TCP_RST,   /**< TCP RST seen */
  R_TCP_FIN,   /**< FIN seen in both directions */
  R_UDP,       /**< UDP timeout */
  R_ICMP,      /**< ICMP timeout */
  R_MAXLIFE,   /**< Maximum lifetime */
  R_OVERBYTES, /**< More than 2 GiB */
  R_OVERFLOWS, /**< Flow table full (maxflows) */
  R_FLUSH,     /**< Flush (expire-all) */
  R_COLLISION, /**< Hash collision (hash mode) */
  R_COUNT      /**< Number of reasons; not a reason itself */
};

/** Parameters, limits, timeouts and statistics of the flow tracker. */
struct FLOWTRACKPARAMETERS {
  unsigned int num_flows;  /**< # of active flows */
  unsigned int max_flows;  /**< Max # of active flows */
  u_int64_t next_flow_seq; /**< Next flow ID */

  /* Stuff related to flow export */
  struct timeval system_boot_time; /**< SysUptime */
  int track_level;                 /**< See TRACK_* above */
  int full_l4hdr_check;            /**< Non-zero: require whole transport headers (-f) */

  /* Flow timeouts */
  int tcp_timeout;      /**< Open TCP connections */
  int tcp_rst_timeout;  /**< TCP flows after RST */
  int tcp_fin_timeout;  /**< TCP flows after bidi FIN */
  int udp_timeout;      /**< UDP flows */
  int icmp_timeout;     /**< ICMP flows */
  int general_timeout;  /**< Everything else */
  int maximum_lifetime; /**< Maximum life for flows */
  int expiry_interval;  /**< Interval between expiries */

  /* Statistics */
  u_int64_t total_packets;       /**< # of good packets */
  u_int64_t non_sampled_packets; /**< # of not sampled packets */
  u_int64_t frag_packets;        /**< # of fragmented packets */
  u_int64_t non_ip_packets;      /**< # of not-IP packets */
  u_int64_t bad_packets;         /**< # of bad packets */
  u_int64_t flows_expired;       /**< # expired */
  u_int64_t flows_exported;      /**< # of flows sent */
  u_int64_t flows_dropped;       /**< # of flows dropped */
  u_int64_t flows_force_expired; /**< # of flows forced out */
  u_int64_t packets_sent;        /**< # netflow packets sent */
  u_int64_t records_sent;        /**< # netflow records sent */
  struct STATISTIC duration;     /**< Flow duration */
  struct STATISTIC octets;       /**< Bytes (bidir) */
  struct STATISTIC packets;      /**< Packets (bidir) */

  /* Per protocol statistics */
  u_int64_t flows_pp[256];   /**< Flows per IP protocol number */
  u_int64_t octets_pp[256];  /**< Octets per IP protocol number */
  u_int64_t packets_pp[256]; /**< Packets per IP protocol number */
  struct STATISTIC
    duration_pp[256]; /**< Flow duration per IP protocol number */

  /* Timeout statistics */
  u_int64_t expired[R_COUNT]; /**< Flows expired, indexed by enum EXPIRY_REASON */

  /* Optional information */
  struct OPTION option; /**< Data of the options record */
  char time_format;     /**< Absolute time format of IPFIX records (-A): 's', 'm',
                       'M', 'n'; otherwise sysUpTime */
  u_int8_t bidirection; /**< Non-zero to export IPFIX biflow records */
  u_int8_t
    adjust_time;                   /**< Non-zero to base export time on the last packet time */
  u_int8_t is_psamp;               /**< Non-zero when exporting PSAMP */
  u_int8_t max_num_label;          /**< Maximum number of MPLS labels exported */
  struct timeval last_packet_time; /**< Timestamp of the last captured packet */
  u_int32_t boot_time_reinit;      /**< seconds */

  /* Optional MAC for IPFIX flowDirection (Src = Egress, Dst = Ingress).
   * Requires track_level >= TRACK_FULL_VLAN_ETHER. */
  u_int8_t direction_mac[6];  /**< MAC address used to decide flowDirection */
  u_int8_t direction_mac_set; /**< Non-zero when direction_mac is valid */
};
/** Head of a tree of flows; one per bucket of the flow table. */
FLOW_HEAD (FLOWS, FLOW);

/** How active flows are looked up (--flow-lookup). */
enum FLOW_LOOKUP {
  FLOW_LOOKUP_TREE,      /**< One tree of all flows */
  FLOW_LOOKUP_HASH_TREE, /**< Hash table; flows sharing a bucket are kept in a
                            tree (default) */
  FLOW_LOOKUP_HASH       /**< Hash table; a colliding flow expires the resident one */
};

/**
 * This structure is the root of the flow tracking system.
 * It holds the flow table and the head of the tree of expiry events.
 * It also collects miscellaneous statistics
 */
struct FLOWTRACK {
  /* The flows and their expiry events */
  enum FLOW_LOOKUP flow_lookup; /**< Lookup mode of the flow table */
  u_int32_t
    flow_nbuckets;            /**< Number of buckets (power of two; 1 in tree mode) */
  struct FLOWS *flow_buckets; /**< Tree per bucket (tree and hash-tree modes) */
  struct FLOW **flow_slots;   /**< One flow per bucket (hash mode) */
  size_t flow_table_bytes;    /**< Memory used by the bucket array */
  EXPIRY_HEAD (EXPIRIES, EXPIRY)
  expiries; /**< Top of expiries tree */

  struct freelist flow_freelist;   /**< Freelist for flows */
  struct freelist expiry_freelist; /**< Freelist for expiry events */

  struct FLOWTRACKPARAMETERS param; /**< Parameters, limits, timeouts and statistics */
};

/**
 * This structure is an entry in the tree of flows that we are
 * currently tracking.
 *
 * Because flows are matched _bi-directionally_, they must be stored in
 * a canonical format: the numerically lowest address and port number must
 * be stored in the first address and port array slot respectively.
 */
struct FLOW {
  /* Housekeeping */
  struct EXPIRY *expiry; /**< Pointer to expiry record */
  FLOW_ENTRY (FLOW)
  trp; /**< Tree pointer */

  /* Per-flow statistics (all in _host_ byte order) */
  u_int64_t flow_seq;        /**< Flow ID */
  struct timeval flow_start; /**< Time of creation */
  struct timeval flow_last;  /**< Time of last traffic */

  /* Per-endpoint statistics (all in _host_ byte order) */
  u_int32_t octets[2];  /**< Octets so far */
  u_int32_t packets[2]; /**< Packets so far */

  /* Flow identity (all are in network byte order) */
  int af;                     /**< Address family of flow */
  u_int32_t ip6_flowlabel[2]; /**< IPv6 Flowlabel */
  union {
    struct in_addr v4;
    struct in6_addr v6;
  } addr[2];                     /**< Endpoint addresses */
  u_int16_t port[2];             /**< Endpoint ports */
  u_int8_t tcp_flags[2];         /**< Cumulative OR of flags */
  u_int8_t tos[2];               /**< Tos */
  u_int16_t vlanid[2];           /**< vlanid */
  uint8_t ethermac[2][6];        /**< Endpoint MAC addresses */
  u_int8_t protocol;             /**< Protocol */
  u_int8_t flowEndReason;        /**< IPFIX flowEndReason (IPFIX_flowEndReason_*) */
  u_int32_t mplsLabelStackDepth; /**< Number of MPLS labels seen */
  u_int32_t mplsLabels[10];      /**< MPLS labels (three octets each) */
};

/**
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
  EXPIRY_ENTRY (EXPIRY)
  trp;               /**< Tree pointer */
  struct FLOW *flow; /**< pointer to flow */

  u_int32_t expires_at;      /**< time_t */
  enum EXPIRY_REASON reason; /**< Why the flow is expired */
};

/** One export destination. */
struct DESTINATION {
  char *arg;                  /**< The host:port argument as given */
  int sock;                   /**< Connected socket */
  struct sockaddr_storage ss; /**< Resolved address */
  socklen_t sslen;            /**< Length of ss */
  char hostname[NI_MAXHOST];  /**< Numeric host name */
  char servname[NI_MAXSERV];  /**< Numeric service (port) */
#ifdef ENABLE_NTOPNG
  struct ZMQ zmq; /**< ZeroMQ context and socket for ntopng */
#endif
};

/** Describes a location where we send NetFlow packets to */
struct NETFLOW_TARGET {
  int num_destinations; /**< Number of entries in destinations[] */
  struct DESTINATION
    destinations[SOFTFLOWD_MAX_DESTINATIONS]; /**< Export destinations */
  const struct NETFLOW_SENDER
    *dialect;              /**< Export functions for the selected version */
  u_int8_t is_loadbalance; /**< Non-zero to alternate between destinations
                              instead of sending to all */
};

/** Everything an export function needs to send a batch of expired flows. */
struct SENDPARAMETER {
  struct FLOW **flows;               /**< Flows to export */
  int num_flows;                     /**< Number of entries in flows */
  struct NETFLOW_TARGET *target;     /**< Where to send */
  u_int16_t ifidx;                   /**< Interface index put into the records */
  struct FLOWTRACKPARAMETERS *param; /**< Tracking parameters and counters */
  int verbose_flag;                  /**< Non-zero for debug logging */
};

/** Context for libpcap callback functions */
struct CB_CTXT {
  struct FLOWTRACK *ft;          /**< Flow tracking state */
  struct NETFLOW_TARGET *target; /**< Export target */
  int linktype;                  /**< libpcap data link type */
  int fatal;                     /**< Set when an unrecoverable error occurred */
  int want_v6;                   /**< Non-zero if IPv6 flows are wanted */
};

/* Prototype for functions shared from softflowd.c */
u_int32_t
timeval_sub_ms (const struct timeval *t1, const struct timeval *t2);
int
send_multi_destinations (int num_destinations,
                         struct DESTINATION *destinations,
                         u_int8_t is_loadbalance, u_int8_t *packet, int size,
                         int verbose);
void
flow_cb (u_char *user_data, const struct pcap_pkthdr *phdr,
         const u_char *pkt);

/* Prototypes for functions to send NetFlow/IPFIX packets. Each is defined
 * exactly once in a build: in export.c or in compat/netflow*.c, depending
 * on --enable-compat-export (see the Source Layout section of README). */
int
send_netflow_v1 (struct SENDPARAMETER sp);
int
send_netflow_v5 (struct SENDPARAMETER sp);
int
send_netflow_v9 (struct SENDPARAMETER sp);
int
send_ipfix (struct SENDPARAMETER sp);
int
send_ipfix_bi (struct SENDPARAMETER sp);
#ifdef ENABLE_NTOPNG
/* Protypes for ntopng.c */
int
connect_ntopng (const char *host, const char *port, struct ZMQ *zmq);
void
close_ntopng (struct ZMQ *zmq);
int
send_ntopng (struct SENDPARAMETER sp);
#ifdef ENABLE_NTOPNG_JSON
/* Protypes for compat/ntopng-json.c */
int
send_ntopng_json (struct SENDPARAMETER sp);
#endif /* ENABLE_NTOPNG_JSON */
#endif /* ENABLE_NTOPNG */

#endif /* _SOFTFLOWD_H */
