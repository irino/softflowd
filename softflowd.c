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

#include "softflowd.h"
#include "common.h"
#include "convtime.h"
#include "freelist.h"
#include "export_common.h"
#include "ipfix.h"
#include "log.h"
#include "netflow.h"
#include "psamp.h"
#include "treetype.h"
#include <getopt.h>
#include <stdarg.h> /* va_start and va_end for die_usage() */
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <pcap.h>
#ifdef HAVE_XXHASH
#include <xxhash.h>
#endif /* HAVE_XXHASH */
#ifdef LINUX
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#ifdef HAVE_LINUX_DCCP_H
#include <linux/dccp.h> /* struct dccp_hdr */
#endif
#endif /* LINUX */
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif /* HAVE_IFADDRS_H */
#if !defined(LINUX) && defined(HAVE_IFADDRS_H)
#include <net/if_dl.h>
#endif
#define OPT_FLOW_LOOKUP 256         /* --flow-lookup has no short option */
#define FLOW_MAX_BUCKETS (1U << 24) /* upper bound of the flow table size */

/* Global variables */
static int verbose_flag = 0;   /**< Debugging flag */
static u_int16_t if_index = 0; /**< "manual" interface index */
static int track_level;        /**< Flow tracking level (TRACK_*) */
/** Capture length; 0 selects a default from LIBPCAP_SNAPLEN_V4/V6 */
static int snaplen = 0;
static int gauge_clock = 0; /**< -g: report cpu clocks */
/** cpu clocks spent in the export function */
static clock_t export_clocks = 0;
/** Number of calls to the export function */
static unsigned long export_calls = 0;
#ifdef ENABLE_PTHREAD
pthread_mutex_t read_mutex; /**< Protects packet_header/packet_data handed to
                               the processing thread */
pthread_cond_t read_cond;   /**< Signalled when a new packet is available */
/** Protects export_threads_outstanding */
static pthread_mutex_t export_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
/** Signalled when the last export thread ends */
static pthread_cond_t export_threads_cond = PTHREAD_COND_INITIALIZER;
/** Number of running export threads (-M) */
static int export_threads_outstanding = 0;
/** Signalled when the processing thread has finished the handed-over packet */
static pthread_cond_t slot_cond = PTHREAD_COND_INITIALIZER;
/** Non-zero while packet_data holds a packet that is not processed yet
 * (protected by read_mutex) */
static int packet_ready = 0;
/** Set under read_mutex to make process_packet_loop() return */
static int reader_stop = 0;

/**
 * @brief Block until every detached export thread (-M) has finished.
 *
 * Detached export threads outlive the check_expired() call that spawns them, so
 * this must run before the process tears down.
 */
static void
wait_for_export_threads (void) {
  pthread_mutex_lock (&export_threads_mutex);
  while (export_threads_outstanding > 0)
    pthread_cond_wait (&export_threads_cond, &export_threads_mutex);
  pthread_mutex_unlock (&export_threads_mutex);
}
int use_thread;                   /**< Non-zero when threaded export (-M) is enabled */
u_char packet_data[1500];         /**< Copy of the latest captured packet (threaded
                             capture) */
struct pcap_pkthdr packet_header; /**< libpcap header of packet_data */
struct FLOW
  *send_expired_flows; /**< Expired flows handed to the export thread */
#endif                 /* ENABLE_PTHREAD */

/* Signal handler flags */
/** Set by the signal handler to the received signal number to request a
 * graceful shutdown. */
static volatile sig_atomic_t graceful_shutdown_request = 0;
/** Set by SIGUSR1: log the number of the tracked flows and of the packets. */
static volatile sig_atomic_t stats_log_request = 0;
/** Set by SIGHUP: log that a reload of the configuration is not implemented. */
static volatile sig_atomic_t hup_log_request = 0;

/* Describes a datalink header and how to extract v4/v6 frames from it */
struct DATALINK {
  int dlt;           /* BPF datalink type */
  int skiplen;       /* Number of bytes to skip datalink header */
  int ft_off;        /* Datalink frametype offset */
  int ft_len;        /* Datalink frametype length */
  int ft_is_be;      /* Set if frametype is big-endian */
  u_int32_t ft_mask; /* Mask applied to frametype */
  u_int32_t ft_v4;   /* IPv4 frametype */
  u_int32_t ft_v6;   /* IPv6 frametype */
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

/**
 * @brief Auto-detect the MAC address of an interface.
 *
 * @param ifname Interface name.
 * @param mac    Receives the 6-octet address.
 * @return 0 on success, -1 on failure (e.g. a tunnel or the "any" interface).
 */
static int
get_interface_mac (const char *ifname, u_int8_t mac[6]) {
#ifdef LINUX
  int s;
  struct ifreq ifr;

  if (ifname == NULL)
    return (-1);

  if ((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    return (-1);

  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, ifname, IFNAMSIZ - 1);

  if (ioctl (s, SIOCGIFHWADDR, &ifr) < 0) {
    close (s);
    return (-1);
  }
  close (s);

  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    return (-1);

  memcpy (mac, ifr.ifr_hwaddr.sa_data, 6);
  return (0);
#else  /* LINUX */
  struct ifaddrs *ifap, *p;
  int found = -1;

  if (ifname == NULL)
    return (-1);

  if (getifaddrs (&ifap) != 0)
    return (-1);

  for (p = ifap; p != NULL; p = p->ifa_next) {
    if (p->ifa_addr == NULL || p->ifa_addr->sa_family != AF_LINK)
      continue;
    if (strcmp (p->ifa_name, ifname) != 0)
      continue;

    struct sockaddr_dl *sdl = (struct sockaddr_dl *) p->ifa_addr;
    if (sdl->sdl_alen != 6)
      continue;

    memcpy (mac, LLADDR (sdl), 6);
    found = 0;
    break;
  }
  freeifaddrs (ifap);
  return (found);
#endif /* LINUX */
}

/* Netflow send functions */
typedef int (netflow_send_func_t) (struct SENDPARAMETER);

#ifdef ENABLE_PTHREAD
/* Context for threaded export (-M): unlike netflow_send_func_t, this
 * wrapper's signature actually matches what pthread_create() invokes
 * (void *(*)(void *)), and it owns a deep copy of both the flows and
 * the SENDPARAMETER referencing them, so the sending thread never
 * touches memory the main thread may concurrently reuse via
 * flow_put(). sp.flows points at owned_flows: the export function only
 * reads it, and threaded_send alone frees the array and the flow copies
 * after that call returns, so no return path of an export function can
 * leak them. */
struct THREADED_SENDPARAMETER {
  struct SENDPARAMETER sp;
  netflow_send_func_t *func;
  struct FLOW **owned_flows;
  int num_flows;
};

/**
 * @brief Thread entry point: run one export function, then free its flow copies
 * (-M).
 *
 * @param arg struct THREADED_SENDPARAMETER, which is freed here.
 * @return NULL.
 */
static void *
threaded_send (void *arg) {
  struct THREADED_SENDPARAMETER *tsp = (struct THREADED_SENDPARAMETER *) arg;
  int i;

  tsp->func (tsp->sp);
  for (i = 0; i < tsp->num_flows; i++)
    free (tsp->owned_flows[i]);
  free (tsp->owned_flows);
  free (tsp);
  pthread_mutex_lock (&export_threads_mutex);
  if (--export_threads_outstanding == 0)
    pthread_cond_signal (&export_threads_cond);
  pthread_mutex_unlock (&export_threads_mutex);
  return NULL;
}
#endif /* ENABLE_PTHREAD */

struct NETFLOW_SENDER {
  int version;
  netflow_send_func_t *func;
  netflow_send_func_t *bidir_func;
  int v6_capable;
};

/* Known NetFlow export functions (nf[0] is default).
 * Which source file defines the send_* functions depends on
 * --enable-compat-export (see softflowd.h). */
static const struct NETFLOW_SENDER nf[] = {
  {5, send_netflow_v5, NULL, 0},
  {1, send_netflow_v1, NULL, 0},
  {9, send_netflow_v9, NULL, 1},
  {NF_VERSION_IPFIX, send_ipfix, send_ipfix_bi, 1},
#ifdef ENABLE_NTOPNG
  {SOFTFLOWD_NF_VERSION_NTOPNG, send_ntopng, NULL, 1},
#ifdef ENABLE_NTOPNG_JSON
  {SOFTFLOWD_NF_VERSION_NTOPNG_JSON, send_ntopng_json, NULL, 1},
#endif
#endif
};

/**
 * @brief Find the export function set for an export version.
 *
 * @param version Export version (1, 5, 9, NF_VERSION_IPFIX, or
 * SOFTFLOWD_NF_VERSION_NTOPNG, or SOFTFLOWD_NF_VERSION_NTOPNG_JSON).
 * @return Matching entry of the nf[] table, or NULL if the version is unknown.
 */
static const struct NETFLOW_SENDER *
lookup_netflow_sender (int version) {
  size_t i;
  int r;
  for (i = 0, r = version; i < sizeof (nf) / sizeof (struct NETFLOW_SENDER);
       i++) {
    if (nf[i].version == r)
      return &nf[i];
  }
  return NULL;
}

/**
 * @brief Signal handler that requests a graceful shutdown.
 *
 * @param signum Signal number; stored in graceful_shutdown_request.
 */
static void
sighand_graceful_shutdown (int signum) {
  graceful_shutdown_request = signum;
}

/**
 * @brief Signal handler of SIGUSR1: request the log of the statistics.
 *
 * @param signum Signal number; not used.
 */
static void
sighand_log_stats (int signum) {
  (void) signum;
  stats_log_request = 1;
}

/**
 * @brief Signal handler of SIGHUP: request the log that there is no reload.
 *
 * @param signum Signal number; not used.
 */
static void
sighand_hup (int signum) {
  (void) signum;
  hup_log_request = 1;
}

/**
 * @brief Signal handler for unexpected signals: log and exit immediately.
 *
 * @param signum Signal number.
 */
static void
sighand_other (int signum) {
  /* XXX: this may not be completely safe */
  logit (LOG_WARNING, "Exiting immediately on unexpected signal %d", signum);
  _exit (0);
}

/**
 * @brief Comparison function of the flow tree.
 *
 * Flows are compared on their identity fields, which depend on the tracking
 * level.
 *
 * @param a First flow.
 * @param b Second flow.
 * @return Negative, zero or positive, as for memcmp().
 */
static int
flow_compare (struct FLOW *a, struct FLOW *b) {
  /* Be careful to avoid signed vs unsigned issues here */
  int r;
  u_int32_t i;
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

/**
 * @brief Comparison function of the expiry tree.
 *
 * Ordered by expiry time; ties are broken by flow sequence number so entries
 * are unique.
 *
 * @param a First expiry event.
 * @param b Second expiry event.
 * @return -1, 0 or 1.
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

static const char *
format_flow_brief (struct FLOW *flow);

/**
 * @brief Hash the identity fields of a flow.
 *
 * Uses exactly the fields flow_compare() looks at (and only those), so flows
 * that compare equal always hash equal. The fields are packed into one buffer
 * first, so padding and the unused part of the address union cannot influence
 * the result.
 *
 * @param flow Flow to hash.
 * @return 32-bit hash value.
 */
static u_int32_t
flow_hash (const struct FLOW *flow) {
  u_int8_t key[sizeof (flow->vlanid) + sizeof (flow->ethermac) +
               sizeof (flow->af) + sizeof (flow->addr) + sizeof (flow->protocol) +
               sizeof (flow->port) + sizeof (flow->mplsLabelStackDepth) +
               sizeof (flow->mplsLabels)];
  size_t len = 0, n;
  u_int32_t depth = flow->mplsLabelStackDepth;
#ifdef HAVE_XXHASH
  XXH64_hash_t h;
#else  /* HAVE_XXHASH */
  u_int32_t h = 2166136261U; /* FNV-1a */
  size_t i;
#endif /* HAVE_XXHASH */

#define KEY_ADD(p, size)             \
  do {                               \
    memcpy (key + len, (p), (size)); \
    len += (size);                   \
  } while (0)
  if (track_level == TRACK_FULL_VLAN || track_level == TRACK_FULL_VLAN_ETHER)
    KEY_ADD (flow->vlanid, sizeof (flow->vlanid));
  if (track_level == TRACK_FULL_VLAN_ETHER)
    KEY_ADD (flow->ethermac, sizeof (flow->ethermac));
  KEY_ADD (&flow->af, sizeof (flow->af));
  KEY_ADD (flow->addr, sizeof (flow->addr));
  KEY_ADD (&flow->protocol, sizeof (flow->protocol));
  KEY_ADD (flow->port, sizeof (flow->port));
  KEY_ADD (&flow->mplsLabelStackDepth, sizeof (flow->mplsLabelStackDepth));
  if (depth > sizeof (flow->mplsLabels) / sizeof (flow->mplsLabels[0]))
    depth = sizeof (flow->mplsLabels) / sizeof (flow->mplsLabels[0]);
  n = depth * sizeof (flow->mplsLabels[0]);
  if (n > 0)
    KEY_ADD (flow->mplsLabels, n);
#undef KEY_ADD

#ifdef HAVE_XXHASH
  h = XXH64 (key, len, 0);
  return ((u_int32_t) (h ^ (h >> 32)));
#else  /* HAVE_XXHASH */
  for (i = 0; i < len; i++) {
    h ^= key[i];
    h *= 16777619U;
  }
  return (h);
#endif /* HAVE_XXHASH */
}

/**
 * @brief Name of a flow lookup mode, as given to --flow-lookup.
 *
 * @param mode Lookup mode.
 * @return Name of the mode.
 */
static const char *
flow_lookup_name (enum FLOW_LOOKUP mode) {
  switch (mode) {
    case FLOW_LOOKUP_HASH_TREE:
      return ("hash-tree");
    case FLOW_LOOKUP_HASH:
      return ("hash");
    default:
      return ("tree");
  }
}

/**
 * @brief Allocate the flow table according to the lookup mode and max_flows.
 *
 * Tree mode uses a single bucket. The hash modes use a power of two number of
 * buckets (at least max_flows, twice that in hash mode, capped at
 * FLOW_MAX_BUCKETS). Call after the options are parsed.
 *
 * @param ft Flow tracking state.
 * @return 0 on success, -1 if the allocation failed.
 */
static int
flow_table_init (struct FLOWTRACK *ft) {
  u_int64_t want, n;
  u_int32_t i;

  n = 1;
  if (ft->flow_lookup != FLOW_LOOKUP_TREE) {
    want = ft->param.max_flows;
    if (ft->flow_lookup == FLOW_LOOKUP_HASH)
      want *= 2;
    while (n < want && n < FLOW_MAX_BUCKETS)
      n <<= 1;
  }
  ft->flow_nbuckets = (u_int32_t) n;

  if (ft->flow_lookup == FLOW_LOOKUP_HASH) {
    ft->flow_table_bytes = ft->flow_nbuckets * sizeof (*ft->flow_slots);
    ft->flow_slots = calloc (ft->flow_nbuckets, sizeof (*ft->flow_slots));
    return (ft->flow_slots == NULL ? -1 : 0);
  }
  ft->flow_table_bytes = ft->flow_nbuckets * sizeof (*ft->flow_buckets);
  ft->flow_buckets = calloc (ft->flow_nbuckets, sizeof (*ft->flow_buckets));
  if (ft->flow_buckets == NULL)
    return (-1);
  for (i = 0; i < ft->flow_nbuckets; i++)
    FLOW_INIT (&ft->flow_buckets[i]);
  return (0);
}

/**
 * @brief Bucket index of a flow.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow (only its identity fields are used).
 * @return Index into the flow table.
 */
static u_int32_t
flow_index (const struct FLOWTRACK *ft,
            const struct FLOW *flow) {
  if (ft->flow_nbuckets == 1)
    return (0);
  return (flow_hash (flow) & (ft->flow_nbuckets - 1));
}

/**
 * @brief Look up a flow in the flow table.
 *
 * @param ft  Flow tracking state.
 * @param key Flow holding the identity to look for.
 * @param idx Bucket index of key, from flow_index().
 * @return Matching flow, or NULL.
 */
static struct FLOW *
flow_table_find (struct FLOWTRACK *ft, struct FLOW *key,
                 u_int32_t idx) {
  struct FLOW *resident;

  if (ft->flow_lookup == FLOW_LOOKUP_HASH) {
    resident = ft->flow_slots[idx];
    return (resident != NULL && flow_compare (resident, key) == 0 ? resident
                                                                  : NULL);
  }
  return (FLOW_FIND (FLOWS, &ft->flow_buckets[idx], key));
}

/**
 * @brief Insert a new flow into the flow table.
 *
 * In hash mode a flow already resident in the bucket is taken out of the table
 * and scheduled for immediate expiry (R_COLLISION); it is exported by the next
 * expiry scan.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow to insert.
 * @param idx  Bucket index of flow, from flow_index().
 */
static void
flow_table_insert (struct FLOWTRACK *ft, struct FLOW *flow,
                   u_int32_t idx) {
  struct FLOW *victim;
  struct EXPIRY *expiry;

  if (ft->flow_lookup != FLOW_LOOKUP_HASH) {
    FLOW_INSERT (FLOWS, &ft->flow_buckets[idx], flow);
    return;
  }

  if ((victim = ft->flow_slots[idx]) != NULL) {
    expiry = victim->expiry;
    /* Keep the reason of a flow that is already due for expiry */
    if (expiry != NULL && expiry->expires_at != 0) {
      EXPIRY_REMOVE (EXPIRIES, &ft->expiries, expiry);
      expiry->expires_at = 0;
      expiry->reason = R_COLLISION;
      victim->flowEndReason = IPFIX_flowEndReason_lackOfResource;
      EXPIRY_INSERT (EXPIRIES, &ft->expiries, expiry);
    }
    if (verbose_flag)
      logit (LOG_DEBUG, "COLLISION %s", format_flow_brief (victim));
  }
  ft->flow_slots[idx] = flow;
}

/**
 * @brief Remove a flow from the flow table.
 *
 * A flow that was evicted by a collision (hash mode) is no longer in the table;
 * this is detected by comparing the resident of the bucket with the flow.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow to remove.
 */
static void
flow_table_remove (struct FLOWTRACK *ft, struct FLOW *flow) {
  u_int32_t idx = flow_index (ft, flow);

  if (ft->flow_lookup == FLOW_LOOKUP_HASH) {
    if (ft->flow_slots[idx] == flow)
      ft->flow_slots[idx] = NULL;
    return;
  }
  FLOW_REMOVE (FLOWS, &ft->flow_buckets[idx], flow);
}

/**
 * @brief Print how the flow table was allocated (debug mode).
 *
 * Shows the number of buckets, the memory of the bucket array (also relative to
 * tree mode, which has a single bucket) and, for scale, the memory flows take
 * at max_flows.
 *
 * @param ft Flow tracking state.
 */
static void
flow_table_report (const struct FLOWTRACK *ft) {
  size_t tree_bytes = sizeof (struct FLOWS);

  fprintf (stderr, "Flow table: mode=%s buckets=%u (max_flows=%u%s)\n",
           flow_lookup_name (ft->flow_lookup), ft->flow_nbuckets,
           ft->param.max_flows,
           ft->flow_nbuckets == FLOW_MAX_BUCKETS ? ", at the cap" : "");
  fprintf (stderr,
           "Flow table: bucket array %zu bytes (%zu bytes/bucket), %+lld bytes "
           "vs tree mode\n",
           ft->flow_table_bytes, ft->flow_table_bytes / ft->flow_nbuckets,
           (long long) ft->flow_table_bytes - (long long) tree_bytes);
  fprintf (stderr,
           "Flow table: flows at max_flows: %zu bytes (FLOW %zu + EXPIRY %zu "
           "each)\n",
           (size_t) ft->param.max_flows *
             (sizeof (struct FLOW) + sizeof (struct EXPIRY)),
           sizeof (struct FLOW), sizeof (struct EXPIRY));
}

/**
 * @brief Measure how the active flows are spread over the buckets.
 *
 * Walks every bucket, so it is meant for statistics only.
 *
 * @param ft       Flow tracking state.
 * @param used     Receives the number of non-empty buckets.
 * @param maxdepth Receives the largest number of flows in one bucket.
 */
static void
flow_table_usage (struct FLOWTRACK *ft, u_int32_t *used,
                  u_int32_t *maxdepth) {
  struct FLOW *flow;
  u_int32_t i, depth;

  *used = *maxdepth = 0;
  for (i = 0; i < ft->flow_nbuckets; i++) {
    depth = 0;
    if (ft->flow_lookup == FLOW_LOOKUP_HASH)
      depth = ft->flow_slots[i] != NULL;
    else
      for (flow = FLOW_MIN (FLOWS, &ft->flow_buckets[i]); flow != NULL;
           flow = FLOW_NEXT (FLOWS, &ft->flow_buckets[i], flow))
        depth++;
    if (depth > 0)
      (*used)++;
    if (depth > *maxdepth)
      *maxdepth = depth;
  }
}

/**
 * @brief Allocate a flow record from the flow freelist.
 *
 * @param ft Flow tracking state.
 * @return New flow record, or NULL if out of memory.
 */
static struct FLOW *
flow_get (struct FLOWTRACK *ft) {
  return freelist_get (&ft->flow_freelist);
}

/**
 * @brief Return a flow record to the flow freelist.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow record to release.
 */
static void
flow_put (struct FLOWTRACK *ft, struct FLOW *flow) {
  return freelist_put (&ft->flow_freelist, flow);
}

/**
 * @brief Allocate an expiry event from the expiry freelist.
 *
 * @param ft Flow tracking state.
 * @return New expiry event, or NULL if out of memory.
 */
static struct EXPIRY *
expiry_get (struct FLOWTRACK *ft) {
  return freelist_get (&ft->expiry_freelist);
}

/**
 * @brief Return an expiry event to the expiry freelist.
 *
 * @param ft     Flow tracking state.
 * @param expiry Expiry event to release.
 */
static void
expiry_put (struct FLOWTRACK *ft, struct EXPIRY *expiry) {
  return freelist_put (&ft->expiry_freelist, expiry);
}

#if 0
/* Dump a packet */
static void
dump_packet (const u_int8_t *p, int len) {
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

/**
 * @brief Format a time in an ISO-like format.
 *
 * @param t Time to format.
 * @return Pointer to a string valid until the next call.
 */
static const char *
format_time (time_t t) {
  struct tm *tm;
  static char buf[32];

  tm = gmtime (&t);
  strftime (buf, sizeof (buf), "%Y-%m-%dT%H:%M:%S", tm);

  return (buf);
}

/**
 * @brief Format a flow in a verbose form for logging.
 *
 * @param flow Flow to format.
 * @return Pointer to a string valid until the next call.
 */
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
            "vlan>:%u vlan<:%u ether:" PRI_ETHERMAC " <> " PRI_ETHERMAC,
            flow->flow_seq, addr1, ntohs (flow->port[0]), addr2,
            ntohs (flow->port[1]), (int) flow->protocol, flow->octets[0],
            flow->packets[0], flow->octets[1], flow->packets[1], start_time,
            (long long) ((flow->flow_start.tv_usec + 500) / 1000), fin_time,
            (long long) ((flow->flow_last.tv_usec + 500) / 1000),
            flow->tcp_flags[0], flow->tcp_flags[1], flow->ip6_flowlabel[0],
            flow->ip6_flowlabel[1], flow->vlanid[0], flow->vlanid[1],
            FORMAT_ETHERMAC (flow->ethermac[0]),
            FORMAT_ETHERMAC (flow->ethermac[1]));

  return (buf);
}

/**
 * @brief Format a flow in a brief form for logging.
 *
 * @param flow Flow to format.
 * @return Pointer to a string valid until the next call.
 */
static const char *
format_flow_brief (struct FLOW *flow) {
  char addr1[64], addr2[64];
  static char buf[4096];

  inet_ntop (flow->af, &flow->addr[0], addr1, sizeof (addr1));
  inet_ntop (flow->af, &flow->addr[1], addr2, sizeof (addr2));

  snprintf (buf, sizeof (buf),
            "seq:%" PRIu64 " [%s]:%hu <> [%s]:%hu proto:%u "
            "vlan>:%u vlan<:%u  ether:" PRI_ETHERMAC " <> " PRI_ETHERMAC " ",
            flow->flow_seq, addr1, ntohs (flow->port[0]), addr2,
            ntohs (flow->port[1]), (int) flow->protocol, flow->vlanid[0],
            flow->vlanid[1], FORMAT_ETHERMAC (flow->ethermac[0]),
            FORMAT_ETHERMAC (flow->ethermac[1]));

  return (buf);
}

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
 * @brief Recompute when a flow expires and reinsert its expiry event.
 *
 * Chooses the timeout from the flow state: over 2 GiB of traffic or over the
 * maximum lifetime expires at once; TCP RST/FIN and TCP, UDP, ICMP and general
 * timeouts follow. Also sets flowEndReason and never lets a flow outlive the
 * maximum lifetime.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow whose expiry is updated.
 */
static void
flow_update_expiry (struct FLOWTRACK *ft, struct FLOW *flow) {
  /* Compute the new key first: the flow stays in the tree until the
   * expiry key really changes, so unchanged packets skip the tree work. */
  u_int32_t exp;
  int rsn;

  /* Flows over 2 GiB traffic */
  if (flow->octets[0] > (1U << 31) || flow->octets[1] > (1U << 31)) {
    exp = 0;
    rsn = R_OVERBYTES;
    flow->flowEndReason = IPFIX_flowEndReason_lackOfResource;
    goto out;
  }

  /* Flows over maximum life seconds */
  if (ft->param.maximum_lifetime != 0 &&
      flow->flow_last.tv_sec - flow->flow_start.tv_sec >
        ft->param.maximum_lifetime) {
    exp = 0;
    rsn = R_MAXLIFE;
    flow->flowEndReason = IPFIX_flowEndReason_activeTimeout;
    goto out;
  }

  if (flow->protocol == IPPROTO_TCP) {
    /* Reset TCP flows */
    if (ft->param.tcp_rst_timeout != 0 &&
        ((flow->tcp_flags[0] & TH_RST) || (flow->tcp_flags[1] & TH_RST))) {
      exp = flow->flow_last.tv_sec + ft->param.tcp_rst_timeout;
      rsn = R_TCP_RST;
      flow->flowEndReason = IPFIX_flowEndReason_endOfFlow;
      goto out;
    }
    /* Finished TCP flows */
    if (ft->param.tcp_fin_timeout != 0 &&
        ((flow->tcp_flags[0] & TH_FIN) && (flow->tcp_flags[1] & TH_FIN))) {
      exp = flow->flow_last.tv_sec + ft->param.tcp_fin_timeout;
      rsn = R_TCP_FIN;
      flow->flowEndReason = IPFIX_flowEndReason_endOfFlow;
      goto out;
    }

    /* TCP flows */
    if (ft->param.tcp_timeout != 0) {
      exp = flow->flow_last.tv_sec + ft->param.tcp_timeout;
      rsn = R_TCP;
      flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;
      goto out;
    }
  }

  if (ft->param.udp_timeout != 0 && flow->protocol == IPPROTO_UDP) {
    /* UDP flows */
    exp = flow->flow_last.tv_sec + ft->param.udp_timeout;
    rsn = R_UDP;
    flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;
    goto out;
  }

  if (ft->param.icmp_timeout != 0 &&
      ((flow->af == AF_INET && flow->protocol == IPPROTO_ICMP) ||
       ((flow->af == AF_INET6 && flow->protocol == IPPROTO_ICMPV6)))) {
    /* ICMP flows */
    exp = flow->flow_last.tv_sec + ft->param.icmp_timeout;
    rsn = R_ICMP;
    flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;
    goto out;
  }

  /* Everything else */
  exp = flow->flow_last.tv_sec + ft->param.general_timeout;
  rsn = R_GENERAL;
  flow->flowEndReason = IPFIX_flowEndReason_idleTimeout;

out:
  if (ft->param.maximum_lifetime != 0 && exp != 0) {
    exp = MIN (exp, flow->flow_start.tv_sec + ft->param.maximum_lifetime);
  }

  if (exp != flow->expiry->expires_at) {
    EXPIRY_REMOVE (EXPIRIES, &ft->expiries, flow->expiry);
    flow->expiry->expires_at = exp;
    EXPIRY_INSERT (EXPIRIES, &ft->expiries, flow->expiry);
  }
  flow->expiry->reason = rsn;
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
static int
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
 * @brief Subtract two timevals.
 *
 * @param t1 Minuend.
 * @param t2 Subtrahend.
 * @return t1 - t2 in milliseconds.
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

/**
 * @brief Send a packet to the destinations of a target.
 *
 * Pending socket errors (e.g. from ICMP) are cleared before each send.
 *
 * @param num_destinations Number of entries in destinations.
 * @param destinations     Destination sockets.
 * @param is_loadbalance   Non-zero to send to one destination per call (round
 * robin) instead of all.
 * @param packet           Packet to send.
 * @param size             Length of packet in bytes.
 * @param verbose          Non-zero to log the packet length at debug level.
 * @return -1 if a send failed, 1 in load-balance mode, otherwise the number of
 * destinations.
 */
int
send_multi_destinations (int num_destinations,
                         struct DESTINATION *destinations,
                         u_int8_t is_loadbalance, u_int8_t *packet, int size,
                         int verbose) {
  struct DESTINATION *dest;
  int i, err;
  socklen_t errsz;
  static u_int64_t sent = 0;
  if (verbose)
    logit (LOG_DEBUG, "Sending flow packet len = %d", size);
  for (i = 0; i < num_destinations; i++) {
    if (!is_loadbalance ||
        (is_loadbalance && ((int) (sent % num_destinations) == i))) {
      dest = &destinations[i];
      errsz = sizeof (err);
      getsockopt (dest->sock, SOL_SOCKET, SO_ERROR, &err,
                  &errsz);  // Clear ICMP errors
      if (send (dest->sock, packet, (size_t) size, 0) == -1)
        return (-1);
    }
  }
  sent++;
  return is_loadbalance ? 1 : i;
}

/**
 * @brief Update a running minimum, mean and maximum with a new sample.
 *
 * @param s   Statistic to update.
 * @param new New sample.
 * @param n   Number of samples including this one; 1.0 resets the statistic.
 */
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

/**
 * @brief Update the global statistics with a flow that is being expired.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow being expired.
 */
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

/**
 * @brief Count an expired flow under the counter matching its expiry reason.
 *
 * @param ft Flow tracking state.
 * @param e  Expiry event of the flow.
 */
static void
update_expiry_stats (struct FLOWTRACK *ft, struct EXPIRY *e) {
  ft->param.expired[e->reason]++;
}

/**
 * @brief Time until the next expiry event.
 *
 * @param ft Flow tracking state.
 * @return Milliseconds until the next expiry event.
 */
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
    return (-1); /* indefinite */

  expires_at = expiry->expires_at;

  /* Don't cluster urgent expiries */
  if (expires_at == 0 &&
      (expiry->reason == R_OVERBYTES || expiry->reason == R_OVERFLOWS ||
       expiry->reason == R_FLUSH || expiry->reason == R_COLLISION))
    return (0); /* Now */

  /* Cluster expiries by expiry_interval */
  if (ft->param.expiry_interval > 1) {
    if ((fudge = expires_at % ft->param.expiry_interval) > 0)
      expires_at += ft->param.expiry_interval - fudge;
  }

  if (expires_at < now.tv_sec)
    return (0); /* Now */

  ret = 999 + (expires_at - now.tv_sec) * 1000;
  return (ret);
}

/**
 * @brief Scan the tree of expiry events and process expired flows.
 *
 * @param ft     Flow tracking state.
 * @param target Where to export expired flows.
 * @param ex     CE_EXPIRE_NORMAL, CE_EXPIRE_ALL (expire every flow) or
 * CE_EXPIRE_FORCED (only forced ones).
 * @return Number of flows expired, or -1 on export error.
 */
static int
check_expired (struct FLOWTRACK *ft, struct NETFLOW_TARGET *target,
               int ex) {
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

  for (expiry = EXPIRY_MIN (EXPIRIES, &ft->expiries); expiry != NULL;
       expiry = nexpiry) {
    nexpiry = EXPIRY_NEXT (EXPIRIES, &ft->expiries, expiry);
    if ((expiry->expires_at == 0) || (ex == CE_EXPIRE_ALL) ||
        (ex != CE_EXPIRE_FORCED && (expiry->expires_at < now.tv_sec))) {
      /* Flow has expired */
      if (ft->param.maximum_lifetime != 0 &&
          expiry->flow->flow_last.tv_sec - expiry->flow->flow_start.tv_sec >=
            ft->param.maximum_lifetime)
        expiry->reason = R_MAXLIFE;

      if (verbose_flag)
        logit (LOG_DEBUG,
               "Queuing flow seq:%" PRIu64 " (%p) for expiry "
               "reason %d",
               expiry->flow->flow_seq, expiry->flow, expiry->reason);

      /* Add to array of expired flows */
      oldexp = expired_flows;
      expired_flows =
        realloc (expired_flows, sizeof (*expired_flows) * (num_expired + 1));
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

      /* Remove from flow table, destroy expiry event */
      flow_table_remove (ft, expiry->flow);
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
      struct SENDPARAMETER sp = {expired_flows, num_expired, target,
                                 if_index, &ft->param, verbose_flag};
      netflow_send_func_t *func = ft->param.bidirection == 1
                                    ? target->dialect->bidir_func
                                    : target->dialect->func;
      if (func == NULL) {
        func = target->dialect->func;
      }
#ifdef ENABLE_PTHREAD
      if (use_thread) {
        pthread_t write_thread = 0;
        struct THREADED_SENDPARAMETER *tsp = malloc (sizeof (*tsp));

        tsp->sp = sp;
        /* sp.flows is the array of copies made below; threaded_send
         * frees it, see the comment above. */
        tsp->owned_flows = calloc (num_expired, sizeof (*tsp->owned_flows));
        tsp->sp.flows = tsp->owned_flows;
        for (i = 0; i < num_expired; i++) {
          /* Deep copy: expired_flows[i] is about to be handed back to
           * flow_put() below and may be reused for a new flow before
           * this thread gets to read it. struct FLOW holds no pointers
           * of its own (its "expiry" back-link was already cleared
           * above), so a plain struct copy is a complete copy. */
          tsp->owned_flows[i] = malloc (sizeof (*tsp->owned_flows[i]));
          *tsp->owned_flows[i] = *expired_flows[i];
        }
        tsp->num_flows = num_expired;
        tsp->func = func;
        pthread_mutex_lock (&export_threads_mutex);
        export_threads_outstanding++;
        pthread_mutex_unlock (&export_threads_mutex);
        if (pthread_create (&write_thread, NULL, threaded_send, tsp) < 0) {
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
      {
        clock_t export_start = gauge_clock ? clock() : 0;

        r = func (sp);
        if (gauge_clock) {
          export_clocks += clock() - export_start;
          export_calls++;
        }
      }
      if (verbose_flag)
        logit (LOG_DEBUG, "sent %d netflow packets", r);
      /* XXX what if r < num_expired * 2 ? */
      if (r <= 0)
        ft->param.flows_dropped += num_expired * 2;
    }
    for (i = 0; i < num_expired; i++) {
      if (verbose_flag) {
        logit (LOG_DEBUG, "EXPIRED: %s (%p)", format_flow (expired_flows[i]),
               expired_flows[i]);
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

/**
 * @brief Force expiry of flows, e.g. when the flow table is overfull.
 *
 * @param ft            Flow tracking state.
 * @param num_to_expire Number of flows to expire.
 */
static void
force_expire (struct FLOWTRACK *ft, u_int32_t num_to_expire) {
  struct EXPIRY *expiry, **expiryv;
  u_int32_t i;

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
    logit (LOG_ERR,
           "Needed to expire %d flows, "
           "but only %d active",
           num_to_expire, i);
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

/**
 * @brief Delete all known flows without exporting them.
 *
 * @param ft Flow tracking state.
 * @return Number of flows deleted.
 */
static int
delete_all_flows (struct FLOWTRACK *ft) {
  struct FLOW *flow;
  struct EXPIRY *expiry, *nexpiry;
  int i;

  i = 0;
  /* Every flow has an expiry event, including flows evicted from the table */
  for (expiry = EXPIRY_MIN (EXPIRIES, &ft->expiries); expiry != NULL;
       expiry = nexpiry) {
    nexpiry = EXPIRY_NEXT (EXPIRIES, &ft->expiries, expiry);
    flow = expiry->flow;
    flow_table_remove (ft, flow);

    EXPIRY_REMOVE (EXPIRIES, &ft->expiries, expiry);
    expiry_put (ft, expiry);

    ft->param.num_flows--;
    flow_put (ft, flow);
    i++;
  }

  return (i);
}

/**
 * @brief Log the current status.
 *
 * Includes summary counters and, in verbose mode, the list of current flows and
 * the tree of expiry events.
 *
 * @param ft   Flow tracking state.
 * @param out  Output stream.
 * @param pcap Capture handle for libpcap counters; may be NULL when reading a
 * file.
 * @return 0 on success.
 */
static int
statistics (struct FLOWTRACK *ft, FILE *out, pcap_t *pcap) {
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
           " too short)\n",
           ft->param.non_ip_packets + ft->param.bad_packets,
           ft->param.non_ip_packets, ft->param.bad_packets);
  fprintf (out, "Flows expired: %" PRIu64 " (%" PRIu64 " forced)\n",
           ft->param.flows_expired, ft->param.flows_force_expired);
  fprintf (out,
           "Flows exported: %" PRIu64 " (%" PRIu64 " records) in %" PRIu64
           " packets (%" PRIu64 " failures)\n",
           ft->param.flows_exported, ft->param.records_sent,
           ft->param.packets_sent, ft->param.flows_dropped);

  if (ft->flow_lookup != FLOW_LOOKUP_TREE) {
    u_int32_t used, maxdepth;

    flow_table_usage (ft, &used, &maxdepth);
    char size[32];

    if (ft->flow_table_bytes < 1024)
      snprintf (size, sizeof (size), "%zu B", ft->flow_table_bytes);
    else
      snprintf (size, sizeof (size), "%zu KiB", ft->flow_table_bytes / 1024);
    fprintf (out,
             "Flow table: %s, %u buckets (%s), %u in use, "
             "max depth %u, %" PRIu64 " collisions\n",
             flow_lookup_name (ft->flow_lookup), ft->flow_nbuckets, size, used,
             maxdepth, ft->param.expired[R_COLLISION]);
  }

  if (pcap != NULL && pcap_stats (pcap, &ps) == 0) {
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
             ft->param.octets.min, ft->param.octets.mean, ft->param.octets.max);
    fprintf (out, "  Flow packets:      %12.0f  %12.0f  %12.0f\n",
             ft->param.packets.min, ft->param.packets.mean,
             ft->param.packets.max);
    fprintf (out, "  Duration:          %12.2fs %12.2fs %12.2fs\n",
             ft->param.duration.min, ft->param.duration.mean,
             ft->param.duration.max);

    fprintf (out, "\n");
    fprintf (out, "Expired flow reasons:\n");
    fprintf (out,
             "       tcp = %9" PRIu64 "   tcp.rst = %9" PRIu64 "   "
             "tcp.fin = %9" PRIu64 "\n",
             ft->param.expired[R_TCP], ft->param.expired[R_TCP_RST],
             ft->param.expired[R_TCP_FIN]);
    fprintf (out,
             "       udp = %9" PRIu64 "      icmp = %9" PRIu64 "   "
             "general = %9" PRIu64 "\n",
             ft->param.expired[R_UDP], ft->param.expired[R_ICMP],
             ft->param.expired[R_GENERAL]);
    fprintf (out, "   maxlife = %9" PRIu64 "\n", ft->param.expired[R_MAXLIFE]);
    fprintf (out, "over 2 GiB = %9" PRIu64 "\n", ft->param.expired[R_OVERBYTES]);
    fprintf (out, "  maxflows = %9" PRIu64 "\n", ft->param.expired[R_OVERFLOWS]);
    fprintf (out, "   flushed = %9" PRIu64 "\n", ft->param.expired[R_FLUSH]);
    if (ft->flow_lookup == FLOW_LOOKUP_HASH)
      fprintf (out, "collision = %9" PRIu64 "\n", ft->param.expired[R_COLLISION]);

    fprintf (out, "\n");

    fprintf (out, "Per-protocol statistics:     Octets      "
                  "Packets   Avg Life    Max Life\n");
    for (i = 0; i < 256; i++) {
      if (ft->param.packets_pp[i]) {
        pe = getprotobynumber (i);
        snprintf (proto, sizeof (proto), "%s (%d)",
                  pe != NULL ? pe->p_name : "Unknown", i);
        fprintf (out,
                 "  %17s: %14" PRIu64 " %12" PRIu64 "   %8.2fs "
                 "%10.2fs\n",
                 proto, ft->param.octets_pp[i], ft->param.packets_pp[i],
                 ft->param.duration_pp[i].mean, ft->param.duration_pp[i].max);
      }
    }
  }

  return (0);
}

/**
 * @brief Write every active flow and its expiry event to a stream.
 *
 * @param ft  Flow tracking state.
 * @param out Output stream.
 */
static void
dump_flows (struct FLOWTRACK *ft, FILE *out) {
  struct EXPIRY *expiry;
  time_t now;

  now = time (NULL);

  EXPIRY_FOREACH (expiry, EXPIRIES, &ft->expiries) {
    fprintf (out, "ACTIVE %s\n", format_flow (expiry->flow));
    if ((long int) expiry->expires_at - now < 0) {
      fprintf (out, "EXPIRY EVENT for flow %" PRIu64 " now%s\n",
               expiry->flow->flow_seq,
               expiry->expires_at == 0 ? " (FORCED)" : "");
    } else {
      fprintf (out, "EXPIRY EVENT for flow %" PRIu64 " in %lld seconds\n",
               expiry->flow->flow_seq, (long long) expiry->expires_at - now);
    }
    fprintf (out, "\n");
  }
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
static int
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

/**
 * @brief Per-packet callback function from libpcap.
 *
 * Passes the packet (if it is IP), sans datalink headers, to process_packet().
 *
 * @param user_data struct CB_CTXT for this capture.
 * @param phdr      libpcap packet header.
 * @param pkt       Captured packet.
 */
void
flow_cb (u_char *user_data, const struct pcap_pkthdr *phdr,
         const u_char *pkt) {
  int s, af = 0;
  struct CB_CTXT *cb_ctxt = (struct CB_CTXT *) user_data;
  u_int16_t vlanid = 0;
  u_int8_t num_label = 0;

  if (cb_ctxt->ft->param.total_packets == 0) {
    if (cb_ctxt->ft->param.adjust_time) {
      PCAP_TS_TO_TIMEVAL (cb_ctxt->ft->param.system_boot_time, phdr->ts);
    }
  }

  if (cb_ctxt->ft->param.option.sample &&
      (cb_ctxt->ft->param.total_packets +
       cb_ctxt->ft->param.non_sampled_packets) %
          cb_ctxt->ft->param.option.sample >
        0) {
    cb_ctxt->ft->param.non_sampled_packets++;
    return;
  }
  cb_ctxt->ft->param.total_packets++;
  if (cb_ctxt->ft->param.is_psamp) {
    struct timeval ts;
    PCAP_TS_TO_TIMEVAL (ts, phdr->ts);
    send_psamp (pkt, phdr->caplen, ts, cb_ctxt->target,
                cb_ctxt->ft->param.total_packets,
                cb_ctxt->ft->param.adjust_time);
    return;
  }

  s = datalink_check (cb_ctxt->linktype, pkt, phdr->caplen, &af, &vlanid,
                      &num_label);
  if (s < 0 || (!cb_ctxt->want_v6 && af == AF_INET6)) {
    cb_ctxt->ft->param.non_ip_packets++;
    cb_ctxt->ft->param.total_packets--;
  } else {
    if (process_packet (cb_ctxt, phdr, pkt, s, af, vlanid, num_label) ==
        PP_MALLOC_FAIL)
      cb_ctxt->fatal = 1;
  }
  if (cb_ctxt->ft->param.adjust_time)
    PCAP_TS_TO_TIMEVAL (cb_ctxt->ft->param.last_packet_time, phdr->ts);
}

#ifdef ENABLE_PTHREAD
/** Serialise main thread access to the flow tracking state with the packet
 * processing thread. */
#define FLOWTRACK_LOCK()                \
  do {                                  \
    if (use_thread)                     \
      pthread_mutex_lock (&read_mutex); \
  } while (0)
/** Counterpart of FLOWTRACK_LOCK(). */
#define FLOWTRACK_UNLOCK()                \
  do {                                    \
    if (use_thread)                       \
      pthread_mutex_unlock (&read_mutex); \
  } while (0)
#else /* ENABLE_PTHREAD */
#define FLOWTRACK_LOCK() \
  do {                   \
  } while (0)
#define FLOWTRACK_UNLOCK() \
  do {                     \
  } while (0)
#endif /* ENABLE_PTHREAD */

#ifdef ENABLE_PTHREAD
/**
 * @brief libpcap callback for threaded capture: copy the packet for
 * process_packet_loop() and wake it.
 *
 * Blocks while the previous packet is still being processed, so no packet is
 * overwritten. The copy is limited to the size of packet_data.
 *
 * @param user_data Unused.
 * @param phdr      libpcap packet header.
 * @param pkt       Captured packet.
 */
static void
pcap_memcpy (u_char *user_data, const struct pcap_pkthdr *phdr,
             const u_char *pkt) {
  struct pcap_pkthdr hdr = *phdr;

  (void) user_data;
  /* Never copy more than the buffer holds; flow_cb() trusts caplen. */
  if (hdr.caplen > sizeof (packet_data))
    hdr.caplen = sizeof (packet_data);
  pthread_mutex_lock (&read_mutex);
  /* One packet at a time: wait until the previous one has been processed. */
  while (packet_ready)
    pthread_cond_wait (&slot_cond, &read_mutex);
  memcpy (&packet_header, &hdr, sizeof (struct pcap_pkthdr));
  memcpy (&packet_data, pkt, hdr.caplen);
  packet_ready = 1;
  pthread_cond_signal (&read_cond);
  pthread_mutex_unlock (&read_mutex);
}

/**
 * @brief Thread entry point: process packets handed over by pcap_memcpy() until
 * reader_stop is set.
 *
 * @param arg struct CB_CTXT passed to flow_cb().
 * @return arg.
 */
static void *
process_packet_loop (void *arg) {
  pthread_mutex_lock (&read_mutex);
  for (;;) {
    while (!packet_ready && !reader_stop)
      pthread_cond_wait (&read_cond, &read_mutex);
    if (!packet_ready)
      break;
    flow_cb ((u_char *) arg, &packet_header, (u_char *) &packet_data);
    packet_ready = 0;
    pthread_cond_signal (&slot_cond);
  }
  pthread_mutex_unlock (&read_mutex);
  return (arg);
}

/**
 * @brief Block until the processing thread has finished the packet handed over
 * last.
 */
static void
wait_for_packet_loop_idle (void) {
  pthread_mutex_lock (&read_mutex);
  while (packet_ready)
    pthread_cond_wait (&slot_cond, &read_mutex);
  pthread_mutex_unlock (&read_mutex);
}
#endif /* ENABLE_PTHREAD */

/**
 * @brief Write the configured timeouts to a stream.
 *
 * @param ft  Flow tracking state.
 * @param out Output stream.
 */
static void
print_timeouts (struct FLOWTRACK *ft, FILE *out) {
  fprintf (out, "           TCP timeout: %ds\n", ft->param.tcp_timeout);
  fprintf (out, "  TCP post-RST timeout: %ds\n", ft->param.tcp_rst_timeout);
  fprintf (out, "  TCP post-FIN timeout: %ds\n", ft->param.tcp_fin_timeout);
  fprintf (out, "           UDP timeout: %ds\n", ft->param.udp_timeout);
  fprintf (out, "          ICMP timeout: %ds\n", ft->param.icmp_timeout);
  fprintf (out, "       General timeout: %ds\n", ft->param.general_timeout);
  fprintf (out, "      Maximum lifetime: %ds\n", ft->param.maximum_lifetime);
  fprintf (out, "       Expiry interval: %ds\n", ft->param.expiry_interval);
}

/**
 * @brief Accept one connection on the control socket and run its command.
 *
 * Commands: help, shutdown, exit, expire-all, send-template, delete-all,
 * statistics, debug+, debug-, stop-gather, start-gather, dump-flows and
 * timeouts.
 *
 * @param lsock                Listening control socket.
 * @param target               Export target (for "send-template").
 * @param ft                   Flow tracking state.
 * @param pcap                 Capture handle (for "statistics").
 * @param exit_request         Set to 1 by the "exit" command.
 * @param stop_collection_flag Set by "stop-gather" and "start-gather".
 * @return 0 if the command was handled, 1 if softflowd should stop ("shutdown"
 * and "exit"), -1 on error or for an unknown command.
 */
static int
accept_control (int lsock, struct NETFLOW_TARGET *target,
                struct FLOWTRACK *ft, pcap_t *pcap, int *exit_request,
                int *stop_collection_flag) {
  char buf[64], *p;
  FILE *ctlf;
  int fd, ret = 0, cmd;
  /* A command's position in control_words[] is its number in the switch */
  enum { CTL_HELP,
         CTL_SHUTDOWN,
         CTL_EXIT,
         CTL_EXPIRE_ALL,
         CTL_SEND_TEMPLATE,
         CTL_DELETE_ALL,
         CTL_STATISTICS,
         CTL_DEBUG_ON,
         CTL_DEBUG_OFF,
         CTL_STOP_GATHER,
         CTL_START_GATHER,
         CTL_DUMP_FLOWS,
         CTL_TIMEOUTS,
         CTL_UNKNOWN };
  static const char *const control_words[] = {
    "help", "shutdown", "exit", "expire-all", "send-template", "delete-all",
    "statistics", "debug+", "debug-", "stop-gather", "start-gather",
    "dump-flows", "timeouts"};

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

  for (cmd = 0; cmd < CTL_UNKNOWN && strcmp (buf, control_words[cmd]) != 0;
       cmd++)
    ;
  /* Every reply except help and the unknown command starts with the pid */
  if (cmd != CTL_HELP && cmd != CTL_UNKNOWN)
    fprintf (ctlf, "softflowd[%u]: ", (unsigned int) getpid());
  if (cmd == CTL_EXPIRE_ALL || cmd == CTL_SEND_TEMPLATE)
#if COMPAT_EXPORT == COMPAT_EXPORT_STATIC_SEPARATE
    netflow9_resend_template();
#else  /* COMPAT_EXPORT != COMPAT_EXPORT_STATIC_SEPARATE */
    ipfix_resend_template();
#endif /* COMPAT_EXPORT == COMPAT_EXPORT_STATIC_SEPARATE */
  switch (cmd) {
    case CTL_HELP:
      fprintf (ctlf, "Valid control words are:\n"
                     "\tdebug+ debug- delete-all dump-flows exit expire-all\n"
                     "\tshutdown start-gather statistics stop-gather timeouts\n"
                     "\tsend-template\n");
      break;
    case CTL_SHUTDOWN:
      fprintf (ctlf, "Shutting down gracefully...\n");
      graceful_shutdown_request = 1;
      ret = 1;
      break;
    case CTL_EXIT:
      fprintf (ctlf, "Exiting now...\n");
      *exit_request = 1;
      ret = 1;
      break;
    case CTL_EXPIRE_ALL:
      fprintf (ctlf, "Expired %d flows.\n",
               check_expired (ft, target, CE_EXPIRE_ALL));
      break;
    case CTL_SEND_TEMPLATE:
      fprintf (ctlf, "Template will be sent at next flow export\n");
      break;
    case CTL_DELETE_ALL:
      fprintf (ctlf, "Deleted %d flows.\n", delete_all_flows (ft));
      break;
    case CTL_STATISTICS:
      fprintf (ctlf, "Accumulated statistics since %s UTC:\n",
               format_time (ft->param.system_boot_time.tv_sec));
      statistics (ft, ctlf, pcap);
      break;
    case CTL_DEBUG_ON:
      fprintf (ctlf, "Debug level increased.\n");
      verbose_flag = 1;
      break;
    case CTL_DEBUG_OFF:
      fprintf (ctlf, "Debug level decreased.\n");
      verbose_flag = 0;
      break;
    case CTL_STOP_GATHER:
      fprintf (ctlf, "Data collection stopped.\n");
      *stop_collection_flag = 1;
      break;
    case CTL_START_GATHER:
      fprintf (ctlf, "Data collection resumed.\n");
      *stop_collection_flag = 0;
      break;
    case CTL_DUMP_FLOWS:
      fprintf (ctlf, "Dumping flow data:\n");
      dump_flows (ft, ctlf);
      break;
    case CTL_TIMEOUTS:
      fprintf (ctlf, "Printing timeouts:\n");
      print_timeouts (ft, ctlf);
      break;
    default:
      fprintf (ctlf, "Unknown control command \"%s\"\n", buf);
  }

  fclose (ctlf);
  close (fd);

  return (ret);
}

/**
 * @brief Create a UDP socket bound to a local port on all IPv4 addresses.
 *
 * @param portnumber Port to bind, in host order.
 * @return The socket, or a negative value on error.
 */
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
    fprintf (stderr, "bind to UDP port %u failed: %s\n", (unsigned) portnumber,
             strerror (errno));
    close (rsock);
    return -1;
  }
  return rsock;
}

#ifdef LINUX
/**
 * @brief Bind a socket to a network interface (SO_BINDTODEVICE, Linux only).
 *
 * @param sock   Socket to bind.
 * @param ifname Interface name.
 */
static void
bind_device (int sock, char *ifname) {
  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
  if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) <
      0) {
    perror ("SO_BINDTODEVICE failed");
  }
}
#endif /* LINUX */

/**
 * @brief Create a socket connected to an export destination.
 *
 * @param addr         Destination address.
 * @param len          Length of addr.
 * @param hoplimit     Multicast TTL / hop limit, or -1 for the default (1 for
 * multicast addresses).
 * @param protocol     IPPROTO_UDP or another IP protocol for a stream socket.
 * @param exporterAddr Optional local exporter addresses to bind to (-e); may be
 * NULL.
 * @return The connected socket. Exits the process on error.
 */
static int
connsock (struct sockaddr_storage *addr, socklen_t len, int hoplimit,
          int protocol, struct addrinfo *exporterAddr) {
  int s;
  unsigned int h6;
  unsigned char h4;
  struct sockaddr_in *in4 = (struct sockaddr_in *) addr;
  struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) addr;
  struct addrinfo *rp = NULL;

  if ((s = socket (addr->ss_family,
                   protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
                   protocol)) == -1) {
    fprintf (stderr, "socket() error: %s\n", strerror (errno));
    exit (1);
  }
  if (exporterAddr != NULL) {
    for (rp = exporterAddr; rp != NULL; rp = rp->ai_next) {
      if (bind (s, rp->ai_addr, rp->ai_addrlen) == 0) {
        break;
      }
    }
    exporterAddr = rp;
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
        fprintf (stderr,
                 "setsockopt(IP_MULTICAST_TTL, "
                 "%u): %s\n",
                 h4, strerror (errno));
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
      if (setsockopt (s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &h6, sizeof (h6)) ==
          -1) {
        fprintf (stderr,
                 "setsockopt(IPV6_MULTICAST_HOPS, %u): "
                 "%s\n",
                 h6, strerror (errno));
        exit (1);
      }
  }

  return (s);
}

/**
 * @brief Create the listening UNIX-domain socket for the control interface.
 *
 * @param path Socket path; an existing file at that path is removed first.
 * @return The listening socket. Exits the process on error.
 */
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
    fprintf (stderr, "unix domain bind(\"%s\") error: %s\n", addr.sun_path,
             strerror (errno));
    exit (1);
  }
  if (listen (s, 64) == -1) {
    fprintf (stderr, "unix domain listen() error: %s\n", strerror (errno));
    exit (1);
  }

  return (s);
}

/**
 * @brief Open a live capture or a capture file and set up filtering.
 *
 * Exits the process on error.
 *
 * @param pcap                 Receives the libpcap handle.
 * @param linktype             Receives the data link type.
 * @param dev                  Interface to capture on, or NULL.
 * @param capfile              Capture file to read when dev is NULL.
 * @param bpf_prog             BPF filter expression, or NULL.
 * @param need_v6              Non-zero if IPv6 is needed, which selects the
 * larger default snap length.
 * @param promisc              Non-zero for promiscuous mode.
 * @param buffer_size_override Capture buffer size in bytes, or 0 for the
 * default.
 */
static void
setup_packet_capture (struct pcap **pcap, int *linktype, char *dev,
                      char *capfile, char *bpf_prog, int need_v6,
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
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
    /*
     * Deliver packets to the read loop as soon as they arrive instead of
     * batching them. On Linux (libpcap >= 1.5) capture uses a memory-mapped
     * PACKET_RX_RING; combined with the 0 read timeout set above, a ring block
     * is only handed to userspace once it fills, so poll() on the pcap fd never
     * signals POLLIN on low-rate interfaces and the pcap_dispatch() callback
     * never runs -- "Packets processed" stays 0 while pcap_stats() still counts
     * the frames as received. Immediate mode disables that batching so poll()
     * wakes per packet. (Related: low-traffic interfaces exporting only in long
     * intervals, issue #48.)
     */
    if ((res = pcap_set_immediate_mode (*pcap, 1)) != 0) {
      fprintf (stderr, "pcap_set_immediate_mode: %s\n", pcap_geterr (*pcap));
      exit (1);
    }
#endif /* HAVE_PCAP_SET_IMMEDIATE_MODE */
    if (buffer_size_override > 0)
      if ((res = pcap_set_buffer_size (*pcap, buffer_size_override)) != 0) {
        fprintf (stderr, "pcap_set_buffer_size: %s\n", pcap_geterr (*pcap));
        exit (1);
      }
    if (pcap_lookupnet (dev, &bpf_net, &bpf_mask, ebuf) == -1)
      bpf_net = bpf_mask = 0;
    if ((res = pcap_activate (*pcap)) < 0) {
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
  if (datalink_check (*linktype, NULL, 0, NULL, NULL, NULL) == -1) {
    fprintf (stderr, "Unsupported datalink type %d\n", *linktype);
    exit (1);
  }
  /* Attach BPF filter, if specified */
  if (bpf_prog != NULL) {
    if (pcap_compile (*pcap, &prog_c, bpf_prog, 1, bpf_mask) == -1) {
      fprintf (stderr, "pcap_compile(\"%s\"): %s\n", bpf_prog,
               pcap_geterr (*pcap));
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

/**
 * @brief Initialise the flow tracking state with the default limits and
 * timeouts.
 *
 * @param ft Flow tracking state.
 */
static void
init_flowtrack (struct FLOWTRACK *ft) {
  /* Set up flow-tracking structure */
  memset (ft, '\0', sizeof (*ft));
  ft->param.next_flow_seq = 1;
  ft->flow_lookup = FLOW_LOOKUP_HASH_TREE; /* default; -F selects another */
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

/**
 * @brief Join command line arguments into one space-separated string.
 *
 * @param argc Number of arguments.
 * @param argv Arguments to join.
 * @return Newly allocated string (used for the BPF filter). Exits on
 * out-of-memory.
 */
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
      ret_len++; /* Make room for ' ' */
      strlcat (ret, " ", ret_len + 1);
    }

    strlcat (ret, argv[i], ret_len + 1);
  }

  return (ret);
}

/**
 * @brief Display commandline usage information.
 */
static void
usage (void) {
  fprintf (
    stderr,
    "Usage: %s [options] [bpf_program]\n"
    "This is %s version %s. Valid commandline options:\n"
    "  -i, --interface [idx:]interface\n"
    "                          Specify interface to listen on\n"
    "  -r, --read pcap_file    Specify packet capture file to read\n"
    "  -t, --timeout timeout=time\n"
    "                          Specify named timeout\n"
    "  -m, --max-flows max_flows\n"
    "                          Specify maximum number of flows to track (1 "
    "or more, default %d)\n"
    "  -n, --netflow-dest host:port\n"
    "                          Send Cisco NetFlow(tm)-compatible packets to "
    "host:port\n"
    "  -p, --pidfile pidfile   Record pid in specified file\n"
    "                          (default: %s)\n"
    "  -c, --control-socket socketfile\n"
    "                          Location of control socket\n"
    "                          (default: %s)\n"
    "  -v, --netflow-version 1|5|9|10|psamp\n"
    "                          NetFlow export packet version\n"
    "                          10 means IPFIX and psamp means PSAMP (packet "
    "sampling)\n"
#ifdef ENABLE_NTOPNG
    "     ntopng               ntopng means direct injection to NTOPNG (if "
    "supported, ntopng 6.0 or later).\n"
#ifdef ENABLE_NTOPNG_JSON
    "     ntopng-json          ntopng-json means direct injection to NTOPNG "
    "5.x or earlier\n"
    "                          using JSON\n"
#endif
#endif
    "  -L, --hoplimit hoplimit Set TTL/hoplimit for export datagrams\n"
    "  -T, --track full|port|proto|ip|\n"
    "                          Set flow tracking level (default: full)\n"
    "                          vlan                 (\"vlan\" tracking means "
    "\"full\" tracking with vlanid)\n"
    "                          ether                (\"ether\" tracking "
    "means \"vlan\" tracking with ether header)\n"
    "  -H, --direction-mac MAC Specify MAC Address to determine direction "
    "(requires -T ether)\n"
    "  -6, --track-ipv6        Track IPv6 flows, regardless of whether "
    "selected \n"
    "                          NetFlow export protocol supports it\n"
    "  -d, --foreground        Don't daemonise (run in foreground)\n"
    "  -D, --debug             Debug mode: foreground + verbosity + track v6 "
    "flows\n"
    "  -P, --export-protocol udp|tcp|sctp\n"
    "                          Specify transport layer protocol for "
    "exporting packets\n"
    "  -A, --absolute-time sec|milli|micro|nano\n"
    "                          Specify absolute time format form exporting "
    "records\n"
    "  -s, --sampling-rate rate\n"
    "                          Specify periodical sampling rate "
    "(denominator)\n"
    "  -B, --pcap-buffer-size bytes\n"
    "                          Libpcap buffer size in bytes\n"
    "  -b, --bidirectional     Bidirectional mode in IPFIX (-b work with -v "
    "10)\n"
    "  -a, --adjust-time       Adjusting time for reading pcap file (-a work "
    "with -r)\n"
    "  -C, --snaplen capture_length\n"
    "                          Specify length for packet capture (snaplen)\n"
    "  -l, --load-balance      Load balancing mode for multiple "
    "destinations\n"
    "  -R, --psamp-port receive_port\n"
    "                          Specify port number for PSAMP receive mode\n"
#ifdef ENABLE_PTHREAD
    "  -M, --multithread       Enable multithread\n"
#endif /* ENABLE_PTHREAD */
    "  -N, --no-promisc        Disable promiscuous mode\n"
#ifdef LINUX
    "  -S, --send-interface send_interface_name\n"
    "                          Specify send interface name\n"
#endif /* LINUX */
    "  -x, --mpls-labels labels\n"
    "                          Specify number of MPLS labels (1 to 10)\n"
    "  -I, --reinit-interval seconds\n"
    "                          Specify seconds for reinitialize boot time\n"
    "  -g, --gauge-cpu-clock   Gauge cpu clock (total and export) for "
    "benchmark\n"
    "  -e, --exporter-ip address\n"
    "                          Specify Exporter IP (IPv4 or IPv6) address\n"
    "  -f, --full-transport-header-check\n"
    "                          Require the whole TCP/UDP/ICMP header instead "
    "of\n"
    "                          only the fields used (ports, TCP flags, ICMP "
    "type/code)\n"
    "  -F, --flow-lookup mode  Flow table lookup: tree, hash-tree (default) "
    "or hash\n"
    "                          (hash: a colliding flow expires the resident "
    "one)\n"
    "  -h, --help              Display this help\n"
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
    DEFAULT_CTLSOCK, DEFAULT_TCP_TIMEOUT, DEFAULT_TCP_RST_TIMEOUT,
    DEFAULT_TCP_FIN_TIMEOUT, DEFAULT_UDP_TIMEOUT, DEFAULT_ICMP_TIMEOUT,
    DEFAULT_GENERAL_TIMEOUT, DEFAULT_MAXIMUM_LIFETIME,
    DEFAULT_EXPIRY_INTERVAL);
}

/* Empty fallback where common.h does not define __dead (non-GNU C, non-BSD). */
#ifndef __dead
#define __dead
#endif
/**
 * @brief Print an error message and the usage text to stderr, then exit(1).
 *
 * @param fmt printf-style error message, written to stderr before the usage.
 */
static __dead void
die_usage (const char *fmt, ...) {
  va_list ap;

  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  usage();
  exit (1);
}

/**
 * @brief Parse a "-t name=time" argument and set that timeout.
 *
 * Exits with a usage message on a malformed argument.
 *
 * @param ft      Flow tracking state.
 * @param to_spec Argument of the form name=time; name is tcp, tcp.rst, tcp.fin,
 * udp, icmp, general, maxlife or expint.
 */
static void
set_timeout (struct FLOWTRACK *ft, const char *to_spec) {
  char *name, *value;
  long secs;
  int timeout;

  if ((name = strdup (to_spec)) == NULL) {
    fprintf (stderr, "Out of memory\n");
    exit (1);
  }
  if ((value = strchr (name, '=')) == NULL || *(++value) == '\0') {
    die_usage ("Invalid -t option \"%s\".\n", name);
  }
  *(value - 1) = '\0';
  secs = convtime (value);
  /* The timeouts are kept in an int; a longer one must not be truncated. */
  if (secs < 0 || secs > INT_MAX) {
    die_usage ("Invalid -t timeout.\n");
  }
  timeout = (int) secs;
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
    die_usage ("Invalid -t name.\n");
  }

  if (ft->param.general_timeout == 0) {
    fprintf (stderr, "\"general\" flow timeout must be "
                     "greater than zero\n");
    exit (1);
  }

  free (name);
}

/**
 * @brief Resolve one "host:port" (or "[v6addr]:port") argument.
 *
 * Exits with a message on error.
 *
 * @param s    Argument to parse.
 * @param addr Receives the resolved address.
 * @param len  On entry the size of addr, on return the address length.
 */
static void
parse_hostport (const char *s, struct sockaddr *addr,
                socklen_t *len) {
  char *orig, *host, *port;
  struct addrinfo hints, *res;
  int herr;

  if ((host = orig = strdup (s)) == NULL) {
    fprintf (stderr, "Out of memory\n");
    exit (1);
  }
  if ((port = strrchr (host, ':')) == NULL || *(++port) == '\0' ||
      *host == '\0') {
    die_usage ("Invalid -n argument.\n");
  }
  *(port - 1) = '\0';
  /* getaddrinfo () cuts a numeric port to 16 bits: refuse one that is too big */
  if (*port >= '0' && *port <= '9') {
    char *end;
    unsigned long portnum;
    errno = 0;
    portnum = strtoul (port, &end, 10);
    if (*end == '\0' && (errno == ERANGE || portnum > 65535)) {
      die_usage ("Invalid -n argument.\n");
    }
  }

  /* Accept [host]:port for numeric IPv6 addresses */
  if (*host == '[' && *(port - 2) == ']') {
    host++;
    *(port - 2) = '\0';
  }

  memset (&hints, '\0', sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  /* getaddrinfo () returns a non-zero EAI_* code on failure, not -1 only */
  if ((herr = getaddrinfo (host, port, &hints, &res)) != 0 || res == NULL ||
      res->ai_addr == NULL) {
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

/**
 * @brief Resolve a comma-separated list of host:port destinations.
 *
 * @param s        Comma-separated list.
 * @param dest     Destination array to fill.
 * @param max_dest Size of dest.
 * @return Number of destinations parsed.
 */
static int
parse_hostports (const char *s, struct DESTINATION *dest,
                 int max_dest) {
  int i = 0;
  char *hostport;
  for (hostport = strsep ((char **) &s, ","); hostport != NULL && i < max_dest;
       hostport = strsep ((char **) &s, ",")) {
    dest[i].sslen = sizeof (dest[i].ss);
    parse_hostport (hostport, (struct sockaddr *) &dest[i].ss, &dest[i].sslen);
    i++;
  }
  return i;
}

/**
 * @brief Drop privileges and chroot; exits on failure.
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
    logit (LOG_ERR, "Couldn't setgroups (%u): %s", (unsigned int) pw->pw_gid,
           strerror (errno));
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
    logit (LOG_ERR, "Couldn't set gid (%u): %s", (unsigned int) pw->pw_gid,
           strerror (errno));
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
    logit (LOG_ERR, "Couldn't set uid (%u): %s", (unsigned int) pw->pw_uid,
           strerror (errno));
    exit (1);
  }
}

/**
 * @brief Parse a MAC address string into a 6-octet array.
 *
 * @param str Address as aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff.
 * @param mac Receives the address.
 * @return 0 on success, -1 on error.
 */
static int
parse_mac_address (const char *str, u_int8_t mac[6]) {
  unsigned int b[6];
  int i;

  if (sscanf (str, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3], &b[4],
              &b[5]) != 6 &&
      sscanf (str, "%2x-%2x-%2x-%2x-%2x-%2x", &b[0], &b[1], &b[2], &b[3], &b[4],
              &b[5]) != 6)
    return (-1);

  for (i = 0; i < 6; i++) {
    if (b[i] > 0xff)
      return (-1);
    mac[i] = (u_int8_t) b[i];
  }
  return (0);
}

#ifdef ENABLE_NTOPNG
/**
 * @brief Create the ZeroMQ sockets of the -n destinations of -v ntopng.
 *
 * ZeroMQ starts its I/O threads in the process that makes the socket, and a
 * fork () does not carry them to the child: the sockets are made after
 * daemon (), and before drop_privs ().  Exits on failure.
 *
 * @param target Export target; the destinations are numeric (getnameinfo ()).
 */
static void
connect_ntopng_destinations (struct NETFLOW_TARGET *target) {
  int dest_idx, rc;
  struct DESTINATION *dest;

  if (target->dialect->version != SOFTFLOWD_NF_VERSION_NTOPNG
#ifdef ENABLE_NTOPNG_JSON
      && target->dialect->version != SOFTFLOWD_NF_VERSION_NTOPNG_JSON
#endif
  )
    return;
  for (dest_idx = 0; dest_idx < target->num_destinations; dest_idx++) {
    dest = &target->destinations[dest_idx];
    if (dest->ss.ss_family == 0)
      continue;
    if ((rc = connect_ntopng (dest->hostname, dest->servname, &dest->zmq)) !=
        0) {
      logit (LOG_ERR, "Could not create ZeroMQ socket for %s:%s: (%d) %s",
             dest->hostname, dest->servname, rc, strerror (rc));
      exit (1);
    }
  }
}
#endif /* ENABLE_NTOPNG */

/**
 * @brief softflowd entry point: parse options, set up capture and export, and
 * run the main loop.
 *
 * @param argc Argument count.
 * @param argv Arguments.
 * @return 0 on success, 1 if the main loop ended with an error.
 */
int
main (int argc, char **argv) {
  clock_t boottime = clock();
  char *dev, *capfile, *bpf_prog;
  const char *pidfile_path, *ctlsock_path;
  extern char *optarg;
  extern int optind;
  int ch, dontfork_flag, linktype = 0, ctlsock, err, always_v6, r, dest_idx;
  static const struct option long_options[] = {
    {"track-ipv6", no_argument, NULL, '6'},
    {"adjust-time", no_argument, NULL, 'a'},
    {"absolute-time", required_argument, NULL, 'A'},
    {"bidirectional", no_argument, NULL, 'b'},
    {"pcap-buffer-size", required_argument, NULL, 'B'},
    {"control-socket", required_argument, NULL, 'c'},
    {"snaplen", required_argument, NULL, 'C'},
    {"foreground", no_argument, NULL, 'd'},
    {"debug", no_argument, NULL, 'D'},
    {"exporter-ip", required_argument, NULL, 'e'},
    {"full-transport-header-check", no_argument, NULL, 'f'},
    {"flow-lookup", required_argument, NULL, 'F'},
    {"gauge-cpu-clock", no_argument, NULL, 'g'},
    {"help", no_argument, NULL, 'h'},
    {"direction-mac", required_argument, NULL, 'H'},
    {"interface", required_argument, NULL, 'i'},
    {"reinit-interval", required_argument, NULL, 'I'},
    {"load-balance", no_argument, NULL, 'l'},
    {"hoplimit", required_argument, NULL, 'L'},
    {"max-flows", required_argument, NULL, 'm'},
#ifdef ENABLE_PTHREAD
    {"multithread", no_argument, NULL, 'M'},
#endif /* ENABLE_PTHREAD */
    {"netflow-dest", required_argument, NULL, 'n'},
    {"no-promisc", no_argument, NULL, 'N'},
    {"pidfile", required_argument, NULL, 'p'},
    {"export-protocol", required_argument, NULL, 'P'},
    {"read", required_argument, NULL, 'r'},
    {"psamp-port", required_argument, NULL, 'R'},
    {"sampling-rate", required_argument, NULL, 's'},
#ifdef LINUX
    {"send-interface", required_argument, NULL, 'S'},
#endif /* LINUX */
    {"timeout", required_argument, NULL, 't'},
    {"track", required_argument, NULL, 'T'},
    {"netflow-version", required_argument, NULL, 'v'},
    {"mpls-labels", required_argument, NULL, 'x'},
    {NULL, 0, NULL, 0}};
  int stop_collection_flag, exit_request, hoplimit;
  pcap_t *pcap = NULL;
  struct FLOWTRACK flowtrack;
  struct NETFLOW_TARGET target;
  struct CB_CTXT cb_ctxt;
  struct pollfd pl[2];
  int pcapfd = -1;
  struct DESTINATION *dest;
  int pcap_override_buffer_size = 0;
  int protocol = IPPROTO_UDP;
  int version = 0;
  int rsock = 0, recvport = IPFIX_PORT, timeout_ms = 0;
  u_int recvloop = 0;
  int user_ifindex_flag = 0;
#ifdef LINUX
  struct ifreq ifr;
  char *send_ifname = NULL;
#endif /* LINUX */
#ifdef ENABLE_PTHREAD
  use_thread = 0;
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

  while (
    (ch = getopt_long (argc, argv,
                       "6aA:bB:c:C:dDe:fF:ghH:i:I:lL:m:Mn:Np:P:r:R:s:S:t:T:v:x:",
                       long_options, NULL)) != -1) {
    switch (ch) {
      case '6':
        always_v6 = 1;
        break;
      case 'a':
        flowtrack.param.adjust_time = 1;
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
          die_usage ("Unknown time format\n");
        }
        break;
      case 'b':
        flowtrack.param.bidirection = 1;
        break;
      case 'B':
        pcap_override_buffer_size = atoi (optarg);
        break;
      case 'c':
        if (strcmp (optarg, "none") == 0)
          ctlsock_path = NULL;
        else
          ctlsock_path = optarg;
        break;
      case 'C': /* Capture Length */
        snaplen = atoi (optarg);
        break;
      case 'd':
        dontfork_flag = 1;
        break;
      case 'D':
        verbose_flag = 1;
        always_v6 = 1;
        dontfork_flag = 1;
        break;
      case 'e':
        if (optarg != NULL) {
          struct addrinfo hints;
          int gai_err;
          memset (&hints, '\0', sizeof (hints));
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
          hints.ai_flags = 0;
          hints.ai_protocol = protocol;
          /* getaddrinfo() does not set errno; report its own error code. */
          if ((gai_err = getaddrinfo (optarg, NULL, &hints,
                                      &flowtrack.param.option.exporterAddr)) !=
              0) {
            fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (gai_err));
            break;
          }
        }
        break;
      case 'f':
        flowtrack.param.full_l4hdr_check = 1;
        break;
      case 'F':
        if (strcmp (optarg, "tree") == 0)
          flowtrack.flow_lookup = FLOW_LOOKUP_TREE;
        else if (strcmp (optarg, "hash-tree") == 0)
          flowtrack.flow_lookup = FLOW_LOOKUP_HASH_TREE;
        else if (strcmp (optarg, "hash") == 0)
          flowtrack.flow_lookup = FLOW_LOOKUP_HASH;
        else {
          die_usage ("Invalid flow lookup mode\n\n");
        }
        break;
      case 'g':
        gauge_clock = 1;
        break;
      case 'h':
        usage();
        return (0);
      case 'H':
        if (optarg != NULL) {
          if (parse_mac_address (optarg, flowtrack.param.direction_mac) != 0) {
            fprintf (stderr, "Invalid MAC address %s\n", optarg);
            exit (1);
          }
          flowtrack.param.direction_mac_set = 1;
        }
        break;
      case 'i':
        if (capfile != NULL || dev != NULL) {
          die_usage ("Packet source already specified.\n\n");
        }
#if defined(HAVE_STRSEP)
        dev = strsep (&optarg, ":");
#else  /* defined(HAVE_STRSEP) */
        dev = strtok (optarg, ":");
#endif /* defined(HAVE_STRSEP) */
        if (optarg != NULL) {
          if (strlen (dev) > 0) {
            if_index = (u_int16_t) atoi (dev);
          }
          dev = optarg;
          user_ifindex_flag = 1;
        }
        if (strlen (dev) == 0) {
          die_usage ("Wrong interface is specified.\n\n");
        }
        if (verbose_flag)
          fprintf (stderr, "Using %s (idx: %d)\n", dev, if_index);
        strlcpy (flowtrack.param.option.interfaceName, dev,
                 sizeof (flowtrack.param.option.interfaceName));
        break;
      case 'I':
        errno = 0; /* strtol() sets errno on error only */
        boot_time_reinit_sec = strtol (optarg, &timeunit, 10);
        if ((errno == ERANGE && (boot_time_reinit_sec == LONG_MAX ||
                                 boot_time_reinit_sec == LONG_MIN)) ||
            (errno != 0 && boot_time_reinit_sec == 0)) {
          perror ("strtol");
          usage();
          exit (EXIT_FAILURE);
        }
        if (timeunit == optarg) {
          die_usage ("No digits were found in boot_time_reinit\n");
        }
        if (*timeunit == 'd' || *timeunit == 'D') { /* days */
          if (boot_time_reinit_sec > BOOTTIME_MAX_DAY) {
            boot_time_reinit_sec = BOOTTIME_MAX_DAY;
          }
          boot_time_reinit_sec *= (24 * 60 * 60);          /* convert to seconds */
        } else if (*timeunit == 'h' || *timeunit == 'H') { /* hours */
          if (boot_time_reinit_sec > BOOTTIME_MAX_HOUR) {
            boot_time_reinit_sec = BOOTTIME_MAX_HOUR;
          }
          boot_time_reinit_sec *= (60 * 60);               /* convert to seconds */
        } else if (*timeunit == 'm' || *timeunit == 'M') { /* minutes */
          if (boot_time_reinit_sec > BOOTTIME_MAX_MIN) {
            boot_time_reinit_sec = BOOTTIME_MAX_MIN;
          }
          boot_time_reinit_sec *= 60; /* convert to seconds */
        } else {
          if (boot_time_reinit_sec > BOOTTIME_MAX_SEC) { /* seconds */
            boot_time_reinit_sec = BOOTTIME_MAX_SEC;
          }
        }
        if (verbose_flag) {
          fprintf (stderr, "boot_time_reinit is %ld seconds.\n",
                   boot_time_reinit_sec);
        }
        break;
      case 'l':  // load balancing
        target.is_loadbalance = 1;
        break;
      case 'L':
        hoplimit = atoi (optarg);
        if (hoplimit < 0 || hoplimit > 255) {
          die_usage ("Invalid hop limit\n\n");
        }
        break;
      case 'm': {
        /* Range check on an int: max_flows is unsigned and would wrap. */
        int max_flows = atoi (optarg);
        if (max_flows < 1) {
          die_usage ("Invalid maximum flows\n\n");
        }
        flowtrack.param.max_flows = max_flows;
      } break;
      case 'M':
#ifdef ENABLE_PTHREAD
        use_thread = 1;
#endif /* ENABLE_PTHREAD */
        break;
      case 'n':
        /* Will exit on failure */
        target.num_destinations = parse_hostports (optarg, target.destinations,
                                                   SOFTFLOWD_MAX_DESTINATIONS);
        break;
      case 'N':
        use_promisc = 0;
        break;
      case 'p':
        pidfile_path = optarg;
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
          die_usage ("Unknown transport layer protocol\n");
        }
        break;
      case 'r':
        if (capfile != NULL || dev != NULL) {
          die_usage ("Packet source already specified.\n\n");
        }
        capfile = optarg;
        dontfork_flag = 1;
        ctlsock_path = NULL;
        strlcpy (flowtrack.param.option.interfaceName, capfile,
                 sizeof (flowtrack.param.option.interfaceName));
        break;
      case 'R':
        recvport = atoi (optarg);
        if (recvport < 0 || recvport > 65535) {
          /* Say so with the usage, and go on with the default port */
          fprintf (stderr, "Invalid -R port, using the default %d.\n",
                   IPFIX_PORT);
          usage();
          recvport = IPFIX_PORT;
        }
        rsock = recvsock ((uint16_t) recvport);
        if (rsock < 0)
          exit (1);
        break;
      case 's':
        flowtrack.param.option.sample = atoi (optarg);
        if (flowtrack.param.option.sample < 2) {
          flowtrack.param.option.sample = 0;
        }
        break;
#ifdef LINUX
      case 'S':
        send_ifname = optarg;
        break;
#endif /* LINUX */
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
          die_usage ("Unknown flow tracking level\n");
        }
        track_level = flowtrack.param.track_level;
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
#ifdef ENABLE_NTOPNG_JSON
        if (!strncmp (optarg, SOFTFLOWD_NF_VERSION_NTOPNG_JSON_STRING,
                      sizeof (SOFTFLOWD_NF_VERSION_NTOPNG_JSON_STRING))) {
          version = SOFTFLOWD_NF_VERSION_NTOPNG_JSON;
        }
#endif /* ENABLE_NTOPNG_JSON */
#endif /* ENABLE_NTOPNG */
        version = version ? version : atoi (optarg);
        target.dialect = lookup_netflow_sender (version);
        if (target.dialect == NULL) {
          fprintf (stderr, "Invalid NetFlow version\n");
          exit (1);
        }
        break;
      case 'x': {
        /* Range check on an int: max_num_label is u_int8_t and would wrap. */
        int num_label = atoi (optarg);
        if (num_label < 1 || num_label > 10) {
          die_usage ("Invalid number of MPLS label (1 to 10)\n\n");
        }
        flowtrack.param.max_num_label = num_label;
      } break;
      default:
        die_usage ("Invalid commandline option.\n");
    }
  }

  if (capfile == NULL && dev == NULL && rsock <= 0) {
    die_usage ("-i, -r or -R option not specified.\n");
  }

  /* max_flows is final now, so the flow table can be sized */
  if (flow_table_init (&flowtrack) < 0) {
    fprintf (stderr, "Unable to allocate the flow table\n");
    exit (1);
  }
  if (verbose_flag)
    flow_table_report (&flowtrack);

  /* join remaining arguments (if any) into bpf program */
  bpf_prog = argv_join (argc - optind, argv + optind);

  /* Will exit on failure */
  if (capfile != NULL || dev != NULL)
    setup_packet_capture (&pcap, &linktype, dev, capfile, bpf_prog,
                          target.dialect->v6_capable || always_v6, use_promisc,
                          pcap_override_buffer_size);
  else if (rsock > 0)
    linktype = 1;  // LINKTYPE_ETHERNET

  /*
   * If ethernet-level tracking is enabled and the user has not
   * explicitly specified a direction MAC address with -H, try to
   * auto-detect it from the capture interface.
   */
  if (flowtrack.param.track_level >= TRACK_FULL_VLAN_ETHER &&
      flowtrack.param.direction_mac_set == 0 && dev != NULL) {
    if (get_interface_mac (dev, flowtrack.param.direction_mac) == 0) {
      flowtrack.param.direction_mac_set = 1;
      if (verbose_flag)
        fprintf (
          stderr,
          "Auto-detected direction MAC %02x:%02x:%02x:%02x:%02x:%02x "
          "from interface %s\n",
          flowtrack.param.direction_mac[0], flowtrack.param.direction_mac[1],
          flowtrack.param.direction_mac[2], flowtrack.param.direction_mac[3],
          flowtrack.param.direction_mac[4], flowtrack.param.direction_mac[5],
          dev);
    } else if (verbose_flag) {
      fprintf (stderr,
               "Could not auto-detect MAC address of %s; "
               "flowDirection will use canonical ordering\n",
               dev);
    }
  }

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
      if (target.dialect->version == SOFTFLOWD_NF_VERSION_NTOPNG
#ifdef ENABLE_NTOPNG_JSON
          || target.dialect->version == SOFTFLOWD_NF_VERSION_NTOPNG_JSON
#endif
      ) {
        /* The ZeroMQ socket is made after the fork: connect_ntopng_destinations () */
      } else
#endif
        dest->sock = connsock (&dest->ss, dest->sslen, hoplimit, protocol,
                               flowtrack.param.option.exporterAddr);
#ifdef LINUX
      if (dest->sock > 0 && send_ifname != NULL) {
        bind_device (dest->sock, send_ifname);
      }
      if (dev != NULL && user_ifindex_flag == 0) {
        strncpy (ifr.ifr_name, dev, IFNAMSIZ - 1);
        if (ioctl (pcap_get_selectable_fd (pcap), SIOCGIFINDEX, &ifr) < 0) {
          perror ("ioctl SIOCGIFINDEX");
        }
        if_index = ifr.ifr_ifindex;
        if (verbose_flag)
          fprintf (stderr, "Using %s (idx: %d as result of SIOCGIFINDEX)\n", dev,
                   if_index);
      }
#endif /* LINUX */
    }
  }

  /* Control socket */
  if (ctlsock_path != NULL)
    ctlsock = unix_listener (ctlsock_path); /* Will exit on fail */

  if (dontfork_flag) {
    loginit (PROGNAME, 1);
#ifdef ENABLE_NTOPNG
    connect_ntopng_destinations (&target);
#endif
  } else {
    FILE *pidfile;

    r = daemon (0, 0);
    loginit (PROGNAME, 0);
    /* clock () counts the cpu time of this process, which starts at 0 in the
     * child of the fork of daemon (): measure from here for -g. */
    boottime = clock();

    if ((pidfile = fopen (pidfile_path, "r")) != NULL) {
      int pid;
      if (fscanf (pidfile, "%u", &pid) == EOF) {
        // fscanf error
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
      fprintf (stderr, "Couldn't open pidfile %s: %s\n", pidfile_path,
               strerror (errno));
      exit (1);
    }
    fprintf (pidfile, "%u\n", (unsigned int) getpid());
    fclose (pidfile);

    signal (SIGSEGV, sighand_other);

#ifdef ENABLE_NTOPNG
    connect_ntopng_destinations (&target);
#endif
    setprotoent (1);
    drop_privs();
  }

  /* For both the daemon and the foreground process, as the C++ version does:
   * the default action of these signals would be to terminate at once, without
   * the expiry of the flows and the removal of the control socket. SIGUSR1 and
   * SIGHUP are logged by the main loop. */
  signal (SIGINT, sighand_graceful_shutdown);
  signal (SIGTERM, sighand_graceful_shutdown);
  signal (SIGUSR1, sighand_log_stats);
  signal (SIGHUP, sighand_hup);

  logit (LOG_NOTICE, "%s v%s starting data collection", PROGNAME, PROGVER);
  for (dest_idx = 0; dest_idx < target.num_destinations; dest_idx++) {
    dest = &target.destinations[dest_idx];
    if (dest->ss.ss_family != 0) {
      /* interfaceName holds IFNAMSIZ - 1 characters only: not for a file name */
      logit (LOG_NOTICE, "Exporting flows from %s to [%s]:%s",
             capfile != NULL ? capfile : flowtrack.param.option.interfaceName,
             dest->hostname, dest->servname);
    }
  }
  flowtrack.param.option.meteringProcessId = getpid();
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
    if (pthread_create (&read_thread, NULL, process_packet_loop,
                        (void *) &cb_ctxt) < 0) {
      perror ("pthread_create error");
      exit (1);
    }
  }
#endif /* ENABLE_PTHREAD */
  /*
   * pl[] is also read when a capture file is replayed, so it must always be
   * initialised.  With a control socket, wait for the capture file and the
   * control socket together (as for a live capture) so that control
   * connections are served even while a file such as a FIFO has no data.
   */
  memset (pl, '\0', sizeof (pl));
  if (capfile != NULL && ctlsock != -1)
    pcapfd = pcap_get_selectable_fd (pcap);

  for (r = 0; graceful_shutdown_request == 0; r = 0) {
    /*
     * Silly libpcap's timeout function doesn't work, so we
     * do it here (only if we are reading live)
     */
    if (capfile == NULL && (dev != NULL || rsock > 0)) {  // online
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

      FLOWTRACK_LOCK();
      timeout_ms = next_expire (&flowtrack);
      FLOWTRACK_UNLOCK();
      r = poll (pl, (ctlsock == -1) ? 1 : 2, timeout_ms);
      if (r == -1 && errno != EINTR) {
        logit (LOG_ERR, "Exiting on poll: %s", strerror (errno));
        break;
      }
    } else if (pcapfd >= 0) {  // capture file with a control socket
      memset (pl, '\0', sizeof (pl));
      pl[0].fd = stop_collection_flag ? -1 : pcapfd;
      pl[0].events = POLLIN | POLLERR | POLLHUP;
      pl[1].fd = ctlsock;
      pl[1].events = POLLIN | POLLERR | POLLHUP;
      r = poll (pl, 2, -1);
      if (r == -1 && errno != EINTR) {
        logit (LOG_ERR, "Exiting on poll: %s", strerror (errno));
        break;
      }
    }

    /* Requests of SIGUSR1 and SIGHUP; the handlers only set the flags */
    if (stats_log_request) {
      stats_log_request = 0;
      FLOWTRACK_LOCK();
      logit (LOG_INFO, "stats: tracked=%u total_packets=%llu",
             flowtrack.param.num_flows,
             (unsigned long long) flowtrack.param.total_packets);
      FLOWTRACK_UNLOCK();
    }
    if (hup_log_request) {
      hup_log_request = 0;
      logit (LOG_INFO, "SIGHUP received (config reload not implemented)");
    }

    /* Accept connection on control socket if present */
    if (ctlsock != -1 && pl[1].revents != 0) {
      FLOWTRACK_LOCK();
      r = accept_control (ctlsock, &target, &flowtrack, pcap, &exit_request,
                          &stop_collection_flag);
      FLOWTRACK_UNLOCK();
      if (r != 0)
        break;
    }

    /* If we have data, run it through libpcap */
    if (!stop_collection_flag &&
        ((capfile != NULL && pcapfd < 0) || pl[0].revents != 0)) {
      if (capfile != NULL || dev != NULL) {
#ifdef ENABLE_PTHREAD
        if (use_thread)
          r = pcap_dispatch (pcap, flowtrack.param.max_flows, pcap_memcpy, NULL);
        else
#endif /* ENABLE_PTHREAD */
          r = pcap_dispatch (pcap, flowtrack.param.max_flows, flow_cb,
                             (void *) &cb_ctxt);
        if (r == -1) {
          logit (LOG_ERR, "Exiting on pcap_dispatch: %s", pcap_geterr (pcap));
          break;
        } else if (r == 0 && capfile != NULL) {
          logit (LOG_NOTICE, "Shutting down after "
                             "pcap EOF");
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
          /* recv() blocks if the queue is empty: look at it again. */
          r = poll (pl, 1, 0);
          if (r == -1) {
            pl[0].revents = 0;
            if (errno != EINTR) {
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
    FLOWTRACK_LOCK();
    if (flowtrack.param.num_flows > flowtrack.param.max_flows ||
        next_expire (&flowtrack) == 0) {
    expiry_check:
      /*
       * If we are reading from a capture file, we never
       * expire flows based on time - instead we only
       * expire flows when the flow table is full.
       */
      if (check_expired (&flowtrack, &target,
                         capfile == NULL ? CE_EXPIRE_NORMAL : CE_EXPIRE_FORCED) <
          0)
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
    FLOWTRACK_UNLOCK();
  }

#ifdef ENABLE_PTHREAD
  /* Let the processing thread finish the packet that was handed over last. */
  if (use_thread)
    wait_for_packet_loop_idle();
#endif /* ENABLE_PTHREAD */

  /* Flags set by signal handlers or control socket */
  if (graceful_shutdown_request) {
    logit (LOG_WARNING, "Shutting down on user request");
    check_expired (&flowtrack, &target, CE_EXPIRE_ALL);
  } else if (exit_request)
    logit (LOG_WARNING, "Exiting immediately on user request");
  else
    logit (LOG_ERR, "Exiting immediately on internal error");

#ifdef ENABLE_PTHREAD
  /* The export threads update the counters that statistics() prints. */
  if (use_thread)
    wait_for_export_threads();
#endif /* ENABLE_PTHREAD */

  if (capfile != NULL && dontfork_flag)
    statistics (&flowtrack, stdout, pcap);

#ifdef ENABLE_PTHREAD
  if (use_thread) {
    pthread_mutex_lock (&read_mutex);
    reader_stop = 1;
    pthread_cond_signal (&read_cond);
    pthread_mutex_unlock (&read_mutex);
    pthread_join (read_thread, NULL);
  }
#endif /* ENABLE_PTHREAD */

  if (pcap != NULL)
    pcap_close (pcap);

  for (dest_idx = 0; dest_idx < target.num_destinations; dest_idx++) {
    dest = &target.destinations[dest_idx];
    if (dest->sock != -1)
      close (dest->sock);
#ifdef ENABLE_NTOPNG
    if (dest->zmq.socket != NULL)
      close_ntopng (&dest->zmq);
#endif /* ENABLE_NTOPNG */
  }

  unlink (pidfile_path);
  if (ctlsock_path != NULL)
    unlink (ctlsock_path);

  if (rsock > 0)
    close (rsock);
  if (gauge_clock) {
    logit (LOG_INFO, "cpu clocks: %ld\n", clock() - boottime);
#ifdef ENABLE_PTHREAD
    if (use_thread)
      logit (LOG_INFO, "cpu clocks (export): n/a with threaded export\n");
    else
#endif /* ENABLE_PTHREAD */
      logit (LOG_INFO, "cpu clocks (export): %ld (%lu calls)\n",
             (long) export_clocks, export_calls);
  }
  return (r == 0 ? 0 : 1);
}
