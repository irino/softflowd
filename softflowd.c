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

/**
 * @file softflowd.c
 * @brief softflowd, a flow-based traffic analyser: it reads packets from an
 *   interface or a capture file, tracks them as flows, expires the flows and
 *   exports them as NetFlow or IPFIX; the control socket, the daemon set-up
 *   and the command line are here too.
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
#include "globals.h"
#include "expire.h"
#include "flow.h"
#include "format.h"
#include "netsock.h"
#include "options.h"
#include "packet.h"
#include "sender.h"
#include "stats.h"
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
/**
 * The value that getopt_long () returns for --flow-lookup, which has no
 * short option.
 */
#define OPT_FLOW_LOOKUP 256         /* --flow-lookup has no short option */

/* Global variables */
int verbose_flag = 0;   /**< Debugging flag */
u_int16_t if_index = 0; /**< "manual" interface index */
int track_level;        /**< Flow tracking level (TRACK_*) */
/** Capture length; 0 selects a default from LIBPCAP_SNAPLEN_V4/V6 */
int snaplen = 0;
int gauge_clock = 0; /**< -g: report cpu clocks */
/** cpu clocks spent in the export function */
clock_t export_clocks = 0;
/** Number of calls to the export function */
unsigned long export_calls = 0;
#ifdef ENABLE_PTHREAD
pthread_mutex_t read_mutex; /**< Protects packet_header/packet_data handed to
                               the processing thread */
pthread_cond_t read_cond;   /**< Signalled when a new packet is available */
/** Signalled when the processing thread has finished the handed-over packet */
static pthread_cond_t slot_cond = PTHREAD_COND_INITIALIZER;
/** Non-zero while packet_data holds a packet that is not processed yet
 * (protected by read_mutex) */
static int packet_ready = 0;
/** Set under read_mutex to make process_packet_loop() return */
static int reader_stop = 0;

int use_thread;                   /**< Non-zero when threaded export (-M) is enabled */
u_char packet_data[1500];         /**< Copy of the latest captured packet (threaded
                             capture) */
struct pcap_pkthdr packet_header; /**< libpcap header of packet_data */
#endif                 /* ENABLE_PTHREAD */

/* Signal handler flags */
/** Set by the signal handler to the received signal number to request a
 * graceful shutdown. */
volatile sig_atomic_t graceful_shutdown_request = 0;
/** Set by SIGUSR1: log the number of the tracked flows and of the packets. */
static volatile sig_atomic_t stats_log_request = 0;
/** Set by SIGHUP: log that a reload of the configuration is not implemented. */
static volatile sig_atomic_t hup_log_request = 0;

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
