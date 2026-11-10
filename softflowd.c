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
 *   exports them as NetFlow or IPFIX. This file holds the entry point, which
 *   sets up the capture and the export, and runs the main loop; the other
 *   parts are in capture.c, control.c, daemon_setup.c, expire.c, flow.c,
 *   format.c, netsock.c, options.c, packet.c, sender.c and stats.c.
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
#include "log.h"
#include "netflow.h"
#include "psamp.h"
#include "treetype.h"
#include "globals.h"
#include "capture.h"
#include "control.h"
#include "daemon_setup.h"
#include "expire.h"
#include "flow.h"
#include "format.h"
#include "netsock.h"
#include "options.h"
#include "packet.h"
#include "sender.h"
#include "stats.h"
#include <netinet/in.h>
#include <pcap.h>
#ifdef LINUX
#include <net/if.h>
#include <sys/ioctl.h>
#endif /* LINUX */

/**
 * The value that getopt_long () returns for --flow-lookup, which has no
 * short option.
 */
#define OPT_FLOW_LOOKUP 256 /* --flow-lookup has no short option */

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

/**
 * @brief softflowd entry point: parse options (parse_command_line ()), set up
 * capture and export, and run the main loop.
 *
 * @param argc Argument count.
 * @param argv Arguments.
 * @return 0 on success, 1 if the main loop ended with an error.
 */
int
main (int argc, char **argv) {
  clock_t boottime = clock();
  char *bpf_prog;
  extern int optind;
  int linktype = 0, ctlsock, err, r, dest_idx;
  int stop_collection_flag, exit_request;
  pcap_t *pcap = NULL;
  struct FLOWTRACK flowtrack;
  struct NETFLOW_TARGET target;
  struct CB_CTXT cb_ctxt;
  struct pollfd pl[2];
  int pcapfd = -1;
  struct DESTINATION *dest;
  int timeout_ms = 0;
  u_int recvloop = 0;
#ifdef LINUX
  struct ifreq ifr;
#endif /* LINUX */
#ifdef ENABLE_PTHREAD
  use_thread = 0;
  pthread_t read_thread = 0;

  pthread_mutex_init (&read_mutex, NULL);
  pthread_cond_init (&read_cond, NULL);
#endif /* ENABLE_PTHREAD */
  struct DAEMON_CONFIG cfg;

  closefrom (STDERR_FILENO + 1);

  init_flowtrack (&flowtrack);

  memset (&target, '\0', sizeof (target));
  target.dialect = &nf[0];
  bpf_prog = NULL;
  ctlsock = -1;

  parse_command_line (argc, argv, &cfg, &flowtrack, &target);

  if (cfg.capfile == NULL && cfg.dev == NULL && cfg.rsock <= 0) {
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
  if (cfg.capfile != NULL || cfg.dev != NULL)
    setup_packet_capture (&pcap, &linktype, cfg.dev, cfg.capfile, bpf_prog,
                          target.dialect->v6_capable || cfg.always_v6, cfg.use_promisc,
                          cfg.pcap_override_buffer_size);
  else if (cfg.rsock > 0)
    linktype = 1;  // LINKTYPE_ETHERNET

  /*
   * If ethernet-level tracking is enabled and the user has not
   * explicitly specified a direction MAC address with -H, try to
   * auto-detect it from the capture interface.
   */
  if (flowtrack.param.track_level >= TRACK_FULL_VLAN_ETHER &&
      flowtrack.param.direction_mac_set == 0 && cfg.dev != NULL) {
    if (get_interface_mac (cfg.dev, flowtrack.param.direction_mac) == 0) {
      flowtrack.param.direction_mac_set = 1;
      if (verbose_flag)
        fprintf (
          stderr,
          "Auto-detected direction MAC %02x:%02x:%02x:%02x:%02x:%02x "
          "from interface %s\n",
          flowtrack.param.direction_mac[0], flowtrack.param.direction_mac[1],
          flowtrack.param.direction_mac[2], flowtrack.param.direction_mac[3],
          flowtrack.param.direction_mac[4], flowtrack.param.direction_mac[5],
          cfg.dev);
    } else if (verbose_flag) {
      fprintf (stderr,
               "Could not auto-detect MAC address of %s; "
               "flowDirection will use canonical ordering\n",
               cfg.dev);
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
        dest->sock = connsock (&dest->ss, dest->sslen, cfg.hoplimit, cfg.protocol,
                               flowtrack.param.option.exporterAddr);
#ifdef LINUX
      if (dest->sock > 0 && cfg.send_ifname != NULL) {
        bind_device (dest->sock, cfg.send_ifname);
      }
      if (cfg.dev != NULL && cfg.user_ifindex_flag == 0) {
        strncpy (ifr.ifr_name, cfg.dev, IFNAMSIZ - 1);
        if (ioctl (pcap_get_selectable_fd (pcap), SIOCGIFINDEX, &ifr) < 0) {
          perror ("ioctl SIOCGIFINDEX");
        }
        if_index = ifr.ifr_ifindex;
        if (verbose_flag)
          fprintf (stderr, "Using %s (idx: %d as result of SIOCGIFINDEX)\n", cfg.dev,
                   if_index);
      }
#endif /* LINUX */
    }
  }

  /* Control socket */
  if (cfg.ctlsock_path != NULL)
    ctlsock = unix_listener (cfg.ctlsock_path); /* Will exit on fail */

  if (cfg.dontfork_flag) {
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

    if ((pidfile = fopen (cfg.pidfile_path, "r")) != NULL) {
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
    if ((pidfile = fopen (cfg.pidfile_path, "w")) == NULL) {
      fprintf (stderr, "Couldn't open pidfile %s: %s\n", cfg.pidfile_path,
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
             cfg.capfile != NULL ? cfg.capfile : flowtrack.param.option.interfaceName,
             dest->hostname, dest->servname);
    }
  }
  flowtrack.param.option.meteringProcessId = getpid();
  flowtrack.param.boot_time_reinit = cfg.boot_time_reinit_sec;

  /* Main processing loop */
  gettimeofday (&flowtrack.param.system_boot_time, NULL);
  stop_collection_flag = 0;
  memset (&cb_ctxt, '\0', sizeof (cb_ctxt));
  cb_ctxt.ft = &flowtrack;
  cb_ctxt.target = &target;
  cb_ctxt.linktype = linktype;
  cb_ctxt.want_v6 = target.dialect->v6_capable || cfg.always_v6;
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
  if (cfg.capfile != NULL && ctlsock != -1)
    pcapfd = pcap_get_selectable_fd (pcap);

  for (r = 0; graceful_shutdown_request == 0; r = 0) {
    /*
     * Silly libpcap's timeout function doesn't work, so we
     * do it here (only if we are reading live)
     */
    if (cfg.capfile == NULL && (cfg.dev != NULL || cfg.rsock > 0)) {  // online
      memset (pl, '\0', sizeof (pl));

      /* This can only be set via the control socket */
      if (!stop_collection_flag && cfg.dev != NULL) {
        pl[0].events = POLLIN | POLLERR | POLLHUP;
        pl[0].fd = pcap_fileno (pcap);
      } else if (!stop_collection_flag && cfg.rsock > 0) {
        pl[0].fd = cfg.rsock;
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
        ((cfg.capfile != NULL && pcapfd < 0) || pl[0].revents != 0)) {
      if (cfg.capfile != NULL || cfg.dev != NULL) {
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
        } else if (r == 0 && cfg.capfile != NULL) {
          logit (LOG_NOTICE, "Shutting down after "
                             "pcap EOF");
          graceful_shutdown_request = 1;
          break;
        }
      } else if (cfg.rsock > 0) {
        for (recvloop = 0;
             recvloop < flowtrack.param.max_flows && pl[0].revents != 0;
             recvloop++) {
          r = recv_psamp (cfg.rsock, &cb_ctxt);
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
                         cfg.capfile == NULL ? CE_EXPIRE_NORMAL : CE_EXPIRE_FORCED) <
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

  if (cfg.capfile != NULL && cfg.dontfork_flag)
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

  unlink (cfg.pidfile_path);
  if (cfg.ctlsock_path != NULL)
    unlink (cfg.ctlsock_path);

  if (cfg.rsock > 0)
    close (cfg.rsock);
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
