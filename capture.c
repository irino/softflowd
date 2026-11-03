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
 * @file capture.c
 * @brief Packet capture: the libpcap set-up and callback, the processing
 *   thread of the threaded capture (-M) and the lookup of the MAC
 *   address of an interface. This file was split from softflowd.c.
 */

#include "softflowd.h"
#include "capture.h"
#include "globals.h"
#include "log.h"
#include "packet.h"
#include "psamp.h"
#include <pcap.h>
#ifdef LINUX
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#endif /* LINUX */
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif /* HAVE_IFADDRS_H */
#if !defined(LINUX) && defined(HAVE_IFADDRS_H)
#include <net/if_dl.h>
#endif

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
int reader_stop = 0;
int use_thread;                   /**< Non-zero when threaded export (-M) is enabled */
u_char packet_data[1500];         /**< Copy of the latest captured packet (threaded
                             capture) */
struct pcap_pkthdr packet_header; /**< libpcap header of packet_data */
#endif /* ENABLE_PTHREAD */

/**
 * @brief Auto-detect the MAC address of an interface.
 *
 * @param ifname Interface name.
 * @param mac    Receives the 6-octet address.
 * @return 0 on success, -1 on failure (e.g. a tunnel or the "any" interface).
 */
int
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
void
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
void *
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
void
wait_for_packet_loop_idle (void) {
  pthread_mutex_lock (&read_mutex);
  while (packet_ready)
    pthread_cond_wait (&slot_cond, &read_mutex);
  pthread_mutex_unlock (&read_mutex);
}
#endif /* ENABLE_PTHREAD */

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
void
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
