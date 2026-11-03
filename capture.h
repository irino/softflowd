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
 * @file capture.h
 * @brief Declarations of capture.c: packet capture: the libpcap set-up and
 *   callback, the processing thread of the threaded capture (-M) and the
 *   lookup of the MAC address of an interface. This file was split from
 *   softflowd.c.
 */

#ifndef _CAPTURE_H
#define _CAPTURE_H
#include "softflowd.h"

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
extern pthread_mutex_t read_mutex;
extern pthread_cond_t read_cond;
extern int reader_stop;
#endif /* ENABLE_PTHREAD */

int
get_interface_mac (const char *ifname, u_int8_t mac[6]);
void
flow_cb (u_char *user_data, const struct pcap_pkthdr *phdr,
         const u_char *pkt);
void
setup_packet_capture (struct pcap **pcap, int *linktype, char *dev,
                      char *capfile, char *bpf_prog, int need_v6,
                      int promisc, int buffer_size_override);
#ifdef ENABLE_PTHREAD
void
pcap_memcpy (u_char *user_data, const struct pcap_pkthdr *phdr,
             const u_char *pkt);
void *
process_packet_loop (void *arg);
void
wait_for_packet_loop_idle (void);
#endif /* ENABLE_PTHREAD */

#endif /* _CAPTURE_H */
