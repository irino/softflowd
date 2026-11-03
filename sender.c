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
 * @file sender.c
 * @brief Export senders: the table of the export versions, sending a packet
 *   to the destinations, and the threaded export (-M). This file was
 *   split from softflowd.c.
 */

#include "softflowd.h"
#include "sender.h"
#include "log.h"

#ifdef ENABLE_PTHREAD
/** Protects export_threads_outstanding */
pthread_mutex_t export_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
/** Signalled when the last export thread ends */
static pthread_cond_t export_threads_cond = PTHREAD_COND_INITIALIZER;
/** Number of running export threads (-M) */
int export_threads_outstanding = 0;
struct FLOW
  *send_expired_flows; /**< Expired flows handed to the export thread */

/**
 * @brief Block until every detached export thread (-M) has finished.
 *
 * Detached export threads outlive the check_expired() call that spawns them, so
 * this must run before the process tears down.
 */
void
wait_for_export_threads (void) {
  pthread_mutex_lock (&export_threads_mutex);
  while (export_threads_outstanding > 0)
    pthread_cond_wait (&export_threads_cond, &export_threads_mutex);
  pthread_mutex_unlock (&export_threads_mutex);
}

/**
 * @brief Thread entry point: run one export function, then free its flow copies
 * (-M).
 *
 * @param arg struct THREADED_SENDPARAMETER, which is freed here.
 * @return NULL.
 */
void *
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

/* Known NetFlow export functions (nf[0] is default).
 * Which source file defines the send_* functions depends on
 * --enable-compat-export (see softflowd.h). */
/**
 * The versions that can be exported and the functions that export them;
 * nf[0] (NetFlow v5) is the default.
 */
const struct NETFLOW_SENDER nf[] = {
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
const struct NETFLOW_SENDER *
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
