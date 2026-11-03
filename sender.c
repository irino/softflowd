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
static pthread_mutex_t export_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
/** Signalled when the last export thread ends */
static pthread_cond_t export_threads_cond = PTHREAD_COND_INITIALIZER;
/** Number of running export threads (-M) */
static int export_threads_outstanding = 0;

/**
 * @brief Context for threaded export (-M): unlike netflow_send_func_t, this
 * wrapper's signature actually matches what pthread_create() invokes
 * (void *(*)(void *)), and it owns a deep copy of both the flows and
 * the SENDPARAMETER referencing them, so the sending thread never
 * touches memory the main thread may concurrently reuse via
 * flow_put(). sp.flows points at owned_flows: the export function only
 * reads it, and threaded_send alone frees the array and the flow copies
 * after that call returns, so no return path of an export function can
 * leak them. */
struct THREADED_SENDPARAMETER {
  struct SENDPARAMETER sp;   /**< The parameters of the export; sp.flows points at owned_flows */
  netflow_send_func_t *func; /**< The export function to run */
  struct FLOW **owned_flows; /**< The copies of the flows, which threaded_send () frees */
  int num_flows;             /**< Number of entries of owned_flows */
};
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

/**
 * @brief Export flows from a detached thread (-M).
 *
 * The flows are copied first: the caller hands the originals back to
 * flow_put () as soon as this returns, and they may be reused for new flows
 * before the thread gets to read them. struct FLOW holds no pointers of its
 * own (its "expiry" back-link was already cleared by the caller), so a plain
 * struct copy is a complete copy. threaded_send () frees the copies.
 *
 * @param sp   The parameters of the export; sp.flows are the flows to copy.
 * @param func The export function to run in the thread.
 * @return 1, as the thread has started; the result of func is not available.
 */
int
send_threaded (struct SENDPARAMETER sp, netflow_send_func_t *func) {
  pthread_t write_thread = 0;
  struct THREADED_SENDPARAMETER *tsp = malloc (sizeof (*tsp));
  int i;

  tsp->sp = sp;
  /* sp.flows is the array of copies made below; threaded_send frees it, see
   * the comment of struct THREADED_SENDPARAMETER. */
  tsp->owned_flows = calloc (sp.num_flows, sizeof (*tsp->owned_flows));
  tsp->sp.flows = tsp->owned_flows;
  for (i = 0; i < sp.num_flows; i++) {
    tsp->owned_flows[i] = malloc (sizeof (*tsp->owned_flows[i]));
    *tsp->owned_flows[i] = *sp.flows[i];
  }
  tsp->num_flows = sp.num_flows;
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
  return 1;
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
