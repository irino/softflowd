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
 * @file expire.c
 * @brief Expiry of flows: the expiry timers, the selection of the flows that
 *   are due and the hand-over of the expired flows to the export
 *   functions. This file was split from softflowd.c.
 */

#include "softflowd.h"
#include "expire.h"
#include "flow.h"
#include "format.h"
#include "globals.h"
#include "ipfix.h"
#include "log.h"
#include "sender.h"
#include "stats.h"

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
void
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
 * @brief Time until the next expiry event.
 *
 * @param ft Flow tracking state.
 * @return Milliseconds until the next expiry event.
 */
int
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
int
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
void
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
int
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
