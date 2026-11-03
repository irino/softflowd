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
 * @file stats.c
 * @brief Statistics of the flow tracker: the running statistics, the
 *   statistics report and the dumps of the flows and of the timeouts.
 *   This file was split from softflowd.c.
 */

#include "softflowd.h"
#include "stats.h"
#include "flow.h"
#include "format.h"
#include "log.h"

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
void
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
void
update_expiry_stats (struct FLOWTRACK *ft, struct EXPIRY *e) {
  ft->param.expired[e->reason]++;
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
int
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
void
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
 * @brief Write the configured timeouts to a stream.
 *
 * @param ft  Flow tracking state.
 * @param out Output stream.
 */
void
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
