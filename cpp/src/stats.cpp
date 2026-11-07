/**
 * @file stats.cpp
 * @brief The statistics of the flow table and the debug lines of the expiry scans.
 *
 * Split from softflowd.cpp. See stats.hpp.
 */
#include "softflowd_cpp/stats.hpp"

#include "softflowd_cpp/format.hpp"
#include "softflowd_cpp/log.hpp"

#include <cstddef>
#include <cstdio>

namespace softflowd_cpp {

/**
 * @brief Prints the statistics of the flow table in the format of the C version.
 *
 * The "Flow table" line is left out for the tree lookup, the counters of libpcap are printed only when the handle has them, and the statistics of the expired flows only when there are some.
 *
 * @param s The statistics.
 * @param active_flows The number of flows in the table.
 * @param lookup The way flows are looked up (-F).
 * @param usage The memory and the buckets of the table.
 * @param out Where to print.
 * @param handle The capture, for the counters of libpcap; null when there is none.
 *
 * @original softflowd.c's statistics(), called only when reading from a
 * pcap file (-r) in foreground mode (-d) -- see the call site in
 * run_pcap_file() below. Formatting intentionally mirrors the C version.
 */
void
print_statistics (const softflowd_cpp::FlowTableStats &s, std::size_t active_flows,
                  softflowd_cpp::FlowLookup lookup,
                  const softflowd_cpp::FlowTableUsage &usage,
                  std::FILE *out, const softflowd_cpp::PcapHandle *handle) {
  std::fprintf (out, "Number of active flows: %zu\n", active_flows);
  std::fprintf (out, "Packets processed: %llu\n",
                static_cast<unsigned long long> (s.total_packets));
  std::fprintf (out, "Fragments: %llu\n",
                static_cast<unsigned long long> (s.frag_packets));
  std::fprintf (out,
                "Ignored packets: %llu (%llu non-IP, %llu too short)\n",
                static_cast<unsigned long long> (s.non_ip_packets + s.bad_packets),
                static_cast<unsigned long long> (s.non_ip_packets),
                static_cast<unsigned long long> (s.bad_packets));
  std::fprintf (out, "Flows expired: %llu (%llu forced)\n",
                static_cast<unsigned long long> (s.flows_expired),
                static_cast<unsigned long long> (s.flows_force_expired));
  std::fprintf (out,
                "Flows exported: %llu (%llu records) in %llu packets (%llu failures)\n",
                static_cast<unsigned long long> (s.flows_exported),
                static_cast<unsigned long long> (s.records_sent),
                static_cast<unsigned long long> (s.packets_sent),
                static_cast<unsigned long long> (s.flows_dropped));

  if (lookup != softflowd_cpp::FlowLookup::Tree) {
    // Original: "Flow table: ..." of statistics().
    char size[32];
    if (usage.bytes < 1024) {
      std::snprintf (size, sizeof (size), "%zu B", usage.bytes);
    } else {
      std::snprintf (size, sizeof (size), "%zu KiB", usage.bytes / 1024);
    }
    std::fprintf (out,
                  "Flow table: %s, %zu buckets (%s), %zu in use, "
                  "max depth %zu, %llu collisions\n",
                  softflowd_cpp::flow_lookup_name (lookup), usage.buckets, size,
                  usage.used, usage.max_depth,
                  static_cast<unsigned long long> (s.expired_collision));
  }

  if (auto ps = handle != nullptr ? handle->stats() : std::nullopt;
      ps.has_value()) {
    std::fprintf (out, "Packets received by libpcap: %u\n", ps->ps_recv);
    std::fprintf (out, "Packets dropped by libpcap: %u\n", ps->ps_drop);
    std::fprintf (out, "Packets dropped by interface: %u\n", ps->ps_ifdrop);
  }

  std::fprintf (out, "\n");

  if (s.flows_expired == 0) {
    return;
  }

  std::fprintf (out, "Expired flow statistics:  minimum       average       maximum\n");
  std::fprintf (out, "  Flow bytes:        %12.0f  %12.0f  %12.0f\n",
                s.octets.min, s.octets.mean, s.octets.max);
  std::fprintf (out, "  Flow packets:      %12.0f  %12.0f  %12.0f\n",
                s.packets.min, s.packets.mean, s.packets.max);
  std::fprintf (out, "  Duration:          %12.2fs %12.2fs %12.2fs\n",
                s.duration.min, s.duration.mean, s.duration.max);

  std::fprintf (out, "\n");
  std::fprintf (out, "Expired flow reasons:\n");
  std::fprintf (out, "       tcp = %9llu   tcp.rst = %9llu   tcp.fin = %9llu\n",
                static_cast<unsigned long long> (s.expired_tcp),
                static_cast<unsigned long long> (s.expired_tcp_rst),
                static_cast<unsigned long long> (s.expired_tcp_fin));
  std::fprintf (out, "       udp = %9llu      icmp = %9llu   general = %9llu\n",
                static_cast<unsigned long long> (s.expired_udp),
                static_cast<unsigned long long> (s.expired_icmp),
                static_cast<unsigned long long> (s.expired_general));
  std::fprintf (out, "   maxlife = %9llu\n",
                static_cast<unsigned long long> (s.expired_maxlife));
  std::fprintf (out, "over 2 GiB = %9llu\n",
                static_cast<unsigned long long> (s.expired_overbytes));
  std::fprintf (out, "  maxflows = %9llu\n",
                static_cast<unsigned long long> (s.expired_maxflows));
  std::fprintf (out, "   flushed = %9llu\n",
                static_cast<unsigned long long> (s.expired_flush));
  if (lookup == softflowd_cpp::FlowLookup::Hash) {
    std::fprintf (out, "collision = %9llu\n",
                  static_cast<unsigned long long> (s.expired_collision));
  }

  std::fprintf (out, "\n");
  std::fprintf (out, "Per-protocol statistics:     Octets      Packets   Avg Life    Max Life\n");
  for (std::size_t i = 0; i < 256; ++i) {
    if (s.packets_pp[i] == 0)
      continue;
    const struct protoent *pe = getprotobynumber (static_cast<int> (i));
    char proto[32];
    std::snprintf (proto, sizeof (proto), "%s (%zu)",
                   pe != nullptr ? pe->p_name : "Unknown", i);
    std::fprintf (out, "  %17s: %14llu %12llu   %8.2fs %10.2fs\n", proto,
                  static_cast<unsigned long long> (s.octets_pp[i]),
                  static_cast<unsigned long long> (s.packets_pp[i]),
                  s.duration_pp[i].mean, s.duration_pp[i].max);
  }
}

/**
 * @brief Logs the start of a scan for expired flows (-D).
 *
 * @param debug true with -D; nothing is logged otherwise.
 * @param mode kCeExpireNormal, kCeExpireAll or kCeExpireForced.
 *
 * @original softflowd.c's check_expired(), whose -D (verbose_flag) debug
 * output this reproduces exactly: "Starting expiry scan: mode %d" before
 * the scan, "Queuing flow seq:... (%p) for expiry reason %d" per flow
 * found to be expiring, "Finished scan %d flow(s) to be evicted"
 * afterward, "sent %d netflow packets" once export has been attempted
 * (if there was anything to send), and "EXPIRED: %s (%p)" (the *verbose*
 * format_flow(), not format_flow_brief()) per expired flow. mode mirrors
 * the original's CE_EXPIRE_NORMAL(0)/CE_EXPIRE_ALL(-1)/
 * CE_EXPIRE_FORCED(1).
 */
void
log_expiry_debug_start (bool debug, int mode) {
  if (debug) {
    logit (LOG_DEBUG, "Starting expiry scan: mode %d", mode);
  }
}

/**
 * @brief Logs the flows that are to expire, and the end of the scan (-D).
 *
 * @param debug true with -D; nothing is logged otherwise.
 * @param expired The flows that expire.
 */
void
log_expiry_debug_queued (bool debug, const std::vector<softflowd_cpp::ExportRecord> &expired) {
  if (!debug) {
    return;
  }
  for (const auto &record : expired) {
    logit (LOG_DEBUG, "Queuing flow seq:%llu (%p) for expiry reason %d",
           static_cast<unsigned long long> (record.flow.flow_seq),
           static_cast<const void *> (&record.flow),
           static_cast<int> (record.flow.reason));
  }
  logit (LOG_DEBUG, "Finished scan %zu flow(s) to be evicted", expired.size());
}

/**
 * @brief Logs how many packets the export of expired flows sent (-D).
 *
 * @param debug true with -D; nothing is logged otherwise.
 * @param packets_sent The number of packets sent.
 * @param flows The number of flows exported; nothing is logged when it is 0.
 *
 * @original only when there is a flow to send (num_expired \> 0).
 */
void
log_expiry_debug_sent (bool debug, int packets_sent, std::size_t flows) {
  if (flows == 0) {
    return;
  }
  if (debug) {
    logit (LOG_DEBUG, "sent %d netflow packets", packets_sent);
  }
}

/**
 * @brief Logs each expired flow in full (-D).
 *
 * @param debug true with -D; nothing is logged otherwise.
 * @param expired The flows that expired.
 */
void
log_expiry_debug_expired (bool debug, const std::vector<softflowd_cpp::ExportRecord> &expired) {
  if (!debug) {
    return;
  }
  for (const auto &record : expired) {
    logit (LOG_DEBUG, "EXPIRED: %s (%p)",
           format_flow (record.key, record.flow).c_str(),
           static_cast<const void *> (&record.flow));
  }
}

}  // namespace softflowd_cpp
