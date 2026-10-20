// Original files: softflowd.c, freelist.c, treetype.h, sys-tree.h
//
// This translation unit intentionally holds almost everything, mirroring
// how the original softflowd.c contained main(), process_packet(),
// ipv4_to_flowrec(), ipv6_to_flowrec(), transport_to_flowrec(), and
// check_expired() all in one file. See softflowd.hpp for the rationale
// behind merging freelist.c / treetype.h / sys-tree.h's functionality
// (FlowTable) into this project's single header/source pair as well.
//
// Build note: main() is compiled out when SOFTFLOW_NO_MAIN is defined, so
// this same file can be linked into unit tests (which supply their own
// main()) without a duplicate-symbol error. See CMakeLists.txt.
#include "softflow/softflowd.hpp"

// Original: common.h's PROGNAME/PROGVER macros. There, they're literal
// #defines that happen to be kept in sync with configure.ac's AC_INIT by
// hand, not actually generated from it. Here, SOFTFLOWDPP_NAME/
// SOFTFLOWDPP_VERSION are genuinely injected by CMakeLists.txt's
// project(softflowd+ VERSION ...) declaration (see target_compile_
// definitions(softflow_core ...)), so there is exactly one place --
// CMakeLists.txt -- that defines this project's version. The fallback
// definitions below only matter if this file is ever compiled outside
// that CMake build (e.g. by a stray IDE indexer).
#ifndef SOFTFLOWDPP_NAME
#define SOFTFLOWDPP_NAME "softflowd+"
#endif
#ifndef SOFTFLOWDPP_VERSION
#define SOFTFLOWDPP_VERSION "0.0.0"
#endif

#include "softflow/daemon.hpp"
#include "softflow/ipfix.hpp"
#include "softflow/netflow1.hpp"
#include "softflow/netflow5.hpp"
#include "softflow/psamp.hpp"
#include "softflow/softflowctl.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <cctype>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __linux__
#include <net/if_arp.h>
#else
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#include <sys/un.h>
#include <unistd.h>
#include <getopt.h>

#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#if __has_include(<linux/dccp.h>)
#include <linux/dccp.h>
#define SOFTFLOW_HAVE_LINUX_DCCP_H 1
#endif

namespace softflow {

// =======================================================================
// FlowTable<Backend> (original: struct FLOWTRACK, freelist.c, treetype.h,
//                      sys-tree.h)
// =======================================================================

template <FlowIndexBackend Backend>
FlowTable<Backend>::FlowTable (std::size_t max_flows, TrackLevel track_level,
                               FlowTimeouts timeouts)
    : max_flows_ (max_flows), track_level_ (track_level), timeouts_ (timeouts) {
  if (max_flows_ == 0) {
    // The original never checked for max_flows == 0; that case would
    // eventually misbehave somewhere downstream instead. A constructor
    // precondition turns it into an immediate, well-defined exception.
    throw std::invalid_argument ("max_flows must be > 0");
  }
  // std::map (the tree backend) has no reserve() -- only the hash backend
  // benefits from pre-sizing its bucket array.
  if constexpr (Backend == FlowIndexBackend::Hash) {
    flows_.reserve (max_flows_);
  }
}

template <FlowIndexBackend Backend>
std::pair<TimePoint, ExpiryReason>
FlowTable<Backend>::compute_expiry (
  const Flow &flow, std::uint8_t protocol, AddressFamily af) const {
  // Original: softflowd.c's flow_update_expiry(). Priority order:
  // over-2GiB > max-lifetime > TCP RST > TCP FIN (both directions) >
  // TCP general > UDP > ICMP/ICMPv6 > general fallback.
  TimePoint expires_at;
  ExpiryReason reason;

  constexpr std::uint64_t kOverbytesThreshold = 1ULL << 31;
  if (flow.octets[0] > kOverbytesThreshold || flow.octets[1] > kOverbytesThreshold) {
    expires_at = flow.flow_last;
    reason = ExpiryReason::OverBytes;
  } else if (timeouts_.maximum_lifetime.count() != 0 &&
             flow.flow_last - flow.flow_start > timeouts_.maximum_lifetime) {
    expires_at = flow.flow_last;
    reason = ExpiryReason::MaxLife;
  } else {
    constexpr std::uint8_t kTcpFin = 0x01;
    constexpr std::uint8_t kTcpRst = 0x04;
    bool matched = false;

    if (protocol == IPPROTO_TCP) {
      if (timeouts_.tcp_rst.count() != 0 &&
          ((flow.tcp_flags[0] & kTcpRst) || (flow.tcp_flags[1] & kTcpRst))) {
        expires_at = flow.flow_last + timeouts_.tcp_rst;
        reason = ExpiryReason::TcpRst;
        matched = true;
      } else if (timeouts_.tcp_fin.count() != 0 &&
                 ((flow.tcp_flags[0] & kTcpFin) && (flow.tcp_flags[1] & kTcpFin))) {
        expires_at = flow.flow_last + timeouts_.tcp_fin;
        reason = ExpiryReason::TcpFin;
        matched = true;
      } else if (timeouts_.tcp.count() != 0) {
        expires_at = flow.flow_last + timeouts_.tcp;
        reason = ExpiryReason::Tcp;
        matched = true;
      }
    }

    if (!matched && timeouts_.udp.count() != 0 && protocol == IPPROTO_UDP) {
      expires_at = flow.flow_last + timeouts_.udp;
      reason = ExpiryReason::Udp;
      matched = true;
    }

    if (!matched && timeouts_.icmp.count() != 0 &&
        ((af == AddressFamily::IPv4 && protocol == IPPROTO_ICMP) ||
         (af == AddressFamily::IPv6 && protocol == IPPROTO_ICMPV6))) {
      expires_at = flow.flow_last + timeouts_.icmp;
      reason = ExpiryReason::Icmp;
      matched = true;
    }

    if (!matched) {
      expires_at = flow.flow_last + timeouts_.general;
      reason = ExpiryReason::General;
    }
  }

  if (timeouts_.second_granularity) {
    // Original: expiry->expires_at is a plain time_t (whole seconds).
    // Truncate (not round) to match `flow_last.tv_sec + N` integer
    // arithmetic exactly.
    //
    // TimePoint (Clock::steady_clock) has no fixed relationship to
    // real calendar seconds -- its epoch is an arbitrary point at
    // process start, so directly flooring a TimePoint's own
    // time_since_epoch() to whole seconds would align to an
    // arbitrary phase, not to real wall-clock second boundaries
    // (two packets on either side of a real second could end up in
    // the same truncated bucket, or vice versa, depending on where
    // that arbitrary phase happens to fall). Instead, compute how
    // far *past* its own wall-clock second flow.wall_last (a real,
    // correctly-epoched system_clock timestamp) is, and shift the
    // monotonic expires_at back by that same amount -- equivalent to
    // truncating in wall-clock space without needing to convert the
    // whole computation there.
    const auto wall_last_frac =
      flow.wall_last - std::chrono::floor<std::chrono::seconds> (flow.wall_last);
    expires_at -= std::chrono::duration_cast<Clock::duration> (wall_last_frac);
  }

  return {expires_at, reason};
}

template <FlowIndexBackend Backend>
void
FlowTable<Backend>::reschedule_expiry (const FlowKey &key,
                                       TimePoint new_expiry) {
  // Original: the RB_REMOVE + RB_INSERT pair in sys-tree.h. Instead of
  // relinking a raw-pointer-based RB node, this simply erases the old
  // multimap entry (if any) and inserts a new one.
  //
  // Skip the erase+reinsert entirely when the new expiry time is
  // unchanged from what's already scheduled: the original's tree node
  // stays exactly where it is in this situation too (nothing calls
  // RB_REMOVE/RB_INSERT unless the computed expiry actually differs),
  // which matters for more than just efficiency -- for ties (several
  // flows sharing the same expiry time, e.g. under
  // --expiry-second-granularity), an unconditional reinsert would
  // reorder a flow to the back of its tie group on every packet even
  // when nothing about its schedule changed, diverging from the
  // original's traversal order (and thus -D debug log order, and
  // NetFlow/IPFIX export record order) for those flows.
  auto lookup_it = expiry_lookup_.find (key);
  if (lookup_it != expiry_lookup_.end()) {
    if (lookup_it->second->first == new_expiry) {
      return;
    }
    expiry_index_.erase (lookup_it->second);
  }
  auto new_it = expiry_index_.emplace (new_expiry, key);
  expiry_lookup_[key] = new_it;
}

template <FlowIndexBackend Backend>
Flow &
FlowTable<Backend>::record_packet (const FlowKey &key, TimePoint now,
                                   std::chrono::system_clock::time_point wall_now,
                                   std::uint8_t direction,
                                   std::uint64_t octet_delta,
                                   std::uint8_t tcp_flags,
                                   std::uint8_t tos) {
  if (direction > 1) {
    throw std::out_of_range ("direction must be 0 or 1");
  }

  if (!slots_.empty()) {
    // Original: flow_table_insert() in hash mode. The slot of the flow is
    // taken by another flow: that one is evicted and exported as expired
    // by collision.
    auto &slot = slots_[std::hash<FlowKey>{}(key) & (slots_.size() - 1)];
    if (slot.has_value() && *slot != key) {
      const FlowKey victim_key = *slot;
      if (auto victim_it = flows_.find (victim_key); victim_it != flows_.end()) {
        Flow victim = std::move (victim_it->second);
        flows_.erase (victim_it);
        if (auto lookup_it = expiry_lookup_.find (victim_key);
            lookup_it != expiry_lookup_.end()) {
          expiry_index_.erase (lookup_it->second);
          expiry_lookup_.erase (lookup_it);
        }
        victim.reason = ExpiryReason::Collision;
        victim.flow_end_reason = 0x05;  // lackOfResource
        collided_.push_back (ExportRecord{victim_key, std::move (victim)});
      }
    }
    slot = key;
  }

  auto [it, inserted] = flows_.try_emplace (key);
  Flow &flow = it->second;

  if (inserted) {
    flow.flow_start = now;
    flow.wall_start = wall_now;
    flow.flow_seq = static_cast<std::uint64_t> (flows_.size());
  }

  flow.flow_last = now;
  flow.wall_last = wall_now;
  flow.octets[direction] += octet_delta;
  flow.packets[direction] += 1;
  // Original: `flow->tos[*ndx] = ip->ip_tos` only runs inside
  // ipv4_to_flowrec()/ipv6_to_flowrec(), which fill a scratch `tmp`
  // FLOW that gets memcpy()'d wholesale into the real flow *only* when
  // the flow is first created. For every subsequent packet on an
  // already-existing flow, process_packet()'s "update flow statistics"
  // branch touches only packets[]/octets[]/tcp_flags[] -- ToS is never
  // revisited. Concretely: whichever direction's packet arrives first
  // fixes flow.tos[0] (or [1]) for the flow's whole lifetime, and the
  // *other* direction's slot stays at the scratch struct's zero-fill
  // until (unless) a first packet from that direction happens to also
  // arrive while the flow is being created -- which, since creation
  // happens on the very first packet seen for the flow, only occurs for
  // the direction of that first packet. So in practice one direction's
  // ToS is "live" (set once, at creation, from that same first packet)
  // and the other is always 0, regardless of what ToS any later
  // opposite-direction packets actually carried. Reproduced here by
  // only writing tos[] when the flow is new.
  if (inserted) {
    flow.tos[direction] = tos;
  }
  if (key.protocol() == IPPROTO_TCP) {
    // Original: flow->tcp_flags[ndx] |= tcp_flags; -- flags accumulate
    // over the flow's whole lifetime, not just the current packet.
    flow.tcp_flags[direction] |= tcp_flags;
  }

  const auto [expires_at, reason] =
    compute_expiry (flow, key.protocol(), key.addr()[0].family);
  flow.reason = reason;
  // Original: flow_update_expiry() sets flow->flowEndReason (IPFIX IE
  // 136) alongside expiry->reason, from the same classification. Unlike
  // expiry->reason, flowEndReason is never overwritten again when a flow
  // is later force-flushed (R_FLUSH) or evicted for table space
  // (R_OVERFLOWS) -- those only affect the expiry-reason *statistics*
  // bucket, not the wire-format reason already recorded on the flow.
  // Values are RFC 7011's flowEndReason code points.
  switch (reason) {
    case ExpiryReason::TcpRst:
    case ExpiryReason::TcpFin:
      flow.flow_end_reason = 0x03;  // endOfFlow
      break;
    case ExpiryReason::MaxLife:
      flow.flow_end_reason = 0x02;  // activeTimeout
      break;
    case ExpiryReason::OverBytes:
      flow.flow_end_reason = 0x05;  // lackOfResource
      break;
    default:
      flow.flow_end_reason = 0x01;  // idleTimeout
      break;
  }
  reschedule_expiry (key, expires_at);

  stats_.total_packets += 1;
  return flow;
}

template <FlowIndexBackend Backend>
void
FlowTable<Backend>::record_expiry_stats (const Flow &flow,
                                         std::uint8_t protocol,
                                         ExpiryReason reason_override,
                                         bool override_reason) {
  // Original: update_statistics() -- always runs for every expired flow.
  const double duration_sec = std::chrono::duration<double> (
                                flow.flow_last - flow.flow_start)
                                .count();
  const double clamped_duration = std::max (duration_sec, 0.0);
  stats_.duration.update (clamped_duration);

  const double total_octets =
    static_cast<double> (flow.octets[0]) + static_cast<double> (flow.octets[1]);
  stats_.octets.update (total_octets);

  const double total_packets =
    static_cast<double> (flow.packets[0]) + static_cast<double> (flow.packets[1]);
  stats_.packets.update (total_packets);

  stats_.flows_pp[protocol] += 1;
  stats_.octets_pp[protocol] += static_cast<std::uint64_t> (total_octets);
  stats_.packets_pp[protocol] += static_cast<std::uint64_t> (total_packets);
  stats_.duration_pp[protocol].update (clamped_duration);

  // Original: update_expiry_stats() -- per-reason counters. Force
  // eviction (R_OVERFLOWS) and shutdown flush (R_FLUSH) override
  // whatever compute_expiry() had last computed for this flow.
  const ExpiryReason reason = override_reason ? reason_override : flow.reason;
  switch (reason) {
    case ExpiryReason::General:
      stats_.expired_general += 1;
      break;
    case ExpiryReason::Tcp:
      stats_.expired_tcp += 1;
      break;
    case ExpiryReason::TcpRst:
      stats_.expired_tcp_rst += 1;
      break;
    case ExpiryReason::TcpFin:
      stats_.expired_tcp_fin += 1;
      break;
    case ExpiryReason::Udp:
      stats_.expired_udp += 1;
      break;
    case ExpiryReason::Icmp:
      stats_.expired_icmp += 1;
      break;
    case ExpiryReason::MaxLife:
      stats_.expired_maxlife += 1;
      break;
    case ExpiryReason::OverBytes:
      stats_.expired_overbytes += 1;
      break;
    case ExpiryReason::OverFlows:
      stats_.expired_maxflows += 1;
      break;
    case ExpiryReason::Flush:
      stats_.expired_flush += 1;
      break;
    case ExpiryReason::Collision:
      stats_.expired_collision += 1;
      break;
  }
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord>
FlowTable<Backend>::expire_flows (TimePoint now, bool flush_all) {
  // Original: the flows that were evicted by a collision have expires_at 0,
  // so they are the first to expire.
  std::vector<ExportRecord> expired;
  std::vector<ExportRecord> collided = expire_collisions();

  auto it = expiry_index_.begin();
  while (it != expiry_index_.end() && (flush_all || it->first <= now)) {
    const FlowKey key = it->second;  // copy before the iterator is invalidated

    auto flow_it = flows_.find (key);
    if (flow_it != flows_.end()) {
      record_expiry_stats (flow_it->second, key.protocol(),
                           ExpiryReason::Flush, flush_all);
      expired.push_back (ExportRecord{key, flow_it->second});
      flows_.erase (flow_it);
      forget_slot (key);
    }
    expiry_lookup_.erase (key);
    it = expiry_index_.erase (it);  // erase() returns the next valid iterator
  }

  stats_.flows_expired += expired.size();
  collided.insert (collided.end(), std::make_move_iterator (expired.begin()),
                   std::make_move_iterator (expired.end()));
  return collided;
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord>
FlowTable<Backend>::force_expire_oldest (std::size_t count) {
  std::vector<ExportRecord> expired;
  expired.reserve (count);

  auto it = expiry_index_.begin();
  while (it != expiry_index_.end() && expired.size() < count) {
    const FlowKey key = it->second;

    auto flow_it = flows_.find (key);
    if (flow_it != flows_.end()) {
      record_expiry_stats (flow_it->second, key.protocol(),
                           ExpiryReason::OverFlows, true);
      expired.push_back (ExportRecord{key, flow_it->second});
      flows_.erase (flow_it);
      forget_slot (key);
    }
    expiry_lookup_.erase (key);
    it = expiry_index_.erase (it);
  }

  // Original: a forced flow is expired later like any other, so it is
  // counted in flows_expired too (update_statistics()).
  stats_.flows_expired += expired.size();
  stats_.flows_force_expired += expired.size();
  return expired;
}

template <FlowIndexBackend Backend>
void
FlowTable<Backend>::enable_collision_mode (std::size_t buckets) {
  if constexpr (Backend != FlowIndexBackend::Hash) {
    (void) buckets;
    throw std::logic_error ("collision mode needs the hash backend");
  } else {
    // Original: flow_table_init(). A power of two, capped at 2^24.
    constexpr std::size_t kMaxBuckets = std::size_t{1} << 24;
    std::size_t n = 1;
    while (n < buckets && n < kMaxBuckets) {
      n <<= 1;
    }
    slots_.assign (n, std::nullopt);
  }
}

template <FlowIndexBackend Backend>
void
FlowTable<Backend>::forget_slot (const FlowKey &key) {
  if (slots_.empty()) {
    return;
  }
  auto &slot = slots_[std::hash<FlowKey>{}(key) & (slots_.size() - 1)];
  if (slot.has_value() && *slot == key) {
    slot.reset();
  }
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord>
FlowTable<Backend>::expire_collisions() {
  std::vector<ExportRecord> out;
  out.swap (collided_);
  for (const auto &record : out) {
    record_expiry_stats (record.flow, record.key.protocol(),
                         ExpiryReason::Collision, true);
  }
  stats_.flows_expired += out.size();
  return out;
}

template <FlowIndexBackend Backend>
FlowTableUsage
FlowTable<Backend>::usage() const {
  // Original: flow_table_usage().
  FlowTableUsage u;
  if (!slots_.empty()) {
    u.buckets = slots_.size();
    u.bytes = u.buckets * sizeof (void *);
    for (const auto &slot : slots_) {
      u.used += slot.has_value() ? std::size_t{1} : std::size_t{0};
    }
    u.max_depth = u.used != 0 ? 1 : 0;
    return u;
  }
  if constexpr (Backend == FlowIndexBackend::Hash) {
    u.buckets = flows_.bucket_count();
    u.bytes = u.buckets * sizeof (void *);
    for (std::size_t i = 0; i < u.buckets; ++i) {
      const std::size_t depth = flows_.bucket_size (i);
      u.used += depth != 0 ? std::size_t{1} : std::size_t{0};
      u.max_depth = std::max (u.max_depth, depth);
    }
  } else {
    u.buckets = 1;
    u.bytes = sizeof (void *);
    u.used = flows_.empty() ? 0 : 1;
    u.max_depth = flows_.size();
  }
  return u;
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord>
FlowTable<Backend>::snapshot () const {
  // Original: softflowctl(8)'s dump-flows. A read-only copy of every
  // tracked flow; unlike expire_flows()/force_expire_oldest(), nothing
  // is removed from flows_ or expiry_index_.
  std::vector<ExportRecord> result;
  result.reserve (flows_.size());
  for (const auto &[key, flow] : flows_) {
    result.push_back (ExportRecord{key, flow});
  }
  return result;
}

// Explicit instantiation: this is the one translation unit where
// FlowTable<Hash> and FlowTable<Tree> are actually compiled. Every other
// translation unit only sees the `extern template` declaration in
// softflowd.hpp and links against the definitions generated here -- the
// same "declare in the header, define once in the source file" shape as a
// non-template class, just applied to a template with a closed set of
// instantiations.
template class FlowTable<FlowIndexBackend::Hash>;
template class FlowTable<FlowIndexBackend::Tree>;

// =======================================================================
// FlowTableRuntime
// =======================================================================

// =======================================================================
// FlowTableRuntime
// =======================================================================

FlowTableRuntime::FlowTableRuntime (FlowLookup lookup, std::size_t max_flows,
                                    TrackLevel track_level,
                                    FlowTimeouts timeouts)
    : lookup_ (lookup),
      table_ ([&] () -> std::variant<FlowTable<FlowIndexBackend::Hash>,
                                     FlowTable<FlowIndexBackend::Tree>> {
        switch (lookup) {
          case FlowLookup::HashTree:
            return FlowTable<FlowIndexBackend::Hash> (max_flows, track_level,
                                                      timeouts);
          case FlowLookup::Hash: {
            FlowTable<FlowIndexBackend::Hash> table (max_flows, track_level,
                                                     timeouts);
            // Original: twice max_flows slots in hash mode.
            table.enable_collision_mode (max_flows * 2);
            return table;
          }
          case FlowLookup::Tree:
            return FlowTable<FlowIndexBackend::Tree> (max_flows, track_level,
                                                      timeouts);
        }
        throw std::invalid_argument ("unknown FlowLookup");
      }()) {
}

std::vector<ExportRecord>
FlowTableRuntime::expire_collisions() {
  return std::visit ([] (auto &table) { return table.expire_collisions(); },
                     table_);
}

FlowTableUsage
FlowTableRuntime::usage() const {
  return std::visit ([] (const auto &table) { return table.usage(); }, table_);
}

Flow &
FlowTableRuntime::record_packet (const FlowKey &key, TimePoint now,
                                 std::chrono::system_clock::time_point wall_now,
                                 std::uint8_t direction,
                                 std::uint64_t octet_delta,
                                 std::uint8_t tcp_flags,
                                 std::uint8_t tos) {
  return std::visit (
    [&] (auto &table) -> Flow & {
      return table.record_packet (key, now, wall_now, direction,
                                  octet_delta, tcp_flags, tos);
    },
    table_);
}

std::vector<ExportRecord>
FlowTableRuntime::expire_flows (TimePoint now, bool flush_all) {
  return std::visit (
    [&] (auto &table) { return table.expire_flows (now, flush_all); },
    table_);
}

std::vector<ExportRecord>
FlowTableRuntime::force_expire_oldest (std::size_t count) {
  return std::visit (
    [&] (auto &table) { return table.force_expire_oldest (count); },
    table_);
}

std::vector<ExportRecord>
FlowTableRuntime::snapshot () const {
  return std::visit ([] (const auto &table) { return table.snapshot(); },
                     table_);
}

const FlowTimeouts &
FlowTableRuntime::timeouts () const noexcept {
  return std::visit (
    [] (const auto &table) -> const FlowTimeouts & {
      return table.timeouts();
    },
    table_);
}

std::size_t
FlowTableRuntime::size () const noexcept {
  return std::visit ([] (const auto &table) { return table.size(); }, table_);
}

std::size_t
FlowTableRuntime::max_flows () const noexcept {
  return std::visit ([] (const auto &table) { return table.max_flows(); },
                     table_);
}

const FlowTableStats &
FlowTableRuntime::stats () const noexcept {
  return std::visit (
    [] (const auto &table) -> const FlowTableStats & {
      return table.stats();
    },
    table_);
}

void
FlowTableRuntime::record_export_stats (std::uint64_t flows, std::uint64_t records,
                                       std::uint64_t packets, std::uint64_t failures) noexcept {
  std::visit (
    [&] (auto &table) {
      table.record_export_stats (flows, records, packets, failures);
    },
    table_);
}

TrackLevel
FlowTableRuntime::track_level () const noexcept {
  return std::visit ([] (const auto &table) { return table.track_level(); },
                     table_);
}

FlowIndexBackend
FlowTableRuntime::backend () const noexcept {
  return std::visit ([] (const auto &table) { return table.backend(); },
                     table_);
}

// =======================================================================
// PacketParser (original: softflowd.c's ipv4_to_flowrec() /
//               ipv6_to_flowrec() / transport_to_flowrec())
// =======================================================================

namespace {

std::uint16_t
read_be16 (std::span<const std::uint8_t> data,
           std::size_t offset) {
  return static_cast<std::uint16_t> ((data[offset] << 8) | data[offset + 1]);
}

std::uint32_t
read_be32 (std::span<const std::uint8_t> data,
           std::size_t offset) {
  return (static_cast<std::uint32_t> (data[offset]) << 24) |
         (static_cast<std::uint32_t> (data[offset + 1]) << 16) |
         (static_cast<std::uint32_t> (data[offset + 2]) << 8) |
         static_cast<std::uint32_t> (data[offset + 3]);
}

constexpr std::uint8_t kProtoIcmp = 1;
constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kProtoUdp = 17;
constexpr std::uint8_t kProtoDccp = 33;
constexpr std::uint8_t kProtoSctp = 132;
constexpr std::uint8_t kProtoIcmpV6 = 58;
constexpr std::uint8_t kNextHopByHop = 0;
constexpr std::uint8_t kNextRouting = 43;
constexpr std::uint8_t kNextFragment = 44;
constexpr std::uint8_t kNextDstOptions = 60;

}  // namespace

std::optional<ParsedPacket>
PacketParser::parse (std::span<const std::uint8_t> ip_payload,
                     AddressFamily af) const {
  if (af == AddressFamily::IPv4) {
    return parse_ipv4 (ip_payload);
  }
  if (af == AddressFamily::IPv6) {
    return parse_ipv6 (ip_payload);
  }
  return std::nullopt;
}

std::optional<ParsedPacket>
PacketParser::parse_ipv4 (std::span<const std::uint8_t> data) const {
  // Original: `caplen < 20 || caplen < ip->ip_hl * 4 || ip->ip_v != 4`.
  // Here, each subsequent stage only proceeds once the required length
  // is actually available (a subspan can never read past the end of the
  // span it was taken from).
  if (data.size() < 20) {
    return std::nullopt;  // runt packet
  }
  const std::uint8_t version = static_cast<std::uint8_t> (data[0] >> 4);
  if (version != 4) {
    return std::nullopt;
  }
  const std::size_t header_len =
    static_cast<std::size_t> (data[0] & 0x0F) * 4;
  if (header_len < 20 || data.size() < header_len) {
    return std::nullopt;
  }

  ParsedPacket packet;
  packet.tos = data[1];

  const std::uint16_t frag_field = read_be16 (data, 6);
  packet.is_fragment = (frag_field & 0x3FFF) != 0;
  packet.is_first_fragment = (frag_field & 0x1FFF) == 0;

  packet.protocol =
    track_level_ >= TrackLevel::IpProto ? data[9] : std::uint8_t{0};

  packet.src.family = AddressFamily::IPv4;
  packet.dst.family = AddressFamily::IPv4;
  for (int i = 0; i < 4; ++i) {
    packet.src.bytes[static_cast<std::size_t> (i)] =
      data[12 + static_cast<std::size_t> (i)];
    packet.dst.bytes[static_cast<std::size_t> (i)] =
      data[16 + static_cast<std::size_t> (i)];
  }

  if (track_level_ < TrackLevel::IpProtoPort) {
    packet.tos = 0;
  }

  if (packet.is_first_fragment &&
      track_level_ >= TrackLevel::IpProtoPort) {
    parse_transport (packet, data.subspan (header_len), data[9]);
  }

  return packet;
}

std::optional<ParsedPacket>
PacketParser::parse_ipv6 (std::span<const std::uint8_t> data) const {
  // Original: ipv6_to_flowrec()'s extension-header walk. As noted in
  // softflowd.hpp, the original had a real bug here:
  //   eh6 = (const struct ip6_ext *) pkt + size;
  // Using data.subspan(size), whose offset is unambiguously byte-based by
  // its type signature, prevents the same kind of bug from resurfacing.
  if (data.size() < 40) {
    return std::nullopt;  // runt packet
  }
  const std::uint8_t version = static_cast<std::uint8_t> (data[0] >> 4);
  if (version != 6) {
    return std::nullopt;
  }

  ParsedPacket packet;
  packet.src.family = AddressFamily::IPv6;
  packet.dst.family = AddressFamily::IPv6;
  for (int i = 0; i < 16; ++i) {
    packet.src.bytes[static_cast<std::size_t> (i)] =
      data[8 + static_cast<std::size_t> (i)];
    packet.dst.bytes[static_cast<std::size_t> (i)] =
      data[24 + static_cast<std::size_t> (i)];
  }

  const std::uint32_t vtc_flow = read_be32 (data, 0);
  packet.ip6_flowlabel = vtc_flow & 0x000FFFFFu;
  packet.tos = track_level_ >= TrackLevel::IpProtoPort
                 ? static_cast<std::uint8_t> ((vtc_flow >> 20) & 0xFFu)
                 : std::uint8_t{0};

  std::uint8_t next_header = data[6];
  std::size_t offset = 40;
  packet.is_fragment = false;
  packet.is_first_fragment = true;

  // Original: an unbounded `for (;;) { ... }` loop. It exited via
  // `if (remain < eh6size) return (size);`, but remain was a signed int
  // and could reach exactly 0 without the loop making further progress if
  // eh6size also evaluated to 0 along some path -- a latent
  // infinite-loop risk. Here the loop condition itself guarantees
  // forward progress: it requires at least 8 more bytes to remain before
  // even considering another iteration, so it always terminates.
  while (offset + 8 <= data.size()) {
    if (next_header == kNextHopByHop || next_header == kNextRouting ||
        next_header == kNextDstOptions) {
      const std::uint8_t ext_len_units = data[offset + 1];
      const std::size_t ext_header_size =
        (static_cast<std::size_t> (ext_len_units) + 1) * 8;
      if (offset + ext_header_size > data.size()) {
        return packet;  // runt: return what was parsed so far
      }
      next_header = data[offset];
      offset += ext_header_size;
    } else if (next_header == kNextFragment) {
      packet.is_fragment = true;
      if (offset + 8 > data.size()) {
        return packet;
      }
      const std::uint16_t off_flags = read_be16 (data, offset + 2);
      packet.is_first_fragment = (off_flags >> 3) == 0;
      next_header = data[offset];
      offset += 8;
    } else {
      break;
    }
  }

  packet.protocol =
    track_level_ >= TrackLevel::IpProto ? next_header : std::uint8_t{0};

  if (packet.is_first_fragment && track_level_ >= TrackLevel::IpProtoPort &&
      offset <= data.size()) {
    parse_transport (packet, data.subspan (offset), next_header);
  }

  return packet;
}

// Bytes up to and including a member, as in C's MEMBER_END().
#define SOFTFLOW_MEMBER_END(type, member) \
  (offsetof (type, member) + sizeof (static_cast<type *> (nullptr)->member))

void
PacketParser::parse_transport (
  ParsedPacket &packet, std::span<const std::uint8_t> transport_payload,
  std::uint8_t protocol) const {
  // Original: transport_to_flowrec(). By default only the bytes that are
  // read are required (the ports, the TCP flags, the ICMP type and code);
  // full_l4hdr_check_ (-f) requires the whole header instead. Protocols
  // other than TCP, UDP, DCCP, SCTP, ICMP and ICMPv6 are not looked at.
  std::size_t min_len = 0;
  switch (protocol) {
    case kProtoTcp:
      min_len = full_l4hdr_check_
                  ? sizeof (struct tcphdr)
                  : SOFTFLOW_MEMBER_END (struct tcphdr, th_flags);
      break;
    case kProtoUdp:
      min_len = full_l4hdr_check_
                  ? sizeof (struct udphdr)
                  : SOFTFLOW_MEMBER_END (struct udphdr, uh_dport);
      break;
    case kProtoDccp:
#ifdef SOFTFLOW_HAVE_LINUX_DCCP_H
      min_len = full_l4hdr_check_
                  ? sizeof (struct dccp_hdr)
                  : SOFTFLOW_MEMBER_END (struct dccp_hdr, dccph_dport);
#else
      min_len = SOFTFLOW_MEMBER_END (struct udphdr, uh_dport);
#endif
      break;
    case kProtoSctp:  // no header struct available: ports only
      min_len = SOFTFLOW_MEMBER_END (struct udphdr, uh_dport);
      break;
    case kProtoIcmp:
      min_len = full_l4hdr_check_
                  ? sizeof (struct icmp)
                  : SOFTFLOW_MEMBER_END (struct icmp, icmp_code);
      break;
    case kProtoIcmpV6:
      min_len = full_l4hdr_check_
                  ? sizeof (struct icmp6_hdr)
                  : SOFTFLOW_MEMBER_END (struct icmp6_hdr, icmp6_code);
      break;
    default:
      return;
  }
  if (transport_payload.size() < min_len) {
    return;  // runt packet
  }

  if (protocol == kProtoTcp) {
    packet.tcp_flags = transport_payload[offsetof (struct tcphdr, th_flags)];
  }
  if (protocol == kProtoIcmp || protocol == kProtoIcmpV6) {
    // Original: the Cisco-router-compatible encoding (icmp_type * 256 +
    // icmp_code, stored as the destination port). ICMP and ICMPv6 both
    // start with type and code.
    packet.src_port = 0;
    packet.dst_port = static_cast<std::uint16_t> (
      (static_cast<std::uint16_t> (
         transport_payload[offsetof (struct icmp, icmp_type)])
       << 8) |
      transport_payload[offsetof (struct icmp, icmp_code)]);
  } else {
    // UDP, TCP, DCCP and SCTP all start with the source and destination
    // ports.
    packet.src_port =
      read_be16 (transport_payload, offsetof (struct udphdr, uh_sport));
    packet.dst_port =
      read_be16 (transport_payload, offsetof (struct udphdr, uh_dport));
  }
}

FlowKey
make_flow_key (const ParsedPacket &packet, TrackLevel track_level,
               std::array<std::uint16_t, 2> vlanid,
               std::array<std::array<std::uint8_t, 6>, 2> ethermac) {
  const std::uint8_t tos = track_level >= TrackLevel::FullTos ? packet.tos : 0;
  if (track_level < TrackLevel::FullVlan) {
    vlanid = {0, 0};
  }
  if (track_level < TrackLevel::FullVlanEther) {
    ethermac = {};
  }
  return FlowKey::make_canonical (packet.src, packet.dst, packet.src_port,
                                  packet.dst_port, packet.protocol, tos,
                                  vlanid, ethermac);
}

// =======================================================================
// PcapHandle (original: softflowd.c's main(), which managed pcap_t* by
//             hand)
// =======================================================================

DatalinkKind
classify_datalink (int pcap_dlt) {
  switch (pcap_dlt) {
    case DLT_EN10MB:
      return DatalinkKind::Ethernet;
#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
      return DatalinkKind::LinuxSll;
#endif
    case DLT_RAW:
      return DatalinkKind::Raw;
    case DLT_NULL:
      return DatalinkKind::NullLoop;
#ifdef DLT_LOOP
    case DLT_LOOP:
      return DatalinkKind::NullLoop;
#endif
    default:
      return DatalinkKind::Unsupported;
  }
}

std::size_t
datalink_header_len (DatalinkKind kind) {
  // Original: the DATALINK table's skiplen field.
  switch (kind) {
    case DatalinkKind::Ethernet:
      return 14;
    case DatalinkKind::LinuxSll:
      return 16;
    case DatalinkKind::Raw:
      return 0;
    case DatalinkKind::NullLoop:
      return 4;
    case DatalinkKind::Unsupported:
      return 0;
  }
  return 0;
}

PcapHandle
PcapHandle::open_live (const std::string &device, int snaplen,
                       bool promiscuous,
                       std::chrono::milliseconds read_timeout,
                       std::size_t buffer_bytes) {
  std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
  pcap_t *handle = pcap_create (device.c_str(), errbuf.data());
  if (handle == nullptr) {
    throw PcapError ("pcap_create failed for device '" + device +
                     "': " + errbuf.data());
  }
  // pcap_create()/pcap_activate() is used instead of the legacy
  // pcap_open_live() specifically so buffer_bytes (original: -B) and
  // immediate mode can both be configured; pcap_open_live() offers
  // neither. Original: `logit(LOG_ERR, "pcap_open_live: %s", ebuf);
  // exit(1);` -- here every setup step below throws instead of exiting,
  // matching the rest of this project's RAII/exception-based error
  // handling.
  pcap_set_snaplen (handle, snaplen);
  pcap_set_promisc (handle, promiscuous ? 1 : 0);
  pcap_set_timeout (handle, static_cast<int> (read_timeout.count()));
  // Immediate mode delivers each packet to the application as soon as
  // it's captured, rather than waiting for libpcap's internal buffer to
  // fill or its timeout to elapse. Without this, next_packet() can take
  // up to the full read_timeout to return even when poll() has already
  // reported the underlying descriptor readable -- exactly the kind of
  // latency that would make a live daemon sluggish to react to control
  // commands and signals interleaved with packet processing (see
  // run_live_capture() in softflowd.cpp).
  pcap_set_immediate_mode (handle, 1);
  if (buffer_bytes > 0) {
    pcap_set_buffer_size (handle, static_cast<int> (buffer_bytes));
  }

  const int activate_result = pcap_activate (handle);
  if (activate_result < 0) {
    const std::string err = pcap_geterr (handle);
    pcap_close (handle);
    throw PcapError ("pcap_activate failed for device '" + device +
                     "': " + err);
  }
  return PcapHandle (handle);
}

PcapHandle
PcapHandle::open_offline (const std::string &path) {
  std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
  pcap_t *handle = pcap_open_offline (path.c_str(), errbuf.data());
  if (handle == nullptr) {
    throw PcapError ("pcap_open_offline failed for '" + path +
                     "': " + errbuf.data());
  }
  return PcapHandle (handle);
}

void
PcapHandle::set_filter (const std::string &bpf_expression) {
  struct bpf_program program{};
  if (pcap_compile (handle_.get(), &program, bpf_expression.c_str(), 1,
                    PCAP_NETMASK_UNKNOWN) < 0) {
    throw PcapError (std::string ("pcap_compile failed: ") +
                     pcap_geterr (handle_.get()));
  }
  // Original: forgetting to call `pcap_freecode(&program)` is a
  // low-impact leak, but easy to miss especially on an exception path.
  // A tiny RAII guard makes sure it always runs.
  struct ProgramGuard {
    struct bpf_program *p;
    ~ProgramGuard () {
      pcap_freecode (p);
    }
  } guard{&program};

  if (pcap_setfilter (handle_.get(), &program) < 0) {
    throw PcapError (std::string ("pcap_setfilter failed: ") +
                     pcap_geterr (handle_.get()));
  }
}

std::optional<CapturedPacket>
PcapHandle::next_packet () {
  struct pcap_pkthdr *header = nullptr;
  const u_char *data = nullptr;
  const int result = pcap_next_ex (handle_.get(), &header, &data);

  if (result == 1) {
    CapturedPacket packet;
    // Original: `const u_int8_t *pkt = frame + datalink_size + ...`,
    // always carried alongside a separate `phdr->caplen` variable.
    // std::span combines the two into a single value.
    packet.data = std::span<const std::uint8_t> (
      reinterpret_cast<const std::uint8_t *> (data), header->caplen);
    packet.original_length = header->len;
    packet.timestamp = Clock::now();
    // Original: -a ("adjust time for reading pcap file") switches
    // between using libpcap's own recorded timestamp (phdr->ts, this
    // process's wall clock otherwise) as the reference time for flow
    // expiry when replaying a capture file. Both this process's
    // current time and libpcap's recorded time are always captured
    // here; run_pcap_file()/run_live_capture() (softflowd.cpp) decide
    // which one to actually use based on whether -a was given.
    packet.wall_timestamp = std::chrono::system_clock::from_time_t (header->ts.tv_sec) +
                            std::chrono::microseconds (header->ts.tv_usec);
    return packet;
  }
  if (result == 0) {
    return std::nullopt;  // live-capture read timeout
  }
  if (result == -2) {
    return std::nullopt;  // EOF on an offline file
  }
  // result == -1: an error occurred
  throw PcapError (std::string ("pcap_next_ex failed: ") +
                   pcap_geterr (handle_.get()));
}

// =======================================================================
// ExportDestination / ExportDestinationSet (original: softflowd.c's -n /
// -l / -L / -e / -S handling)
// =======================================================================

ExportDestination::ExportDestination (const std::string &host,
                                      const std::string &port,
                                      TransportKind transport,
                                      std::optional<int> ttl,
                                      const std::string &source_address,
                                      const std::string &send_interface) {
  struct addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  switch (transport) {
    case TransportKind::Udp:
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
      break;
    case TransportKind::Tcp:
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      stream_oriented_ = true;
      break;
    case TransportKind::Sctp:
#ifdef IPPROTO_SCTP
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_SCTP;
      stream_oriented_ = true;
      break;
#else
      throw ExportError (
        "SCTP is not available on this platform (IPPROTO_SCTP is not "
        "declared)");
#endif
  }

  struct addrinfo *result = nullptr;
  const int gai_err = getaddrinfo (host.c_str(), port.c_str(), &hints, &result);
  if (gai_err != 0) {
    throw ExportError ("failed to resolve export destination '" + host +
                       ":" + port + "': " + gai_strerror (gai_err));
  }
  struct AddrinfoGuard {
    struct addrinfo *p;
    ~AddrinfoGuard () {
      freeaddrinfo (p);
    }
  } addrinfo_guard{result};

  fd_ = socket (result->ai_family, result->ai_socktype, result->ai_protocol);
  if (fd_ < 0) {
    throw ExportError ("socket() failed for export destination '" + host +
                       ":" + port + "'");
  }

  if (!source_address.empty()) {
    // Original: -e. Resolve the requested source address in the same
    // family as the destination and bind() to it before connect()ing,
    // so the OS picks the requested address rather than whatever
    // routing would otherwise select.
    struct addrinfo src_hints{};
    src_hints.ai_family = result->ai_family;
    src_hints.ai_socktype = result->ai_socktype;
    struct addrinfo *src_result = nullptr;
    const int src_err = getaddrinfo (source_address.c_str(), nullptr,
                                     &src_hints, &src_result);
    if (src_err == 0) {
      struct AddrinfoGuard src_guard{src_result};
      bind (fd_, src_result->ai_addr, src_result->ai_addrlen);
      // A failed bind() here is intentionally non-fatal: falling
      // back to default source-address selection is preferable to
      // refusing to export at all.
    }
  }

  if (!send_interface.empty()) {
#ifdef SO_BINDTODEVICE
    // Original: -S. Linux-only, as the man page notes.
    setsockopt (fd_, SOL_SOCKET, SO_BINDTODEVICE, send_interface.c_str(),
                static_cast<socklen_t> (send_interface.size()));
#endif
  }

  if (ttl.has_value()) {
    // Original: -L. IPv4 and IPv6 use different setsockopt levels/
    // names for the equivalent setting.
    if (result->ai_family == AF_INET) {
      const int ttl_value = *ttl;
      setsockopt (fd_, IPPROTO_IP, IP_TTL, &ttl_value, sizeof (ttl_value));
      setsockopt (fd_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_value,
                  sizeof (ttl_value));
    } else if (result->ai_family == AF_INET6) {
      const int ttl_value = *ttl;
      setsockopt (fd_, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl_value,
                  sizeof (ttl_value));
      setsockopt (fd_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl_value,
                  sizeof (ttl_value));
    }
  }

  // Original: with tcp/sctp, this connect() actually establishes the
  // long-lived connection the destination is streamed over for the
  // exporter's entire lifetime (matching the original's own behavior);
  // with udp, connect() on a datagram socket just fixes the peer address
  // so later calls can use send() instead of sendto().
  if (connect (fd_, result->ai_addr, result->ai_addrlen) < 0) {
    const std::string err = std::strerror (errno);
    close (fd_);
    fd_ = -1;
    throw ExportError ("connect() failed for export destination '" + host +
                       ":" + port + "': " + err);
  }

  description_ = host + ":" + port;
}

ExportDestination::~ExportDestination () {
  if (fd_ >= 0) {
    close (fd_);
  }
}

ExportDestination::ExportDestination (ExportDestination &&other) noexcept
    : fd_ (other.fd_), stream_oriented_ (other.stream_oriented_),
      description_ (std::move (other.description_)) {
  other.fd_ = -1;
}

ExportDestination &
ExportDestination::operator= (ExportDestination &&other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      close (fd_);
    }
    fd_ = other.fd_;
    stream_oriented_ = other.stream_oriented_;
    description_ = std::move (other.description_);
    other.fd_ = -1;
  }
  return *this;
}

void
ExportDestination::send_packet (const std::vector<std::uint8_t> &packet) const {
  if (fd_ < 0) {
    return;
  }
  if (!stream_oriented_) {
    // A single UDP datagram send either succeeds atomically or fails;
    // there is no partial-send loop to write here the way there is
    // below for tcp/sctp (or for the control socket's
    // read_line()/write_line() in softflowctl.cpp).
    static_cast<void> (send (fd_, packet.data(), packet.size(), 0));
    return;
  }
  // tcp/sctp are stream-oriented: a single send() is not guaranteed to
  // consume the entire buffer, so this loops until it has, the same
  // pattern softflowctl.cpp's write_line() uses for the control socket.
  std::size_t offset = 0;
  while (offset < packet.size()) {
    const ssize_t n =
      send (fd_, packet.data() + offset, packet.size() - offset, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;  // give up silently; a dead collector shouldn't crash the daemon
    }
    offset += static_cast<std::size_t> (n);
  }
}

void
ExportDestinationSet::add (ExportDestination destination) {
  destinations_.push_back (std::move (destination));
}

void
ExportDestinationSet::send_packet (const std::vector<std::uint8_t> &packet,
                                   bool load_balance) {
  if (destinations_.empty()) {
    return;
  }
  if (load_balance) {
    // Original: -l. Successive *export packets* (not individual flow
    // records within a packet) rotate through the configured
    // destinations.
    destinations_[sent_ % destinations_.size()].send_packet (packet);
  } else {
    for (const auto &destination : destinations_) {
      destination.send_packet (packet);
    }
  }
  // Original: send_multi_destinations() counts every packet, so a packet
  // that went to all destinations also advances the rotation.
  ++sent_;
}

}  // namespace softflow

// =======================================================================
// main() (original: softflowd.c's main())
// =======================================================================
#ifndef SOFTFLOW_NO_MAIN

namespace {

// =======================================================================
// Configuration parsing (original: softflowd.c's getopt() loop)
// =======================================================================
//
// Everything in this section exists to give softflowd_cpp the exact same
// command-line grammar as the original softflowd(8) -- same option
// letters, same argument syntax, same defaults -- so that existing
// deployment scripts, init files, and muscle memory keep working
// unchanged. A handful of options are accepted for compatibility but only
// partially implemented (noted where they're parsed, below); this project
// prints a clear warning rather than silently ignoring them.
//
// This project's own additions (the ability to choose the flow-tracking
// data structure, and a couple of testing/debugging conveniences) use
// GNU-style `--long-options` specifically so they cannot collide with any
// of the original's single-letter flags, and are filtered out of argv
// before the original's getopt()-based option string is parsed.

enum class ExportFormat { None,
                          Netflow1,
                          Netflow5,
                          Netflow9,
                          Ipfix,
                          Psamp };

enum class TransportProtocol { Udp,
                               Tcp,
                               Sctp };

enum class TimeFormat { SysUpTime,
                        Seconds,
                        Milliseconds,
                        Microseconds,
                        Nanoseconds };

softflow::IpfixTimeFormat
to_ipfix_time_format (TimeFormat format) {
  switch (format) {
    case TimeFormat::SysUpTime:
      return softflow::IpfixTimeFormat::SysUpTime;
    case TimeFormat::Seconds:
      return softflow::IpfixTimeFormat::Seconds;
    case TimeFormat::Milliseconds:
      return softflow::IpfixTimeFormat::Milliseconds;
    case TimeFormat::Microseconds:
      return softflow::IpfixTimeFormat::Microseconds;
    case TimeFormat::Nanoseconds:
      return softflow::IpfixTimeFormat::Nanoseconds;
  }
  return softflow::IpfixTimeFormat::SysUpTime;
}

const char *
format_name (ExportFormat format) {
  switch (format) {
    case ExportFormat::None:
      return "none";
    case ExportFormat::Netflow1:
      return "netflow1";
    case ExportFormat::Netflow5:
      return "netflow5";
    case ExportFormat::Netflow9:
      return "netflow9";
    case ExportFormat::Ipfix:
      return "ipfix";
    case ExportFormat::Psamp:
      return "psamp";
  }
  return "unknown";
}

const char *
track_level_name (softflow::TrackLevel level) {
  using softflow::TrackLevel;
  switch (level) {
    case TrackLevel::IpOnly:
      return "ip";
    case TrackLevel::IpProto:
      return "proto";
    case TrackLevel::IpProtoPort:
      return "full";
    case TrackLevel::FullTos:
      return "full-tos";
    case TrackLevel::FullVlan:
      return "vlan";
    case TrackLevel::FullVlanEther:
      return "ether";
  }
  return "full";
}

// Original: softflowd.c's -n / -p / -c / -m / -t / -T / -v / -L / etc.
// gathered into one struct rather than threaded through main() as
// individual local variables, since there are simply too many of them for
// that to stay readable. Field-by-field comments note the corresponding
// original option letter.
struct DaemonConfig {
  std::string interface;        // -i
  std::string pcap_file;        // -r
  bool no_promiscuous = false;  // -N

  std::vector<std::pair<std::string, std::string>> destinations;  // -n (host,port)
  bool load_balance = false;                                      // -l
  std::optional<int> ttl;                                         // -L
  std::string source_address;                                     // -e
  std::string send_interface;                                     // -S

  std::string pidfile = softflow::kDefaultPidFilePath;         // -p
  std::string ctl_sock = softflow::kDefaultControlSocketPath;  // -c

  std::size_t max_flows = 8192;  // -m (original default)

  softflow::FlowTimeouts timeouts;          // -t
  std::chrono::seconds expiry_interval{0};  // -t expint (0 = check every cycle)

  bool no_daemonize = false;  // -d
  bool force_ipv6 = false;    // -6
  bool debug = false;         // -D (implies -d and -6, plus extra output)

  softflow::TrackLevel track_level = softflow::TrackLevel::IpProtoPort;  // -T

  ExportFormat export_format = ExportFormat::Netflow5;  // -v (default: version 5)

  TransportProtocol transport = TransportProtocol::Udp;  // -P (udp and tcp implemented; see README for sctp)
  TimeFormat time_format = TimeFormat::SysUpTime;        // -A (sec/milli/micro/nano/sysuptime[default] -- IPFIX/PSAMP only)
  std::uint32_t sampling_rate = 1;                       // -s (1 = every packet, no sampling)
  int snaplen = 65535;                                   // -C
  std::size_t buffer_bytes = 0;                          // -B (0 = let libpcap choose)
  bool bidirectional_ipfix = false;                      // -b (simplified; see README)
  int mpls_labels = 0;                                   // -x (implemented for -v 9/10)
  std::optional<int> psamp_receive_port;                 // -R (implemented; -i only)
  bool adjust_pcap_time = false;                         // -a
  std::chrono::seconds boot_time_reinit{0};              // -I (0 = disabled)
  bool gauge_clock = false;                              // -g
  bool full_l4hdr_check = false;                         // -f
  bool multithread = false;                              // -M
  std::optional<std::array<std::uint8_t, 6>> direction_mac;  // -H

  std::string bpf_filter;  // trailing bpf_expression

  // --- This project's own additions (not part of the original grammar) ---
  softflow::FlowLookup flow_lookup = softflow::FlowLookup::HashTree;      // -F
  std::string export_out;                                                 // --export-out=PATH
  std::optional<std::chrono::seconds> max_runtime;                        // --max-runtime=SECONDS
};

// Original: softflowd command-line arguments that specify a time use a
// sequence of the form time[qualifier][time[qualifier]...], e.g. "10m",
// "1h30m", or a bare number of seconds like "600". Each term is summed.
std::chrono::seconds
parse_time_spec (const std::string &spec) {
  if (spec.empty()) {
    throw std::invalid_argument ("empty time specification");
  }
  long total = 0;
  std::size_t i = 0;
  while (i < spec.size()) {
    const std::size_t digits_start = i;
    while (i < spec.size() && std::isdigit (static_cast<unsigned char> (spec[i]))) {
      ++i;
    }
    if (i == digits_start) {
      throw std::invalid_argument ("invalid time specification: " + spec);
    }
    const long value = std::stol (spec.substr (digits_start, i - digits_start));

    long multiplier = 1;
    if (i < spec.size()) {
      switch (spec[i]) {
        case 's':
        case 'S':
          multiplier = 1;
          ++i;
          break;
        case 'm':
        case 'M':
          multiplier = 60;
          ++i;
          break;
        case 'h':
        case 'H':
          multiplier = 3600;
          ++i;
          break;
        case 'd':
        case 'D':
          multiplier = 86400;
          ++i;
          break;
        case 'w':
        case 'W':
          multiplier = 604800;
          ++i;
          break;
        default:
          throw std::invalid_argument ("invalid time qualifier in: " + spec);
      }
    }
    total += value * multiplier;
  }
  return std::chrono::seconds (total);
}

// Original: -t timeout_name=time. Named timeouts are: general, tcp,
// tcp.rst, tcp.fin, udp, maxlife, expint (see softflowd(8)'s "Timeouts"
// section).
void
apply_timeout_option (DaemonConfig &config, const std::string &spec) {
  const auto eq = spec.find ('=');
  if (eq == std::string::npos) {
    throw std::invalid_argument ("invalid -t argument (expected name=time): " + spec);
  }
  const std::string name = spec.substr (0, eq);
  const auto value = parse_time_spec (spec.substr (eq + 1));

  if (name == "general") {
    config.timeouts.general = value;
  } else if (name == "tcp") {
    config.timeouts.tcp = value;
  } else if (name == "tcp.rst") {
    config.timeouts.tcp_rst = value;
  } else if (name == "tcp.fin") {
    config.timeouts.tcp_fin = value;
  } else if (name == "udp") {
    config.timeouts.udp = value;
  } else if (name == "maxlife") {
    config.timeouts.maximum_lifetime = value;
  } else if (name == "expint") {
    config.expiry_interval = value;
  } else {
    throw std::invalid_argument ("unknown timeout name: " + name);
  }
}

// Original: -T track_level.
softflow::TrackLevel
parse_track_level (const std::string &s) {
  using softflow::TrackLevel;
  if (s == "ip")
    return TrackLevel::IpOnly;
  if (s == "proto")
    return TrackLevel::IpProto;
  if (s == "full")
    return TrackLevel::IpProtoPort;
  if (s == "full-tos")
    return TrackLevel::FullTos;
  if (s == "vlan")
    return TrackLevel::FullVlan;
  if (s == "ether")
    return TrackLevel::FullVlanEther;
  throw std::invalid_argument (
    "unknown track level '" + s +
    "' (expected ip, proto, full, full-tos, vlan, or ether)");
}

// Original: -v netflow_version.
ExportFormat
parse_netflow_version (const std::string &s) {
  if (s == "1")
    return ExportFormat::Netflow1;
  if (s == "5")
    return ExportFormat::Netflow5;
  if (s == "9")
    return ExportFormat::Netflow9;
  if (s == "10")
    return ExportFormat::Ipfix;
  if (s == "psamp")
    return ExportFormat::Psamp;
  throw std::invalid_argument ("unknown NetFlow version '" + s +
                               "' (expected 1, 5, 9, 10, or psamp)");
}

// Original: -P transport_protocol. Only udp is actually implemented in
// this project (see the warning printed in main() if tcp/sctp is
// requested); TCP/SCTP export would need a connection-oriented framing
// layer this project does not yet have.
TransportProtocol
parse_transport_protocol (const std::string &s) {
  if (s == "udp")
    return TransportProtocol::Udp;
  if (s == "tcp")
    return TransportProtocol::Tcp;
  if (s == "sctp")
    return TransportProtocol::Sctp;
  throw std::invalid_argument ("unknown transport protocol '" + s +
                               "' (expected udp, tcp, or sctp)");
}

// Original: -A time_format. Only sec/milli are actually implemented (see
// the warning printed in main() if micro/nano is requested) -- the IPFIX
// abstract data types for microsecond/nanosecond timestamps use an
// NTP-derived fixed-point encoding rather than a plain integer count,
// which this project's exporters don't yet produce.
TimeFormat
parse_time_format (const std::string &s) {
  if (s == "sec")
    return TimeFormat::Seconds;
  if (s == "milli")
    return TimeFormat::Milliseconds;
  if (s == "micro")
    return TimeFormat::Microseconds;
  if (s == "nano")
    return TimeFormat::Nanoseconds;
  throw std::invalid_argument ("unknown time format '" + s +
                               "' (expected sec, milli, micro, or nano)");
}

// Original: -n host:port[,host:port...]. A numeric IPv6 address must be
// bracketed (e.g. "[::1]:4432") to disambiguate its colons from the
// port separator, exactly as the original requires.
std::vector<std::pair<std::string, std::string>>
parse_destinations (const std::string &spec) {
  std::vector<std::pair<std::string, std::string>> result;
  std::size_t pos = 0;
  while (pos <= spec.size()) {
    const auto comma = spec.find (',', pos);
    const std::string token =
      spec.substr (pos, comma == std::string::npos ? std::string::npos
                                                   : comma - pos);
    if (token.empty()) {
      throw std::invalid_argument ("empty destination in -n argument: " + spec);
    }

    std::string host, port;
    if (token.front() == '[') {
      const auto close = token.find (']');
      if (close == std::string::npos) {
        throw std::invalid_argument ("malformed IPv6 destination: " + token);
      }
      host = token.substr (1, close - 1);
      const auto colon = token.find (':', close);
      if (colon == std::string::npos) {
        throw std::invalid_argument ("missing port in destination: " + token);
      }
      port = token.substr (colon + 1);
    } else {
      const auto colon = token.rfind (':');
      if (colon == std::string::npos) {
        throw std::invalid_argument ("missing port in destination: " + token);
      }
      host = token.substr (0, colon);
      port = token.substr (colon + 1);
    }
    result.emplace_back (std::move (host), std::move (port));

    if (comma == std::string::npos) {
      break;
    }
    pos = comma + 1;
  }
  return result;
}

// Original: -6's documented purpose ("force softflowd to track IPv6 flows
// even if the NetFlow export protocol does not support reporting them").
// NetFlow v1 and v5 have no IPv6 record format at all; v9, IPFIX, and
// PSAMP all support IPv6 natively (see netflow9.hpp/ipfix.hpp/psamp.hpp).
bool
should_track_ipv6 (const DaemonConfig &config) {
  if (config.force_ipv6) {
    return true;
  }
  switch (config.export_format) {
    case ExportFormat::Netflow1:
    case ExportFormat::Netflow5:
      return false;
    default:
      return true;
  }
}

// =======================================================================
// write_framed_packets (this project's own --export-out extension)
// =======================================================================
//
// Writes each export packet to `path` with a simple 4-byte big-endian
// length prefix, so a human or a small script can split the file back
// into individual UDP payloads without needing to parse each protocol's
// framing just to find record boundaries. This is specific to this
// project's own debug/demo output file, not part of any of the wire
// protocols themselves, and not part of the original softflowd (which
// only ever sends export packets over the network via -n).
void
write_framed_packets (const std::string &path,
                      const std::vector<std::vector<std::uint8_t>> &packets,
                      bool append) {
  if (packets.empty()) {
    return;
  }
  std::FILE *f = std::fopen (path.c_str(), append ? "ab" : "wb");
  if (f == nullptr) {
    throw std::runtime_error ("failed to open '" + path + "' for writing");
  }
  struct FileCloser {
    std::FILE *file;
    ~FileCloser () {
      if (file != nullptr) {
        std::fclose (file);
      }
    }
  } closer{f};

  for (const auto &pkt : packets) {
    const std::uint32_t len = static_cast<std::uint32_t> (pkt.size());
    const std::uint8_t len_be[4] = {
      static_cast<std::uint8_t> (len >> 24),
      static_cast<std::uint8_t> (len >> 16),
      static_cast<std::uint8_t> (len >> 8),
      static_cast<std::uint8_t> (len),
    };
    std::fwrite (len_be, 1, sizeof (len_be), f);
    std::fwrite (pkt.data(), 1, pkt.size(), f);
  }
}

// Original: pcap_memcpy () and process_packet_loop () with -M. The capture
// loop hands one packet at a time to another thread, which does the flow
// tracking, and waits for it to be finished with the previous packet first.
// The packet is copied because libpcap reuses its buffer.
class PacketProcessor {
public:
  explicit PacketProcessor (
    std::function<void (const softflow::CapturedPacket &)> process)
      : process_ (std::move (process)), thread_ ([this] { run(); }) {
  }

  PacketProcessor (const PacketProcessor &) = delete;
  PacketProcessor &
  operator= (const PacketProcessor &) = delete;

  ~PacketProcessor() {
    {
      std::lock_guard<std::mutex> lock (mutex_);
      stop_ = true;
    }
    cv_.notify_all();
    thread_.join();
  }

  void
  submit (const softflow::CapturedPacket &pkt) {
    std::unique_lock<std::mutex> lock (mutex_);
    idle_cv_.wait (lock, [&] { return !ready_; });
    rethrow();
    storage_.assign (pkt.data.begin(), pkt.data.end());
    packet_ = pkt;
    packet_.data = std::span<const std::uint8_t> (storage_);
    ready_ = true;
    cv_.notify_one();
  }

  // Original: wait_for_packet_loop_idle (). What the processing thread
  // shares with the main thread may be used again after this returns.
  void
  wait_idle () {
    std::unique_lock<std::mutex> lock (mutex_);
    idle_cv_.wait (lock, [&] { return !ready_; });
    rethrow();
  }

private:
  void
  rethrow () {
    if (error_) {
      std::rethrow_exception (std::exchange (error_, nullptr));
    }
  }

  void
  run () {
    std::unique_lock<std::mutex> lock (mutex_);
    for (;;) {
      cv_.wait (lock, [&] { return ready_ || stop_; });
      if (!ready_) {
        return;
      }
      try {
        process_ (packet_);
      } catch (...) {
        error_ = std::current_exception();
      }
      ready_ = false;
      idle_cv_.notify_all();
    }
  }

  std::function<void (const softflow::CapturedPacket &)> process_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::condition_variable idle_cv_;
  std::vector<std::uint8_t> storage_;
  softflow::CapturedPacket packet_{};
  std::exception_ptr error_;
  bool ready_ = false;
  bool stop_ = false;
  std::thread thread_;  // last: it starts using the members above
};

// =======================================================================
// ExportPipeline (original: softflowd.c's per-destination NetFlow/IPFIX/
// PSAMP state and send_multi_destinations())
// =======================================================================
//
// Owns exactly one of the five Stage 3 exporters (selected by -v),
// this run's -n destinations (if any), and this project's own
// --export-out file (if requested). Every place that needs to export
// flows or PSAMP samples goes through this one object instead of
// repeating the "which exporter, which destinations, which file" dispatch
// logic at each call site.
class ExportPipeline {
public:
  ExportPipeline (const DaemonConfig &config, softflow::TimePoint boot_time)
      : format_ (config.export_format), gauge_clock_ (config.gauge_clock),
        multithread_ (config.multithread) {
    const auto transport_kind = [&] {
      switch (config.transport) {
        case TransportProtocol::Udp:
          return softflow::TransportKind::Udp;
        case TransportProtocol::Tcp:
          return softflow::TransportKind::Tcp;
        case TransportProtocol::Sctp:
          return softflow::TransportKind::Sctp;
      }
      return softflow::TransportKind::Udp;
    }();

    for (const auto &[host, port] : config.destinations) {
      try {
        destinations_.add (softflow::ExportDestination (
          host, port, transport_kind, config.ttl,
          config.source_address, config.send_interface));
      } catch (const softflow::ExportError &e) {
        if (config.transport == TransportProtocol::Sctp) {
          // Original: -P sctp. SCTP support depends on kernel
          // module availability, which isn't guaranteed, so a
          // failure here falls back to UDP rather than
          // preventing the daemon from starting at all.
          std::fprintf (stderr,
                        "warning: SCTP export to '%s:%s' failed "
                        "(%s); falling back to udp\n",
                        host.c_str(), port.c_str(), e.what());
          destinations_.add (softflow::ExportDestination (
            host, port, softflow::TransportKind::Udp, config.ttl,
            config.source_address, config.send_interface));
        } else {
          throw;
        }
      }
    }
    load_balance_ = config.load_balance;

    if (!config.export_out.empty()) {
      export_out_ = config.export_out;
      write_framed_packets (export_out_, {}, /*append=*/false);  // truncate/create
    }

    switch (format_) {
      case ExportFormat::Netflow1:
        netflow1_.emplace (boot_time, config.debug);
        break;
      case ExportFormat::Netflow5:
        netflow5_.emplace (boot_time, config.debug);
        break;
      case ExportFormat::Netflow9:
      case ExportFormat::Ipfix:
        // Original: send_netflow_v9() and send_ipfix() share
        // send_ipfix_flows().
        ipfix_.emplace (/*observation_domain_id=*/0,
                        static_cast<std::uint8_t> (config.mpls_labels),
                        to_ipfix_time_format (config.time_format),
                        config.bidirectional_ipfix, boot_time,
                        std::chrono::system_clock::now(),
                        format_ == ExportFormat::Netflow9
                          ? softflow::MessageVersion::NetFlow9
                          : softflow::MessageVersion::Ipfix,
                        /*if_index=*/0, config.sampling_rate, config.track_level);
        if (config.direction_mac.has_value() &&
            config.track_level >= softflow::TrackLevel::FullVlanEther) {
          ipfix_->set_direction_mac (*config.direction_mac);
        }
        if (!config.source_address.empty()) {
          ipfix_->set_exporter_addresses (
            softflow::resolve_exporter_addresses (config.source_address));
        }
        break;
      case ExportFormat::Psamp:
        psamp_.emplace (/*observation_domain_id=*/0,
                        to_ipfix_time_format (config.time_format));
        break;
      case ExportFormat::None:
        break;
    }
  }

  // True if there is anywhere for export packets to actually go
  // (a real -n destination and/or this project's --export-out file).
  // Original: with no -n, softflowd runs in "statistics gathering
  // mode only" -- flows are still tracked and expired, but no export
  // packets are built or sent at all.
  ExportPipeline (const ExportPipeline &) = delete;
  ExportPipeline &
  operator= (const ExportPipeline &) = delete;

  ~ExportPipeline() {
    // Original: wait_for_export_threads () before the process exits.
    if (worker_.joinable()) {
      {
        std::lock_guard<std::mutex> lock (queue_mutex_);
        stop_ = true;
      }
      queue_cv_.notify_all();
      worker_.join();
    }
  }

  // Original: wait_for_export_threads (). Blocks until every export that
  // was queued by -M has been sent.
  void
  wait_idle () {
    std::unique_lock<std::mutex> lock (queue_mutex_);
    idle_cv_.wait (lock, [&] { return queue_.empty() && !busy_; });
  }

  // Moves what the export thread has sent since the last call into the
  // statistics of the flow table; a no-op without -M.
  template <typename Table>
  void
  sync_stats (Table &table) {
    ExportOutcome o;
    {
      std::lock_guard<std::mutex> lock (queue_mutex_);
      o = async_outcome_;
      async_outcome_ = {};
    }
    if (o.flows != 0 || o.records != 0 || o.packets != 0 || o.failures != 0) {
      table.record_export_stats (o.flows, o.records, o.packets, o.failures);
    }
  }

  bool
  has_sink () const noexcept {
    return !destinations_.empty() || !export_out_.empty();
  }

  bool
  wants_flows () const noexcept {
    return has_sink() && format_ != ExportFormat::Psamp &&
           format_ != ExportFormat::None;
  }
  bool
  wants_samples () const noexcept {
    return has_sink() && format_ == ExportFormat::Psamp;
  }

  // Original: softflowctl(8)'s send-template ("Has no effect for other
  // flow export versions" besides NetFlow v9). Returns true if this
  // pipeline was actually able to honor the request (i.e. is running
  // NetFlow v9), so the control-command handler can report accurately
  // whether anything happened.
  bool
  resend_template () {
    std::lock_guard<std::mutex> state_lock (state_mutex_);
    if (ipfix_.has_value()) {
      ipfix_->force_template_resend();
      return true;
    }
    return false;
  }

  // Original: -I boot_time_reinit periodic reset, driven by the main
  // loop's expiry-check cadence. No-op for exporters that don't use
  // boot_time (PSAMP; IPFIX's SysUpTime encoding uses it too, but is
  // reinitialized here alongside the others).
  void
  reinit_boot_time (softflow::TimePoint now,
                    std::chrono::system_clock::time_point wall_now =
                      std::chrono::system_clock::now()) {
    std::lock_guard<std::mutex> state_lock (state_mutex_);
    if (netflow1_.has_value())
      netflow1_->set_boot_time (now);
    if (netflow5_.has_value())
      netflow5_->set_boot_time (now);
    if (ipfix_.has_value()) {
      ipfix_->set_boot_time (now, wall_now);
    }
  }

  // flows/records/packets/failures actually sent, so the caller can
  // report them into FlowTableStats (see FlowTable::record_export_stats).
  struct ExportOutcome {
    std::uint64_t flows = 0;
    std::uint64_t records = 0;
    std::uint64_t packets = 0;
    std::uint64_t failures = 0;
  };

  std::clock_t
  export_clocks () const {
    return export_clocks_;
  }

  unsigned long
  export_calls () const {
    return export_calls_;
  }

  // Original: with -M the expired flows are copied and sent by another
  // thread. A single export thread keeps the packets, and so the sequence
  // numbers, in order. The outcome is then reported later, by sync_stats ().
  ExportOutcome
  export_flows (const std::vector<softflow::ExportRecord> &records,
                softflow::TimePoint now,
                std::chrono::system_clock::time_point wall_now) {
    if (!multithread_) {
      return export_now (records, now, wall_now);
    }
    if (records.empty() || !wants_flows()) {
      return {};
    }
    {
      std::lock_guard<std::mutex> lock (queue_mutex_);
      if (!worker_.joinable()) {
        worker_ = std::thread ([this] { export_thread(); });
      }
      queue_.push_back (Job{records, now, wall_now});
    }
    queue_cv_.notify_one();
    return {};
  }

  struct Job {
    std::vector<softflow::ExportRecord> records;
    softflow::TimePoint now;
    std::chrono::system_clock::time_point wall_now;
  };

  void
  export_thread () {
    std::unique_lock<std::mutex> lock (queue_mutex_);
    for (;;) {
      queue_cv_.wait (lock, [&] { return stop_ || !queue_.empty(); });
      if (queue_.empty()) {
        return;  // stopped and drained
      }
      Job job = std::move (queue_.front());
      queue_.pop_front();
      busy_ = true;
      lock.unlock();
      const ExportOutcome o = export_now (job.records, job.now, job.wall_now);
      lock.lock();
      async_outcome_.flows += o.flows;
      async_outcome_.records += o.records;
      async_outcome_.packets += o.packets;
      async_outcome_.failures += o.failures;
      busy_ = false;
      idle_cv_.notify_all();
    }
  }

  ExportOutcome
  export_now (const std::vector<softflow::ExportRecord> &records,
              softflow::TimePoint now,
              std::chrono::system_clock::time_point wall_now) {
    std::lock_guard<std::mutex> state_lock (state_mutex_);
    if (records.empty() || !wants_flows()) {
      return {};
    }
    // Original: -g also reports the CPU clocks spent in the export function.
    struct ExportClock {
      bool enabled;
      std::clock_t &total;
      unsigned long &calls;
      std::clock_t start;
      ~ExportClock() {
        if (enabled) {
          total += std::clock() - start;
          ++calls;
        }
      }
    } export_clock{gauge_clock_, export_clocks_, export_calls_,
                   gauge_clock_ ? std::clock() : 0};
    std::vector<std::vector<std::uint8_t>> packets;
    std::vector<std::size_t> template_only;
    switch (format_) {
      case ExportFormat::Netflow1:
        packets = netflow1_->build_packets (records, now, wall_now);
        break;
      case ExportFormat::Netflow5:
        packets = netflow5_->build_packets (records, now, wall_now);
        break;
      case ExportFormat::Netflow9:
      case ExportFormat::Ipfix:
        // Original: with -l and several destinations the templates go to
        // all of them in a packet of their own.
        packets = ipfix_->build_packets (
          records, now, wall_now,
          load_balance_ && destinations_.size() > 1 ? &template_only : nullptr);
        break;
      case ExportFormat::Psamp:
      case ExportFormat::None:
        break;
    }
    dispatch (packets, template_only);
    // Original: NetFlow v1/v5/v9 and IPFIX (non-biflow) each split a
    // single (bidirectional) internal flow into up to two exported
    // records -- one per direction that actually carried traffic
    // (softflowd.c's `if (flows[i]->octets[0] > 0) {...}` /
    // `octets[1] > 0` in compat/netflow5.c, mirrored by this project's own
    // flatten() helpers in netflow1.cpp/netflow5.cpp/netflow9.cpp/
    // ipfix.cpp). So "records sent" is *not* the same as the number
    // of input flows -- count directions with packets independently.
    std::uint64_t record_count = 0;
    for (const auto &r : records) {
      record_count += (r.flow.packets[0] > 0 ? 1u : 0u) +
                      (r.flow.packets[1] > 0 ? 1u : 0u);
    }
    // No per-record encoding failures are currently detectable, and
    // send_packet() doesn't report per-destination failures -- so
    // failures is always 0 for now.
    //
    // Original: compat/netflow5.c's send_netflow_v5_v1() (used for both -v1
    // and -v5) increments *both* `flows_exported` and `records_sent`
    // via the *same* per-record `j++` -- i.e. for those two formats,
    // "flows exported" and "records sent" are identical counts, not
    // flows-before-splitting vs records-after.
    //
    // compat/netflow9.c's send_netflow_v9() and export_common.c's
    // send_ipfix_flows() do NOT follow this: their outer packing
    // loop does `j += i;` where `i` is the index over the *original*
    // (pre-split) flows array, while `records_sent`/`nf9->flows`
    // separately accumulate the actual per-direction record count
    // returned by nf_flow_to_flowset()/ipfix_flow_to_flowset(). So
    // for v9/IPFIX, "flows exported" counts original flows and
    // "records sent" counts post-split records -- these two counts
    // genuinely differ whenever any flow has traffic in both
    // directions, unlike v1/v5.
    const bool flows_equals_records =
      format_ == ExportFormat::Netflow1 || format_ == ExportFormat::Netflow5;
    const std::uint64_t flow_count =
      flows_equals_records ? record_count : records.size();
    return ExportOutcome{flow_count, record_count, packets.size(), 0};
  }

  void
  export_samples (const std::vector<softflow::SampledPacket> &samples,
                  softflow::TimePoint now,
                  std::chrono::system_clock::time_point wall_now) {
    if (samples.empty() || !wants_samples()) {
      return;
    }
    auto packets = psamp_->build_packets (samples, now, wall_now);
    dispatch (packets);
  }

private:
  void
  dispatch (const std::vector<std::vector<std::uint8_t>> &packets,
            const std::vector<std::size_t> &to_all_destinations = {}) {
    if (packets.empty()) {
      return;
    }
    for (std::size_t i = 0; i < packets.size(); ++i) {
      // A template-only packet goes to every destination even with -l.
      const bool to_all =
        std::find (to_all_destinations.begin(), to_all_destinations.end(), i) !=
        to_all_destinations.end();
      destinations_.send_packet (packets[i], load_balance_ && !to_all);
    }
    if (!export_out_.empty()) {
      write_framed_packets (export_out_, packets, /*append=*/true);
    }
  }

  ExportFormat format_;
  bool gauge_clock_;
  bool multithread_;
  std::clock_t export_clocks_ = 0;
  unsigned long export_calls_ = 0;
  std::string export_out_;

  // -M: the queue of the export thread. state_mutex_ protects the exporters
  // against the template and boot time requests of the main thread.
  std::mutex state_mutex_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::condition_variable idle_cv_;
  std::deque<Job> queue_;
  ExportOutcome async_outcome_;
  bool stop_ = false;
  bool busy_ = false;
  std::thread worker_;
  softflow::ExportDestinationSet destinations_;
  bool load_balance_ = false;
  std::optional<softflow::Netflow1Exporter> netflow1_;
  std::optional<softflow::Netflow5Exporter> netflow5_;
  std::optional<softflow::IpfixExporter> ipfix_;
  std::optional<softflow::PsampExporter> psamp_;
};

// Original: -x number_of_mpls_labels. An MPLS-encapsulated frame (EtherType
// 0x8847 unicast / 0x8848 multicast) carries one or more 4-byte label
// stack entries before the actual IP header; there is no explicit
// "next protocol" field, so -- following the same convention other MPLS-
// aware tools use -- the IP version nibble of the first byte after the
// label stack determines whether what follows is IPv4 or IPv6.
// Original: `tmp.mplsLabels[i] = *(((const u_int32_t *) (frame +
// datalink_size)) + i);` -- a raw, NOT byte-swapped, 4-byte memory copy of
// each MPLS shim header straight from the wire into a u_int32_t. Read
// this way (no ntohl()) and later written out the same way (another raw
// memcpy(), not htonl()) in ipfix_flow_to_flowset(), the net effect
// cancels out to a verbatim pass-through of the original wire bytes' top
// 3 octets (label(20 bits) | EXP(3 bits) | S(1 bit), dropping only the
// TTL octet) into the IPFIX mplsTopLabelStackSectionN field -- see
// ipfix.cpp's write_mpls_labels(). So `section` here is exactly those
// top 3 octets (bits 31-8 of the 4-byte shim), stored verbatim rather
// than decomposed into a label number, so it can be passed through
// unchanged instead of needing to be (incompletely -- see the EXP bits)
// reconstructed at export time.
struct MplsShimEntry {
  std::uint32_t section;  // top 3 octets of the shim: label(20)|EXP(3)|S(1)
  bool bottom_of_stack;
};

// Parses consecutive 4-byte MPLS label stack entries from the front of
// `data`, stopping at the entry with the bottom-of-stack (S) bit set.
// Returns std::nullopt for a truncated or pathologically deep (more than
// 32 entries -- comfortably beyond anything a real network would ever
// impose) label stack, the same way the rest of this project's parsing
// functions signal "not a well-formed packet" rather than reading past
// the end of `data`.
std::optional<std::vector<MplsShimEntry>>
parse_mpls_label_stack (std::span<const std::uint8_t> data, std::size_t &consumed) {
  std::vector<MplsShimEntry> labels;
  std::size_t offset = 0;
  for (;;) {
    if (offset + 4 > data.size()) {
      return std::nullopt;  // truncated label stack
    }
    const std::uint32_t shim =
      (static_cast<std::uint32_t> (data[offset]) << 24) |
      (static_cast<std::uint32_t> (data[offset + 1]) << 16) |
      (static_cast<std::uint32_t> (data[offset + 2]) << 8) |
      static_cast<std::uint32_t> (data[offset + 3]);
    const bool bottom = (shim & 0x00000100u) != 0;  // the S bit
    labels.push_back (MplsShimEntry{shim >> 8, bottom});
    offset += 4;
    if (bottom) {
      break;
    }
    if (labels.size() > 32) {
      return std::nullopt;  // implausibly deep; treat as malformed
    }
  }
  consumed = offset;
  return labels;
}

struct FrameClassification {
  softflow::AddressFamily af;
  std::size_t ip_offset;                   // bytes to skip, from the start of ip_bytes, to reach the IP header
  std::vector<std::uint32_t> mpls_labels;  // outermost label first; empty if not MPLS-encapsulated
  std::size_t vlan_size = 0;               // 4 for an 802.1Q tagged Ethernet frame
  std::uint16_t vlanid = 0;
  std::array<std::array<std::uint8_t, 6>, 2> ethermac{};  // source, destination
};

// Shared by run_pcap_file() and run_live_capture(): classifies one
// captured frame's address family (and, for MPLS-encapsulated frames, its
// label stack) from its data-link header, mapping the original DATALINK
// table's ft_off/ft_len fields onto this project's DatalinkKind.
std::optional<FrameClassification>
classify_frame (const softflow::CapturedPacket &pkt, softflow::DatalinkKind dl_kind,
                std::span<const std::uint8_t> ip_bytes) {
  using namespace softflow;
  if (dl_kind == DatalinkKind::Ethernet) {
    if (pkt.data.size() < 14) {
      return std::nullopt;
    }
    FrameClassification frame;
    // Original: ether_to_flowrec() -- the frame's source and destination.
    std::copy_n (pkt.data.begin() + 6, 6, frame.ethermac[0].begin());
    std::copy_n (pkt.data.begin(), 6, frame.ethermac[1].begin());
    std::uint16_t ethertype =
      static_cast<std::uint16_t> ((pkt.data[12] << 8) | pkt.data[13]);
    if (ethertype == 0x8100) {
      // Original: datalink_check() reads the 802.1Q tag, keeps the VID
      // without the PCP and DEI bits, and looks at the encapsulated type.
      if (pkt.data.size() < 18) {
        return std::nullopt;
      }
      frame.vlanid =
        static_cast<std::uint16_t> (((pkt.data[14] << 8) | pkt.data[15]) & 0xFFF);
      frame.vlan_size = 4;
      ethertype =
        static_cast<std::uint16_t> ((pkt.data[16] << 8) | pkt.data[17]);
    }
    ip_bytes = ip_bytes.subspan (std::min (frame.vlan_size, ip_bytes.size()));
    if (ethertype == 0x0800) {
      frame.af = AddressFamily::IPv4;
      frame.ip_offset = frame.vlan_size;
      return frame;
    }
    if (ethertype == 0x86dd) {
      frame.af = AddressFamily::IPv6;
      frame.ip_offset = frame.vlan_size;
      return frame;
    }
    if (ethertype == 0x8847 || ethertype == 0x8848) {
      std::size_t consumed = 0;
      auto shim_entries = parse_mpls_label_stack (ip_bytes, consumed);
      if (!shim_entries.has_value() || consumed >= ip_bytes.size()) {
        return std::nullopt;
      }
      frame.mpls_labels.reserve (shim_entries->size());
      for (const auto &entry : *shim_entries) {
        frame.mpls_labels.push_back (entry.section);
      }
      frame.af = (ip_bytes[consumed] >> 4) == 6 ? AddressFamily::IPv6
                                                : AddressFamily::IPv4;
      frame.ip_offset = frame.vlan_size + consumed;
      return frame;
    }
    return std::nullopt;  // not an IP (or MPLS-encapsulated IP) frame
  }
  if (ip_bytes.empty()) {
    return std::nullopt;
  }
  const AddressFamily af =
    (ip_bytes[0] >> 4) == 6 ? AddressFamily::IPv6 : AddressFamily::IPv4;
  return FrameClassification{af, 0, {}, 0, 0, {}};
}

// =======================================================================
// Original: softflowd.c's statistics(), called only when reading from a
// pcap file (-r) in foreground mode (-d) -- see the call site in
// run_pcap_file() below. Formatting intentionally mirrors the C version.
void
print_statistics (const softflow::FlowTableStats &s, std::size_t active_flows,
                  softflow::FlowLookup lookup,
                  const softflow::FlowTableUsage &usage,
                  std::FILE *out, const softflow::PcapHandle &handle) {
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

  if (lookup != softflow::FlowLookup::Tree) {
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
                  softflow::flow_lookup_name (lookup), usage.buckets, size,
                  usage.used, usage.max_depth,
                  static_cast<unsigned long long> (s.expired_collision));
  }

  if (auto ps = handle.stats(); ps.has_value()) {
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
  if (lookup == softflow::FlowLookup::Hash) {
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

// run_pcap_file (original: softflowd.c's -r mode -- process a capture
// file in a single pass, then print statistics and exit without forking)
// =======================================================================
// Original: softflowd.c's format_ethermac().
std::string
format_ethermac (const std::array<std::uint8_t, 6> &mac) {
  char buf[32];
  std::snprintf (buf, sizeof (buf), "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0],
                 mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

// Original: softflowd.c's format_time() -- gmtime + "%Y-%m-%dT%H:%M:%S".
std::string
format_time (std::chrono::system_clock::time_point t) {
  const std::time_t tt = std::chrono::system_clock::to_time_t (t);
  struct tm tm_buf{};
  gmtime_r (&tt, &tm_buf);
  char buf[32];
  std::strftime (buf, sizeof (buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
  return buf;
}

std::string
format_address (const softflow::IpAddress &addr);

// Original: softflowd.c's format_flow_brief() -- used by the "ADD FLOW"
// debug log line (-D).
std::string
format_flow_brief (std::uint64_t flow_seq,
                   const softflow::FlowKey &key) {
  char buf[256];
  std::snprintf (
    buf, sizeof (buf),
    "seq:%llu [%s]:%hu <> [%s]:%hu proto:%u vlan>:%u vlan<:%u  ether:%s <> %s ",
    static_cast<unsigned long long> (flow_seq),
    format_address (key.addr()[0]).c_str(), key.port()[0],
    format_address (key.addr()[1]).c_str(), key.port()[1],
    static_cast<unsigned> (key.protocol()), key.vlanid()[0], key.vlanid()[1],
    format_ethermac (key.ethermac()[0]).c_str(),
    format_ethermac (key.ethermac()[1]).c_str());
  return buf;
}

// Original: softflowd.c's format_flow() -- used by the "EXPIRED" debug
// log line (-D). Note flow_start.tv_usec/flow_last.tv_usec in the
// original are rounded to milliseconds via `(usec + 500) / 1000`; this
// project's TimePoint doesn't retain sub-millisecond precision from the
// pcap timestamp the same way internally, so milliseconds are derived
// from the TimePoint's own duration instead of a separate usec field.
std::string
format_flow (const softflow::FlowKey &key,
             const softflow::Flow &flow) {
  using namespace std::chrono;
  const auto start_wall = flow.wall_start;
  const auto last_wall = flow.wall_last;
  // Original: `(flow->flow_start.tv_usec + 500) / 1000` -- round to the
  // nearest millisecond (not truncate), matching this exactly.
  const auto start_usec =
    duration_cast<microseconds> (start_wall.time_since_epoch()).count() % 1000000;
  const auto last_usec =
    duration_cast<microseconds> (last_wall.time_since_epoch()).count() % 1000000;
  const auto start_ms = (start_usec + 500) / 1000;
  const auto last_ms = (last_usec + 500) / 1000;

  char buf[512];
  std::snprintf (
    buf, sizeof (buf),
    "seq:%llu [%s]:%hu <> [%s]:%hu proto:%u "
    "octets>:%llu packets>:%llu octets<:%llu packets<:%llu "
    "start:%s.%03lld finish:%s.%03lld tcp>:%02x tcp<:%02x "
    "flowlabel>:%08x flowlabel<:%08x "
    "vlan>:%u vlan<:%u ether:%s <> %s",
    static_cast<unsigned long long> (flow.flow_seq),
    format_address (key.addr()[0]).c_str(), key.port()[0],
    format_address (key.addr()[1]).c_str(), key.port()[1],
    static_cast<unsigned> (key.protocol()),
    static_cast<unsigned long long> (flow.octets[0]),
    static_cast<unsigned long long> (flow.packets[0]),
    static_cast<unsigned long long> (flow.octets[1]),
    static_cast<unsigned long long> (flow.packets[1]),
    format_time (start_wall).c_str(), static_cast<long long> (start_ms),
    format_time (last_wall).c_str(), static_cast<long long> (last_ms),
    flow.tcp_flags[0], flow.tcp_flags[1], flow.ip6_flowlabel_a,
    flow.ip6_flowlabel_b, key.vlanid()[0], key.vlanid()[1],
    format_ethermac (key.ethermac()[0]).c_str(),
    format_ethermac (key.ethermac()[1]).c_str());
  return buf;
}

// Original: softflowd.c's check_expired(), whose -D (verbose_flag) debug
// output this reproduces exactly: "Starting expiry scan: mode %d" before
// the scan, "Queuing flow seq:... (%p) for expiry reason %d" per flow
// found to be expiring, "Finished scan %d flow(s) to be evicted"
// afterward, "sent %d netflow packets" once export has been attempted
// (if there was anything to send), and "EXPIRED: %s (%p)" (the *verbose*
// format_flow(), not format_flow_brief()) per expired flow. mode mirrors
// the original's CE_EXPIRE_NORMAL(0)/CE_EXPIRE_ALL(-1)/
// CE_EXPIRE_FORCED(1).
void
log_expiry_debug_start (bool debug, int mode) {
  if (debug) {
    std::fprintf (stderr, "Starting expiry scan: mode %d\n", mode);
  }
}

void
log_expiry_debug_queued (bool debug, const std::vector<softflow::ExportRecord> &expired) {
  if (!debug) {
    return;
  }
  for (const auto &record : expired) {
    std::fprintf (stderr, "Queuing flow seq:%llu (%p) for expiry reason %d\n",
                  static_cast<unsigned long long> (record.flow.flow_seq),
                  static_cast<const void *> (&record.flow),
                  static_cast<int> (record.flow.reason));
  }
  std::fprintf (stderr, "Finished scan %zu flow(s) to be evicted\n", expired.size());
}

void
log_expiry_debug_sent (bool debug, int packets_sent) {
  if (debug) {
    std::fprintf (stderr, "sent %d netflow packets\n", packets_sent);
  }
}

void
log_expiry_debug_expired (bool debug, const std::vector<softflow::ExportRecord> &expired) {
  if (!debug) {
    return;
  }
  for (const auto &record : expired) {
    std::fprintf (stderr, "EXPIRED: %s (%p)\n",
                  format_flow (record.key, record.flow).c_str(),
                  static_cast<const void *> (&record.flow));
  }
}

// Original: softflowd.c's CE_EXPIRE_NORMAL(0)/CE_EXPIRE_ALL(-1)/
// CE_EXPIRE_FORCED(1), passed to check_expired() and echoed in its
// "Starting expiry scan: mode %d" debug line.
constexpr int kCeExpireNormal = 0;
constexpr int kCeExpireAll = -1;
constexpr int kCeExpireForced = 1;

int
run_pcap_file (const DaemonConfig &config) {
  using namespace softflow;

  PcapHandle handle = PcapHandle::open_offline (config.pcap_file);
  if (!config.bpf_filter.empty()) {
    handle.set_filter (config.bpf_filter);
  }
  const auto dl_kind = handle.datalink_kind();
  if (dl_kind == DatalinkKind::Unsupported) {
    std::fprintf (stderr, "unsupported datalink type (pcap_datalink=%d)\n",
                  handle.datalink());
    return 1;
  }
  const std::size_t skip = datalink_header_len (dl_kind);

  PacketParser parser (config.track_level, config.full_l4hdr_check);
  FlowTableRuntime table (config.flow_lookup, config.max_flows, config.track_level,
                          config.timeouts);
  const TimePoint boot_time = Clock::now();
  ExportPipeline exporter (config, boot_time);
  TimePoint system_boot_time = boot_time;       // mutable copy, tracks -I reinit
  const std::clock_t cpu_start = std::clock();  // -g

  // Original: softflowd.c's startup logit() calls (logit(LOG_NOTICE,
  // "%s v%s starting data collection", PROGNAME, PROGVER); plus one
  // "Exporting flows from %s to [%s]:%s" per destination). Mirrored
  // here (full pcap path, not truncated to IFNAMSIZ like the original)
  // so the two implementations' output is easy to diff line-for-line.
  // Original: `logit(LOG_NOTICE, "%s v%s starting data collection",
  // PROGNAME, PROGVER);`
  std::fprintf (stderr, "%s v%s starting data collection\n",
                SOFTFLOWDPP_NAME, SOFTFLOWDPP_VERSION);
  for (const auto &[host, port] : config.destinations) {
    std::fprintf (stderr, "Exporting flows from %s to [%s]:%s\n",
                  config.pcap_file.c_str(), host.c_str(), port.c_str());
  }

  bool time_base_established = false;
  TimePoint time_base_mono{};
  std::chrono::system_clock::time_point time_base_wall{};

  // Original: SET_EXPORT_NOW(). With -a the export time is the time of the
  // last packet read from the file instead of this process's clock.
  TimePoint last_packet_mono{};
  std::chrono::system_clock::time_point last_packet_wall{};

  std::vector<SampledPacket> pending_samples;
  std::uint64_t total = 0;
  std::uint64_t parsed_ok = 0;
  std::uint32_t sample_counter = 0;

  // Original: softflowd.c's main loop reads a capture file with
  // pcap_dispatch(pcap, max_flows, ...), so the table is checked only after
  // every max_flows packets (and after the last, shorter batch); a table
  // that is over max_flows is then reduced by force-expiring the oldest
  // flows. No time-based expiry happens mid-file.
  std::uint64_t batch_packets = 0;
  const auto force_expire_over_max = [&] () {
    // Original: check_expired() also expires the flows that were evicted by
    // a collision, which are due at once.
    if (auto collided = table.expire_collisions(); !collided.empty()) {
      const auto outcome =
        config.adjust_pcap_time
          ? exporter.export_flows (collided, last_packet_mono, last_packet_wall)
          : exporter.export_flows (collided, last_packet_mono,
                                   std::chrono::system_clock::now());
      table.record_export_stats (outcome.flows, outcome.records,
                                 outcome.packets, outcome.failures);
    }
    if (table.size() <= table.max_flows()) {
      return;
    }
    log_expiry_debug_start (config.debug, kCeExpireForced);
    const auto forced =
      table.force_expire_oldest (table.size() - table.max_flows());
    log_expiry_debug_queued (config.debug, forced);
    const auto outcome =
      config.adjust_pcap_time
        ? exporter.export_flows (forced, last_packet_mono,
                                 last_packet_wall)
        : exporter.export_flows (forced, last_packet_mono,
                                 std::chrono::system_clock::now());
    table.record_export_stats (outcome.flows, outcome.records,
                               outcome.packets, outcome.failures);
    log_expiry_debug_sent (config.debug, static_cast<int> (outcome.packets));
    log_expiry_debug_expired (config.debug, forced);
  };

  while (auto pkt = handle.next_packet()) {
    if (batch_packets != 0 && batch_packets % table.max_flows() == 0) {
      force_expire_over_max();
    }
    ++batch_packets;
    ++total;
    if (pkt->data.size() <= skip) {
      continue;
    }
    const auto ip_bytes = pkt->data.subspan (skip);

    const auto frame = classify_frame (*pkt, dl_kind, ip_bytes);
    if (!frame.has_value()) {
      continue;
    }
    if (frame->af == AddressFamily::IPv6 && !should_track_ipv6 (config)) {
      continue;
    }

    auto parsed = parser.parse (ip_bytes.subspan (frame->ip_offset), frame->af);
    if (!parsed.has_value()) {
      continue;
    }
    ++parsed_ok;

    // Original: -s sampling_rate. A systematic 1-in-N sample: every
    // Nth successfully parsed packet is processed, the rest are
    // discarded outright (counts are not scaled up to compensate,
    // matching the original's behavior).
    if (config.sampling_rate > 1) {
      // Original: `(total_packets + non_sampled_packets) % sample > 0`
      // is tested before the packet is counted, so the first packet
      // is the first one that is kept.
      if ((sample_counter++ % config.sampling_rate) != 0) {
        continue;
      }
    }

    // Original: softflowd.c's process_packet() *always* sources
    // flow->flow_start/flow->flow_last from phdr->ts (the pcap file's
    // own recorded timestamp) via PCAP_TS_TO_TIMEVAL -- this is not
    // conditional on -a. (-a/adjust_time only affects the separate
    // system_boot_time/last_packet_time fields used for uptime-style
    // export encoding, not per-flow timing.) So effective_time must
    // always be derived from the file's own timestamps here, not from
    // this process's wall clock -- otherwise flow durations reflect
    // how fast this process reads the file instead of the capture's
    // real elapsed time. The very first packet establishes the mapping
    // between the pcap file's timestamps and this process's monotonic
    // clock; every subsequent packet's effective_time is that anchor
    // plus its own delta from the first packet's recorded time.
    if (!time_base_established) {
      time_base_mono = Clock::now();
      time_base_wall = pkt->wall_timestamp;
      time_base_established = true;
      if (config.adjust_pcap_time) {
        // Original: -a makes the first packet's time the boot time.
        system_boot_time = time_base_mono;
        exporter.reinit_boot_time (time_base_mono, pkt->wall_timestamp);
        last_packet_mono = time_base_mono;
        last_packet_wall = pkt->wall_timestamp;
      }
    }
    const TimePoint effective_time =
      time_base_mono + std::chrono::duration_cast<Clock::duration> (
                         pkt->wall_timestamp - time_base_wall);

    // Original: when a capture file is read, check_expired() runs with
    // CE_EXPIRE_FORCED only, so no flow is expired for being idle mid-file,
    // with or without -a: flows accumulate until EOF, apart from the forced
    // eviction at max_flows (force_expire_over_max below). -a only makes the
    // export and boot times follow the packets' own times.

    if (config.export_format == ExportFormat::Psamp) {
      pending_samples.push_back (make_sampled_packet (
        *parsed, pkt->original_length, effective_time));
    }

    const auto key = make_flow_key (*parsed, parser.track_level(),
                                    {frame->vlanid, 0}, frame->ethermac);
    const std::uint8_t direction = (key.addr()[0] == parsed->src) ? 0 : 1;
    // Original: `tmp.octets[ndx] = phdr->len - datalink_size;` --
    // octet counts exclude the L2 (e.g. Ethernet) header. Using the
    // raw on-the-wire length here over-counted every packet by the
    // L2 header size (e.g. +14 bytes/packet for Ethernet).
    const std::size_t size_before = table.size();
    Flow &flow = table.record_packet (key, effective_time, pkt->wall_timestamp,
                                      direction, pkt->original_length - skip - frame->vlan_size,
                                      parsed->tcp_flags, parsed->tos);
    // Original: `if (verbose_flag) logit(LOG_DEBUG, "ADD FLOW %s", ...)`
    // in process_packet(), logged only when a *new* flow entry is
    // created (not on every packet belonging to an existing flow).
    if (config.debug && table.size() != size_before) {
      std::fprintf (stderr, "ADD FLOW %s\n",
                    format_flow_brief (flow.flow_seq, key).c_str());
    }
    // Original: -x. Only actually stored (and later exported) when
    // requested, capped both by -x's own argument and by the IPFIX/
    // NetFlow v9 Information Element registry's defined range of 10
    // label-stack-section fields.
    if (config.mpls_labels > 0 && !frame->mpls_labels.empty()) {
      const std::size_t keep = std::min<std::size_t> (
        {frame->mpls_labels.size(),
         static_cast<std::size_t> (config.mpls_labels), 10});
      flow.mpls_labels.assign (frame->mpls_labels.begin(),
                               frame->mpls_labels.begin() +
                                 static_cast<std::ptrdiff_t> (keep));
    }

    // Original: softflowd.c's check_expired() -- if boot_time_reinit
    // (-I) is set and more time than that has elapsed since the last
    // reset, treat the current packet's time as the new reference
    // point that uptime-based export fields are measured from.
    if (config.boot_time_reinit.count() != 0 &&
        effective_time - system_boot_time > config.boot_time_reinit) {
      system_boot_time = effective_time;
      exporter.reinit_boot_time (system_boot_time);
    }
    last_packet_mono = effective_time;
    last_packet_wall = pkt->wall_timestamp;
  }

  force_expire_over_max();

  // Original: softflowd.c's main() -- reaching EOF on a pcap file sets
  // graceful_shutdown_request, which the shared shutdown path then logs
  // as both of these lines (yes, the original really does log "on user
  // request" here too, even though EOF triggered it, not a user signal).
  std::fprintf (stderr, "Shutting down after pcap EOF\n");
  std::fprintf (stderr, "Shutting down on user request\n");

  const auto now = config.adjust_pcap_time ? last_packet_mono : Clock::now();
  const auto wall_now = config.adjust_pcap_time
                          ? last_packet_wall
                          : std::chrono::system_clock::now();
  log_expiry_debug_start (config.debug, kCeExpireAll);
  const auto expired = table.expire_flows (now, /*flush_all=*/true);
  log_expiry_debug_queued (config.debug, expired);
  const auto eof_outcome = exporter.export_flows (expired, now, wall_now);
  table.record_export_stats (eof_outcome.flows, eof_outcome.records,
                             eof_outcome.packets, eof_outcome.failures);
  log_expiry_debug_sent (config.debug, static_cast<int> (eof_outcome.packets));
  log_expiry_debug_expired (config.debug, expired);
  exporter.export_samples (pending_samples, now, wall_now);

  // Original: `if (capfile != NULL && dontfork_flag) statistics(...)`.
  // dontfork_flag looks like it depends on -d, but softflowd.c's own
  // `case 'r':` unconditionally sets `dontfork_flag = 1` as a side
  // effect of choosing -r -- so in the original, reading from a pcap
  // file *always* forces foreground mode and this condition is always
  // true, with or without -d. run_pcap_file() here only ever runs for
  // -r, so the equivalent is: always print.
  exporter.wait_idle();
  exporter.sync_stats (table);
  print_statistics (table.stats(), table.size(), table.lookup(), table.usage(),
                    stdout, handle);
  if (config.gauge_clock) {
    std::printf ("cpu clocks: %ld\n",
                 static_cast<long> (std::clock() - cpu_start));
    std::printf ("cpu clocks (export): %ld (%lu calls)\n",
                 static_cast<long> (exporter.export_clocks()),
                 exporter.export_calls());
  }
  return 0;
}

// =======================================================================
// Live capture with daemon control (original: softflowd.c's main loop
// when running against a live interface, plus its control-socket
// handling)
// =======================================================================
struct ControlState {
  bool capturing = true;
  bool shutting_down = false;
  bool immediate_exit = false;
  int debug_level = 0;  // original: softflowctl(8)'s debug+/debug-
};

// Original: the %-based address formatting softflowd.c's dump-flows
// output uses. IPv6 addresses are printed as plain colon-separated hex
// groups (not the canonical "::"-compressed form RFC 5952 prefers) --
// simpler to implement correctly and still a valid, parseable IPv6
// text representation.
std::string
format_address (const softflow::IpAddress &addr) {
  using namespace softflow;
  if (addr.family == AddressFamily::IPv4) {
    char buf[16];
    std::snprintf (buf, sizeof (buf), "%u.%u.%u.%u", addr.bytes[0],
                   addr.bytes[1], addr.bytes[2], addr.bytes[3]);
    return buf;
  }
  std::string result;
  for (int i = 0; i < 8; ++i) {
    if (i > 0) {
      result += ':';
    }
    char buf[8];
    std::snprintf (buf, sizeof (buf), "%x",
                   (addr.bytes[static_cast<std::size_t> (i) * 2] << 8) |
                     addr.bytes[static_cast<std::size_t> (i) * 2 + 1]);
    result += buf;
  }
  return result;
}

// Original: softflowctl(8)'s dump-flows, one line per tracked flow.
std::string
format_flow_dump_line (const softflow::ExportRecord &record) {
  const auto &key = record.key;
  const auto &flow = record.flow;
  return "ACTIVE seq:" + std::to_string (flow.flow_seq) + " [" +
         format_address (key.addr()[0]) + "]:" + std::to_string (key.port()[0]) +
         " <> [" + format_address (key.addr()[1]) +
         "]:" + std::to_string (key.port()[1]) +
         " proto:" + std::to_string (key.protocol()) +
         " octets>:" + std::to_string (flow.octets[0]) +
         " packets>:" + std::to_string (flow.packets[0]) +
         " octets<:" + std::to_string (flow.octets[1]) +
         " packets<:" + std::to_string (flow.packets[1]);
}

// Original: softflowctl(8)'s command set, dispatched here since softflowd.c
// (not softflowctl.c) owned the listening/accepting side of the control
// socket. See softflowctl.hpp for the shared command-name constants and
// wire helpers used by both sides.
std::string
handle_control_command (const std::string &command,
                        softflow::FlowTableRuntime &table,
                        ControlState &state, ExportPipeline &exporter) {
  using namespace softflow;
  using namespace control_commands;

  if (command == kShutdown) {
    state.shutting_down = true;
    return "OK shutting down (flows will be expired and exported)";
  }
  if (command == kExit) {
    state.immediate_exit = true;
    return "OK exiting immediately (no expiry/export)";
  }
  if (command == kExpireAll) {
    const auto count = table.size();
    const bool debug = state.debug_level > 0;
    log_expiry_debug_start (debug, kCeExpireAll);
    const auto expired = table.force_expire_oldest (count);
    log_expiry_debug_queued (debug, expired);
    const auto outcome = exporter.export_flows (
      expired, Clock::now(), std::chrono::system_clock::now());
    table.record_export_stats (outcome.flows, outcome.records,
                               outcome.packets, outcome.failures);
    log_expiry_debug_sent (debug, static_cast<int> (outcome.packets));
    log_expiry_debug_expired (debug, expired);
    return "OK expire-all: expired " + std::to_string (count) + " flows";
  }
  if (command == kDeleteAll) {
    const auto count = table.size();
    const bool debug = state.debug_level > 0;
    log_expiry_debug_start (debug, kCeExpireAll);
    const auto deleted = table.force_expire_oldest (count);
    log_expiry_debug_queued (debug, deleted);
    return "OK delete-all: deleted " + std::to_string (count) +
           " flows (no export)";
  }
  if (command == kStatistics) {
    exporter.sync_stats (table);
    const auto &stats = table.stats();
    return "OK tracked=" + std::to_string (table.size()) +
           " max_flows=" + std::to_string (table.max_flows()) +
           " total_packets=" + std::to_string (stats.total_packets) +
           " flows_expired=" + std::to_string (stats.flows_expired) +
           " flows_force_expired=" +
           std::to_string (stats.flows_force_expired) +
           " flow_lookup=" + flow_lookup_name (table.lookup()) +
           " capturing=" + (state.capturing ? "yes" : "no") +
           " debug_level=" + std::to_string (state.debug_level);
  }
  if (command == kDebugPlus) {
    ++state.debug_level;
    return "OK debug level now " + std::to_string (state.debug_level);
  }
  if (command == kDebugMinus) {
    if (state.debug_level > 0) {
      --state.debug_level;
    }
    return "OK debug level now " + std::to_string (state.debug_level);
  }
  if (command == kStopGather) {
    state.capturing = false;
    return "OK packet processing stopped";
  }
  if (command == kStartGather) {
    state.capturing = true;
    return "OK packet processing resumed";
  }
  if (command == kDumpFlows) {
    const auto records = table.snapshot();
    std::string response = "OK " + std::to_string (records.size()) + " flows";
    for (const auto &record : records) {
      response += "\n" + format_flow_dump_line (record);
    }
    return response;
  }
  if (command == kTimeouts) {
    const auto &t = table.timeouts();
    return "OK general=" + std::to_string (t.general.count()) +
           "s tcp=" + std::to_string (t.tcp.count()) +
           "s tcp.rst=" + std::to_string (t.tcp_rst.count()) +
           "s tcp.fin=" + std::to_string (t.tcp_fin.count()) +
           "s udp=" + std::to_string (t.udp.count()) +
           "s maxlife=" + std::to_string (t.maximum_lifetime.count()) + "s";
  }
  if (command == kSendTemplate) {
    if (exporter.resend_template()) {
      return "OK template will be resent before the next export";
    }
    return "OK send-template has no effect for this export format";
  }
  return "ERROR unknown command '" + command + "'";
}

int
run_live_capture (const DaemonConfig &config) {
  using namespace softflow;

  // A short read timeout plus immediate mode (see PcapHandle::open_live)
  // keeps this daemon responsive to control-socket commands and signals
  // even under sustained traffic -- see the packet-draining loop below
  // for the other half of this responsiveness story (it also caps how
  // many packets it drains per poll() cycle).
  PcapHandle handle = PcapHandle::open_live (
    config.interface, config.snaplen, !config.no_promiscuous,
    std::chrono::milliseconds (100), config.buffer_bytes);
  if (!config.bpf_filter.empty()) {
    handle.set_filter (config.bpf_filter);
  }
  const auto dl_kind = handle.datalink_kind();
  if (dl_kind == DatalinkKind::Unsupported) {
    std::fprintf (stderr, "unsupported datalink type (pcap_datalink=%d)\n",
                  handle.datalink());
    return 1;
  }
  const std::size_t skip = datalink_header_len (dl_kind);

  PacketParser parser (config.track_level, config.full_l4hdr_check);
  FlowTableRuntime table (config.flow_lookup, config.max_flows, config.track_level,
                          config.timeouts);
  const TimePoint boot_time = Clock::now();
  const auto start_time = boot_time;
  ExportPipeline exporter (config, boot_time);

  // Original: softflowd.c bound and listened on /var/run/softflowd.ctl
  // (or -c's argument) for softflowctl(8) connections. RAII (this small
  // guard struct) ensures both the listening socket and its filesystem
  // entry are cleaned up on every return path from this function,
  // including an exception.
  ::unlink (config.ctl_sock.c_str());
  const int ctl_fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (ctl_fd < 0) {
    throw std::runtime_error ("socket() for control socket failed");
  }
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (config.ctl_sock.size() >= sizeof (addr.sun_path)) {
    ::close (ctl_fd);
    throw std::runtime_error ("control socket path too long: " + config.ctl_sock);
  }
  std::strncpy (addr.sun_path, config.ctl_sock.c_str(), sizeof (addr.sun_path) - 1);
  struct CtlSocketGuard {
    int fd;
    std::string path;
    ~CtlSocketGuard () {
      if (fd >= 0) {
        ::close (fd);
      }
      ::unlink (path.c_str());
    }
  } ctl_guard{ctl_fd, config.ctl_sock};

  if (bind (ctl_fd, reinterpret_cast<struct sockaddr *> (&addr), sizeof (addr)) < 0 ||
      listen (ctl_fd, 5) < 0) {
    throw std::runtime_error ("failed to set up control socket at '" +
                              config.ctl_sock + "'");
  }

  // Original: -R receive_port. An additional UDP socket, listened on
  // alongside the pcap capture descriptor, control socket, and signal
  // pipe -- see PsampReceiver (psamp.hpp) for how received datagrams are
  // decoded back into SampledPacket values, which are then fed into
  // FlowTable::record_packet() exactly as if they'd been locally
  // captured.
  int psamp_fd = -1;
  PsampReceiver psamp_receiver;
  struct PsampSocketGuard {
    int fd;
    ~PsampSocketGuard () {
      if (fd >= 0) {
        ::close (fd);
      }
    }
  } psamp_guard{-1};
  if (config.psamp_receive_port.has_value()) {
    // Prefer a dual-stack IPv6 socket (accepting both IPv4- and
    // IPv6-sourced datagrams); fall back to IPv4-only if the platform
    // or environment doesn't support IPv6 at all (e.g. some
    // containers/sandboxes disable it entirely).
    psamp_fd = socket (AF_INET6, SOCK_DGRAM, 0);
    const bool using_ipv6 = psamp_fd >= 0;
    if (!using_ipv6) {
      psamp_fd = socket (AF_INET, SOCK_DGRAM, 0);
    }
    if (psamp_fd < 0) {
      throw std::runtime_error ("socket() for PSAMP receive port failed");
    }

    int bind_result = -1;
    if (using_ipv6) {
      // Accept both IPv4 and IPv6 senders on one dual-stack socket
      // where the platform supports it; a failure to clear
      // IPV6_V6ONLY is non-fatal (the socket still works for
      // IPv6-only use).
#ifdef IPV6_V6ONLY
      const int v6only = 0;
      setsockopt (psamp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof (v6only));
#endif
      struct sockaddr_in6 psamp_addr{};
      psamp_addr.sin6_family = AF_INET6;
      psamp_addr.sin6_addr = in6addr_any;
      psamp_addr.sin6_port =
        htons (static_cast<std::uint16_t> (*config.psamp_receive_port));
      bind_result = bind (psamp_fd, reinterpret_cast<struct sockaddr *> (&psamp_addr),
                          sizeof (psamp_addr));
    } else {
      struct sockaddr_in psamp_addr{};
      psamp_addr.sin_family = AF_INET;
      psamp_addr.sin_addr.s_addr = INADDR_ANY;
      psamp_addr.sin_port =
        htons (static_cast<std::uint16_t> (*config.psamp_receive_port));
      bind_result = bind (psamp_fd, reinterpret_cast<struct sockaddr *> (&psamp_addr),
                          sizeof (psamp_addr));
    }
    if (bind_result < 0) {
      ::close (psamp_fd);
      throw std::runtime_error ("failed to bind PSAMP receive port " +
                                std::to_string (*config.psamp_receive_port));
    }
    // Set O_NONBLOCK on the socket itself, rather than relying solely
    // on passing MSG_DONTWAIT to each individual recv() call below --
    // belt-and-braces, matching the same reasoning as SignalPipe's
    // pipe file descriptors (daemon.cpp): a blocking recv() here,
    // even briefly, would stall the entire event loop (control
    // socket, signals, pcap capture) until another PSAMP datagram
    // happened to arrive.
    const int psamp_flags = fcntl (psamp_fd, F_GETFL, 0);
    if (psamp_flags >= 0) {
      fcntl (psamp_fd, F_SETFL, psamp_flags | O_NONBLOCK);
    }
    psamp_guard.fd = psamp_fd;
    std::printf ("[softflowd] PSAMP receive mode: listening on UDP port %d "
                 "(%s)\n",
                 *config.psamp_receive_port, using_ipv6 ? "IPv6" : "IPv4");
  }

  SignalPipe signals;
  ControlState state;

  std::vector<SampledPacket> pending_samples;
  std::uint32_t sample_counter = 0;
  TimePoint last_expiry_check = Clock::now();

  std::printf ("[softflowd] listening on %s, control socket %s, version=%s, "
               "track=%s\n",
               config.interface.c_str(), config.ctl_sock.c_str(),
               format_name (config.export_format),
               track_level_name (config.track_level));

  // The flow tracking of one captured packet. With -M it runs in another
  // thread (see PacketProcessor); the main loop waits for it before it uses
  // the table, the exporter or the samples.
  const auto process_packet = [&] (const softflow::CapturedPacket &pkt) {
    if (pkt.data.size() <= skip) {
      return;
    }
    const auto ip_bytes = pkt.data.subspan (skip);

    const auto frame = classify_frame (pkt, dl_kind, ip_bytes);
    if (!frame.has_value()) {
      return;
    }
    if (frame->af == AddressFamily::IPv6 && !should_track_ipv6 (config)) {
      return;
    }

    auto parsed =
      parser.parse (ip_bytes.subspan (frame->ip_offset), frame->af);
    if (!parsed.has_value()) {
      return;
    }

    if (config.sampling_rate > 1) {
      if ((sample_counter++ % config.sampling_rate) != 0) {
        return;
      }
    }

    if (config.export_format == ExportFormat::Psamp) {
      pending_samples.push_back (make_sampled_packet (
        *parsed, pkt.original_length, pkt.timestamp));
    }

    const auto key = make_flow_key (*parsed, parser.track_level(),
                                    {frame->vlanid, 0}, frame->ethermac);
    const std::uint8_t direction =
      (key.addr()[0] == parsed->src) ? 0 : 1;
    const std::size_t size_before = table.size();
    Flow &flow = table.record_packet (
      key, pkt.timestamp, pkt.wall_timestamp, direction,
      pkt.original_length - skip - frame->vlan_size, parsed->tcp_flags, parsed->tos);
    if (config.debug && table.size() != size_before) {
      std::fprintf (stderr, "ADD FLOW %s\n",
                    format_flow_brief (flow.flow_seq, key).c_str());
    }
    if (config.mpls_labels > 0 && !frame->mpls_labels.empty()) {
      const std::size_t keep = std::min<std::size_t> (
        {frame->mpls_labels.size(),
         static_cast<std::size_t> (config.mpls_labels), 10});
      flow.mpls_labels.assign (
        frame->mpls_labels.begin(),
        frame->mpls_labels.begin() + static_cast<std::ptrdiff_t> (keep));
    }

    if (table.size() > table.max_flows()) {
      log_expiry_debug_start (config.debug, kCeExpireForced);
      const auto forced = table.force_expire_oldest (
        table.size() - table.max_flows());
      log_expiry_debug_queued (config.debug, forced);
      const auto outcome = exporter.export_flows (
        forced, pkt.timestamp, std::chrono::system_clock::now());
      table.record_export_stats (outcome.flows, outcome.records,
                                 outcome.packets, outcome.failures);
      log_expiry_debug_sent (config.debug,
                             static_cast<int> (outcome.packets));
      log_expiry_debug_expired (config.debug, forced);
    }
  };
  std::optional<PacketProcessor> processor;
  if (config.multithread) {
    processor.emplace (process_packet);
  }

  while (!state.shutting_down && !state.immediate_exit) {
    struct pollfd fds[4];
    fds[0] = {signals.read_fd(), POLLIN, 0};
    fds[1] = {ctl_fd, POLLIN, 0};
    const int pcap_fd = handle.selectable_fd();
    fds[2] = {pcap_fd >= 0 ? pcap_fd : -1, POLLIN, 0};
    fds[3] = {psamp_fd >= 0 ? psamp_fd : -1, POLLIN, 0};

    const int ready = poll (fds, 4, 1000 /* ms */);
    if (ready < 0 && errno != EINTR) {
      throw std::runtime_error ("poll() failed");
    }
    if (processor.has_value()) {
      processor->wait_idle();
    }

    for (int sig : signals.drain()) {
      if (sig == SIGTERM || sig == SIGINT) {
        state.shutting_down = true;
      } else if (sig == SIGUSR1) {
        std::printf ("[softflowd] stats: tracked=%zu total_packets=%llu\n",
                     table.size(),
                     static_cast<unsigned long long> (
                       table.stats().total_packets));
      } else if (sig == SIGHUP) {
        std::printf (
          "[softflowd] SIGHUP received (config reload not "
          "implemented in this stage)\n");
      }
    }

    if ((fds[1].revents & POLLIN) != 0) {
      const int client_fd = accept (ctl_fd, nullptr, nullptr);
      if (client_fd >= 0) {
        struct ClientCloser {
          int fd;
          ~ClientCloser () {
            ::close (fd);
          }
        } client_closer{client_fd};

        try {
          const std::string command = read_line (client_fd);
          const std::string response =
            handle_control_command (command, table, state, exporter);
          write_line (client_fd, response);
        } catch (const std::exception &) {
          // A malformed client is not the daemon's problem;
          // just drop the connection.
        }
      }
    }

    if (pcap_fd >= 0 && (fds[2].revents & POLLIN) != 0 && state.capturing) {
      // Bounded rather than "drain until next_packet() times out":
      // under sustained traffic, an unbounded drain here could
      // starve the control socket and signal handling below of any
      // chance to run. Any packets still waiting after this many
      // are picked up on the very next poll() iteration instead,
      // since poll() will immediately report the pcap fd readable
      // again if there's more queued -- no packets are lost, only
      // their processing is interleaved with servicing the control
      // socket and signals.
      //
      // Each iteration re-checks readiness with a zero-timeout
      // poll() before calling next_packet() again, rather than
      // relying on next_packet()'s own configured read timeout to
      // return promptly once no more packets are queued -- in some
      // environments (observed with certain virtualized/sandboxed
      // loopback interfaces) libpcap's internal timeout has been
      // seen to not reliably bound how long a call blocks once the
      // underlying descriptor has genuinely gone quiet. Checking
      // readiness explicitly here means this loop only ever calls
      // next_packet() when a packet is truly known to be waiting.
      constexpr int kMaxPacketsPerCycle = 32;
      for (int n = 0; n < kMaxPacketsPerCycle; ++n) {
        if (n > 0) {
          struct pollfd recheck = {pcap_fd, POLLIN, 0};
          if (poll (&recheck, 1, 0) <= 0 ||
              (recheck.revents & POLLIN) == 0) {
            break;  // nothing more queued right now
          }
        }
        auto pkt = handle.next_packet();
        if (!pkt.has_value()) {
          break;
        }
        if (processor.has_value()) {
          processor->submit (*pkt);
        } else {
          process_packet (*pkt);
        }
      }
      if (processor.has_value()) {
        processor->wait_idle();
      }
    }

    if (psamp_fd >= 0 && (fds[3].revents & POLLIN) != 0) {
      // Original: -R. Drains every currently-queued datagram (not
      // just one) each time the socket is readable, the same
      // bounded-batch reasoning as the pcap-draining loop above
      // applies here too, so a burst of incoming PSAMP messages
      // can't starve the control socket or signal handling either.
      constexpr int kMaxDatagramsPerCycle = 32;
      std::array<std::uint8_t, 65536> buffer;
      for (int n = 0; n < kMaxDatagramsPerCycle; ++n) {
        struct sockaddr_storage sender_addr{};
        socklen_t sender_len = sizeof (sender_addr);
        const ssize_t received =
          recvfrom (psamp_fd, buffer.data(), buffer.size(), MSG_DONTWAIT,
                    reinterpret_cast<struct sockaddr *> (&sender_addr),
                    &sender_len);
        if (received <= 0) {
          break;  // no more datagrams queued right now
        }
        // Original: hardening added while validating -R (Stage 7).
        // Scoping received templates by sender address (rather
        // than by template ID alone) prevents two different
        // exporters that happen to reuse the same numeric
        // template ID for two *different* record layouts from
        // corrupting each other's decoded data -- template IDs
        // are only required to be unique per exporter, not
        // globally.
        std::array<char, INET6_ADDRSTRLEN> addr_str{};
        std::uint16_t sender_port = 0;
        if (sender_addr.ss_family == AF_INET) {
          const auto *sin = reinterpret_cast<struct sockaddr_in *> (&sender_addr);
          inet_ntop (AF_INET, &sin->sin_addr, addr_str.data(), addr_str.size());
          sender_port = ntohs (sin->sin_port);
        } else if (sender_addr.ss_family == AF_INET6) {
          const auto *sin6 = reinterpret_cast<struct sockaddr_in6 *> (&sender_addr);
          inet_ntop (AF_INET6, &sin6->sin6_addr, addr_str.data(), addr_str.size());
          sender_port = ntohs (sin6->sin6_port);
        }
        const std::string source_id =
          std::string (addr_str.data()) + ":" + std::to_string (sender_port);

        const auto received_at = Clock::now();
        auto samples = psamp_receiver.decode_message (
          std::span<const std::uint8_t> (buffer.data(),
                                         static_cast<std::size_t> (received)),
          received_at, source_id);
        for (const auto &sample : samples) {
          const std::uint8_t key_tos =
            config.track_level >= softflow::TrackLevel::FullTos
              ? sample.tos
              : 0;
          const auto key = FlowKey::make_canonical (
            sample.src, sample.dst, sample.src_port, sample.dst_port,
            sample.protocol, key_tos, {0, 0});
          const std::uint8_t direction =
            (key.addr()[0] == sample.src) ? 0 : 1;
          table.record_packet (key, sample.observed_at,
                               std::chrono::system_clock::now(),
                               direction, sample.observed_length, 0,
                               sample.tos);
        }
      }
    }

    // Original: -t expint controls how often flow expiry is checked
    // (a larger interval groups more flows into fewer, larger export
    // packets). expiry_interval == 0 means "check every cycle", which
    // is what the poll() loop already naturally does roughly once per
    // second.
    const auto now = Clock::now();
    if (config.expiry_interval.count() == 0 ||
        now - last_expiry_check >= config.expiry_interval) {
      log_expiry_debug_start (config.debug, kCeExpireNormal);
      const auto due = table.expire_flows (now);
      log_expiry_debug_queued (config.debug, due);
      const auto outcome = exporter.export_flows (
        due, now, std::chrono::system_clock::now());
      table.record_export_stats (outcome.flows, outcome.records,
                                 outcome.packets, outcome.failures);
      log_expiry_debug_sent (config.debug, static_cast<int> (outcome.packets));
      log_expiry_debug_expired (config.debug, due);
      exporter.export_samples (pending_samples, now,
                               std::chrono::system_clock::now());
      pending_samples.clear();
      last_expiry_check = now;
    }

    if (config.max_runtime.has_value() &&
        now - start_time >= *config.max_runtime) {
      state.shutting_down = true;
    }
  }

  if (state.shutting_down) {
    // Original: "receipt of a SIGTERM or SIGINT will cause softflowd
    // to exit, after expiring all flows (and thus sending flow export
    // packets if -n was specified)".
    const auto now = Clock::now();
    const auto wall_now = std::chrono::system_clock::now();
    log_expiry_debug_start (config.debug, kCeExpireAll);
    const auto expired = table.expire_flows (now, /*flush_all=*/true);
    log_expiry_debug_queued (config.debug, expired);
    const auto outcome = exporter.export_flows (expired, now, wall_now);
    table.record_export_stats (outcome.flows, outcome.records,
                               outcome.packets, outcome.failures);
    log_expiry_debug_sent (config.debug, static_cast<int> (outcome.packets));
    log_expiry_debug_expired (config.debug, expired);
    exporter.export_samples (pending_samples, now, wall_now);
  }

  std::printf ("[softflowd] exiting (%s)\n",
               state.immediate_exit ? "immediate" : "graceful");
  return 0;
}

// Original: parse_mac_address(). "xx:xx:xx:xx:xx:xx" or "xx-xx-xx-xx-xx-xx".
bool
parse_mac_address (const char *str, std::array<std::uint8_t, 6> &mac) {
  unsigned int b[6];
  if (std::sscanf (str, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3],
                   &b[4], &b[5]) != 6 &&
      std::sscanf (str, "%2x-%2x-%2x-%2x-%2x-%2x", &b[0], &b[1], &b[2], &b[3],
                   &b[4], &b[5]) != 6) {
    return false;
  }
  for (std::size_t i = 0; i < 6; ++i) {
    mac[i] = static_cast<std::uint8_t> (b[i]);
  }
  return true;
}

// Original: get_interface_mac(). The Ethernet address of a capture
// interface, used as the direction MAC when -H is not given.
std::optional<std::array<std::uint8_t, 6>>
get_interface_mac (const std::string &ifname) {
  std::array<std::uint8_t, 6> mac{};
#ifdef __linux__
  const int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return std::nullopt;
  }
  struct ifreq ifr {};
  std::strncpy (ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
  const bool ok = ioctl (fd, SIOCGIFHWADDR, &ifr) == 0 &&
                  ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER;
  ::close (fd);
  if (!ok) {
    return std::nullopt;
  }
  std::memcpy (mac.data(), ifr.ifr_hwaddr.sa_data, 6);
  return mac;
#else
  struct ifaddrs *list = nullptr;
  if (getifaddrs (&list) != 0) {
    return std::nullopt;
  }
  bool found = false;
  for (const struct ifaddrs *p = list; p != nullptr; p = p->ifa_next) {
    if (p->ifa_addr == nullptr || p->ifa_addr->sa_family != AF_LINK ||
        ifname != p->ifa_name) {
      continue;
    }
    const auto *sdl = reinterpret_cast<const struct sockaddr_dl *> (p->ifa_addr);
    if (sdl->sdl_alen == 6) {
      std::memcpy (mac.data(), LLADDR (sdl), 6);
      found = true;
      break;
    }
  }
  freeifaddrs (list);
  return found ? std::optional (mac) : std::nullopt;
#endif
}

void
print_usage (const char *argv0) {
  std::fprintf (
    stderr,
    "usage: %s [-6dDfhMNbal] [-F tree|hash|hash-tree] [-H direction_mac] [-L hoplimit] [-T track_level] [-c ctl_sock]\n"
    "               [-i [if_ndx:]interface] [-m max_flows (1 or more)] [-n host:port]\n"
    "               [-p pidfile] [-r pcap_file] [-t timeout_name=seconds]\n"
    "               [-v netflow_version] [-P transport_protocol]\n"
    "               [-A time_format] [-s sampling_rate] [-C capture_length]\n"
    "               [-R receive_port] [-S send_interface_name]\n"
    "               [-x number_of_mpls_labels (1 to 10)] [-e exporter_ip_address]\n"
    "               [-B size_bytes] [bpf_expression]\n"
    "\n"
    "Either -i or -r must be given. See softflowd(8) for full option\n"
    "documentation; this project implements the same option grammar as\n"
    "the original softflowd. -P, -A, -x, and -b are fully implemented\n"
    "(see README for details, e.g. SCTP availability and biflow's\n"
    "encoding); -R (PSAMP receive mode) is not implemented.\n"
    "\n"
    "This project's own additions (not part of the original softflowd):\n"
    "  --export-out=PATH     additionally write export packets to a file,\n"
    "                        each length-prefixed with 4 big-endian bytes\n"
    "  --max-runtime=SECONDS shut down automatically after SECONDS (testing)\n",
    argv0);
}

// Original: die_usage(). Prints the message and the usage, then exits.
[[noreturn]] void
die_usage (const char *argv0, const char *message) {
  std::fputs (message, stderr);
  print_usage (argv0);
  std::exit (1);
}

}  // namespace

int
main (int argc, char **argv) {
  // A daemon's log output is much more useful flushed promptly than
  // batched up in a large buffer -- especially relevant once stdout is
  // redirected to a file or pipe (as it always is once daemonizing
  // redirects it, and as it commonly is under a supervisor like
  // systemd). This has no effect on interactive/TTY use, where stdout is
  // already line-buffered by default.
  std::setvbuf (stdout, nullptr, _IOLBF, 0);

  DaemonConfig config;

  // This project's own additions are exposed as GNU-style long options
  // via getopt_long(). Every existing short option keeps its exact
  // original letter and argument-taking behavior (the optstring below is
  // unchanged), so any script or invocation built against the original
  // softflowd's short-option grammar continues to work unmodified;
  // getopt_long() simply also accepts these long forms alongside them.
  enum {
    kOptExportOut = 1000,
    kOptMaxRuntime,
    kOptIcmpTypecodeOnly,
    kOptExpirySecondGranularity,
    kOptNoExpirySecondGranularity,
  };
  static const struct option long_options[] = {
    {"track-ipv6", no_argument, nullptr, '6'},
    {"adjust-time", no_argument, nullptr, 'a'},
    {"absolute-time", required_argument, nullptr, 'A'},
    {"bidirectional", no_argument, nullptr, 'b'},
    {"pcap-buffer-size", required_argument, nullptr, 'B'},
    {"control-socket", required_argument, nullptr, 'c'},
    {"snaplen", required_argument, nullptr, 'C'},
    {"foreground", no_argument, nullptr, 'd'},
    {"debug", no_argument, nullptr, 'D'},
    {"exporter-ip", required_argument, nullptr, 'e'},
    {"full-transport-header-check", no_argument, nullptr, 'f'},
    {"flow-lookup", required_argument, nullptr, 'F'},
    {"gauge-cpu-clock", no_argument, nullptr, 'g'},
    {"help", no_argument, nullptr, 'h'},
    {"direction-mac", required_argument, nullptr, 'H'},
    {"interface", required_argument, nullptr, 'i'},
    {"reinit-interval", required_argument, nullptr, 'I'},
    {"load-balance", no_argument, nullptr, 'l'},
    {"hoplimit", required_argument, nullptr, 'L'},
    {"max-flows", required_argument, nullptr, 'm'},
    {"multithread", no_argument, nullptr, 'M'},
    {"netflow-dest", required_argument, nullptr, 'n'},
    {"no-promisc", no_argument, nullptr, 'N'},
    {"pidfile", required_argument, nullptr, 'p'},
    {"export-protocol", required_argument, nullptr, 'P'},
    {"read", required_argument, nullptr, 'r'},
    {"psamp-port", required_argument, nullptr, 'R'},
    {"sampling-rate", required_argument, nullptr, 's'},
    {"send-interface", required_argument, nullptr, 'S'},
    {"timeout", required_argument, nullptr, 't'},
    {"track", required_argument, nullptr, 'T'},
    {"netflow-version", required_argument, nullptr, 'v'},
    {"mpls-labels", required_argument, nullptr, 'x'},
    // Additions of the C++ version.
    {"export-out", required_argument, nullptr, kOptExportOut},
    {"max-runtime", required_argument, nullptr, kOptMaxRuntime},
    {"icmp-typecode-only", no_argument, nullptr, kOptIcmpTypecodeOnly},
    {"expiry-second-granularity", no_argument, nullptr,
     kOptExpirySecondGranularity},
    {"no-expiry-second-granularity", no_argument, nullptr,
     kOptNoExpirySecondGranularity},
    {nullptr, 0, nullptr, 0},
  };

  const int fargc = argc;
  char **fargv = argv;
  bool export_format_explicit = false;

  ::optind = 1;
  int opt;
  try {
    while ((opt = getopt_long (
              fargc, fargv,
              "n:Ni:r:p:c:m:t:d6DhL:T:v:P:A:s:C:R:S:e:x:B:bfF:alI:gH:M",
              long_options, nullptr)) != -1) {
      switch (opt) {
        case 'F':
          // Original: -F flow-lookup, tree | hash | hash-tree.
          if (std::string (optarg) == "tree") {
            config.flow_lookup = softflow::FlowLookup::Tree;
          } else if (std::string (optarg) == "hash") {
            config.flow_lookup = softflow::FlowLookup::Hash;
          } else if (std::string (optarg) == "hash-tree") {
            config.flow_lookup = softflow::FlowLookup::HashTree;
          } else {
            std::fprintf (stderr, "Invalid flow lookup %s\n\n", optarg);
            print_usage (argv[0]);
            return 1;
          }
          break;
        case kOptExportOut:
          config.export_out = optarg;
          break;
        case kOptMaxRuntime:
          config.max_runtime = std::chrono::seconds (std::stol (optarg));
          break;
        case kOptIcmpTypecodeOnly:
          // Now the default: only the bytes that are read (ICMP type
          // and code) are required. Kept as a no-op so existing
          // invocations still work; -f requires the whole header.
          break;
        case 'f':
          config.full_l4hdr_check = true;
          break;
        case 'M':
          config.multithread = true;
          break;
        case kOptExpirySecondGranularity:
          // See FlowTimeouts::second_granularity's comment. This is
          // now the default (matching the original's only actual
          // behavior); the flag is kept as a harmless no-op so
          // existing invocations that pass it explicitly still work.
          config.timeouts.second_granularity = true;
          break;
        case kOptNoExpirySecondGranularity:
          // Opts into full sub-second expiry-scheduling precision,
          // deviating from the original's whole-second `time_t`
          // expires_at (and, as a result, its expiry queue/export
          // ordering) in exchange for more precise expiry timing.
          config.timeouts.second_granularity = false;
          break;
        case 'n': {
          auto dests = parse_destinations (optarg);
          config.destinations.insert (config.destinations.end(),
                                      dests.begin(), dests.end());
          break;
        }
        case 'N':
          config.no_promiscuous = true;
          break;
        case 'i':
          config.interface = optarg;
          break;
        case 'r':
          config.pcap_file = optarg;
          break;
        case 'p':
          config.pidfile = optarg;
          break;
        case 'c':
          config.ctl_sock = optarg;
          break;
        case 'm': {
          // Range check on an int, as in the C version: 0, negative
          // values and non-numeric arguments are rejected.
          const int max_flows = std::atoi (optarg);
          if (max_flows < 1) {
            die_usage (argv[0], "Invalid maximum flows\n\n");
          }
          config.max_flows = static_cast<std::size_t> (max_flows);
          break;
        }
        case 't':
          apply_timeout_option (config, optarg);
          break;
        case 'd':
          config.no_daemonize = true;
          break;
        case '6':
          config.force_ipv6 = true;
          break;
        case 'D':
          config.debug = true;
          config.no_daemonize = true;
          config.force_ipv6 = true;
          break;
        case 'h':
          print_usage (argv[0]);
          return 0;
        case 'L':
          config.ttl = std::stoi (optarg);
          break;
        case 'T':
          config.track_level = parse_track_level (optarg);
          break;
        case 'v':
          config.export_format = parse_netflow_version (optarg);
          export_format_explicit = true;
          break;
        case 'P':
          config.transport = parse_transport_protocol (optarg);
          break;
        case 'A':
          config.time_format = parse_time_format (optarg);
          break;
        case 's':
          config.sampling_rate = static_cast<std::uint32_t> (std::stoul (optarg));
          break;
        case 'C':
          config.snaplen = std::stoi (optarg);
          break;
        case 'R':
          config.psamp_receive_port = std::stoi (optarg);
          break;
        case 'S':
          config.send_interface = optarg;
          break;
        case 'e':
          config.source_address = optarg;
          break;
        case 'x': {
          const int num_label = std::atoi (optarg);
          if (num_label < 1 || num_label > 10) {
            die_usage (argv[0],
                       "Invalid number of MPLS label (1 to 10)\n\n");
          }
          config.mpls_labels = num_label;
          break;
        }
        case 'B':
          config.buffer_bytes = static_cast<std::size_t> (std::stoul (optarg));
          break;
        case 'b':
          config.bidirectional_ipfix = true;
          break;
        case 'a':
          config.adjust_pcap_time = true;
          break;
        case 'l':
          config.load_balance = true;
          break;
        case 'I': {
          // Original: BOOTTIME_MAX_DAY/HOUR/MIN/SEC clamps in
          // softflowd.c's -I parsing.
          constexpr long kBoottimeMaxDay = 49;
          constexpr long kBoottimeMaxHour = 1193;
          constexpr long kBoottimeMaxMin = 71582;
          constexpr long kBoottimeMaxSec = 4294944;

          char *timeunit = nullptr;
          errno = 0;
          long sec = std::strtol (optarg, &timeunit, 10);
          if ((errno == ERANGE && (sec == LONG_MAX || sec == LONG_MIN)) ||
              (errno != 0 && sec == 0)) {
            std::perror ("strtol");
            print_usage (argv[0]);
            return 1;
          }
          if (timeunit == optarg) {
            std::fprintf (stderr,
                          "No digits were found in boot_time_reinit\n");
            print_usage (argv[0]);
            return 1;
          }
          if (*timeunit == 'd' || *timeunit == 'D') {
            if (sec > kBoottimeMaxDay)
              sec = kBoottimeMaxDay;
            sec *= 24 * 60 * 60;
          } else if (*timeunit == 'h' || *timeunit == 'H') {
            if (sec > kBoottimeMaxHour)
              sec = kBoottimeMaxHour;
            sec *= 60 * 60;
          } else if (*timeunit == 'm' || *timeunit == 'M') {
            if (sec > kBoottimeMaxMin)
              sec = kBoottimeMaxMin;
            sec *= 60;
          } else {
            if (sec > kBoottimeMaxSec)
              sec = kBoottimeMaxSec;
          }
          config.boot_time_reinit = std::chrono::seconds (sec);
          break;
        }
        case 'g':
          config.gauge_clock = true;
          break;
        case 'H': {
          std::array<std::uint8_t, 6> mac;
          if (!parse_mac_address (optarg, mac)) {
            std::fprintf (stderr, "Invalid MAC address %s\n", optarg);
            return 1;
          }
          config.direction_mac = mac;
          break;
        }
        case '?':
        default:
          print_usage (argv[0]);
          return 1;
      }
    }
  } catch (const std::exception &e) {
    std::fprintf (stderr, "%s: %s\n", argv[0], e.what());
    return 1;
  }
  (void) export_format_explicit;  // Netflow5 is already config's default

  std::string bpf;
  for (int i = optind; i < fargc; ++i) {
    if (!bpf.empty()) {
      bpf += " ";
    }
    bpf += fargv[i];
  }
  config.bpf_filter = bpf;

  if (config.interface.empty() && config.pcap_file.empty()) {
    std::fprintf (stderr, "%s: either -i or -r must be specified\n", argv[0]);
    print_usage (argv[0]);
    return 1;
  }
  if (!config.interface.empty() && !config.pcap_file.empty()) {
    std::fprintf (stderr, "%s: -i and -r are mutually exclusive\n", argv[0]);
    return 1;
  }
  if (config.psamp_receive_port.has_value() && !config.pcap_file.empty()) {
    std::fprintf (stderr,
                  "%s: -R only has an effect with -i (live capture); "
                  "ignored with -r\n",
                  argv[0]);
    config.psamp_receive_port.reset();
  }
  if (config.mpls_labels > 0 && config.export_format != ExportFormat::Netflow9 &&
      config.export_format != ExportFormat::Ipfix) {
    std::fprintf (stderr,
                  "%s: warning: -x only has an effect with -v 9 or -v "
                  "10 (NetFlow v1/v5/PSAMP have no MPLS label fields); "
                  "no MPLS labels will be exported\n",
                  argv[0]);
  }
  if (config.bidirectional_ipfix && config.export_format != ExportFormat::Ipfix) {
    std::fprintf (stderr,
                  "%s: warning: -b only has an effect with -v 10 (IPFIX)\n",
                  argv[0]);
  }
  if (config.debug) {
    std::printf (
      "[softflowd] debug: interface=%s pcap_file=%s max_flows=%zu "
      "track_level=%s version=%s destinations=%zu flow_lookup=%s\n",
      config.interface.c_str(), config.pcap_file.c_str(),
      config.max_flows, track_level_name (config.track_level),
      format_name (config.export_format), config.destinations.size(),
      softflow::flow_lookup_name (config.flow_lookup));
  }

  try {
    if (!config.pcap_file.empty()) {
      return run_pcap_file (config);
    }

    // Original: softflowd defaults to daemonizing (forking into the
    // background) when run against a live interface, unless -d is
    // given.
    std::optional<softflow::PidFile> pidfile;
    if (!config.no_daemonize) {
      softflow::daemonize();
      pidfile.emplace (config.pidfile);
    }
    // Original: with ethernet tracking and no -H, the MAC address of the
    // capture interface is the direction MAC.
    if (config.track_level >= softflow::TrackLevel::FullVlanEther &&
        !config.direction_mac.has_value() && !config.interface.empty()) {
      config.direction_mac = get_interface_mac (config.interface);
      if (config.debug) {
        if (config.direction_mac.has_value()) {
          const auto &m = *config.direction_mac;
          std::fprintf (stderr,
                        "Auto-detected direction MAC "
                        "%02x:%02x:%02x:%02x:%02x:%02x from interface %s\n",
                        m[0], m[1], m[2], m[3], m[4], m[5],
                        config.interface.c_str());
        } else {
          std::fprintf (stderr,
                        "Could not auto-detect MAC address of %s; "
                        "flowDirection will use canonical ordering\n",
                        config.interface.c_str());
        }
      }
    }
    return run_live_capture (config);
  } catch (const std::exception &e) {
    std::fprintf (stderr, "%s: %s\n", argv[0], e.what());
    return 1;
  }
}

#endif  // SOFTFLOW_NO_MAIN
