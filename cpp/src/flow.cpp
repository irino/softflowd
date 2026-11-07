/**
 * @file flow.cpp
 * @brief The flow table: the hash and the tree backends, and the expiry of its flows.
 *
 * Split from softflowd.cpp. The class template FlowTable is declared in
 * softflowd.hpp and is instantiated for both backends at the end of this file.
 *
 * @original struct FLOWTRACK, freelist.c, treetype.h and sys-tree.h, and
 * flow.c of the C version.
 */
#include "softflowd_cpp/softflowd.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace softflowd_cpp {

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
             // Original: flow_last.tv_sec - flow_start.tv_sec, whole seconds
             std::chrono::floor<std::chrono::seconds> (flow.wall_last) -
                 std::chrono::floor<std::chrono::seconds> (flow.wall_start) >
               timeouts_.maximum_lifetime) {
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

  // Original: `exp = MIN (exp, flow->flow_start.tv_sec + maximum_lifetime)`
  // for every expiry time but 0 (over 2 GiB, over its maximum lifetime).
  if (timeouts_.maximum_lifetime.count() != 0 && reason != ExpiryReason::OverBytes &&
      reason != ExpiryReason::MaxLife) {
    auto limit = flow.flow_start + timeouts_.maximum_lifetime;
    if (timeouts_.second_granularity) {
      limit -= std::chrono::duration_cast<Clock::duration> (
        flow.wall_start - std::chrono::floor<std::chrono::seconds> (flow.wall_start));
    }
    expires_at = std::min (expires_at, limit);
  }

  return {expires_at, reason};
}

template <FlowIndexBackend Backend>
void
FlowTable<Backend>::reschedule_expiry (const FlowKey &key, std::uint64_t flow_seq,
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
    if (lookup_it->second->first == ExpiryKey{new_expiry, flow_seq}) {
      return;
    }
    expiry_index_.erase (lookup_it->second);
  }
  auto new_it = expiry_index_.emplace (ExpiryKey{new_expiry, flow_seq}, key).first;
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
    flow.flow_seq = next_flow_seq_++;
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
  // Original: expires_at 0 for a flow that is over 2 GiB or over its maximum
  // lifetime, which sorts in front of every other flow.
  const bool at_once =
    reason == ExpiryReason::OverBytes || reason == ExpiryReason::MaxLife;
  reschedule_expiry (key, flow.flow_seq, at_once ? TimePoint::min() : expires_at);

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
ExpiryReason
FlowTable<Backend>::reason_at_expiry (const Flow &flow, ExpiryReason reason) const {
  if (timeouts_.maximum_lifetime.count() != 0 &&
      std::chrono::floor<std::chrono::seconds> (flow.wall_last) -
          std::chrono::floor<std::chrono::seconds> (flow.wall_start) >=
        timeouts_.maximum_lifetime) {
    return ExpiryReason::MaxLife;
  }
  return reason;
}

template <FlowIndexBackend Backend>
template <class Due>
std::vector<ExportRecord>
FlowTable<Backend>::expire_while (Due due, bool flush_all) {
  // Original: check_expired (). The flows that were evicted by a collision
  // have expires_at 0, like the flows that are due at once.
  std::vector<ExportRecord> expired;
  std::vector<ExportRecord> collided = expire_collisions();
  std::size_t urgent = 0;  // the leading flows of expired that were due at once

  auto it = expiry_index_.begin();
  while (it != expiry_index_.end() && (flush_all || due (it->first))) {
    const FlowKey key = it->second;  // copy before the iterator is invalidated
    const bool at_once = it->first.first == TimePoint::min();

    auto flow_it = flows_.find (key);
    if (flow_it != flows_.end()) {
      // A flush counts as R_FLUSH, but the debug log keeps this reason.
      flow_it->second.reason = reason_at_expiry (flow_it->second, flow_it->second.reason);
      record_expiry_stats (flow_it->second, key.protocol(),
                           ExpiryReason::Flush, flush_all);
      expired.push_back (ExportRecord{key, flow_it->second});
      urgent += at_once ? 1 : 0;
      flows_.erase (flow_it);
      forget_slot (key);
    }
    expiry_lookup_.erase (key);
    it = expiry_index_.erase (it);  // erase() returns the next valid iterator
  }

  stats_.flows_expired += expired.size();
  const std::size_t collided_count = collided.size();
  collided.insert (collided.end(), std::make_move_iterator (expired.begin()),
                   std::make_move_iterator (expired.end()));
  // Original: the flows with expires_at 0 are ordered by their sequence.
  std::stable_sort (collided.begin(),
                    collided.begin() + static_cast<std::ptrdiff_t> (collided_count + urgent),
                    [] (const ExportRecord &x, const ExportRecord &y) {
                      return x.flow.flow_seq < y.flow.flow_seq;
                    });
  return collided;
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord>
FlowTable<Backend>::expire_flows (TimePoint now, bool flush_all) {
  // Original: check_expired () expires a flow when its expires_at, whole
  // seconds, is less than the current second, so a flow is due one second
  // after the instant its expiry time names.
  const auto grace = timeouts_.second_granularity ? std::chrono::seconds (1)
                                                  : std::chrono::seconds (0);
  return expire_while ([&] (const ExpiryKey &key) { return key.first + grace <= now; },
                       flush_all);
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord>
FlowTable<Backend>::expire_urgent () {
  return expire_while (
    [] (const ExpiryKey &key) { return key.first == TimePoint::min(); }, false);
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
      // Original: force_expire () sets expiry->reason to R_OVERFLOWS, and the
      // scan that expires the flow may make it R_MAXLIFE.
      const ExpiryReason reason =
        reason_at_expiry (flow_it->second, ExpiryReason::OverFlows);
      flow_it->second.reason = reason;
      record_expiry_stats (flow_it->second, key.protocol(), reason, true);
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
  // Original: force_expire () sets expires_at of every one of them to 0, so
  // the next scan finds them in the order of their sequence.
  std::stable_sort (expired.begin(), expired.end(),
                    [] (const ExportRecord &x, const ExportRecord &y) {
                      return x.flow.flow_seq < y.flow.flow_seq;
                    });
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
FlowTable<Backend>::expire_collisions () {
  std::vector<ExportRecord> out;
  out.swap (collided_);
  for (auto &record : out) {
    record.flow.reason = reason_at_expiry (record.flow, ExpiryReason::Collision);
    record_expiry_stats (record.flow, record.key.protocol(), record.flow.reason, true);
  }
  stats_.flows_expired += out.size();
  return out;
}

template <FlowIndexBackend Backend>
FlowTableUsage
FlowTable<Backend>::usage () const {
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
    // Original: flow_table_init () for hash-tree; a power of two of at least
    // max_flows, up to 2^24, one pointer each. std::unordered_map has a
    // bucket count of its own, which is only used to measure the spread.
    constexpr std::size_t kMaxBuckets = std::size_t{1} << 24;
    std::size_t n = 1;
    while (n < max_flows_ && n < kMaxBuckets) {
      n <<= 1;
    }
    u.buckets = n;
    u.bytes = n * sizeof (void *);
    for (std::size_t i = 0; i < flows_.bucket_count(); ++i) {
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

template <FlowIndexBackend Backend>
std::vector<ExpiryEntry>
FlowTable<Backend>::expiry_snapshot () const {
  std::vector<ExpiryEntry> result;
  result.reserve (expiry_index_.size());
  for (const auto &[expiry_key, key] : expiry_index_) {
    const auto it = flows_.find (key);
    if (it != flows_.end()) {
      result.push_back (
        ExpiryEntry{ExportRecord{key, it->second}, expiry_key.first});
    }
  }
  return result;
}

template <FlowIndexBackend Backend>
int
FlowTable<Backend>::next_expire (std::chrono::system_clock::time_point wall_now,
                                 std::chrono::seconds interval) const {
  // Flows that were evicted by a collision have expires_at 0.
  if (!collided_.empty()) {
    return 0;
  }
  const auto it = expiry_index_.begin();
  if (it == expiry_index_.end()) {
    return -1;  // indefinite
  }
  const auto flow_it = flows_.find (it->second);
  if (flow_it == flows_.end()) {
    return -1;
  }
  long long expires_at = expiry_epoch_seconds (flow_it->second, it->first.first);
  const long long now =
    std::chrono::duration_cast<std::chrono::seconds> (wall_now.time_since_epoch()).count();
  if (expires_at == 0) {
    return 0;  // Now
  }
  // Cluster expiries by expiry_interval
  if (interval.count() > 1) {
    const long long fudge = expires_at % interval.count();
    if (fudge > 0) {
      expires_at += interval.count() - fudge;
    }
  }
  if (expires_at < now) {
    return 0;  // Now
  }
  const long long ms = 999 + (expires_at - now) * 1000;
  return ms > std::numeric_limits<int>::max() ? std::numeric_limits<int>::max()
                                              : static_cast<int> (ms);
}

template <FlowIndexBackend Backend>
std::size_t
FlowTable<Backend>::delete_all () {
  const std::size_t count = flows_.size() + collided_.size();
  flows_.clear();
  expiry_index_.clear();
  expiry_lookup_.clear();
  collided_.clear();
  for (auto &slot : slots_) {
    slot.reset();
  }
  return count;
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

}  // namespace softflowd_cpp
