/**
 * @file flow.hpp
 * @brief The flow table: the container of the flows with the hash and the tree backends, its lookups, statistics and timeouts, and the table that the daemon uses.
 *
 * Split from softflowd.hpp, which keeps the types that the flow table holds
 * (FlowKey, Flow and ExportRecord). The member functions are defined in
 * flow.cpp (FlowTable) and flow_runtime.cpp (FlowTableRuntime).
 *
 * @original struct FLOWTRACK, freelist.h, treetype.h and sys-tree.h of the
 * original softflowd, and flow.h of the C version.
 */
#ifndef SOFTFLOWD_CPP_FLOW_HPP
#define SOFTFLOWD_CPP_FLOW_HPP

#include "softflowd_cpp/softflowd.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace softflowd_cpp {

/**
 * @brief The container that holds the flows of a FlowTable.
 *
 * See FlowTable for why the container is selectable.
 */
enum class FlowIndexBackend {
  Hash,  ///< std::unordered_map\<FlowKey, Flow\> -- closest to a hash table.
  Tree,  ///< std::map\<FlowKey, Flow\> -- a genuine red-black tree.
};

/**
 * @brief How the flows are looked up, selected with -F/--flow-lookup.
 *
 * Tree is an ordered map, HashTree a hash table that keeps colliding flows (the default) and Hash a hash table with one slot per bucket.
 *
 * @original enum FLOW_LOOKUP, selected with -F/--flow-lookup.
 *   Tree     -- an ordered map (FlowIndexBackend::Tree).
 *   HashTree -- a hash table that keeps colliding flows (the default;
 *               FlowIndexBackend::Hash).
 *   Hash     -- a hash table with one slot per bucket (FlowIndexBackend::Hash
 *               plus collision mode): a flow that hashes to a slot that is
 *               taken evicts the resident flow, which is exported as
 *               expired by collision.
 */
enum class FlowLookup {
  Tree,      ///< An ordered map (FlowIndexBackend::Tree).
  HashTree,  ///< A hash table that keeps colliding flows (FlowIndexBackend::Hash); the default.
  Hash       ///< A hash table with one slot per bucket: a flow that hashes to a taken slot evicts the resident flow.
};

/**
 * @brief The name of a lookup mode, as -F and the statistics write it.
 *
 * @param lookup The mode.
 * @return "tree", "hash-tree" or "hash".
 */
constexpr const char *
flow_lookup_name (FlowLookup lookup) noexcept {
  switch (lookup) {
    case FlowLookup::HashTree:
      return "hash-tree";
    case FlowLookup::Hash:
      return "hash";
    default:
      return "tree";
  }
}

/**
 * @brief How the active flows are spread over the buckets of the flow table.
 *
 * @original flow_table_usage(). How the active flows are spread over the
 * buckets of the flow table.
 */
struct FlowTableUsage {
  std::size_t buckets{0};    ///< The number of buckets.
  std::size_t bytes{0};      ///< The memory that the table uses, in bytes.
  std::size_t used{0};       ///< The number of buckets that hold at least one flow.
  std::size_t max_depth{0};  ///< The most flows in one bucket.
};

/**
 * @brief The timeouts after which flows expire, set with -t.
 *
 * @original struct FLOWTRACKPARAMETERS' timeout fields. Plain `int` (in
 * seconds) is replaced with std::chrono::seconds so that passing a value in
 * the wrong unit (e.g. milliseconds by mistake) becomes a compile error
 * rather than a runtime bug.
 */
struct FlowTimeouts {
  std::chrono::seconds tcp{3600};                        ///< The idle time of a TCP flow.
  std::chrono::seconds tcp_rst{120};                     ///< The idle time of a TCP flow after a RST.
  std::chrono::seconds tcp_fin{300};                     ///< The idle time of a TCP flow after a FIN from both ends.
  std::chrono::seconds udp{300};                         ///< The idle time of a UDP flow.
  std::chrono::seconds icmp{300};                        ///< The idle time of an ICMP or ICMPv6 flow.
  std::chrono::seconds general{3600};                    ///< The idle time of any other flow.
  std::chrono::seconds maximum_lifetime{3600 * 24 * 7};  ///< The longest life of a flow; 0 for no limit.

  // Original: expiry->expires_at is a plain `time_t`, computed as
  // `flow->flow_last.tv_sec + timeout_value` -- whole-second integer
  // arithmetic that silently discards flow_last's tv_usec, UNCONDITIONALLY
  // (the original has no finer-grained mode to opt into). This project's
  // TimePoint retains full (sub-second) precision, so flows that would
  // tie (same whole second) in the original can end up with distinct,
  // differently-ordered expiry times here instead -- this is not a rare
  // edge case: many real captures have several flows finishing within
  // the same wall-clock second, especially under -r where a whole
  // multi-second capture can be read in milliseconds, and every one of
  // those ties changes NetFlow/IPFIX export packet record ordering
  // relative to the original. So this defaults to true, matching the
  // original's only actual behavior; --no-expiry-second-granularity is
  // available to opt into full sub-second precision instead. Only
  // affects expiry *scheduling*; flow.flow_start/flow.flow_last
  // themselves (and thus exported Duration/octets/packets statistics)
  // keep full precision either way.
  bool second_granularity = true;  ///< Schedule the expiry in whole seconds, as the original does (--no-expiry-second-granularity turns it off).
};

/**
 * @brief A running minimum, mean and maximum.
 *
 * The mean is updated with Welford's online method.
 *
 * @original struct FLOWTRACKPARAMETERS' statistics fields. The original had
 * a dozen-plus flat u_int64_t counters; only the subset needed so far is
 * kept here (NetFlow export statistics will be added in a later stage).
 * Original: struct STATISTIC (softflowd.h) + update_statistic() in
 * softflowd.c -- a running min/mean/max accumulator using Welford's
 * online-mean update.
 */
struct StatAccumulator {
  double min{0.0};     ///< The smallest value.
  double mean{0.0};    ///< The mean.
  double max{0.0};     ///< The largest value.
  std::uint64_t n{0};  ///< The number of values.

  /**
     * @brief Adds a value.
     *
     * @param value The value.
     */
  void
  update (double value) noexcept {
    if (n == 0 || value < min)
      min = value;
    if (n == 0 || value > max)
      max = value;
    ++n;
    mean += (value - mean) / static_cast<double> (n);
  }
};

/**
 * @brief The counters that the statistics report.
 */
struct FlowTableStats {
  std::uint64_t total_packets{0};        ///< The packets processed ("Packets processed").
  std::uint64_t bad_packets{0};          ///< The packets that were too short for their headers ("too short").
  std::uint64_t non_ip_packets{0};       ///< The packets that were not IP ("non-IP").
  std::uint64_t frag_packets{0};         ///< The fragments ("Fragments").
  std::uint64_t flows_expired{0};        ///< The flows that expired ("Flows expired").
  std::uint64_t flows_force_expired{0};  ///< The flows that were forced to expire ("forced"), because there were too many.

  std::uint64_t flows_exported{0};  ///< The flows that were exported.
  std::uint64_t records_sent{0};    ///< The records that were sent.
  std::uint64_t packets_sent{0};    ///< The export packets that were sent.
  std::uint64_t flows_dropped{0};   ///< The flows that could not be exported.

  StatAccumulator duration;  ///< The duration of the expired flows, in seconds.
  StatAccumulator octets;    ///< The octets of the expired flows (both directions).
  StatAccumulator packets;   ///< The packets of the expired flows (both directions).

  std::array<std::uint64_t, 256> flows_pp{};       ///< The expired flows by protocol.
  std::array<std::uint64_t, 256> octets_pp{};      ///< The octets of the expired flows by protocol.
  std::array<std::uint64_t, 256> packets_pp{};     ///< The packets of the expired flows by protocol.
  std::array<StatAccumulator, 256> duration_pp{};  ///< The duration of the expired flows by protocol, in seconds.

  std::uint64_t expired_general{0};    ///< The flows that expired for ExpiryReason::General.
  std::uint64_t expired_tcp{0};        ///< The flows that expired for ExpiryReason::Tcp.
  std::uint64_t expired_tcp_rst{0};    ///< The flows that expired for ExpiryReason::TcpRst.
  std::uint64_t expired_tcp_fin{0};    ///< The flows that expired for ExpiryReason::TcpFin.
  std::uint64_t expired_udp{0};        ///< The flows that expired for ExpiryReason::Udp.
  std::uint64_t expired_icmp{0};       ///< The flows that expired for ExpiryReason::Icmp.
  std::uint64_t expired_maxlife{0};    ///< The flows that expired for ExpiryReason::MaxLife.
  std::uint64_t expired_overbytes{0};  ///< The flows that expired for ExpiryReason::OverBytes.
  std::uint64_t expired_maxflows{0};   ///< The flows that expired for ExpiryReason::OverFlows.
  std::uint64_t expired_flush{0};      ///< The flows that expired for ExpiryReason::Flush.
  std::uint64_t expired_collision{0};  ///< The flows that expired for ExpiryReason::Collision.
};

/**
 * @brief The table of the active flows, with their expiry schedule.
 *
 * The original implementation combined three pieces of manual memory
 * management:
 *   1. freelist.c: a hand-rolled malloc/free wrapper (a separate free list
 *      for flows and one for expiry events)
 *   2. sys-tree.h: an intrusive red-black tree via the RB_HEAD/RB_ENTRY
 *      macros (the FLOW struct itself doubled as a tree node, via
 *      `FLOW_ENTRY(FLOW) trp;`)
 *   3. Mutual raw pointers between FLOW and EXPIRY
 *
 * This design allowed for the classic bug patterns the article warns about:
 *   - freeing a flow but forgetting to remove it from the expiry tree,
 *     leaving a pointer to freed memory (dangling pointer / use-after-free)
 *   - forgetting to return memory to the free list, or returning it twice
 *     (double free)
 *   - calling RB_INSERT/RB_REMOVE in the wrong order (corrupting the tree)
 *
 * In the modern C++ version, ownership of every flow lives in exactly one
 * place: the associative container inside FlowTable. No free list is
 * needed -- insertion/removal is the container's job, and a double free is
 * structurally impossible. Expiry bookkeeping never touches a raw pointer;
 * it maps "time -\> FlowKey", and looking up an expired flow is just a
 * lookup by key -- if that lookup somehow fails, find() returns "not
 * found" instead of crashing.
 *
 * New in this revision: which associative container backs the primary flow
 * index is a template parameter, so the same code that used to hard-code a
 * red-black tree (sys-tree.h) in the original C project can now be selected
 * explicitly:
 *   - FlowIndexBackend::Hash -\> std::unordered_map (average O(1) lookup)
 *   - FlowIndexBackend::Tree -\> std::map (a genuine red-black tree in
 *     libstdc++/libc++, giving ordered iteration -- the closest modern
 *     equivalent of the original's RB_HEAD/RB_ENTRY-based flow tree)
 * FlowTable\<Backend\> selects the backend at compile time (zero overhead,
 * the classic C++ template approach). FlowTableRuntime, defined further
 * below, wraps both instantiations in a std::variant so the choice can also
 * be made at run time (e.g. from a command-line flag).

 * @tparam Backend The container of the flows.
 *
 * @original struct FLOWTRACK as a whole, plus the functionality of
 * freelist.c / sys-tree.h.
 *
 * Member function bodies are defined out-of-line in flow.cpp and
 * explicitly instantiated for both FlowIndexBackend values (see the
 * `extern template` declarations below), mirroring the original's
 * declaration-in-.h / definition-in-.c split even though this is a
 * template.
 */
template <FlowIndexBackend Backend>
class FlowTable {
public:
  /**
     * @brief The container of the flows, keyed by FlowKey.
     *
     * @original RB_HEAD(FLOWS, FLOW) flows; (an intrusive red-black tree
     * keyed by the FLOW struct itself), or with FlowIndexBackend::Hash, the
     * modern equivalent of a from-scratch hash table.
     */
  using FlowMap =
    std::conditional_t<Backend == FlowIndexBackend::Hash,
                       std::unordered_map<FlowKey, Flow>,
                       std::map<FlowKey, Flow>>;

  /**
     * @brief Creates an empty table.
     *
     * @param max_flows The most flows that are tracked (-m).
     * @param track_level The -T level.
     * @param timeouts The timeouts after which flows expire.
     */
  explicit FlowTable (std::size_t max_flows,
                      TrackLevel track_level = TrackLevel::IpProtoPort,
                      FlowTimeouts timeouts = {});

  /**
     * @brief Copying is not allowed: the expiry lookup holds iterators into the expiry index of this object.
     *
     * Copying is deleted rather than left to the implicitly-generated
     * (and subtly wrong) default: expiry_lookup_ holds std::multimap
     * iterators that point into this object's own expiry_index_. A
     * member-wise *copy* would copy those iterator values verbatim, so the
     * copy's expiry_lookup_ would end up pointing into the *original's*
     * expiry_index_ rather than its own -- silently corrupting the
     * invariant the moment either object is destroyed or modified. Moving
     * does not have this problem: per the standard, moving a container
     * preserves the validity of iterators into it, so a moved-from
     * FlowTable's expiry_lookup_ iterators remain correctly associated with
     * the moved-to object's expiry_index_.
     */
  FlowTable (const FlowTable &) = delete;
  /**
     * @brief Copy assignment is not allowed.
     */
  FlowTable &
  operator= (const FlowTable &) = delete;
  /**
     * @brief Moves a table; the iterators of the expiry lookup stay valid.
     */
  FlowTable (FlowTable &&) noexcept = default;
  /**
     * @brief Move assignment.
     */
  FlowTable &
  operator= (FlowTable &&) noexcept = default;
  /**
     * @brief Destroys the table with its flows.
     */
  ~FlowTable () = default;

  /**
     * @brief Adds a packet to its flow, which is created when it is new, and schedules the expiry of the flow.
     *
     * @param key The key of the flow.
     * @param now The monotonic time of the packet.
     * @param wall_now The wall-clock time of the packet.
     * @param direction Which end of the key the source of the packet is (0 or 1).
     * @param octet_delta The octets of the packet.
     * @param tcp_flags The TCP flags of the packet.
     * @param tos The type of service of the packet.
     * @return The updated flow; use it at once, as it is valid only until the flow expires.
     *
     * @original the "look up the flow, update it if found, otherwise
     * allocate + RB_INSERT" sequence that softflowd.c performed for every
     * packet in process_packet(). Here, unordered_map/map::%try_emplace does
     * "construct if absent, otherwise return the existing entry" in a
     * single lookup.
     *
     * Returns: a reference to the updated Flow. The reference is valid only
     * while this FlowTable is alive and the flow has not yet been expired
     * (by design, this reference is meant to be used immediately by the
     * caller rather than stored, so no raw pointer needs to be handed out).
     */
  Flow &
  record_packet (const FlowKey &key, TimePoint now,
                 std::chrono::system_clock::time_point wall_now,
                 std::uint8_t direction, std::uint64_t octet_delta,
                 std::uint8_t tcp_flags, std::uint8_t tos);

  /**
     * @brief Removes the flows that are due, and the flows that were evicted by a collision.
     *
     * flush_all: original's CE_EXPIRE_ALL (used on graceful shutdown).
     * Expires every remaining flow regardless of its normal expiry time,
     * tagging each with ExpiryReason::Flush for statistics purposes.
     *
     * @param now The monotonic time that flows are due at.
     * @param flush_all Expire every flow whatever its time (shutdown, expire-all); ExpiryReason::Flush is counted.
     * @return The expired flows, in the order of their expiry.
     */
  std::vector<ExportRecord>
  expire_flows (TimePoint now, bool flush_all = false);

  /**
     * @brief Removes only the flows that are due at once and those evicted by a collision.
     *
     * @return The expired flows.
     *
     * @original check_expired (CE_EXPIRE_FORCED), which a capture file is
     * checked with: only the flows that are due at once (expires_at 0) and
     * those evicted by a collision.
     */
  std::vector<ExportRecord>
  expire_urgent ();

  /**
     * @brief Evicts flows because there are too many (-m); those with the nearest expiry go first.
     *
     * Explicit forced eviction (original: softflowd.c's handling of
     * exceeding the configured maximum flow count with -m). Evicts the
     * flows with the nearest expiry first (i.e. the least recently active).
     *
     * @param count How many flows to evict.
     * @return The evicted flows.
     */
  std::vector<ExportRecord>
  force_expire_oldest (std::size_t count);

  /**
     * @brief Turns on -F hash: one slot per bucket, and a flow that finds its slot taken evicts the resident flow.
     *
     * @param buckets The number of slots, rounded up to a power of two.
     * @note Only the FlowIndexBackend::Hash backend has it.
     *
     * @original -F hash. Gives the table one slot per bucket (a power of
     * two, at least `buckets`); only the std::unordered_map backend has it.
     * A flow that finds its slot taken evicts the resident one.
     */
  void
  enable_collision_mode (std::size_t buckets);

  /**
     * @brief Takes the flows that were evicted by a collision, to be exported now.
     *
     * @return The evicted flows.
     *
     * @original the flows with expires_at == 0 and R_COLLISION: the flows
     * that were evicted by a collision, to be exported now.
     */
  std::vector<ExportRecord>
  expire_collisions ();

  /**
     * @brief How the flows are spread over the buckets.
     *
     * @return The usage.
     *
     * @original flow_table_usage().
     */
  FlowTableUsage
  usage () const;

  /**
     * @brief Copies every tracked flow without expiring any.
     *
     * @return The flows.
     *
     * @original softflowctl(8)'s dump-flows command. Returns a copy of
     * every currently tracked flow *without* removing or expiring any of
     * them (unlike expire_flows()/force_expire_oldest()) -- purely a
     * read-only snapshot for diagnostic reporting.
     */
  std::vector<ExportRecord>
  snapshot () const;

  /**
     * @brief Copies every tracked flow with its expiry event, in the order of the expiry.
     *
     * @return The flows.
     *
     * @original dump-flows walks the expiry tree, so this is the same flows
     * in the order of their expiry events.
     */
  std::vector<ExpiryEntry>
  expiry_snapshot () const;

  /**
     * @brief Tells when the table has to be checked again.
     *
     * @param wall_now The current wall-clock time.
     * @param interval The interval of -t expint: the earliest expiry is moved up to a multiple of it.
     * @return Milliseconds until the check; 0 when a check is due, -1 when there is no flow.
     *
     * @original next_expire (). Milliseconds until the flow table has to be
     * checked again: 0 when a check is due, -1 when there is no flow. The
     * earliest expiry is moved up to a multiple of `interval` seconds
     * (clustering), which is what makes -t expint group the expiries.
     */
  int
  next_expire (std::chrono::system_clock::time_point wall_now,
               std::chrono::seconds interval) const;

  /**
     * @brief Drops every flow, including those that wait to be exported after a collision, without export and without counting them.
     *
     * @return The number of flows dropped.
     *
     * @original delete_all_flows (). Drops every flow, including those that
     * wait to be exported after a collision, without export and without
     * counting them. Returns the number of flows dropped.
     */
  std::size_t
  delete_all ();

  /**
     * @brief The number of tracked flows.
     *
     * @return The number.
     */
  std::size_t
  size () const noexcept {
    return flows_.size();
  }
  /**
     * @brief The most flows that are tracked.
     *
     * @return The limit.
     */
  std::size_t
  max_flows () const noexcept {
    return max_flows_;
  }
  /**
     * @brief The counters of the table.
     *
     * @return The statistics.
     */
  const FlowTableStats &
  stats () const noexcept {
    return stats_;
  }

  /**
     * @brief Adds the outcome of an export to the statistics.
     *
     * @param flows The flows exported.
     * @param records The records sent.
     * @param packets The packets sent.
     * @param failures The flows that could not be sent.
     *
     * @original send_nflow5()/send_nflow9()/send_ipfix() etc. incrementing
     * ft-\>param.flows_exported/records_sent/packets_sent/flows_dropped as
     * a side effect of exporting. ExportPipeline is a standalone class
     * with no reference to this table's stats_, so the caller (the main
     * loop) reports the outcome of each export_flows() call back here.
     */
  void
  record_export_stats (std::uint64_t flows, std::uint64_t records,
                       std::uint64_t packets, std::uint64_t failures) noexcept {
    stats_.flows_exported += flows;
    stats_.records_sent += records;
    stats_.packets_sent += packets;
    stats_.flows_dropped += failures;
  }
  /**
     * @brief Counts a packet that does not become a flow as processed.
     *
     * @original flow_cb () and process_packet () count the packets that do not
     * become a flow in the statistics as well. A packet with -v psamp is
     * counted as processed, one that is not IP is counted as ignored, and one
     * that is too short for its headers is counted as ignored and as processed.
     */
  void
  count_packet_without_flow () noexcept {
    stats_.total_packets += 1;
  }
  /**
     * @brief Counts a packet that is not IP as ignored.
     */
  void
  count_non_ip_packet () noexcept {
    stats_.non_ip_packets += 1;
  }
  /**
     * @brief Counts a packet that is too short for its headers as ignored and as processed.
     */
  void
  count_bad_packet () noexcept {
    stats_.bad_packets += 1;
    stats_.total_packets += 1;
  }
  /**
     * @brief The -T level.
     *
     * @return The level.
     */
  TrackLevel
  track_level () const noexcept {
    return track_level_;
  }
  /**
     * @brief The timeouts.
     *
     * @return The timeouts.
     */
  const FlowTimeouts &
  timeouts () const noexcept {
    return timeouts_;
  }
  /**
     * @brief The container of the flows.
     *
     * @return The backend.
     */
  static constexpr FlowIndexBackend
  backend () noexcept {
    return Backend;
  }

private:
  /**
     * @brief Works out when a flow expires and why.
     *
     * @param flow The flow.
     * @param protocol Its IP protocol.
     * @param af Its address family.
     * @return The expiry time and the reason.
     */
  std::pair<TimePoint, ExpiryReason>
  compute_expiry (
    const Flow &flow, std::uint8_t protocol, AddressFamily af) const;
  /**
     * @brief Updates the statistics for a flow that expired.
     *
     * @param flow The flow.
     * @param protocol Its IP protocol.
     * @param reason_override The reason to count when @p override_reason is set.
     * @param override_reason Count @p reason_override instead of the reason of the flow.
     */
  void
  record_expiry_stats (const Flow &flow, std::uint8_t protocol,
                       ExpiryReason reason_override, bool override_reason);
  /**
     * @brief Moves the expiry event of a flow to a new time.
     *
     * @param key The key of the flow.
     * @param flow_seq The sequence number of the flow.
     * @param new_expiry The new expiry time.
     */
  void
  reschedule_expiry (const FlowKey &key, std::uint64_t flow_seq, TimePoint new_expiry);

  /**
     * @brief Removes the flows from the front of the expiry index while they are due.
     *
     * @param due Tells whether an expiry key is due.
     * @param flush_all Remove every flow.
     * @return The expired flows.
     * @tparam Due A callable that takes an ExpiryKey and returns bool.
     */
  template <class Due>
  std::vector<ExportRecord>
  expire_while (Due due, bool flush_all);

  /**
     * @brief The reason to count when a flow expires.
     *
     * @param flow The flow.
     * @param reason The reason of the schedule.
     * @return ExpiryReason::MaxLife when the flow lived at least the maximum lifetime, otherwise @p reason.
     *
     * @original check_expired () makes the reason of a flow that lived at
     * least maximum_lifetime (whole seconds) R_MAXLIFE, whatever it was.
     */
  ExpiryReason
  reason_at_expiry (const Flow &flow, ExpiryReason reason) const;
  /**
     * @brief Frees the slot of a flow in collision mode, when the flow is the resident.
     *
     * @param key The key of the flow.
     */
  void
  forget_slot (const FlowKey &key);

  std::size_t max_flows_;  ///< The most flows that are tracked.
  /**
     * @brief The sequence number of the next flow.
     *
     * @original ft-\>param.next_flow_seq, which starts at 1 and counts every
     * flow ever created, not the flows being tracked.
     */
  std::uint64_t next_flow_seq_{1};
  TrackLevel track_level_;  ///< The -T level.
  FlowTimeouts timeouts_;   ///< The timeouts.
  FlowTableStats stats_;    ///< The counters.

  FlowMap flows_;  ///< The flows.

  /**
     * @brief The key of the expiry index: the expiry time and the sequence number of the flow.
     *
     * @original RB_HEAD(EXPIRIES, EXPIRY) expiries; (an intrusive red-black
     * tree whose EXPIRY nodes pointed back to a FLOW via a raw pointer).
     * Here it's a "expiry time -\> flow key" map -- the expiry index never
     * holds the flow itself or a pointer to it. Kept as std::multimap
     * (i.e. always tree-backed) regardless of the primary FlowMap backend,
     * because ordered iteration by time is fundamental to expiry
     * processing either way.
     * Original: expiry_compare () orders the tree by expires_at and then by
     * the flow sequence. A flow that is due at once (expires_at 0: over 2 GiB,
     * over its maximum lifetime) is kept at TimePoint::min (), in front.
     */
  using ExpiryKey = std::pair<TimePoint, std::uint64_t>;
  std::map<ExpiryKey, FlowKey> expiry_index_;  ///< The expiry events, in time order.

  /**
     * @brief Finds the expiry event of a flow by its key, so that it can be rescheduled in O(log n).
     *
     * Auxiliary index used to look up a flow's current position in
     * expiry_index_ by FlowKey, so that rescheduling (extending a timeout
     * when new traffic arrives) can be done in O(log n) instead of a linear
     * scan. This holds std::multimap iterators, not raw pointers; inserting
     * or erasing *other* elements of a std::map/std::multimap never
     * invalidates the iterators to elements that remain (a guarantee of the
     * standard library's map family), so holding on to them here is safe.
     */
  std::unordered_map<FlowKey, std::map<ExpiryKey, FlowKey>::iterator>
    expiry_lookup_;

  /**
     * @brief The resident flow of every slot, in collision mode (-F hash).
     *
     * Collision mode (-F hash): the resident flow of every slot, and the
     * evicted flows that wait to be exported.
     */
  std::vector<std::optional<FlowKey>> slots_;
  /**
     * @brief The flows that a collision evicted, which wait to be exported.
     */
  std::vector<ExportRecord> collided_;
};

// Explicit instantiation declarations: tells any translation unit that
// includes this header not to implicitly instantiate FlowTable<Hash> /
// FlowTable<Tree> itself, but to expect the definitions from flow.cpp
// at link time. This keeps the (fairly large) template body out of every
// including file's compiled output, exactly as if FlowTable were a plain
// non-template class declared in a .h and defined once in a .c file.
extern template class FlowTable<FlowIndexBackend::Hash>;
extern template class FlowTable<FlowIndexBackend::Tree>;

/**
 * @brief A FlowTable whose backend is chosen at run time, from -F.
 *
 * It holds the two FlowTable instantiations in a std::variant and forwards every call.
 *
 * A non-template wrapper that allows the backend to be chosen at run time
 * (e.g. from a command-line flag) rather than fixed at compile time. This
 * directly answers "should flow tracking use a tree or a hash table" as a
 * runtime decision, the same way the original build could be configured
 * with -DFLOW_RB or an equivalent choice at build time -- except here it's
 * a single binary that can do either.
 *
 * Internally this simply holds a std::variant of the two FlowTable
 * instantiations and forwards every call through std::visit. There is no
 * dynamic dispatch / vtable overhead beyond what std::variant already adds
 * (a single tag check per call), and no raw pointers or manual ownership
 * are introduced by this wrapper.
 */
class FlowTableRuntime {
public:
  /**
   * @brief Creates an empty table.
   *
   * @param lookup The lookup mode (-F).
   * @param max_flows The most flows that are tracked (-m).
   * @param track_level The -T level.
   * @param timeouts The timeouts after which flows expire.
   */
  FlowTableRuntime (FlowLookup lookup, std::size_t max_flows,
                    TrackLevel track_level = TrackLevel::IpProtoPort,
                    FlowTimeouts timeouts = {});

  /**
   * @brief Forwards to the table; see FlowTable::record_packet.
   * @copydoc FlowTable::record_packet
   */
  Flow &
  record_packet (const FlowKey &key, TimePoint now,
                 std::chrono::system_clock::time_point wall_now,
                 std::uint8_t direction, std::uint64_t octet_delta,
                 std::uint8_t tcp_flags, std::uint8_t tos);
  /**
   * @brief Forwards to the table; see FlowTable::expire_flows.
   * @copydoc FlowTable::expire_flows
   */
  std::vector<ExportRecord>
  expire_flows (TimePoint now, bool flush_all = false);
  /**
   * @brief Forwards to the table; see FlowTable::expire_urgent.
   * @copydoc FlowTable::expire_urgent
   */
  std::vector<ExportRecord>
  expire_urgent ();
  /**
   * @brief Forwards to the table; see FlowTable::force_expire_oldest.
   * @copydoc FlowTable::force_expire_oldest
   */
  std::vector<ExportRecord>
  force_expire_oldest (std::size_t count);
  /**
   * @brief Forwards to the table; see FlowTable::expire_collisions.
   * @copydoc FlowTable::expire_collisions
   */
  std::vector<ExportRecord>
  expire_collisions ();
  /**
   * @brief Forwards to the table; see FlowTable::snapshot.
   * @copydoc FlowTable::snapshot
   */
  std::vector<ExportRecord>
  snapshot () const;
  /**
   * @brief Forwards to the table; see FlowTable::expiry_snapshot.
   * @copydoc FlowTable::expiry_snapshot
   */
  std::vector<ExpiryEntry>
  expiry_snapshot () const;
  /**
   * @brief Forwards to the table; see FlowTable::next_expire.
   * @copydoc FlowTable::next_expire
   */
  int
  next_expire (std::chrono::system_clock::time_point wall_now,
               std::chrono::seconds interval) const;
  /**
   * @brief Forwards to the table; see FlowTable::delete_all.
   * @copydoc FlowTable::delete_all
   */
  std::size_t
  delete_all ();
  /**
   * @brief Forwards to the table; see FlowTable::usage.
   * @copydoc FlowTable::usage
   */
  FlowTableUsage
  usage () const;
  /**
   * @brief The lookup mode.
   *
   * @return The mode.
   */
  FlowLookup
  lookup () const noexcept {
    return lookup_;
  }

  /**
     * @brief Forwards to the table; see FlowTable::timeouts.
     * @copydoc FlowTable::timeouts
     */
  const FlowTimeouts &
  timeouts () const noexcept;

  /**
     * @brief Forwards to the table; see FlowTable::size.
     * @copydoc FlowTable::size
     */
  std::size_t
  size () const noexcept;
  /**
     * @brief Forwards to the table; see FlowTable::max_flows.
     * @copydoc FlowTable::max_flows
     */
  std::size_t
  max_flows () const noexcept;
  /**
     * @brief Forwards to the table; see FlowTable::stats.
     * @copydoc FlowTable::stats
     */
  const FlowTableStats &
  stats () const noexcept;
  /**
     * @brief Forwards to the table; see FlowTable::record_export_stats.
     * @copydoc FlowTable::record_export_stats
     */
  void
  record_export_stats (std::uint64_t flows, std::uint64_t records,
                       std::uint64_t packets, std::uint64_t failures) noexcept;
  /**
     * @brief Forwards to the table; see FlowTable::count_packet_without_flow.
     * @copydoc FlowTable::count_packet_without_flow
     */
  void
  count_packet_without_flow () noexcept;
  /**
     * @brief Forwards to the table; see FlowTable::count_non_ip_packet.
     * @copydoc FlowTable::count_non_ip_packet
     */
  void
  count_non_ip_packet () noexcept;
  /**
     * @brief Forwards to the table; see FlowTable::count_bad_packet.
     * @copydoc FlowTable::count_bad_packet
     */
  void
  count_bad_packet () noexcept;
  /**
     * @brief Forwards to the table; see FlowTable::track_level.
     * @copydoc FlowTable::track_level
     */
  TrackLevel
  track_level () const noexcept;
  /**
     * @brief The container that holds the flows.
     *
     * @return The backend.
     */
  FlowIndexBackend
  backend () const noexcept;

private:
  FlowLookup lookup_;  ///< The lookup mode.
  std::variant<FlowTable<FlowIndexBackend::Hash>,
               FlowTable<FlowIndexBackend::Tree>>
    table_;  ///< The table of the chosen backend.
};

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_FLOW_HPP
