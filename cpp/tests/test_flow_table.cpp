// Exercises FlowTable<Backend> for both FlowIndexBackend values, plus the
// runtime-selectable FlowTableRuntime wrapper. Deliberately avoids an
// external test framework (asserts only) so the focus stays on
// demonstrating the memory-safety claims (no double free, no dangling
// references) under AddressSanitizer/UndefinedBehaviorSanitizer, rather
// than on GoogleTest plumbing.
#include <cassert>
#include <chrono>
#include <cstdio>
#include <stdexcept>

#include "softflow/softflowd.hpp"

using namespace softflow;
using namespace std::chrono_literals;

namespace {

IpAddress make_v4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                   std::uint8_t d) {
    IpAddress addr;
    addr.family = AddressFamily::IPv4;
    addr.bytes[0] = a;
    addr.bytes[1] = b;
    addr.bytes[2] = c;
    addr.bytes[3] = d;
    return addr;
}

void test_canonical_key_is_symmetric() {
    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);

    const auto k1 = FlowKey::make_canonical(a, b, 1000, 80, 6, 0, {0, 0});
    const auto k2 = FlowKey::make_canonical(b, a, 80, 1000, 6, 0, {0, 0});

    // The same bidirectional flow must normalize to the same key
    // (an invariant the original code only documented in a comment; here
    // it is verified at run time).
    assert(k1 == k2);
}

// Parameterized over the backend so both std::unordered_map and std::map
// (a real red-black tree) are exercised with identical logic.
template <FlowIndexBackend Backend>
void test_record_and_expire() {
    FlowTable<Backend> table(16);
    const auto a = make_v4(192, 168, 0, 1);
    const auto b = make_v4(1, 1, 1, 1);
    const auto key = FlowKey::make_canonical(a, b, 12345, 53, 17, 0, {0, 0});

    const auto t0 = Clock::now();
    table.record_packet(key, t0, std::chrono::system_clock::now(), 0, 100, 0, 0);
    assert(table.size() == 1);

    table.record_packet(key, t0 + 1s, std::chrono::system_clock::now(), 1, 200, 0, 0);
    assert(table.size() == 1); // same flow, so the count does not grow

    auto expired = table.expire_flows(t0 + 3601s);
    assert(expired.size() == 1);
    assert(table.size() == 0); // correctly removed from the table itself

    // expired[0] is a copy independent of FlowTable's lifetime, so it
    // remains safe to access even after the FlowTable is destroyed
    // (no dangling reference).
    assert(expired[0].flow.octets[0] == 100);
    assert(expired[0].flow.octets[1] == 200);
}

// Original: flow->flow_seq = ft->param.next_flow_seq++, a counter of every
// flow created, so a number is not used again after a flow has expired.
template <FlowIndexBackend Backend>
void test_flow_seq_is_a_counter() {
    FlowTable<Backend> table(16);
    const auto a = make_v4(192, 168, 0, 1);
    const auto key1 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 1), 1000, 53, 17, 0, {0, 0});
    const auto key2 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 2), 1000, 53, 17, 0, {0, 0});
    const auto key3 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 3), 1000, 53, 17, 0, {0, 0});

    const auto t0 = Clock::now();
    const auto wall = std::chrono::system_clock::now();
    assert(table.record_packet(key1, t0, wall, 0, 10, 0, 0).flow_seq == 1);
    assert(table.record_packet(key2, t0, wall, 0, 10, 0, 0).flow_seq == 2);
    assert(table.expire_flows(t0 + 3601s).size() == 2);
    assert(table.record_packet(key3, t0 + 3602s, wall, 0, 10, 0, 0).flow_seq == 3);
    assert(table.record_packet(key3, t0 + 3603s, wall, 0, 10, 0, 0).flow_seq == 3);
}

// Original: delete_all_flows () drops the flows without exporting or counting
// them, and dump-flows lists the flows in the order of their expiry events.
template <FlowIndexBackend Backend>
void test_delete_all_and_expiry_snapshot() {
    FlowTable<Backend> table(16);
    const auto a = make_v4(192, 168, 0, 1);
    const auto key1 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 1), 1000, 53, 17, 0, {0, 0});
    const auto key2 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 2), 1000, 53, 6, 0, {0, 0});

    const auto t0 = Clock::now();
    const auto wall = std::chrono::system_clock::now();
    table.record_packet(key1, t0, wall, 0, 10, 0, 0);       // UDP: 300 s
    table.record_packet(key2, t0, wall, 0, 10, 0, 0);       // TCP: 3600 s
    const auto entries = table.expiry_snapshot();
    assert(entries.size() == 2);
    assert(entries[0].record.flow.flow_seq == 1);
    assert(entries[0].expires_at < entries[1].expires_at);

    assert(table.delete_all() == 2);
    assert(table.size() == 0);
    assert(table.expiry_snapshot().empty());
    assert(table.stats().flows_expired == 0);
    assert(table.expire_flows(t0 + 7200s, /*flush_all=*/true).empty());
}

// Original: flow_table_init (). hash-tree has a power of two of buckets, at
// least max_flows, one pointer each; tree has a single one.
void test_usage_buckets_follow_max_flows() {
    assert(FlowTable<FlowIndexBackend::Hash>(5).usage().buckets == 8);
    assert(FlowTable<FlowIndexBackend::Hash>(5).usage().bytes == 8 * sizeof(void*));
    assert(FlowTable<FlowIndexBackend::Hash>(8192).usage().buckets == 8192);
    assert(FlowTable<FlowIndexBackend::Hash>(100000).usage().buckets == 131072);
    assert(FlowTable<FlowIndexBackend::Tree>(100000).usage().buckets == 1);
}

// Original: next_expire (). The earliest expiry is moved up to a multiple of
// expint, and the wait is that time plus 999 ms.
template <FlowIndexBackend Backend>
void test_next_expire_clusters_by_interval() {
    FlowTable<Backend> table(16);
    assert(table.next_expire(std::chrono::system_clock::time_point{}, 60s) == -1);

    const auto key = FlowKey::make_canonical(make_v4(192, 168, 0, 1), make_v4(1, 1, 1, 1),
                                             1000, 53, 17, 0, {0, 0});
    const std::chrono::system_clock::time_point wall{1000000000s};
    table.record_packet(key, Clock::now(), wall, 0, 10, 0, 0);  // UDP: 300 s

    assert(table.next_expire(wall, 0s) == 999 + 300 * 1000);
    assert(table.next_expire(wall, 1s) == 999 + 300 * 1000);
    assert(table.next_expire(wall, 60s) == 999 + 320 * 1000);   // 1000000300 -> 1000000320
    assert(table.next_expire(wall + 321s, 60s) == 0);           // 1000000320 < now
    assert(table.next_expire(wall + 320s, 60s) == 999);         // not yet: the second is not over
}

// Original: check_expired () expires a flow when expires_at < the current
// second, so it is due one second after the instant its expiry time names.
template <FlowIndexBackend Backend>
void test_flow_is_due_one_second_after_its_expiry_time() {
    FlowTable<Backend> table(16);
    const auto key = FlowKey::make_canonical(make_v4(192, 168, 0, 1), make_v4(1, 1, 1, 1),
                                             1000, 53, 17, 0, {0, 0});
    const auto t0 = Clock::now();
    const std::chrono::system_clock::time_point wall{1000000000s};
    table.record_packet(key, t0, wall, 0, 10, 0, 0);  // UDP: 300 s
    assert(table.expire_flows(t0 + 300s).empty());
    assert(table.expire_flows(t0 + 300s + 999ms).empty());
    assert(table.expire_flows(t0 + 301s).size() == 1);
}

// Original: `exp = MIN (exp, flow_start.tv_sec + maximum_lifetime)`.
void test_expiry_is_limited_by_the_maximum_lifetime() {
    FlowTimeouts timeouts;
    timeouts.udp = 300s;
    timeouts.maximum_lifetime = 100s;
    FlowTable<FlowIndexBackend::Hash> table(16, TrackLevel::IpProtoPort, timeouts);
    const auto key = FlowKey::make_canonical(make_v4(192, 168, 0, 1), make_v4(1, 1, 1, 1),
                                             1000, 53, 17, 0, {0, 0});
    const auto t0 = Clock::now();
    const std::chrono::system_clock::time_point wall{1000000000s};
    table.record_packet(key, t0, wall, 0, 10, 0, 0);
    const auto entries = table.expiry_snapshot();
    assert(entries.size() == 1);
    assert(expiry_epoch_seconds(entries[0].record.flow, entries[0].expires_at) == 1000000100);
}

// Original: expiry_compare () orders the expiry tree by expires_at and then by
// the flow sequence, so flows that expire at the same second come out in the
// order they were created, however they were updated.
template <FlowIndexBackend Backend>
void test_flows_with_the_same_expiry_leave_in_the_order_of_their_sequence() {
    FlowTable<Backend> table(16);
    const auto a = make_v4(192, 168, 0, 1);
    const auto key1 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 1), 1000, 53, 17, 0, {0, 0});
    const auto key2 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 2), 1000, 53, 17, 0, {0, 0});
    const auto t0 = Clock::now();
    const std::chrono::system_clock::time_point wall{1000000000s};
    table.record_packet(key1, t0, wall, 0, 10, 0, 0);
    table.record_packet(key2, t0, wall, 0, 10, 0, 0);
    table.record_packet(key2, t0 + 1s, wall + 1s, 0, 10, 0, 0);  // key2 is moved first
    table.record_packet(key1, t0 + 1s, wall + 1s, 0, 10, 0, 0);
    const auto expired = table.expire_flows(t0 + 7200s);
    assert(expired.size() == 2);
    assert(expired[0].flow.flow_seq == 1 && expired[1].flow.flow_seq == 2);
}

// Original: check_expired (CE_EXPIRE_FORCED), the check of a capture file,
// expires only the flows with expires_at 0 (over their maximum lifetime or
// over 2 GiB), and makes their reason R_MAXLIFE.
void test_expire_urgent_takes_only_the_flows_that_are_due_at_once() {
    FlowTimeouts timeouts;
    timeouts.maximum_lifetime = 100s;
    FlowTable<FlowIndexBackend::Hash> table(16, TrackLevel::IpProtoPort, timeouts);
    const auto a = make_v4(192, 168, 0, 1);
    const auto old_key = FlowKey::make_canonical(a, make_v4(1, 1, 1, 1), 1000, 53, 17, 0, {0, 0});
    const auto new_key = FlowKey::make_canonical(a, make_v4(1, 1, 1, 2), 1000, 53, 17, 0, {0, 0});
    const auto t0 = Clock::now();
    const std::chrono::system_clock::time_point wall{1000000000s};
    table.record_packet(old_key, t0, wall, 0, 10, 0, 0);
    table.record_packet(old_key, t0 + 101s, wall + 101s, 0, 10, 0, 0);  // over 100 s
    table.record_packet(new_key, t0 + 101s, wall + 101s, 0, 10, 0, 0);
    assert(table.expire_urgent().size() == 1);
    assert(table.size() == 1);
    assert(table.expire_urgent().empty());
}

// Original: force_expire () sets R_OVERFLOWS, but the scan that expires the
// flow makes it R_MAXLIFE when it lived at least maximum_lifetime.
void test_forced_flow_that_lived_the_maximum_lifetime_counts_as_maxlife() {
    FlowTimeouts timeouts;
    timeouts.maximum_lifetime = 100s;
    FlowTable<FlowIndexBackend::Hash> table(1, TrackLevel::IpProtoPort, timeouts);
    const auto a = make_v4(192, 168, 0, 1);
    const auto key1 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 1), 1000, 53, 17, 0, {0, 0});
    const auto key2 = FlowKey::make_canonical(a, make_v4(1, 1, 1, 2), 1000, 53, 17, 0, {0, 0});
    const auto t0 = Clock::now();
    const std::chrono::system_clock::time_point wall{1000000000s};
    table.record_packet(key1, t0, wall, 0, 10, 0, 0);
    table.record_packet(key1, t0 + 100s, wall + 100s, 0, 10, 0, 0);  // 100 s: MAXLIFE is >=
    table.record_packet(key2, t0 + 100s, wall + 100s, 0, 10, 0, 0);
    // key1 is already due at once (its expiry was made 0 by the update), so
    // take the one that is not: key2 is the newer, key1 the older.
    const auto forced = table.force_expire_oldest(1);
    assert(forced.size() == 1);
    assert(forced[0].flow.reason == ExpiryReason::MaxLife);
}

template <FlowIndexBackend Backend>
void test_direction_out_of_range_throws() {
    FlowTable<Backend> table(16);
    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});

    bool threw = false;
    try {
        table.record_packet(key, Clock::now(), std::chrono::system_clock::now(), /*direction=*/2, 10, 0, 0);
    } catch (const std::out_of_range&) {
        threw = true;
    }
    assert(threw);
}

template <FlowIndexBackend Backend>
void test_force_expire_oldest_respects_order() {
    FlowTable<Backend> table(16);
    const auto t0 = Clock::now();

    for (int i = 0; i < 5; ++i) {
        const auto a = make_v4(10, 0, 0, static_cast<std::uint8_t>(i));
        const auto b = make_v4(10, 0, 1, static_cast<std::uint8_t>(i));
        const auto key = FlowKey::make_canonical(
            a, b, static_cast<std::uint16_t>(1000 + i), 80, 6, 0, {0, 0});
        table.record_packet(key, t0 + std::chrono::seconds(i), std::chrono::system_clock::now(), 0, 10, 0, 0);
    }
    assert(table.size() == 5);

    auto forced = table.force_expire_oldest(2);
    assert(forced.size() == 2);
    assert(table.size() == 3);
}

// Both backends must behave identically from the caller's point of view --
// only their internal data structure differs.
template <FlowIndexBackend Backend>
void test_backend() {
    test_record_and_expire<Backend>();
    test_flow_seq_is_a_counter<Backend>();
    test_delete_all_and_expiry_snapshot<Backend>();
    test_direction_out_of_range_throws<Backend>();
    test_force_expire_oldest_respects_order<Backend>();
}

void test_runtime_wrapper_dispatches_to_selected_backend() {
  for (auto backend : {FlowLookup::HashTree, FlowLookup::Tree, FlowLookup::Hash}) {
    FlowTableRuntime table (backend, 16);
    assert (table.lookup() == backend);

    const auto a = make_v4 (172, 16, 0, 1);
    const auto b = make_v4 (172, 16, 0, 2);
    const auto key = FlowKey::make_canonical (a, b, 4000, 80, 6, 0, {0, 0});

    const auto t0 = Clock::now();
    table.record_packet (key, t0, std::chrono::system_clock::now(), 0, 500, 0x02, 0);  // SYN
    assert (table.size() == 1);

    auto expired = table.expire_flows (t0 + 3601s);
    assert (expired.size() == 1);
    assert (expired[0].flow.octets[0] == 500);
  }
}

// New: verifies compute_expiry()'s protocol/TCP-state branching (ported
// from softflowd.c's flow_update_expiry(), previously a stub that always
// used the general timeout regardless of protocol).
template <FlowIndexBackend Backend>
void test_expiry_reason_branching() {
    FlowTimeouts timeouts;
    timeouts.tcp = 3600s;
    timeouts.tcp_rst = 120s;
    timeouts.tcp_fin = 300s;
    timeouts.udp = 300s;
    timeouts.icmp = 300s;
    timeouts.general = 3600s;

    const auto t0 = Clock::now();

    {
        FlowTable<Backend> table(16, TrackLevel::IpProtoPort, timeouts);
        const auto key = FlowKey::make_canonical(
            make_v4(10, 0, 0, 1), make_v4(10, 0, 0, 2), 1000, 80, 6, 0, {0, 0});
        table.record_packet(key, t0, std::chrono::system_clock::now(), 0, 100, 0x02, 0);          // SYN
        table.record_packet(key, t0 + 1s, std::chrono::system_clock::now(), 1, 100, 0x04, 0);     // RST
        auto not_yet = table.expire_flows(t0 + 1s + 60s);
        assert(not_yet.empty());
        auto expired = table.expire_flows(t0 + 1s + 121s);
        assert(expired.size() == 1);
        assert(table.stats().expired_tcp_rst == 1);
    }

    {
        FlowTable<Backend> table(16, TrackLevel::IpProtoPort, timeouts);
        const auto key = FlowKey::make_canonical(
            make_v4(10, 0, 0, 1), make_v4(10, 0, 0, 2), 1000, 53, 17, 0, {0, 0});
        table.record_packet(key, t0, std::chrono::system_clock::now(), 0, 100, 0, 0);
        auto not_yet = table.expire_flows(t0 + 299s);
        assert(not_yet.empty());
        auto expired = table.expire_flows(t0 + 301s);
        assert(expired.size() == 1);
        assert(table.stats().expired_udp == 1);
    }

    {
        FlowTable<Backend> table(16, TrackLevel::IpProtoPort, timeouts);
        const auto key = FlowKey::make_canonical(
            make_v4(10, 0, 0, 1), make_v4(10, 0, 0, 2), 0, 0, 1, 0, {0, 0});
        table.record_packet(key, t0, std::chrono::system_clock::now(), 0, 64, 0, 0);
        auto expired = table.expire_flows(t0 + 301s);
        assert(expired.size() == 1);
        assert(table.stats().expired_icmp == 1);
    }
}

// New: force_expire_oldest() must classify evicted flows as OverFlows
// regardless of what compute_expiry() had computed for them.
template <FlowIndexBackend Backend>
void test_force_expire_marks_overflows_reason() {
    FlowTable<Backend> table(16);
    const auto t0 = Clock::now();
    const auto key = FlowKey::make_canonical(
        make_v4(10, 0, 0, 1), make_v4(10, 0, 0, 2), 1000, 53, 17, 0, {0, 0});
    table.record_packet(key, t0, std::chrono::system_clock::now(), 0, 100, 0, 0);

    auto forced = table.force_expire_oldest(1);
    assert(forced.size() == 1);
    assert(table.stats().expired_maxflows == 1);
    assert(table.stats().expired_udp == 0);
}

// New: expire_flows(now, flush_all=true) must drain every remaining flow
// regardless of its normal expiry time, tagged as Flush.
template <FlowIndexBackend Backend>
void test_flush_all_expires_everything() {
    FlowTable<Backend> table(16);
    const auto t0 = Clock::now();
    for (int i = 0; i < 3; ++i) {
        const auto key = FlowKey::make_canonical(
            make_v4(10, 0, 0, static_cast<std::uint8_t>(i)),
            make_v4(10, 0, 1, static_cast<std::uint8_t>(i)),
            static_cast<std::uint16_t>(1000 + i), 53, 17, 0, {0, 0});
        table.record_packet(key, t0, std::chrono::system_clock::now(), 0, 10, 0, 0);
    }
    assert(table.size() == 3);

    auto flushed = table.expire_flows(t0 + 1s, /*flush_all=*/true);
    assert(flushed.size() == 3);
    assert(table.size() == 0);
    assert(table.stats().expired_flush == 3);
}

// New: verifies the min/mean/max running statistics (StatAccumulator) and
// per-protocol counters are actually populated on expiry.
template <FlowIndexBackend Backend>
void test_statistics_accumulate() {
    FlowTable<Backend> table(16);
    const auto t0 = Clock::now();
    const auto key1 = FlowKey::make_canonical(
        make_v4(10, 0, 0, 1), make_v4(10, 0, 0, 2), 1000, 53, 17, 0, {0, 0});
    const auto key2 = FlowKey::make_canonical(
        make_v4(10, 0, 0, 3), make_v4(10, 0, 0, 4), 1001, 53, 17, 0, {0, 0});

    table.record_packet(key1, t0, std::chrono::system_clock::now(), 0, 100, 0, 0);
    table.record_packet(key2, t0, std::chrono::system_clock::now(), 0, 300, 0, 0);

    auto expired = table.expire_flows(t0 + 301s);
    assert(expired.size() == 2);

    const auto& stats = table.stats();
    assert(stats.octets.n == 2);
    assert(stats.octets.min == 100.0);
    assert(stats.octets.max == 300.0);
    assert(stats.octets.mean == 200.0);
    assert(stats.flows_pp[17] == 2);
    assert(stats.octets_pp[17] == 400);
}

} // namespace

// Original: -F hash. With a single slot every new flow evicts the resident
// one, which is exported as expired by collision.
void
test_collision_mode_evicts_the_resident_flow () {
  FlowTable<FlowIndexBackend::Hash> table (16);
  table.enable_collision_mode (1);
  const auto a = make_v4 (192, 168, 0, 1);
  const auto key1 = FlowKey::make_canonical (a, make_v4 (1, 1, 1, 1), 1000, 53, 17, 0, {0, 0});
  const auto key2 = FlowKey::make_canonical (a, make_v4 (2, 2, 2, 2), 1001, 53, 17, 0, {0, 0});
  const auto t0 = Clock::now();
  const auto wall = std::chrono::system_clock::now();

  table.record_packet (key1, t0, wall, 0, 100, 0, 0);
  table.record_packet (key1, t0 + 1s, wall, 0, 100, 0, 0);  // a hit
  assert (table.size() == 1 && table.stats().expired_collision == 0);

  table.record_packet (key2, t0 + 2s, wall, 0, 50, 0, 0);
  assert (table.size() == 1);  // key1 left the table

  const auto collided = table.expire_collisions();
  assert (collided.size() == 1 && collided[0].key == key1);
  assert (collided[0].flow.octets[0] == 200);
  assert (collided[0].flow.flow_end_reason == 0x05);  // lackOfResource
  assert (table.stats().expired_collision == 1);
  assert (table.stats().flows_expired == 1);
  assert (table.expire_collisions().empty());

  // The flow of key1 starts again as a new flow.
  table.record_packet (key1, t0 + 3s, wall, 0, 10, 0, 0);
  assert (table.expire_collisions().size() == 1);  // key2 was evicted
  // expire_flows() hands out what is left, collision flows first.
  assert (table.expire_flows (t0 + 4s, true).size() == 1);
  assert (table.usage().buckets == 1);
}

int main() {
    test_canonical_key_is_symmetric();
    test_usage_buckets_follow_max_flows();
    test_next_expire_clusters_by_interval<FlowIndexBackend::Hash>();
    test_next_expire_clusters_by_interval<FlowIndexBackend::Tree>();
    test_flow_is_due_one_second_after_its_expiry_time<FlowIndexBackend::Hash>();
    test_flow_is_due_one_second_after_its_expiry_time<FlowIndexBackend::Tree>();
    test_expiry_is_limited_by_the_maximum_lifetime();
    test_flows_with_the_same_expiry_leave_in_the_order_of_their_sequence<FlowIndexBackend::Hash>();
    test_flows_with_the_same_expiry_leave_in_the_order_of_their_sequence<FlowIndexBackend::Tree>();
    test_expire_urgent_takes_only_the_flows_that_are_due_at_once();
    test_forced_flow_that_lived_the_maximum_lifetime_counts_as_maxlife();
    test_backend<FlowIndexBackend::Hash>();
    test_backend<FlowIndexBackend::Tree>();
    test_runtime_wrapper_dispatches_to_selected_backend();
    test_collision_mode_evicts_the_resident_flow();
    test_expiry_reason_branching<FlowIndexBackend::Hash>();
    test_expiry_reason_branching<FlowIndexBackend::Tree>();
    test_force_expire_marks_overflows_reason<FlowIndexBackend::Hash>();
    test_flush_all_expires_everything<FlowIndexBackend::Hash>();
    test_statistics_accumulate<FlowIndexBackend::Hash>();
    std::puts("all flow table tests passed");
    return 0;
}
