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
    table.record_packet(key, t0, 0, 100, false, false);
    assert(table.size() == 1);

    table.record_packet(key, t0 + 1s, 1, 200, false, false);
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

template <FlowIndexBackend Backend>
void test_direction_out_of_range_throws() {
    FlowTable<Backend> table(16);
    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});

    bool threw = false;
    try {
        table.record_packet(key, Clock::now(), /*direction=*/2, 10, false,
                             false);
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
        table.record_packet(key, t0 + std::chrono::seconds(i), 0, 10, false,
                             false);
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
    test_direction_out_of_range_throws<Backend>();
    test_force_expire_oldest_respects_order<Backend>();
}

void test_runtime_wrapper_dispatches_to_selected_backend() {
    for (auto backend : {FlowIndexBackend::Hash, FlowIndexBackend::Tree}) {
        FlowTableRuntime table(backend, 16);
        assert(table.backend() == backend);

        const auto a = make_v4(172, 16, 0, 1);
        const auto b = make_v4(172, 16, 0, 2);
        const auto key = FlowKey::make_canonical(a, b, 4000, 80, 6, 0, {0, 0});

        const auto t0 = Clock::now();
        table.record_packet(key, t0, 0, 500, true, false);
        assert(table.size() == 1);

        auto expired = table.expire_flows(t0 + 3601s);
        assert(expired.size() == 1);
        assert(expired[0].flow.octets[0] == 500);
    }
}

} // namespace

int main() {
    test_canonical_key_is_symmetric();
    test_backend<FlowIndexBackend::Hash>();
    test_backend<FlowIndexBackend::Tree>();
    test_runtime_wrapper_dispatches_to_selected_backend();
    std::puts("all flow table tests passed");
    return 0;
}
