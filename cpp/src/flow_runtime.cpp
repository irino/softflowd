/**
 * @file flow_runtime.cpp
 * @brief The flow table that the daemon uses: one of the backends of the flow table, chosen at run time.
 *
 * Split from softflowd.cpp. FlowTableRuntime is declared in softflowd.hpp. It
 * holds a FlowTable of the hash or of the tree backend, and forwards each call
 * to it.
 *
 * @original The choice of the flow index of init_flowtrack () in softflowd.c.
 */
#include "softflowd_cpp/softflowd.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <variant>
#include <vector>

namespace softflowd_cpp {

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
FlowTableRuntime::expire_urgent () {
  return std::visit ([] (auto &table) { return table.expire_urgent(); }, table_);
}

std::vector<ExportRecord>
FlowTableRuntime::expire_collisions () {
  return std::visit ([] (auto &table) { return table.expire_collisions(); },
                     table_);
}

FlowTableUsage
FlowTableRuntime::usage () const {
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

std::vector<ExpiryEntry>
FlowTableRuntime::expiry_snapshot () const {
  return std::visit (
    [] (const auto &table) { return table.expiry_snapshot(); }, table_);
}

int
FlowTableRuntime::next_expire (std::chrono::system_clock::time_point wall_now,
                               std::chrono::seconds interval) const {
  return std::visit (
    [&] (const auto &table) { return table.next_expire (wall_now, interval); },
    table_);
}

std::size_t
FlowTableRuntime::delete_all () {
  return std::visit ([] (auto &table) { return table.delete_all(); }, table_);
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

void
FlowTableRuntime::count_packet_without_flow () noexcept {
  std::visit ([] (auto &table) { table.count_packet_without_flow(); }, table_);
}

void
FlowTableRuntime::count_non_ip_packet () noexcept {
  std::visit ([] (auto &table) { table.count_non_ip_packet(); }, table_);
}

void
FlowTableRuntime::count_bad_packet () noexcept {
  std::visit ([] (auto &table) { table.count_bad_packet(); }, table_);
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

}  // namespace softflowd_cpp
