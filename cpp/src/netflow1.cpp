#include "softflow/netflow1.hpp"

#include <algorithm>
#include <cstdio>

namespace softflow {

namespace {

// Original: the SysUptime / First / Last fields are all "milliseconds
// since the exporting device booted", clamped to be non-negative in case
// a timestamp somehow predates boot_time (which should not normally
// happen, but a clamp is cheap insurance against an underflowed unsigned
// value wrapping around to a huge number on export).
std::uint32_t
uptime_ms (TimePoint boot_time, TimePoint t) {
  const auto delta = std::chrono::duration_cast<std::chrono::milliseconds> (
    t - boot_time);
  return static_cast<std::uint32_t> (std::max<std::int64_t> (0, delta.count()));
}

}  // namespace

void
Netflow1Exporter::write_header (
  ByteWriter &writer, std::uint16_t count, TimePoint now,
  std::chrono::system_clock::time_point wall_now) const {
  const auto unix_time = std::chrono::system_clock::to_time_t (wall_now);
  const auto since_epoch = wall_now.time_since_epoch();
  const auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds> (
                       since_epoch % std::chrono::seconds (1))
                       .count();

  writer.put_u16 (1);  // version
  writer.put_u16 (count);
  writer.put_u32 (uptime_ms (boot_time_, now));
  writer.put_u32 (static_cast<std::uint32_t> (unix_time));
  writer.put_u32 (static_cast<std::uint32_t> (nsecs < 0 ? nsecs + 1'000'000'000
                                                        : nsecs));
}

std::vector<std::vector<std::uint8_t>>
Netflow1Exporter::build_packets (
  std::span<const ExportRecord> records, TimePoint now,
  std::chrono::system_clock::time_point wall_now) const {
  std::vector<std::vector<std::uint8_t>> packets;

  // Original: send_fixed_flow() in ipfix.c. A flow adds one record per
  // IPv4 direction that carried data; the two directions of one flow are
  // never split across packets, so the current packet is flushed first
  // when they do not both fit.
  struct DirectionalRecord {
    const IpAddress *src;
    const IpAddress *dst;
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint64_t octets;
    std::uint64_t packets;
    TimePoint first;
    TimePoint last;
    std::uint8_t protocol;
    std::uint8_t tos;
    std::uint8_t tcp_flags;
  };

  std::vector<DirectionalRecord> pending;

  auto flush = [&] () {
    if (pending.empty()) {
      return;
    }
    ByteWriter writer;
    write_header (writer, static_cast<std::uint16_t> (pending.size()), now,
                  wall_now);
    for (const auto &r : pending) {
      // Original: struct NF1_FLOW, 48 bytes.
      writer.put_ipv4 (*r.src);  // srcaddr
      writer.put_ipv4 (*r.dst);  // dstaddr
      writer.put_u32 (0);        // nexthop (not tracked)
      writer.put_u16 (0);        // input ifIndex (not tracked)
      writer.put_u16 (0);        // output ifIndex (not tracked)
      writer.put_u32 (static_cast<std::uint32_t> (
        std::min<std::uint64_t> (r.packets, 0xFFFFFFFFu)));  // dPkts
      writer.put_u32 (static_cast<std::uint32_t> (
        std::min<std::uint64_t> (r.octets, 0xFFFFFFFFu)));  // dOctets
      writer.put_u32 (uptime_ms (boot_time_, r.first));     // First
      writer.put_u32 (uptime_ms (boot_time_, r.last));      // Last
      writer.put_u16 (r.src_port);
      writer.put_u16 (r.dst_port);
      writer.put_u16 (0);  // pad1
      writer.put_u8 (r.protocol);
      writer.put_u8 (r.tos);
      writer.put_u8 (r.tcp_flags);
      writer.put_u8 (0);   // pad2
      writer.put_u32 (0);  // reserved
      writer.put_u16 (0);  // reserved (total record size: 48 bytes)
    }
    auto bytes = writer.take();
    if (debug_) {
      // Original: send_multi_destinations() logs every packet length.
      std::fprintf (stderr, "Sending flow packet len = %zu\n", bytes.size());
    }
    packets.push_back (std::move (bytes));
    pending.clear();
  };

  for (const auto &record : records) {
    const auto &key = record.key;
    const auto &flow = record.flow;

    // NetFlow v1 carries IPv4 only: one record per direction with data.
    std::size_t need = 0;
    for (std::size_t d = 0; d < 2; ++d) {
      if (flow.octets[d] > 0 &&
          key.addr()[d].family == AddressFamily::IPv4) {
        ++need;
      }
    }
    if (need == 0) {
      continue;
    }

    if (pending.size() + need > kNetflow1MaxRecordsPerPacket) {
      flush();
    }

    for (int dir = 0; dir < 2; ++dir) {
      const auto d = static_cast<std::size_t> (dir);
      if (flow.octets[d] == 0 ||
          key.addr()[d].family != AddressFamily::IPv4) {
        continue;  // no IPv4 traffic was seen in this direction
      }
      pending.push_back (DirectionalRecord{
        &key.addr()[d],
        &key.addr()[d ^ 1],
        key.port()[d],
        key.port()[d ^ 1],
        flow.octets[d],
        flow.packets[d],
        flow.flow_start,
        flow.flow_last,
        key.protocol(),
        flow.tos[d],
        flow.tcp_flags[d],
      });
    }
  }
  flush();

  return packets;
}

}  // namespace softflow
