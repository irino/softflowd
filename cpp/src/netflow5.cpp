#include "softflow/netflow5.hpp"

#include <algorithm>

namespace softflow {

namespace {

std::uint32_t uptime_ms(TimePoint boot_time, TimePoint t) {
    const auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
        t - boot_time);
    return static_cast<std::uint32_t>(std::max<std::int64_t>(0, delta.count()));
}

struct DirectionalRecord {
    const IpAddress* src;
    const IpAddress* dst;
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

std::vector<DirectionalRecord> flatten(std::span<const ExportRecord> records) {
    std::vector<DirectionalRecord> flat;
    flat.reserve(records.size() * 2);
    for (const auto& record : records) {
        const auto& key = record.key;
        const auto& flow = record.flow;
        for (int dir = 0; dir < 2; ++dir) {
            if (flow.packets[static_cast<std::size_t>(dir)] == 0) {
                continue;
            }
            flat.push_back(DirectionalRecord{
                &key.addr()[static_cast<std::size_t>(dir)],
                &key.addr()[static_cast<std::size_t>(dir ^ 1)],
                key.port()[static_cast<std::size_t>(dir)],
                key.port()[static_cast<std::size_t>(dir ^ 1)],
                flow.octets[static_cast<std::size_t>(dir)],
                flow.packets[static_cast<std::size_t>(dir)],
                flow.flow_start,
                flow.flow_last,
                key.protocol(),
                key.tos(),
                flow.tcp_flags[static_cast<std::size_t>(dir)],
            });
        }
    }
    return flat;
}

} // namespace

void Netflow5Exporter::write_header(
    ByteWriter& writer, std::uint16_t count, TimePoint now,
    std::chrono::system_clock::time_point wall_now) const {
    const auto unix_time = std::chrono::system_clock::to_time_t(wall_now);
    const auto since_epoch = wall_now.time_since_epoch();
    auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                     since_epoch % std::chrono::seconds(1))
                     .count();
    if (nsecs < 0) {
        nsecs += 1'000'000'000;
    }

    writer.put_u16(5); // version
    writer.put_u16(count);
    writer.put_u32(uptime_ms(boot_time_, now));
    writer.put_u32(static_cast<std::uint32_t>(unix_time));
    writer.put_u32(static_cast<std::uint32_t>(nsecs));
    writer.put_u32(flow_seq_); // flow_sequence
    writer.put_u8(0);          // engine_type
    writer.put_u8(0);          // engine_id
    writer.put_u16(0);         // sampling_interval (no sampling configured)
}

std::vector<std::vector<std::uint8_t>>
Netflow5Exporter::build_packets(
    std::span<const ExportRecord> records, TimePoint now,
    std::chrono::system_clock::time_point wall_now) {
    std::vector<std::vector<std::uint8_t>> packets;

    const auto flat = flatten(records);

    for (std::size_t offset = 0; offset < flat.size();
         offset += kNetflow5MaxRecordsPerPacket) {
        const std::size_t chunk =
            std::min(kNetflow5MaxRecordsPerPacket, flat.size() - offset);

        ByteWriter writer;
        write_header(writer, static_cast<std::uint16_t>(chunk), now, wall_now);

        for (std::size_t i = 0; i < chunk; ++i) {
            const auto& r = flat[offset + i];
            // Original: struct NF5_FLOW, 48 bytes.
            writer.put_ipv4(*r.src);
            writer.put_ipv4(*r.dst);
            writer.put_u32(0); // nexthop
            writer.put_u16(0); // input ifIndex
            writer.put_u16(0); // output ifIndex
            writer.put_u32(static_cast<std::uint32_t>(
                std::min<std::uint64_t>(r.packets, 0xFFFFFFFFu)));
            writer.put_u32(static_cast<std::uint32_t>(
                std::min<std::uint64_t>(r.octets, 0xFFFFFFFFu)));
            writer.put_u32(uptime_ms(boot_time_, r.first));
            writer.put_u32(uptime_ms(boot_time_, r.last));
            writer.put_u16(r.src_port);
            writer.put_u16(r.dst_port);
            writer.put_u8(0); // pad1
            writer.put_u8(r.tcp_flags);
            writer.put_u8(r.protocol);
            writer.put_u8(r.tos);
            writer.put_u16(0); // src_as (not tracked)
            writer.put_u16(0); // dst_as (not tracked)
            writer.put_u8(0);  // src_mask (not tracked)
            writer.put_u8(0);  // dst_mask (not tracked)
            writer.put_u16(0); // pad2
        }

        flow_seq_ += static_cast<std::uint32_t>(chunk);
        packets.push_back(writer.take());
    }

    return packets;
}

} // namespace softflow
