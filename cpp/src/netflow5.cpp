#include "softflow/netflow5.hpp"

#include <algorithm>
#include <cstdio>

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

    // Original: netflow5.c's send_nflow5(). Deliberately iterates the
    // *original* (pre-split) flows, not a flattened list of individual
    // records: before adding each flow's own record(s), it checks
    // `j >= NF5_MAXFLOWS - 1` (29, not 30) and flushes the current packet
    // first if so -- reserving room for a flow that turns out to need two
    // records (both directions), which are never split across a packet
    // boundary. This is a conservative check made once per flow, so a
    // packet can still end up with exactly 30 records (if the last flow
    // added happened to bring it there directly), but will often flush
    // early with only 29, unlike a simple flat chunk-by-30 packing.
    // Replicating this exactly (rather than optimally packing a flattened
    // list) matters for byte-for-byte parity in the reported packet count.
    std::vector<DirectionalRecord> pending;

    auto flush = [&](bool is_final) {
        if (pending.empty()) {
            return;
        }
        ByteWriter writer;
        write_header(writer, static_cast<std::uint16_t>(pending.size()), now,
                     wall_now);
        for (const auto& r : pending) {
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
        flow_seq_ += static_cast<std::uint32_t>(pending.size());
        auto bytes = writer.take();
        if (debug_) {
            // Original: the mid-loop early-flush site (`j >= NF5_MAXFLOWS - 1`)
            // and the trailing leftover-flush site at the end of the
            // function use *different* wording for the same message --
            // "Sending flow packet len = %d" vs "Sending v5 flow packet
            // len = %d" -- regardless of whether this is actually v1 or
            // v5 (both share this one function). Reproduced exactly.
            if (is_final) {
                std::fprintf(stderr, "Sending v5 flow packet len = %zu\n", bytes.size());
            } else {
                std::fprintf(stderr, "Sending flow packet len = %zu\n", bytes.size());
            }
        }
        packets.push_back(std::move(bytes));
        pending.clear();
    };

    for (const auto& record : records) {
        const auto& key = record.key;
        const auto& flow = record.flow;

        // How many records this flow will contribute (0, 1, or 2).
        int this_flow_count = 0;
        for (int dir = 0; dir < 2; ++dir) {
            const auto d = static_cast<std::size_t>(dir);
            if (flow.packets[d] > 0 && key.addr()[d].family == AddressFamily::IPv4) {
                ++this_flow_count;
            }
        }
        if (this_flow_count == 0) {
            continue;
        }

        if (pending.size() >= kNetflow5MaxRecordsPerPacket - 1) {
            flush(false);
        }

        for (int dir = 0; dir < 2; ++dir) {
            const auto d = static_cast<std::size_t>(dir);
            if (flow.packets[d] == 0) {
                continue;
            }
            if (key.addr()[d].family != AddressFamily::IPv4) {
                continue; // NetFlow v5 doesn't do IPv6, matching the original
            }
            pending.push_back(DirectionalRecord{
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
    flush(true);

    return packets;
}

} // namespace softflow
