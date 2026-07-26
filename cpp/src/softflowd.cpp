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

#include "softflow/daemon.hpp"
#include "softflow/ipfix.hpp"
#include "softflow/netflow1.hpp"
#include "softflow/netflow5.hpp"
#include "softflow/netflow9.hpp"
#include "softflow/psamp.hpp"
#include "softflow/softflowctl.hpp"

#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace softflow {

// =======================================================================
// FlowTable<Backend> (original: struct FLOWTRACK, freelist.c, treetype.h,
//                      sys-tree.h)
// =======================================================================

template <FlowIndexBackend Backend>
FlowTable<Backend>::FlowTable(std::size_t max_flows, TrackLevel track_level,
                               FlowTimeouts timeouts)
    : max_flows_(max_flows), track_level_(track_level), timeouts_(timeouts) {
    if (max_flows_ == 0) {
        // The original never checked for max_flows == 0; that case would
        // eventually misbehave somewhere downstream instead. A constructor
        // precondition turns it into an immediate, well-defined exception.
        throw std::invalid_argument("max_flows must be > 0");
    }
    // std::map (the tree backend) has no reserve() -- only the hash backend
    // benefits from pre-sizing its bucket array.
    if constexpr (Backend == FlowIndexBackend::Hash) {
        flows_.reserve(max_flows_);
    }
}

template <FlowIndexBackend Backend>
TimePoint FlowTable<Backend>::compute_expiry(const Flow& flow, bool is_tcp_syn,
                                              bool /*is_tcp_fin_or_rst*/) const {
    // Original: softflowd.c's update_expiry(), simplified. Full per-protocol
    // branching (TCP RST/FIN detection etc.) will be extended once NetFlow
    // export (Stage 3) needs the finer-grained expiry reasons; this covers
    // the data-model skeleton for now.
    (void)is_tcp_syn;
    return flow.flow_last + timeouts_.general;
}

template <FlowIndexBackend Backend>
void FlowTable<Backend>::reschedule_expiry(const FlowKey& key,
                                            TimePoint new_expiry) {
    // Original: the RB_REMOVE + RB_INSERT pair in sys-tree.h. Instead of
    // relinking a raw-pointer-based RB node, this simply erases the old
    // multimap entry (if any) and inserts a new one.
    auto lookup_it = expiry_lookup_.find(key);
    if (lookup_it != expiry_lookup_.end()) {
        expiry_index_.erase(lookup_it->second);
    }
    auto new_it = expiry_index_.emplace(new_expiry, key);
    expiry_lookup_[key] = new_it;
}

template <FlowIndexBackend Backend>
Flow& FlowTable<Backend>::record_packet(const FlowKey& key, TimePoint now,
                                         std::uint8_t direction,
                                         std::uint64_t octet_delta,
                                         bool is_tcp_syn,
                                         bool is_tcp_fin_or_rst) {
    if (direction > 1) {
        // The original trusted the caller to pass a valid 0/1 direction and
        // indexed octets[direction] without a range check. Here an
        // out-of-range direction is caught and turned into an exception
        // right at the boundary.
        throw std::out_of_range("direction must be 0 or 1");
    }

    auto [it, inserted] = flows_.try_emplace(key);
    Flow& flow = it->second;

    if (inserted) {
        flow.flow_start = now;
        // A real deployment would draw this from a global sequence
        // counter; this stage uses the table size as a simple stand-in.
        flow.flow_seq = static_cast<std::uint64_t>(flows_.size());
    }

    flow.flow_last = now;
    flow.octets[direction] += octet_delta;
    flow.packets[direction] += 1;

    reschedule_expiry(key, compute_expiry(flow, is_tcp_syn, is_tcp_fin_or_rst));

    stats_.total_packets += 1;
    return flow;
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord> FlowTable<Backend>::expire_flows(TimePoint now) {
    // Original: softflowd.c's check_expired(), which walked the EXPIRIES
    // tree from its smallest element, RB_REMOVE-ing and returning to the
    // free list anything past its expiry.
    std::vector<ExportRecord> expired;

    auto it = expiry_index_.begin();
    while (it != expiry_index_.end() && it->first <= now) {
        const FlowKey key = it->second; // copy before the iterator is invalidated

        auto flow_it = flows_.find(key);
        if (flow_it != flows_.end()) {
            expired.push_back(ExportRecord{key, flow_it->second});
            flows_.erase(flow_it);
        }
        expiry_lookup_.erase(key);
        it = expiry_index_.erase(it); // erase() returns the next valid iterator
    }

    stats_.flows_expired += expired.size();
    return expired;
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord> FlowTable<Backend>::force_expire_oldest(std::size_t count) {
    // Original: softflowd.c's handling of exceeding the configured maximum
    // flow count, forcibly evicting the flows whose expiry is nearest
    // (i.e. whose most recent traffic is oldest).
    std::vector<ExportRecord> expired;
    expired.reserve(count);

    auto it = expiry_index_.begin();
    while (it != expiry_index_.end() && expired.size() < count) {
        const FlowKey key = it->second;

        auto flow_it = flows_.find(key);
        if (flow_it != flows_.end()) {
            expired.push_back(ExportRecord{key, flow_it->second});
            flows_.erase(flow_it);
        }
        expiry_lookup_.erase(key);
        it = expiry_index_.erase(it);
    }

    stats_.flows_force_expired += expired.size();
    return expired;
}

template <FlowIndexBackend Backend>
std::vector<ExportRecord> FlowTable<Backend>::snapshot() const {
    // Original: softflowctl(8)'s dump-flows. A read-only copy of every
    // tracked flow; unlike expire_flows()/force_expire_oldest(), nothing
    // is removed from flows_ or expiry_index_.
    std::vector<ExportRecord> result;
    result.reserve(flows_.size());
    for (const auto& [key, flow] : flows_) {
        result.push_back(ExportRecord{key, flow});
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

FlowTableRuntime::FlowTableRuntime(FlowIndexBackend backend,
                                    std::size_t max_flows,
                                    TrackLevel track_level,
                                    FlowTimeouts timeouts)
    : table_([&]() -> std::variant<FlowTable<FlowIndexBackend::Hash>,
                                    FlowTable<FlowIndexBackend::Tree>> {
          switch (backend) {
          case FlowIndexBackend::Hash:
              return FlowTable<FlowIndexBackend::Hash>(max_flows, track_level,
                                                         timeouts);
          case FlowIndexBackend::Tree:
              return FlowTable<FlowIndexBackend::Tree>(max_flows, track_level,
                                                         timeouts);
          }
          throw std::invalid_argument("unknown FlowIndexBackend");
      }()) {}

Flow& FlowTableRuntime::record_packet(const FlowKey& key, TimePoint now,
                                       std::uint8_t direction,
                                       std::uint64_t octet_delta,
                                       bool is_tcp_syn,
                                       bool is_tcp_fin_or_rst) {
    return std::visit(
        [&](auto& table) -> Flow& {
            return table.record_packet(key, now, direction, octet_delta,
                                        is_tcp_syn, is_tcp_fin_or_rst);
        },
        table_);
}

std::vector<ExportRecord> FlowTableRuntime::expire_flows(TimePoint now) {
    return std::visit([&](auto& table) { return table.expire_flows(now); },
                       table_);
}

std::vector<ExportRecord> FlowTableRuntime::force_expire_oldest(std::size_t count) {
    return std::visit(
        [&](auto& table) { return table.force_expire_oldest(count); },
        table_);
}

std::vector<ExportRecord> FlowTableRuntime::snapshot() const {
    return std::visit([](const auto& table) { return table.snapshot(); },
                       table_);
}

const FlowTimeouts& FlowTableRuntime::timeouts() const noexcept {
    return std::visit(
        [](const auto& table) -> const FlowTimeouts& {
            return table.timeouts();
        },
        table_);
}

std::size_t FlowTableRuntime::size() const noexcept {
    return std::visit([](const auto& table) { return table.size(); }, table_);
}

std::size_t FlowTableRuntime::max_flows() const noexcept {
    return std::visit([](const auto& table) { return table.max_flows(); },
                       table_);
}

const FlowTableStats& FlowTableRuntime::stats() const noexcept {
    return std::visit(
        [](const auto& table) -> const FlowTableStats& {
            return table.stats();
        },
        table_);
}

TrackLevel FlowTableRuntime::track_level() const noexcept {
    return std::visit([](const auto& table) { return table.track_level(); },
                       table_);
}

FlowIndexBackend FlowTableRuntime::backend() const noexcept {
    return std::visit([](const auto& table) { return table.backend(); },
                       table_);
}

// =======================================================================
// PacketParser (original: softflowd.c's ipv4_to_flowrec() /
//               ipv6_to_flowrec() / transport_to_flowrec())
// =======================================================================

namespace {

std::uint16_t read_be16(std::span<const std::uint8_t> data,
                         std::size_t offset) {
    return static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
}

std::uint32_t read_be32(std::span<const std::uint8_t> data,
                         std::size_t offset) {
    return (static_cast<std::uint32_t>(data[offset]) << 24) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
           static_cast<std::uint32_t>(data[offset + 3]);
}

constexpr std::uint8_t kProtoIcmp = 1;
constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kProtoUdp = 17;
constexpr std::uint8_t kProtoIcmpV6 = 58;
constexpr std::uint8_t kNextHopByHop = 0;
constexpr std::uint8_t kNextRouting = 43;
constexpr std::uint8_t kNextFragment = 44;
constexpr std::uint8_t kNextDstOptions = 60;

} // namespace

std::optional<ParsedPacket>
PacketParser::parse(std::span<const std::uint8_t> ip_payload,
                     AddressFamily af) const {
    if (af == AddressFamily::IPv4) {
        return parse_ipv4(ip_payload);
    }
    if (af == AddressFamily::IPv6) {
        return parse_ipv6(ip_payload);
    }
    return std::nullopt;
}

std::optional<ParsedPacket>
PacketParser::parse_ipv4(std::span<const std::uint8_t> data) const {
    // Original: `caplen < 20 || caplen < ip->ip_hl * 4 || ip->ip_v != 4`.
    // Here, each subsequent stage only proceeds once the required length
    // is actually available (a subspan can never read past the end of the
    // span it was taken from).
    if (data.size() < 20) {
        return std::nullopt; // runt packet
    }
    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    if (version != 4) {
        return std::nullopt;
    }
    const std::size_t header_len =
        static_cast<std::size_t>(data[0] & 0x0F) * 4;
    if (header_len < 20 || data.size() < header_len) {
        return std::nullopt;
    }

    ParsedPacket packet;
    packet.tos = data[1];

    const std::uint16_t frag_field = read_be16(data, 6);
    packet.is_fragment = (frag_field & 0x3FFF) != 0;
    packet.is_first_fragment = (frag_field & 0x1FFF) == 0;

    packet.protocol =
        track_level_ >= TrackLevel::IpProto ? data[9] : std::uint8_t{0};

    packet.src.family = AddressFamily::IPv4;
    packet.dst.family = AddressFamily::IPv4;
    for (int i = 0; i < 4; ++i) {
        packet.src.bytes[static_cast<std::size_t>(i)] =
            data[12 + static_cast<std::size_t>(i)];
        packet.dst.bytes[static_cast<std::size_t>(i)] =
            data[16 + static_cast<std::size_t>(i)];
    }

    if (track_level_ < TrackLevel::IpProtoPort) {
        packet.tos = 0;
    }

    if (packet.is_first_fragment &&
        track_level_ >= TrackLevel::IpProtoPort) {
        parse_transport(packet, data.subspan(header_len), data[9]);
    }

    return packet;
}

std::optional<ParsedPacket>
PacketParser::parse_ipv6(std::span<const std::uint8_t> data) const {
    // Original: ipv6_to_flowrec()'s extension-header walk. As noted in
    // softflowd.hpp, the original had a real bug here:
    //   eh6 = (const struct ip6_ext *) pkt + size;
    // Using data.subspan(size), whose offset is unambiguously byte-based by
    // its type signature, prevents the same kind of bug from resurfacing.
    if (data.size() < 40) {
        return std::nullopt; // runt packet
    }
    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    if (version != 6) {
        return std::nullopt;
    }

    ParsedPacket packet;
    packet.src.family = AddressFamily::IPv6;
    packet.dst.family = AddressFamily::IPv6;
    for (int i = 0; i < 16; ++i) {
        packet.src.bytes[static_cast<std::size_t>(i)] =
            data[8 + static_cast<std::size_t>(i)];
        packet.dst.bytes[static_cast<std::size_t>(i)] =
            data[24 + static_cast<std::size_t>(i)];
    }

    const std::uint32_t vtc_flow = read_be32(data, 0);
    packet.ip6_flowlabel = vtc_flow & 0x000FFFFFu;
    packet.tos = track_level_ >= TrackLevel::IpProtoPort
                     ? static_cast<std::uint8_t>((vtc_flow >> 20) & 0xFFu)
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
                (static_cast<std::size_t>(ext_len_units) + 1) * 8;
            if (offset + ext_header_size > data.size()) {
                return packet; // runt: return what was parsed so far
            }
            next_header = data[offset];
            offset += ext_header_size;
        } else if (next_header == kNextFragment) {
            packet.is_fragment = true;
            if (offset + 8 > data.size()) {
                return packet;
            }
            const std::uint16_t off_flags = read_be16(data, offset + 2);
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
        parse_transport(packet, data.subspan(offset), next_header);
    }

    return packet;
}

void PacketParser::parse_transport(
    ParsedPacket& packet, std::span<const std::uint8_t> transport_payload,
    std::uint8_t protocol) const {
    // Original: transport_to_flowrec(). TCP/UDP had a caplen check, but the
    // ICMP/ICMPv6 branch did not, and read `icmp->icmp_type`/`icmp->icmp_code`
    // unconditionally (a potential out-of-bounds read on a runt packet).
    // Every branch here validates the number of bytes it needs before
    // reading them.
    switch (protocol) {
    case kProtoTcp:
        if (transport_payload.size() < 14) {
            return; // runt packet
        }
        packet.src_port = read_be16(transport_payload, 0);
        packet.dst_port = read_be16(transport_payload, 2);
        packet.tcp_flags = transport_payload[13];
        break;
    case kProtoUdp:
        if (transport_payload.size() < 8) {
            return; // runt packet
        }
        packet.src_port = read_be16(transport_payload, 0);
        packet.dst_port = read_be16(transport_payload, 2);
        break;
    case kProtoIcmp:
    case kProtoIcmpV6:
        if (transport_payload.size() < 2) {
            return; // runt packet (the original had no check here at all)
        }
        // Original: the Cisco-router-compatible encoding (icmp_type * 256 +
        // icmp_code, stored as the destination port).
        packet.src_port = 0;
        packet.dst_port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(transport_payload[0]) << 8) |
            transport_payload[1]);
        break;
    default:
        break;
    }
}

FlowKey make_flow_key(const ParsedPacket& packet,
                      [[maybe_unused]] TrackLevel track_level,
                      std::array<std::uint16_t, 2> vlanid) {
    return FlowKey::make_canonical(packet.src, packet.dst, packet.src_port,
                                    packet.dst_port, packet.protocol,
                                    packet.tos, vlanid);
}

// =======================================================================
// PcapHandle (original: softflowd.c's main(), which managed pcap_t* by
//             hand)
// =======================================================================

DatalinkKind classify_datalink(int pcap_dlt) {
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

std::size_t datalink_header_len(DatalinkKind kind) {
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

PcapHandle PcapHandle::open_live(const std::string& device, int snaplen,
                                  bool promiscuous,
                                  std::chrono::milliseconds read_timeout,
                                  std::size_t buffer_bytes) {
    std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
    pcap_t* handle = pcap_create(device.c_str(), errbuf.data());
    if (handle == nullptr) {
        throw PcapError("pcap_create failed for device '" + device +
                         "': " + errbuf.data());
    }
    // pcap_create()/pcap_activate() is used instead of the legacy
    // pcap_open_live() specifically so buffer_bytes (original: -B) and
    // immediate mode can both be configured; pcap_open_live() offers
    // neither. Original: `logit(LOG_ERR, "pcap_open_live: %s", ebuf);
    // exit(1);` -- here every setup step below throws instead of exiting,
    // matching the rest of this project's RAII/exception-based error
    // handling.
    pcap_set_snaplen(handle, snaplen);
    pcap_set_promisc(handle, promiscuous ? 1 : 0);
    pcap_set_timeout(handle, static_cast<int>(read_timeout.count()));
    // Immediate mode delivers each packet to the application as soon as
    // it's captured, rather than waiting for libpcap's internal buffer to
    // fill or its timeout to elapse. Without this, next_packet() can take
    // up to the full read_timeout to return even when poll() has already
    // reported the underlying descriptor readable -- exactly the kind of
    // latency that would make a live daemon sluggish to react to control
    // commands and signals interleaved with packet processing (see
    // run_live_capture() in softflowd.cpp).
    pcap_set_immediate_mode(handle, 1);
    if (buffer_bytes > 0) {
        pcap_set_buffer_size(handle, static_cast<int>(buffer_bytes));
    }

    const int activate_result = pcap_activate(handle);
    if (activate_result < 0) {
        const std::string err = pcap_geterr(handle);
        pcap_close(handle);
        throw PcapError("pcap_activate failed for device '" + device +
                         "': " + err);
    }
    return PcapHandle(handle);
}

PcapHandle PcapHandle::open_offline(const std::string& path) {
    std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
    pcap_t* handle = pcap_open_offline(path.c_str(), errbuf.data());
    if (handle == nullptr) {
        throw PcapError("pcap_open_offline failed for '" + path +
                         "': " + errbuf.data());
    }
    return PcapHandle(handle);
}

void PcapHandle::set_filter(const std::string& bpf_expression) {
    struct bpf_program program {};
    if (pcap_compile(handle_.get(), &program, bpf_expression.c_str(), 1,
                      PCAP_NETMASK_UNKNOWN) < 0) {
        throw PcapError(std::string("pcap_compile failed: ") +
                         pcap_geterr(handle_.get()));
    }
    // Original: forgetting to call `pcap_freecode(&program)` is a
    // low-impact leak, but easy to miss especially on an exception path.
    // A tiny RAII guard makes sure it always runs.
    struct ProgramGuard {
        struct bpf_program* p;
        ~ProgramGuard() { pcap_freecode(p); }
    } guard{&program};

    if (pcap_setfilter(handle_.get(), &program) < 0) {
        throw PcapError(std::string("pcap_setfilter failed: ") +
                         pcap_geterr(handle_.get()));
    }
}

std::optional<CapturedPacket> PcapHandle::next_packet() {
    struct pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    const int result = pcap_next_ex(handle_.get(), &header, &data);

    if (result == 1) {
        CapturedPacket packet;
        // Original: `const u_int8_t *pkt = frame + datalink_size + ...`,
        // always carried alongside a separate `phdr->caplen` variable.
        // std::span combines the two into a single value.
        packet.data = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(data), header->caplen);
        packet.original_length = header->len;
        packet.timestamp = Clock::now();
        // Original: -a ("adjust time for reading pcap file") switches
        // between using libpcap's own recorded timestamp (phdr->ts, this
        // process's wall clock otherwise) as the reference time for flow
        // expiry when replaying a capture file. Both this process's
        // current time and libpcap's recorded time are always captured
        // here; run_pcap_file()/run_live_capture() (softflowd.cpp) decide
        // which one to actually use based on whether -a was given.
        packet.wall_timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                                 std::chrono::microseconds(header->ts.tv_usec);
        return packet;
    }
    if (result == 0) {
        return std::nullopt; // live-capture read timeout
    }
    if (result == -2) {
        return std::nullopt; // EOF on an offline file
    }
    // result == -1: an error occurred
    throw PcapError(std::string("pcap_next_ex failed: ") +
                     pcap_geterr(handle_.get()));
}

// =======================================================================
// ExportDestination / ExportDestinationSet (original: softflowd.c's -n /
// -l / -L / -e / -S handling)
// =======================================================================

ExportDestination::ExportDestination(const std::string& host,
                                      const std::string& port,
                                      TransportKind transport,
                                      std::optional<int> ttl,
                                      const std::string& source_address,
                                      const std::string& send_interface) {
    struct addrinfo hints {};
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
        throw ExportError(
            "SCTP is not available on this platform (IPPROTO_SCTP is not "
            "declared)");
#endif
    }

    struct addrinfo* result = nullptr;
    const int gai_err = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
    if (gai_err != 0) {
        throw ExportError("failed to resolve export destination '" + host +
                           ":" + port + "': " + gai_strerror(gai_err));
    }
    struct AddrinfoGuard {
        struct addrinfo* p;
        ~AddrinfoGuard() { freeaddrinfo(p); }
    } addrinfo_guard{result};

    fd_ = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd_ < 0) {
        throw ExportError("socket() failed for export destination '" + host +
                           ":" + port + "'");
    }

    if (!source_address.empty()) {
        // Original: -e. Resolve the requested source address in the same
        // family as the destination and bind() to it before connect()ing,
        // so the OS picks the requested address rather than whatever
        // routing would otherwise select.
        struct addrinfo src_hints {};
        src_hints.ai_family = result->ai_family;
        src_hints.ai_socktype = result->ai_socktype;
        struct addrinfo* src_result = nullptr;
        const int src_err = getaddrinfo(source_address.c_str(), nullptr,
                                         &src_hints, &src_result);
        if (src_err == 0) {
            struct AddrinfoGuard src_guard{src_result};
            bind(fd_, src_result->ai_addr, src_result->ai_addrlen);
            // A failed bind() here is intentionally non-fatal: falling
            // back to default source-address selection is preferable to
            // refusing to export at all.
        }
    }

    if (!send_interface.empty()) {
#ifdef SO_BINDTODEVICE
        // Original: -S. Linux-only, as the man page notes.
        setsockopt(fd_, SOL_SOCKET, SO_BINDTODEVICE, send_interface.c_str(),
                   static_cast<socklen_t>(send_interface.size()));
#endif
    }

    if (ttl.has_value()) {
        // Original: -L. IPv4 and IPv6 use different setsockopt levels/
        // names for the equivalent setting.
        if (result->ai_family == AF_INET) {
            const int ttl_value = *ttl;
            setsockopt(fd_, IPPROTO_IP, IP_TTL, &ttl_value, sizeof(ttl_value));
            setsockopt(fd_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_value,
                       sizeof(ttl_value));
        } else if (result->ai_family == AF_INET6) {
            const int ttl_value = *ttl;
            setsockopt(fd_, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl_value,
                       sizeof(ttl_value));
            setsockopt(fd_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl_value,
                       sizeof(ttl_value));
        }
    }

    // Original: with tcp/sctp, this connect() actually establishes the
    // long-lived connection the destination is streamed over for the
    // exporter's entire lifetime (matching the original's own behavior);
    // with udp, connect() on a datagram socket just fixes the peer address
    // so later calls can use send() instead of sendto().
    if (connect(fd_, result->ai_addr, result->ai_addrlen) < 0) {
        const std::string err = std::strerror(errno);
        close(fd_);
        fd_ = -1;
        throw ExportError("connect() failed for export destination '" + host +
                           ":" + port + "': " + err);
    }

    description_ = host + ":" + port;
}

ExportDestination::~ExportDestination() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

ExportDestination::ExportDestination(ExportDestination&& other) noexcept
    : fd_(other.fd_), stream_oriented_(other.stream_oriented_),
      description_(std::move(other.description_)) {
    other.fd_ = -1;
}

ExportDestination& ExportDestination::operator=(ExportDestination&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = other.fd_;
        stream_oriented_ = other.stream_oriented_;
        description_ = std::move(other.description_);
        other.fd_ = -1;
    }
    return *this;
}

void ExportDestination::send_packet(const std::vector<std::uint8_t>& packet) const {
    if (fd_ < 0) {
        return;
    }
    if (!stream_oriented_) {
        // A single UDP datagram send either succeeds atomically or fails;
        // there is no partial-send loop to write here the way there is
        // below for tcp/sctp (or for the control socket's
        // read_line()/write_line() in softflowctl.cpp).
        static_cast<void>(send(fd_, packet.data(), packet.size(), 0));
        return;
    }
    // tcp/sctp are stream-oriented: a single send() is not guaranteed to
    // consume the entire buffer, so this loops until it has, the same
    // pattern softflowctl.cpp's write_line() uses for the control socket.
    std::size_t offset = 0;
    while (offset < packet.size()) {
        const ssize_t n =
            send(fd_, packet.data() + offset, packet.size() - offset, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; // give up silently; a dead collector shouldn't crash the daemon
        }
        offset += static_cast<std::size_t>(n);
    }
}

void ExportDestinationSet::add(ExportDestination destination) {
    destinations_.push_back(std::move(destination));
}

void ExportDestinationSet::send_packet(const std::vector<std::uint8_t>& packet,
                                        bool load_balance) {
    if (destinations_.empty()) {
        return;
    }
    if (load_balance) {
        // Original: -l. Successive *export packets* (not individual flow
        // records within a packet) rotate through the configured
        // destinations.
        destinations_[next_index_].send_packet(packet);
        next_index_ = (next_index_ + 1) % destinations_.size();
    } else {
        for (const auto& destination : destinations_) {
            destination.send_packet(packet);
        }
    }
}

} // namespace softflow

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

enum class ExportFormat { None, Netflow1, Netflow5, Netflow9, Ipfix, Psamp };

enum class TransportProtocol { Udp, Tcp, Sctp };

enum class TimeFormat { Seconds, Milliseconds, Microseconds, Nanoseconds };

softflow::IpfixTimeFormat to_ipfix_time_format(TimeFormat format) {
    switch (format) {
    case TimeFormat::Seconds:
        return softflow::IpfixTimeFormat::Seconds;
    case TimeFormat::Milliseconds:
        return softflow::IpfixTimeFormat::Milliseconds;
    case TimeFormat::Microseconds:
        return softflow::IpfixTimeFormat::Microseconds;
    case TimeFormat::Nanoseconds:
        return softflow::IpfixTimeFormat::Nanoseconds;
    }
    return softflow::IpfixTimeFormat::Milliseconds;
}

const char* format_name(ExportFormat format) {
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

const char* track_level_name(softflow::TrackLevel level) {
    using softflow::TrackLevel;
    switch (level) {
    case TrackLevel::IpOnly:
        return "ip";
    case TrackLevel::IpProto:
        return "proto";
    case TrackLevel::IpProtoPort:
        return "full";
    case TrackLevel::FullVlan:
        return "vlan";
    case TrackLevel::FullVlanEther:
        return "ether";
    }
    return "unknown";
}

// Original: softflowd.c's -n / -p / -c / -m / -t / -T / -v / -L / etc.
// gathered into one struct rather than threaded through main() as
// individual local variables, since there are simply too many of them for
// that to stay readable. Field-by-field comments note the corresponding
// original option letter.
struct DaemonConfig {
    std::string interface;       // -i
    std::string pcap_file;       // -r
    bool no_promiscuous = false; // -N

    std::vector<std::pair<std::string, std::string>> destinations; // -n (host,port)
    bool load_balance = false;                                     // -l
    std::optional<int> ttl;                                        // -L
    std::string source_address;                                    // -e
    std::string send_interface;                                    // -S

    std::string pidfile = softflow::kDefaultPidFilePath; // -p
    std::string ctl_sock = softflow::kDefaultControlSocketPath; // -c

    std::size_t max_flows = 8192; // -m (original default)

    softflow::FlowTimeouts timeouts;                  // -t
    std::chrono::seconds expiry_interval{0};          // -t expint (0 = check every cycle)

    bool no_daemonize = false; // -d
    bool force_ipv6 = false;   // -6
    bool debug = false;        // -D (implies -d and -6, plus extra output)

    softflow::TrackLevel track_level = softflow::TrackLevel::IpProtoPort; // -T

    ExportFormat export_format = ExportFormat::Netflow5; // -v (default: version 5)

    TransportProtocol transport = TransportProtocol::Udp; // -P (udp and tcp implemented; see README for sctp)
    TimeFormat time_format = TimeFormat::Milliseconds;    // -A (sec/milli/micro/nano all implemented, IPFIX/PSAMP only)
    std::uint32_t sampling_rate = 1;                      // -s (1 = every packet, no sampling)
    int snaplen = 65535;                                  // -C
    std::size_t buffer_bytes = 0;                         // -B (0 = let libpcap choose)
    bool bidirectional_ipfix = false;                     // -b (simplified; see README)
    int mpls_labels = 0;                                  // -x (implemented for -v 9/10)
    std::optional<int> psamp_receive_port;                // -R (implemented; -i only)
    bool adjust_pcap_time = false;                         // -a

    std::string bpf_filter; // trailing bpf_expression

    // --- This project's own additions (not part of the original grammar) ---
    softflow::FlowIndexBackend backend = softflow::FlowIndexBackend::Hash; // --backend=hash|tree
    std::string export_out;                          // --export-out=PATH
    std::optional<std::chrono::seconds> max_runtime;  // --max-runtime=SECONDS
};

// Original: softflowd command-line arguments that specify a time use a
// sequence of the form time[qualifier][time[qualifier]...], e.g. "10m",
// "1h30m", or a bare number of seconds like "600". Each term is summed.
std::chrono::seconds parse_time_spec(const std::string& spec) {
    if (spec.empty()) {
        throw std::invalid_argument("empty time specification");
    }
    long total = 0;
    std::size_t i = 0;
    while (i < spec.size()) {
        const std::size_t digits_start = i;
        while (i < spec.size() && std::isdigit(static_cast<unsigned char>(spec[i]))) {
            ++i;
        }
        if (i == digits_start) {
            throw std::invalid_argument("invalid time specification: " + spec);
        }
        const long value = std::stol(spec.substr(digits_start, i - digits_start));

        long multiplier = 1;
        if (i < spec.size()) {
            switch (spec[i]) {
            case 's': case 'S': multiplier = 1; ++i; break;
            case 'm': case 'M': multiplier = 60; ++i; break;
            case 'h': case 'H': multiplier = 3600; ++i; break;
            case 'd': case 'D': multiplier = 86400; ++i; break;
            case 'w': case 'W': multiplier = 604800; ++i; break;
            default:
                throw std::invalid_argument("invalid time qualifier in: " + spec);
            }
        }
        total += value * multiplier;
    }
    return std::chrono::seconds(total);
}

// Original: -t timeout_name=time. Named timeouts are: general, tcp,
// tcp.rst, tcp.fin, udp, maxlife, expint (see softflowd(8)'s "Timeouts"
// section).
void apply_timeout_option(DaemonConfig& config, const std::string& spec) {
    const auto eq = spec.find('=');
    if (eq == std::string::npos) {
        throw std::invalid_argument("invalid -t argument (expected name=time): " + spec);
    }
    const std::string name = spec.substr(0, eq);
    const auto value = parse_time_spec(spec.substr(eq + 1));

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
        throw std::invalid_argument("unknown timeout name: " + name);
    }
}

// Original: -T track_level.
softflow::TrackLevel parse_track_level(const std::string& s) {
    using softflow::TrackLevel;
    if (s == "ip") return TrackLevel::IpOnly;
    if (s == "proto") return TrackLevel::IpProto;
    if (s == "full") return TrackLevel::IpProtoPort;
    if (s == "vlan") return TrackLevel::FullVlan;
    if (s == "ether") return TrackLevel::FullVlanEther;
    throw std::invalid_argument("unknown track level '" + s +
                                 "' (expected ip, proto, full, vlan, or ether)");
}

// Original: -v netflow_version.
ExportFormat parse_netflow_version(const std::string& s) {
    if (s == "1") return ExportFormat::Netflow1;
    if (s == "5") return ExportFormat::Netflow5;
    if (s == "9") return ExportFormat::Netflow9;
    if (s == "10") return ExportFormat::Ipfix;
    if (s == "psamp") return ExportFormat::Psamp;
    throw std::invalid_argument("unknown NetFlow version '" + s +
                                 "' (expected 1, 5, 9, 10, or psamp)");
}

// Original: -P transport_protocol. Only udp is actually implemented in
// this project (see the warning printed in main() if tcp/sctp is
// requested); TCP/SCTP export would need a connection-oriented framing
// layer this project does not yet have.
TransportProtocol parse_transport_protocol(const std::string& s) {
    if (s == "udp") return TransportProtocol::Udp;
    if (s == "tcp") return TransportProtocol::Tcp;
    if (s == "sctp") return TransportProtocol::Sctp;
    throw std::invalid_argument("unknown transport protocol '" + s +
                                 "' (expected udp, tcp, or sctp)");
}

// Original: -A time_format. Only sec/milli are actually implemented (see
// the warning printed in main() if micro/nano is requested) -- the IPFIX
// abstract data types for microsecond/nanosecond timestamps use an
// NTP-derived fixed-point encoding rather than a plain integer count,
// which this project's exporters don't yet produce.
TimeFormat parse_time_format(const std::string& s) {
    if (s == "sec") return TimeFormat::Seconds;
    if (s == "milli") return TimeFormat::Milliseconds;
    if (s == "micro") return TimeFormat::Microseconds;
    if (s == "nano") return TimeFormat::Nanoseconds;
    throw std::invalid_argument("unknown time format '" + s +
                                 "' (expected sec, milli, micro, or nano)");
}

// Original: -n host:port[,host:port...]. A numeric IPv6 address must be
// bracketed (e.g. "[::1]:4432") to disambiguate its colons from the
// port separator, exactly as the original requires.
std::vector<std::pair<std::string, std::string>>
parse_destinations(const std::string& spec) {
    std::vector<std::pair<std::string, std::string>> result;
    std::size_t pos = 0;
    while (pos <= spec.size()) {
        const auto comma = spec.find(',', pos);
        const std::string token =
            spec.substr(pos, comma == std::string::npos ? std::string::npos
                                                          : comma - pos);
        if (token.empty()) {
            throw std::invalid_argument("empty destination in -n argument: " + spec);
        }

        std::string host, port;
        if (token.front() == '[') {
            const auto close = token.find(']');
            if (close == std::string::npos) {
                throw std::invalid_argument("malformed IPv6 destination: " + token);
            }
            host = token.substr(1, close - 1);
            const auto colon = token.find(':', close);
            if (colon == std::string::npos) {
                throw std::invalid_argument("missing port in destination: " + token);
            }
            port = token.substr(colon + 1);
        } else {
            const auto colon = token.rfind(':');
            if (colon == std::string::npos) {
                throw std::invalid_argument("missing port in destination: " + token);
            }
            host = token.substr(0, colon);
            port = token.substr(colon + 1);
        }
        result.emplace_back(std::move(host), std::move(port));

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
bool should_track_ipv6(const DaemonConfig& config) {
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
void write_framed_packets(const std::string& path,
                           const std::vector<std::vector<std::uint8_t>>& packets,
                           bool append) {
    if (packets.empty()) {
        return;
    }
    std::FILE* f = std::fopen(path.c_str(), append ? "ab" : "wb");
    if (f == nullptr) {
        throw std::runtime_error("failed to open '" + path + "' for writing");
    }
    struct FileCloser {
        std::FILE* file;
        ~FileCloser() {
            if (file != nullptr) {
                std::fclose(file);
            }
        }
    } closer{f};

    for (const auto& pkt : packets) {
        const std::uint32_t len = static_cast<std::uint32_t>(pkt.size());
        const std::uint8_t len_be[4] = {
            static_cast<std::uint8_t>(len >> 24),
            static_cast<std::uint8_t>(len >> 16),
            static_cast<std::uint8_t>(len >> 8),
            static_cast<std::uint8_t>(len),
        };
        std::fwrite(len_be, 1, sizeof(len_be), f);
        std::fwrite(pkt.data(), 1, pkt.size(), f);
    }
}

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
    ExportPipeline(const DaemonConfig& config, softflow::TimePoint boot_time)
        : format_(config.export_format) {
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

        for (const auto& [host, port] : config.destinations) {
            try {
                destinations_.add(softflow::ExportDestination(
                    host, port, transport_kind, config.ttl,
                    config.source_address, config.send_interface));
            } catch (const softflow::ExportError& e) {
                if (config.transport == TransportProtocol::Sctp) {
                    // Original: -P sctp. SCTP support depends on kernel
                    // module availability, which isn't guaranteed, so a
                    // failure here falls back to UDP rather than
                    // preventing the daemon from starting at all.
                    std::fprintf(stderr,
                                 "warning: SCTP export to '%s:%s' failed "
                                 "(%s); falling back to udp\n",
                                 host.c_str(), port.c_str(), e.what());
                    destinations_.add(softflow::ExportDestination(
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
            write_framed_packets(export_out_, {}, /*append=*/false); // truncate/create
        }

        switch (format_) {
        case ExportFormat::Netflow1:
            netflow1_.emplace(boot_time);
            break;
        case ExportFormat::Netflow5:
            netflow5_.emplace(boot_time);
            break;
        case ExportFormat::Netflow9:
            netflow9_.emplace(boot_time, /*source_id=*/0,
                               static_cast<std::uint8_t>(config.mpls_labels));
            break;
        case ExportFormat::Ipfix:
            ipfix_.emplace(/*observation_domain_id=*/0,
                            static_cast<std::uint8_t>(config.mpls_labels),
                            to_ipfix_time_format(config.time_format),
                            config.bidirectional_ipfix);
            break;
        case ExportFormat::Psamp:
            psamp_.emplace(/*observation_domain_id=*/0,
                            to_ipfix_time_format(config.time_format));
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
    bool has_sink() const noexcept {
        return !destinations_.empty() || !export_out_.empty();
    }

    bool wants_flows() const noexcept {
        return has_sink() && format_ != ExportFormat::Psamp &&
               format_ != ExportFormat::None;
    }
    bool wants_samples() const noexcept {
        return has_sink() && format_ == ExportFormat::Psamp;
    }

    // Original: softflowctl(8)'s send-template ("Has no effect for other
    // flow export versions" besides NetFlow v9). Returns true if this
    // pipeline was actually able to honor the request (i.e. is running
    // NetFlow v9), so the control-command handler can report accurately
    // whether anything happened.
    bool resend_template() {
        if (netflow9_.has_value()) {
            netflow9_->force_template_resend();
            return true;
        }
        return false;
    }

    void export_flows(const std::vector<softflow::ExportRecord>& records,
                       softflow::TimePoint now,
                       std::chrono::system_clock::time_point wall_now) {
        if (records.empty() || !wants_flows()) {
            return;
        }
        std::vector<std::vector<std::uint8_t>> packets;
        switch (format_) {
        case ExportFormat::Netflow1:
            packets = netflow1_->build_packets(records, now, wall_now);
            break;
        case ExportFormat::Netflow5:
            packets = netflow5_->build_packets(records, now, wall_now);
            break;
        case ExportFormat::Netflow9:
            packets = netflow9_->build_packets(records, now, wall_now);
            break;
        case ExportFormat::Ipfix:
            packets = ipfix_->build_packets(records, now, wall_now);
            break;
        case ExportFormat::Psamp:
        case ExportFormat::None:
            break;
        }
        dispatch(packets);
    }

    void export_samples(const std::vector<softflow::SampledPacket>& samples,
                         softflow::TimePoint now,
                         std::chrono::system_clock::time_point wall_now) {
        if (samples.empty() || !wants_samples()) {
            return;
        }
        auto packets = psamp_->build_packets(samples, now, wall_now);
        dispatch(packets);
    }

private:
    void dispatch(const std::vector<std::vector<std::uint8_t>>& packets) {
        if (packets.empty()) {
            return;
        }
        for (const auto& packet : packets) {
            destinations_.send_packet(packet, load_balance_);
        }
        if (!export_out_.empty()) {
            write_framed_packets(export_out_, packets, /*append=*/true);
        }
    }

    ExportFormat format_;
    std::string export_out_;
    softflow::ExportDestinationSet destinations_;
    bool load_balance_ = false;
    std::optional<softflow::Netflow1Exporter> netflow1_;
    std::optional<softflow::Netflow5Exporter> netflow5_;
    std::optional<softflow::Netflow9Exporter> netflow9_;
    std::optional<softflow::IpfixExporter> ipfix_;
    std::optional<softflow::PsampExporter> psamp_;
};

// Original: -x number_of_mpls_labels. An MPLS-encapsulated frame (EtherType
// 0x8847 unicast / 0x8848 multicast) carries one or more 4-byte label
// stack entries before the actual IP header; there is no explicit
// "next protocol" field, so -- following the same convention other MPLS-
// aware tools use -- the IP version nibble of the first byte after the
// label stack determines whether what follows is IPv4 or IPv6.
struct MplsShimEntry {
    std::uint32_t label; // 20 bits
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
parse_mpls_label_stack(std::span<const std::uint8_t> data, std::size_t& consumed) {
    std::vector<MplsShimEntry> labels;
    std::size_t offset = 0;
    for (;;) {
        if (offset + 4 > data.size()) {
            return std::nullopt; // truncated label stack
        }
        const std::uint32_t shim =
            (static_cast<std::uint32_t>(data[offset]) << 24) |
            (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
            static_cast<std::uint32_t>(data[offset + 3]);
        const std::uint32_t label = shim >> 12;
        const bool bottom = (shim & 0x00000100u) != 0; // the S bit
        labels.push_back(MplsShimEntry{label, bottom});
        offset += 4;
        if (bottom) {
            break;
        }
        if (labels.size() > 32) {
            return std::nullopt; // implausibly deep; treat as malformed
        }
    }
    consumed = offset;
    return labels;
}

struct FrameClassification {
    softflow::AddressFamily af;
    std::size_t ip_offset; // bytes to skip, from the start of ip_bytes, to reach the IP header
    std::vector<std::uint32_t> mpls_labels; // outermost label first; empty if not MPLS-encapsulated
};

// Shared by run_pcap_file() and run_live_capture(): classifies one
// captured frame's address family (and, for MPLS-encapsulated frames, its
// label stack) from its data-link header, mapping the original DATALINK
// table's ft_off/ft_len fields onto this project's DatalinkKind.
std::optional<FrameClassification>
classify_frame(const softflow::CapturedPacket& pkt, softflow::DatalinkKind dl_kind,
                std::span<const std::uint8_t> ip_bytes) {
    using namespace softflow;
    if (dl_kind == DatalinkKind::Ethernet) {
        if (pkt.data.size() < 14) {
            return std::nullopt;
        }
        const std::uint16_t ethertype =
            static_cast<std::uint16_t>((pkt.data[12] << 8) | pkt.data[13]);
        if (ethertype == 0x0800) {
            return FrameClassification{AddressFamily::IPv4, 0, {}};
        }
        if (ethertype == 0x86dd) {
            return FrameClassification{AddressFamily::IPv6, 0, {}};
        }
        if (ethertype == 0x8847 || ethertype == 0x8848) {
            std::size_t consumed = 0;
            auto shim_entries = parse_mpls_label_stack(ip_bytes, consumed);
            if (!shim_entries.has_value() || consumed >= ip_bytes.size()) {
                return std::nullopt;
            }
            std::vector<std::uint32_t> labels;
            labels.reserve(shim_entries->size());
            for (const auto& entry : *shim_entries) {
                labels.push_back(entry.label);
            }
            const AddressFamily af = (ip_bytes[consumed] >> 4) == 6
                                          ? AddressFamily::IPv6
                                          : AddressFamily::IPv4;
            return FrameClassification{af, consumed, std::move(labels)};
        }
        return std::nullopt; // not an IP (or MPLS-encapsulated IP) frame
    }
    if (ip_bytes.empty()) {
        return std::nullopt;
    }
    const AddressFamily af =
        (ip_bytes[0] >> 4) == 6 ? AddressFamily::IPv6 : AddressFamily::IPv4;
    return FrameClassification{af, 0, {}};
}

// =======================================================================
// run_pcap_file (original: softflowd.c's -r mode -- process a capture
// file in a single pass, then print statistics and exit without forking)
// =======================================================================
int run_pcap_file(const DaemonConfig& config) {
    using namespace softflow;

    PcapHandle handle = PcapHandle::open_offline(config.pcap_file);
    if (!config.bpf_filter.empty()) {
        handle.set_filter(config.bpf_filter);
    }
    const auto dl_kind = handle.datalink_kind();
    if (dl_kind == DatalinkKind::Unsupported) {
        std::fprintf(stderr, "unsupported datalink type (pcap_datalink=%d)\n",
                     handle.datalink());
        return 1;
    }
    const std::size_t skip = datalink_header_len(dl_kind);

    PacketParser parser(config.track_level);
    FlowTableRuntime table(config.backend, config.max_flows, config.track_level,
                            config.timeouts);
    const TimePoint boot_time = Clock::now();
    ExportPipeline exporter(config, boot_time);

    bool time_base_established = false;
    TimePoint time_base_mono{};
    std::chrono::system_clock::time_point time_base_wall{};

    std::vector<SampledPacket> pending_samples;
    std::uint64_t total = 0;
    std::uint64_t parsed_ok = 0;
    std::uint32_t sample_counter = 0;

    while (auto pkt = handle.next_packet()) {
        ++total;
        if (pkt->data.size() <= skip) {
            continue;
        }
        const auto ip_bytes = pkt->data.subspan(skip);

        const auto frame = classify_frame(*pkt, dl_kind, ip_bytes);
        if (!frame.has_value()) {
            continue;
        }
        if (frame->af == AddressFamily::IPv6 && !should_track_ipv6(config)) {
            continue;
        }

        auto parsed = parser.parse(ip_bytes.subspan(frame->ip_offset), frame->af);
        if (!parsed.has_value()) {
            continue;
        }
        ++parsed_ok;

        // Original: -s sampling_rate. A systematic 1-in-N sample: every
        // Nth successfully parsed packet is processed, the rest are
        // discarded outright (counts are not scaled up to compensate,
        // matching the original's behavior).
        if (config.sampling_rate > 1) {
            ++sample_counter;
            if ((sample_counter % config.sampling_rate) != 0) {
                continue;
            }
        }

        // Original: -a. Use libpcap's own recorded timestamp (relative to
        // the first packet's) as the reference time for flow tracking,
        // instead of this process's wall-clock time while reading the
        // file. The very first packet establishes the mapping between the
        // pcap file's timestamps and this process's monotonic clock.
        TimePoint effective_time;
        if (config.adjust_pcap_time) {
            if (!time_base_established) {
                time_base_mono = Clock::now();
                time_base_wall = pkt->wall_timestamp;
                time_base_established = true;
            }
            effective_time =
                time_base_mono + std::chrono::duration_cast<Clock::duration>(
                                      pkt->wall_timestamp - time_base_wall);
        } else {
            effective_time = pkt->timestamp;
        }

        if (config.export_format == ExportFormat::Psamp) {
            pending_samples.push_back(make_sampled_packet(
                *parsed, pkt->original_length, effective_time));
        }

        const auto key = make_flow_key(*parsed, parser.track_level());
        const std::uint8_t direction = (key.addr()[0] == parsed->src) ? 0 : 1;
        Flow& flow = table.record_packet(key, effective_time, direction,
                                          pkt->original_length,
                                          (parsed->tcp_flags & 0x02) != 0,
                                          (parsed->tcp_flags & 0x05) != 0);
        // Original: -x. Only actually stored (and later exported) when
        // requested, capped both by -x's own argument and by the IPFIX/
        // NetFlow v9 Information Element registry's defined range of 10
        // label-stack-section fields.
        if (config.mpls_labels > 0 && !frame->mpls_labels.empty()) {
            const std::size_t keep = std::min<std::size_t>(
                {frame->mpls_labels.size(),
                 static_cast<std::size_t>(config.mpls_labels), 10});
            flow.mpls_labels.assign(frame->mpls_labels.begin(),
                                     frame->mpls_labels.begin() +
                                         static_cast<std::ptrdiff_t>(keep));
        }

        // Original: "softflowd processes the whole capture file and only
        // expires flows when max_flows is exceeded" -- no time-based
        // expiry happens mid-file, only this forced eviction.
        if (table.size() > table.max_flows()) {
            const auto forced = table.force_expire_oldest(
                table.size() - table.max_flows());
            exporter.export_flows(forced, effective_time,
                                   std::chrono::system_clock::now());
        }
    }

    std::printf("[pcap, backend=%s, track=%s, version=%s] total frames: "
                "%llu, parsed as IP: %llu\n",
                config.backend == FlowIndexBackend::Hash ? "hash" : "tree",
                track_level_name(config.track_level),
                format_name(config.export_format),
                static_cast<unsigned long long>(total),
                static_cast<unsigned long long>(parsed_ok));
    std::printf("[pcap] tracked flows remaining at EOF: %zu\n", table.size());

    const auto now = Clock::now();
    const auto wall_now = std::chrono::system_clock::now();
    const auto expired = table.expire_flows(now + std::chrono::hours(2));
    exporter.export_flows(expired, now, wall_now);
    exporter.export_samples(pending_samples, now, wall_now);

    std::printf("[pcap] flows expired at end-of-file flush: %zu\n",
                expired.size());
    if (exporter.has_sink()) {
        std::printf("[pcap] export: %s%s%s\n", format_name(config.export_format),
                    config.destinations.empty() ? "" : " -> network destination(s)",
                    config.export_out.empty() ? "" : " + file");
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
    int debug_level = 0; // original: softflowctl(8)'s debug+/debug-
};

// Original: the %-based address formatting softflowd.c's dump-flows
// output uses. IPv6 addresses are printed as plain colon-separated hex
// groups (not the canonical "::"-compressed form RFC 5952 prefers) --
// simpler to implement correctly and still a valid, parseable IPv6
// text representation.
std::string format_address(const softflow::IpAddress& addr) {
    using namespace softflow;
    if (addr.family == AddressFamily::IPv4) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr.bytes[0],
                      addr.bytes[1], addr.bytes[2], addr.bytes[3]);
        return buf;
    }
    std::string result;
    for (int i = 0; i < 8; ++i) {
        if (i > 0) {
            result += ':';
        }
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%x",
                      (addr.bytes[static_cast<std::size_t>(i) * 2] << 8) |
                          addr.bytes[static_cast<std::size_t>(i) * 2 + 1]);
        result += buf;
    }
    return result;
}

// Original: softflowctl(8)'s dump-flows, one line per tracked flow.
std::string format_flow_dump_line(const softflow::ExportRecord& record) {
    const auto& key = record.key;
    const auto& flow = record.flow;
    return "ACTIVE seq:" + std::to_string(flow.flow_seq) + " [" +
           format_address(key.addr()[0]) + "]:" + std::to_string(key.port()[0]) +
           " <> [" + format_address(key.addr()[1]) +
           "]:" + std::to_string(key.port()[1]) +
           " proto:" + std::to_string(key.protocol()) +
           " octets>:" + std::to_string(flow.octets[0]) +
           " packets>:" + std::to_string(flow.packets[0]) +
           " octets<:" + std::to_string(flow.octets[1]) +
           " packets<:" + std::to_string(flow.packets[1]);
}

// Original: softflowctl(8)'s command set, dispatched here since softflowd.c
// (not softflowctl.c) owned the listening/accepting side of the control
// socket. See softflowctl.hpp for the shared command-name constants and
// wire helpers used by both sides.
std::string handle_control_command(const std::string& command,
                                    softflow::FlowTableRuntime& table,
                                    ControlState& state, ExportPipeline& exporter) {
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
        exporter.export_flows(table.force_expire_oldest(count), Clock::now(),
                               std::chrono::system_clock::now());
        return "OK expire-all: expired " + std::to_string(count) + " flows";
    }
    if (command == kDeleteAll) {
        const auto count = table.size();
        static_cast<void>(table.force_expire_oldest(count));
        return "OK delete-all: deleted " + std::to_string(count) +
               " flows (no export)";
    }
    if (command == kStatistics) {
        const auto& stats = table.stats();
        return "OK tracked=" + std::to_string(table.size()) +
               " max_flows=" + std::to_string(table.max_flows()) +
               " total_packets=" + std::to_string(stats.total_packets) +
               " flows_expired=" + std::to_string(stats.flows_expired) +
               " flows_force_expired=" +
               std::to_string(stats.flows_force_expired) +
               " backend=" +
               (table.backend() == FlowIndexBackend::Hash ? "hash" : "tree") +
               " capturing=" + (state.capturing ? "yes" : "no") +
               " debug_level=" + std::to_string(state.debug_level);
    }
    if (command == kDebugPlus) {
        ++state.debug_level;
        return "OK debug level now " + std::to_string(state.debug_level);
    }
    if (command == kDebugMinus) {
        if (state.debug_level > 0) {
            --state.debug_level;
        }
        return "OK debug level now " + std::to_string(state.debug_level);
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
        std::string response = "OK " + std::to_string(records.size()) + " flows";
        for (const auto& record : records) {
            response += "\n" + format_flow_dump_line(record);
        }
        return response;
    }
    if (command == kTimeouts) {
        const auto& t = table.timeouts();
        return "OK general=" + std::to_string(t.general.count()) +
               "s tcp=" + std::to_string(t.tcp.count()) +
               "s tcp.rst=" + std::to_string(t.tcp_rst.count()) +
               "s tcp.fin=" + std::to_string(t.tcp_fin.count()) +
               "s udp=" + std::to_string(t.udp.count()) +
               "s maxlife=" + std::to_string(t.maximum_lifetime.count()) + "s";
    }
    if (command == kSendTemplate) {
        if (exporter.resend_template()) {
            return "OK template will be resent before the next export";
        }
        return "OK send-template has no effect for this export format";
    }
    return "ERROR unknown command '" + command + "'";
}

int run_live_capture(const DaemonConfig& config) {
    using namespace softflow;

    // A short read timeout plus immediate mode (see PcapHandle::open_live)
    // keeps this daemon responsive to control-socket commands and signals
    // even under sustained traffic -- see the packet-draining loop below
    // for the other half of this responsiveness story (it also caps how
    // many packets it drains per poll() cycle).
    PcapHandle handle = PcapHandle::open_live(
        config.interface, config.snaplen, !config.no_promiscuous,
        std::chrono::milliseconds(100), config.buffer_bytes);
    if (!config.bpf_filter.empty()) {
        handle.set_filter(config.bpf_filter);
    }
    const auto dl_kind = handle.datalink_kind();
    if (dl_kind == DatalinkKind::Unsupported) {
        std::fprintf(stderr, "unsupported datalink type (pcap_datalink=%d)\n",
                     handle.datalink());
        return 1;
    }
    const std::size_t skip = datalink_header_len(dl_kind);

    PacketParser parser(config.track_level);
    FlowTableRuntime table(config.backend, config.max_flows, config.track_level,
                            config.timeouts);
    const TimePoint boot_time = Clock::now();
    const auto start_time = boot_time;
    ExportPipeline exporter(config, boot_time);

    // Original: softflowd.c bound and listened on /var/run/softflowd.ctl
    // (or -c's argument) for softflowctl(8) connections. RAII (this small
    // guard struct) ensures both the listening socket and its filesystem
    // entry are cleaned up on every return path from this function,
    // including an exception.
    ::unlink(config.ctl_sock.c_str());
    const int ctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctl_fd < 0) {
        throw std::runtime_error("socket() for control socket failed");
    }
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (config.ctl_sock.size() >= sizeof(addr.sun_path)) {
        ::close(ctl_fd);
        throw std::runtime_error("control socket path too long: " + config.ctl_sock);
    }
    std::strncpy(addr.sun_path, config.ctl_sock.c_str(), sizeof(addr.sun_path) - 1);
    struct CtlSocketGuard {
        int fd;
        std::string path;
        ~CtlSocketGuard() {
            if (fd >= 0) {
                ::close(fd);
            }
            ::unlink(path.c_str());
        }
    } ctl_guard{ctl_fd, config.ctl_sock};

    if (bind(ctl_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
        listen(ctl_fd, 5) < 0) {
        throw std::runtime_error("failed to set up control socket at '" +
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
        ~PsampSocketGuard() {
            if (fd >= 0) {
                ::close(fd);
            }
        }
    } psamp_guard{-1};
    if (config.psamp_receive_port.has_value()) {
        // Prefer a dual-stack IPv6 socket (accepting both IPv4- and
        // IPv6-sourced datagrams); fall back to IPv4-only if the platform
        // or environment doesn't support IPv6 at all (e.g. some
        // containers/sandboxes disable it entirely).
        psamp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
        const bool using_ipv6 = psamp_fd >= 0;
        if (!using_ipv6) {
            psamp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        }
        if (psamp_fd < 0) {
            throw std::runtime_error("socket() for PSAMP receive port failed");
        }

        int bind_result = -1;
        if (using_ipv6) {
            // Accept both IPv4 and IPv6 senders on one dual-stack socket
            // where the platform supports it; a failure to clear
            // IPV6_V6ONLY is non-fatal (the socket still works for
            // IPv6-only use).
#ifdef IPV6_V6ONLY
            const int v6only = 0;
            setsockopt(psamp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
#endif
            struct sockaddr_in6 psamp_addr {};
            psamp_addr.sin6_family = AF_INET6;
            psamp_addr.sin6_addr = in6addr_any;
            psamp_addr.sin6_port =
                htons(static_cast<std::uint16_t>(*config.psamp_receive_port));
            bind_result = bind(psamp_fd, reinterpret_cast<struct sockaddr*>(&psamp_addr),
                                sizeof(psamp_addr));
        } else {
            struct sockaddr_in psamp_addr {};
            psamp_addr.sin_family = AF_INET;
            psamp_addr.sin_addr.s_addr = INADDR_ANY;
            psamp_addr.sin_port =
                htons(static_cast<std::uint16_t>(*config.psamp_receive_port));
            bind_result = bind(psamp_fd, reinterpret_cast<struct sockaddr*>(&psamp_addr),
                                sizeof(psamp_addr));
        }
        if (bind_result < 0) {
            ::close(psamp_fd);
            throw std::runtime_error("failed to bind PSAMP receive port " +
                                      std::to_string(*config.psamp_receive_port));
        }
        // Set O_NONBLOCK on the socket itself, rather than relying solely
        // on passing MSG_DONTWAIT to each individual recv() call below --
        // belt-and-braces, matching the same reasoning as SignalPipe's
        // pipe file descriptors (daemon.cpp): a blocking recv() here,
        // even briefly, would stall the entire event loop (control
        // socket, signals, pcap capture) until another PSAMP datagram
        // happened to arrive.
        const int psamp_flags = fcntl(psamp_fd, F_GETFL, 0);
        if (psamp_flags >= 0) {
            fcntl(psamp_fd, F_SETFL, psamp_flags | O_NONBLOCK);
        }
        psamp_guard.fd = psamp_fd;
        std::printf("[softflowd] PSAMP receive mode: listening on UDP port %d "
                    "(%s)\n",
                    *config.psamp_receive_port, using_ipv6 ? "IPv6" : "IPv4");
    }

    SignalPipe signals;
    ControlState state;

    std::vector<SampledPacket> pending_samples;
    std::uint32_t sample_counter = 0;
    TimePoint last_expiry_check = Clock::now();

    std::printf("[softflowd] listening on %s, control socket %s, version=%s, "
                "track=%s\n",
                config.interface.c_str(), config.ctl_sock.c_str(),
                format_name(config.export_format),
                track_level_name(config.track_level));

    while (!state.shutting_down && !state.immediate_exit) {
        struct pollfd fds[4];
        fds[0] = {signals.read_fd(), POLLIN, 0};
        fds[1] = {ctl_fd, POLLIN, 0};
        const int pcap_fd = handle.selectable_fd();
        fds[2] = {pcap_fd >= 0 ? pcap_fd : -1, POLLIN, 0};
        fds[3] = {psamp_fd >= 0 ? psamp_fd : -1, POLLIN, 0};

        const int ready = poll(fds, 4, 1000 /* ms */);
        if (ready < 0 && errno != EINTR) {
            throw std::runtime_error("poll() failed");
        }

        for (int sig : signals.drain()) {
            if (sig == SIGTERM || sig == SIGINT) {
                state.shutting_down = true;
            } else if (sig == SIGUSR1) {
                std::printf("[softflowd] stats: tracked=%zu total_packets=%llu\n",
                            table.size(),
                            static_cast<unsigned long long>(
                                table.stats().total_packets));
            } else if (sig == SIGHUP) {
                std::printf(
                    "[softflowd] SIGHUP received (config reload not "
                    "implemented in this stage)\n");
            }
        }

        if ((fds[1].revents & POLLIN) != 0) {
            const int client_fd = accept(ctl_fd, nullptr, nullptr);
            if (client_fd >= 0) {
                struct ClientCloser {
                    int fd;
                    ~ClientCloser() { ::close(fd); }
                } client_closer{client_fd};

                try {
                    const std::string command = read_line(client_fd);
                    const std::string response =
                        handle_control_command(command, table, state, exporter);
                    write_line(client_fd, response);
                } catch (const std::exception&) {
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
                    if (poll(&recheck, 1, 0) <= 0 ||
                        (recheck.revents & POLLIN) == 0) {
                        break; // nothing more queued right now
                    }
                }
                auto pkt = handle.next_packet();
                if (!pkt.has_value()) {
                    break;
                }
                if (pkt->data.size() <= skip) {
                    continue;
                }
                const auto ip_bytes = pkt->data.subspan(skip);

                const auto frame = classify_frame(*pkt, dl_kind, ip_bytes);
                if (!frame.has_value()) {
                    continue;
                }
                if (frame->af == AddressFamily::IPv6 && !should_track_ipv6(config)) {
                    continue;
                }

                auto parsed =
                    parser.parse(ip_bytes.subspan(frame->ip_offset), frame->af);
                if (!parsed.has_value()) {
                    continue;
                }

                if (config.sampling_rate > 1) {
                    ++sample_counter;
                    if ((sample_counter % config.sampling_rate) != 0) {
                        continue;
                    }
                }

                if (config.export_format == ExportFormat::Psamp) {
                    pending_samples.push_back(make_sampled_packet(
                        *parsed, pkt->original_length, pkt->timestamp));
                }

                const auto key = make_flow_key(*parsed, parser.track_level());
                const std::uint8_t direction =
                    (key.addr()[0] == parsed->src) ? 0 : 1;
                Flow& flow = table.record_packet(
                    key, pkt->timestamp, direction, pkt->original_length,
                    (parsed->tcp_flags & 0x02) != 0,
                    (parsed->tcp_flags & 0x05) != 0);
                if (config.mpls_labels > 0 && !frame->mpls_labels.empty()) {
                    const std::size_t keep = std::min<std::size_t>(
                        {frame->mpls_labels.size(),
                         static_cast<std::size_t>(config.mpls_labels), 10});
                    flow.mpls_labels.assign(
                        frame->mpls_labels.begin(),
                        frame->mpls_labels.begin() + static_cast<std::ptrdiff_t>(keep));
                }

                if (table.size() > table.max_flows()) {
                    exporter.export_flows(
                        table.force_expire_oldest(table.size() - table.max_flows()),
                        pkt->timestamp, std::chrono::system_clock::now());
                }
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
                struct sockaddr_storage sender_addr {};
                socklen_t sender_len = sizeof(sender_addr);
                const ssize_t received =
                    recvfrom(psamp_fd, buffer.data(), buffer.size(), MSG_DONTWAIT,
                             reinterpret_cast<struct sockaddr*>(&sender_addr),
                             &sender_len);
                if (received <= 0) {
                    break; // no more datagrams queued right now
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
                    const auto* sin = reinterpret_cast<struct sockaddr_in*>(&sender_addr);
                    inet_ntop(AF_INET, &sin->sin_addr, addr_str.data(), addr_str.size());
                    sender_port = ntohs(sin->sin_port);
                } else if (sender_addr.ss_family == AF_INET6) {
                    const auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&sender_addr);
                    inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str.data(), addr_str.size());
                    sender_port = ntohs(sin6->sin6_port);
                }
                const std::string source_id =
                    std::string(addr_str.data()) + ":" + std::to_string(sender_port);

                const auto received_at = Clock::now();
                auto samples = psamp_receiver.decode_message(
                    std::span<const std::uint8_t>(buffer.data(),
                                                   static_cast<std::size_t>(received)),
                    received_at, source_id);
                for (const auto& sample : samples) {
                    const auto key = FlowKey::make_canonical(
                        sample.src, sample.dst, sample.src_port, sample.dst_port,
                        sample.protocol, sample.tos, {0, 0});
                    const std::uint8_t direction =
                        (key.addr()[0] == sample.src) ? 0 : 1;
                    table.record_packet(key, sample.observed_at, direction,
                                         sample.observed_length, false, false);
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
            exporter.export_flows(table.expire_flows(now), now,
                                   std::chrono::system_clock::now());
            exporter.export_samples(pending_samples, now,
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
        exporter.export_flows(table.expire_flows(now + std::chrono::hours(2)),
                               now, wall_now);
        exporter.export_samples(pending_samples, now, wall_now);
    }

    std::printf("[softflowd] exiting (%s)\n",
                state.immediate_exit ? "immediate" : "graceful");
    return 0;
}

void print_usage(const char* argv0) {
    std::fprintf(
        stderr,
        "usage: %s [-6dDhNbal] [-L hoplimit] [-T track_level] [-c ctl_sock]\n"
        "               [-i [if_ndx:]interface] [-m max_flows] [-n host:port]\n"
        "               [-p pidfile] [-r pcap_file] [-t timeout_name=seconds]\n"
        "               [-v netflow_version] [-P transport_protocol]\n"
        "               [-A time_format] [-s sampling_rate] [-C capture_length]\n"
        "               [-R receive_port] [-S send_interface_name]\n"
        "               [-x number_of_mpls_labels] [-e exporter_ip_address]\n"
        "               [-B size_bytes] [bpf_expression]\n"
        "\n"
        "Either -i or -r must be given. See softflowd(8) for full option\n"
        "documentation; this project implements the same option grammar as\n"
        "the original softflowd. -P, -A, -x, and -b are fully implemented\n"
        "(see README for details, e.g. SCTP availability and biflow's\n"
        "encoding); -R (PSAMP receive mode) is not implemented.\n"
        "\n"
        "This project's own additions (not part of the original softflowd):\n"
        "  --backend=hash|tree   flow-tracking data structure (default: hash)\n"
        "  --export-out=PATH     additionally write export packets to a file,\n"
        "                        each length-prefixed with 4 big-endian bytes\n"
        "  --max-runtime=SECONDS shut down automatically after SECONDS (testing)\n",
        argv0);
}

} // namespace

int main(int argc, char** argv) {
    // A daemon's log output is much more useful flushed promptly than
    // batched up in a large buffer -- especially relevant once stdout is
    // redirected to a file or pipe (as it always is once daemonizing
    // redirects it, and as it commonly is under a supervisor like
    // systemd). This has no effect on interactive/TTY use, where stdout is
    // already line-buffered by default.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    DaemonConfig config;

    // This project's own GNU-style long options are filtered out of argv
    // before the original's getopt()-based short options are parsed, so
    // they can never collide with any of softflowd's own single-letter
    // flags.
    std::vector<char*> filtered_argv;
    filtered_argv.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--backend=hash") {
            config.backend = softflow::FlowIndexBackend::Hash;
        } else if (arg == "--backend=tree") {
            config.backend = softflow::FlowIndexBackend::Tree;
        } else if (arg.rfind("--export-out=", 0) == 0) {
            config.export_out = arg.substr(std::string("--export-out=").size());
        } else if (arg.rfind("--max-runtime=", 0) == 0) {
            config.max_runtime = std::chrono::seconds(
                std::stol(arg.substr(std::string("--max-runtime=").size())));
        } else {
            filtered_argv.push_back(argv[i]);
        }
    }

    const int fargc = static_cast<int>(filtered_argv.size());
    char** fargv = filtered_argv.data();
    bool export_format_explicit = false;

    ::optind = 1;
    int opt;
    try {
        while ((opt = getopt(fargc, fargv,
                              "n:Ni:r:p:c:m:t:d6DhL:T:v:P:A:s:C:R:S:e:x:B:bal")) != -1) {
            switch (opt) {
            case 'n': {
                auto dests = parse_destinations(optarg);
                config.destinations.insert(config.destinations.end(),
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
            case 'm':
                config.max_flows = static_cast<std::size_t>(std::stoul(optarg));
                break;
            case 't':
                apply_timeout_option(config, optarg);
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
                print_usage(argv[0]);
                return 0;
            case 'L':
                config.ttl = std::stoi(optarg);
                break;
            case 'T':
                config.track_level = parse_track_level(optarg);
                break;
            case 'v':
                config.export_format = parse_netflow_version(optarg);
                export_format_explicit = true;
                break;
            case 'P':
                config.transport = parse_transport_protocol(optarg);
                break;
            case 'A':
                config.time_format = parse_time_format(optarg);
                break;
            case 's':
                config.sampling_rate = static_cast<std::uint32_t>(std::stoul(optarg));
                break;
            case 'C':
                config.snaplen = std::stoi(optarg);
                break;
            case 'R':
                config.psamp_receive_port = std::stoi(optarg);
                break;
            case 'S':
                config.send_interface = optarg;
                break;
            case 'e':
                config.source_address = optarg;
                break;
            case 'x':
                config.mpls_labels = std::stoi(optarg);
                break;
            case 'B':
                config.buffer_bytes = static_cast<std::size_t>(std::stoul(optarg));
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
            case '?':
            default:
                print_usage(argv[0]);
                return 1;
            }
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s: %s\n", argv[0], e.what());
        return 1;
    }
    (void)export_format_explicit; // Netflow5 is already config's default

    std::string bpf;
    for (int i = optind; i < fargc; ++i) {
        if (!bpf.empty()) {
            bpf += " ";
        }
        bpf += fargv[i];
    }
    config.bpf_filter = bpf;

    if (config.interface.empty() && config.pcap_file.empty()) {
        std::fprintf(stderr, "%s: either -i or -r must be specified\n", argv[0]);
        print_usage(argv[0]);
        return 1;
    }
    if (!config.interface.empty() && !config.pcap_file.empty()) {
        std::fprintf(stderr, "%s: -i and -r are mutually exclusive\n", argv[0]);
        return 1;
    }
    if (config.psamp_receive_port.has_value() && !config.pcap_file.empty()) {
        std::fprintf(stderr,
                     "%s: -R only has an effect with -i (live capture); "
                     "ignored with -r\n",
                     argv[0]);
        config.psamp_receive_port.reset();
    }
    if (config.mpls_labels > 0 && config.export_format != ExportFormat::Netflow9 &&
        config.export_format != ExportFormat::Ipfix) {
        std::fprintf(stderr,
                     "%s: warning: -x only has an effect with -v 9 or -v "
                     "10 (NetFlow v1/v5/PSAMP have no MPLS label fields); "
                     "no MPLS labels will be exported\n",
                     argv[0]);
    }
    if (config.bidirectional_ipfix && config.export_format != ExportFormat::Ipfix) {
        std::fprintf(stderr,
                     "%s: warning: -b only has an effect with -v 10 (IPFIX)\n",
                     argv[0]);
    }
    if (config.debug) {
        std::printf(
            "[softflowd] debug: interface=%s pcap_file=%s max_flows=%zu "
            "track_level=%s version=%s destinations=%zu backend=%s\n",
            config.interface.c_str(), config.pcap_file.c_str(),
            config.max_flows, track_level_name(config.track_level),
            format_name(config.export_format), config.destinations.size(),
            config.backend == softflow::FlowIndexBackend::Hash ? "hash" : "tree");
    }

    try {
        if (!config.pcap_file.empty()) {
            return run_pcap_file(config);
        }

        // Original: softflowd defaults to daemonizing (forking into the
        // background) when run against a live interface, unless -d is
        // given.
        std::optional<softflow::PidFile> pidfile;
        if (!config.no_daemonize) {
            softflow::daemonize();
            pidfile.emplace(config.pidfile);
        }
        return run_live_capture(config);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s: %s\n", argv[0], e.what());
        return 1;
    }
}

#endif // SOFTFLOW_NO_MAIN
