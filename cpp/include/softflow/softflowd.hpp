// Original files: softflowd.h, common.h, freelist.h, treetype.h, sys-tree.h
//
// This single header intentionally mirrors the original softflowd's
// monolithic layout: softflowd.h declared struct FLOW / EXPIRY / FLOWTRACK /
// FLOWTRACKPARAMETERS together, and softflowd.c contained essentially all of
// the logic (packet parsing, flow tracking, capture loop, main()). We follow
// the same file boundary here -- everything the daemon needs is declared in
// softflowd.hpp and defined in softflowd.cpp -- while still applying the
// memory-safety practices described in the accompanying article
// (https://mecanik.dev/ja/posts/c++-vs-rust-memory-safety-practical-examples-with-modern-c++/).
//
// packet_parser.* and capture.* from earlier iterations of this project have
// been folded back into this file and softflowd.cpp, since the original
// softflowd had no separate files for that logic either -- it all lived in
// softflowd.c. freelist.* has also been folded in, since it directly
// implements what used to be struct FLOWTRACK.
#ifndef SOFTFLOWD_HPP
#define SOFTFLOWD_HPP

#include <array>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

extern "C" {
#include <pcap/pcap.h>
}

namespace softflow {

// ---------------------------------------------------------------------
// Common types (original: common.h, and the top of softflowd.h)
// ---------------------------------------------------------------------

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration = Clock::duration;

// Original: struct FLOW used a raw int / u_int8_t for protocol, tcp_flags,
// etc. enum class gives these fields compile-time type safety.
enum class AddressFamily : std::uint8_t {
    IPv4,
    IPv6,
};

// Original: TRACK_IP_ONLY .. TRACK_FULL_VLAN_ETHER (softflowd.h)
// Original: -T track_level, exactly five levels named "ip", "proto",
// "full" (the default), "vlan", and "ether". An earlier revision of this
// project had a spurious sixth level between IpProtoPort and FullVlan
// (used only to gate ToS capture); that distinction doesn't exist in the
// original and has been removed so -T's five values map onto this enum
// one-to-one.
enum class TrackLevel : std::uint8_t {
    IpOnly,       // "ip":    source/destination address only
    IpProto,      // "proto": + protocol
    IpProtoPort,  // "full":  + source/destination port (the default)
    FullVlan,     // "vlan":  + VLAN ID
    FullVlanEther, // "ether": + source/destination Ethernet address
};

// Original:
//   union { struct in_addr v4; struct in6_addr v6; } addr[2];
// A union plus a separate "which member is active" flag requires the
// programmer to remember which member is valid; accessing the wrong one
// (type punning) is undetected undefined behavior. Here a single fixed-size
// array is used, and AddressFamily only changes how many of the bytes are
// meaningful. (std::variant would be even safer, but this packet-processing
// hot path favors a representation with low copy/branch overhead.)
struct IpAddress {
    AddressFamily family{AddressFamily::IPv4};
    std::array<std::uint8_t, 16> bytes{}; // only the first 4 bytes are used for IPv4

    // A defaulted three-way comparison gives us both operator== (needed for
    // the hash-based backend) and a strict total order (needed for the
    // tree-based backend) for free, with no hand-written comparator that
    // could get out of sync between the two.
    friend auto operator<=>(const IpAddress&, const IpAddress&) = default;
    friend bool operator==(const IpAddress&, const IpAddress&) = default;
};

// Original: struct FLOW's mplsLabelStackDepth + mplsLabels[10] -- a fixed
// buffer with its length tracked in a *separate* variable. Any place that
// forgets to keep the two in sync is a buffer overrun / uninitialized read
// waiting to happen (this is exactly the pattern in the article's second
// example). std::vector ties the length to the data itself.
using MplsLabelStack = std::vector<std::uint32_t>;

// ---------------------------------------------------------------------
// FlowKey / Flow (original: struct FLOW in softflowd.h)
// ---------------------------------------------------------------------

// Original: struct FLOW mixed two responsibilities in one struct:
//   (a) the fields used as a lookup key (addr/port/protocol/tos/vlanid...)
//   (b) the fields updated as a result of a lookup (octets/packets/flow_seq)
// It also carried an `EXPIRY *expiry` raw pointer to a matching EXPIRY
// struct, and EXPIRY carried a `FLOW *flow` raw pointer back. This mutual
// raw-pointer relationship is exactly the dangling-pointer / use-after-free
// pattern called out in the article: freeing one side without updating the
// other leaves a dangling pointer on the other side.
//
// Here the lookup key (FlowKey) and the value (Flow) are separate types, and
// any association between a flow and its expiry bookkeeping is made through
// a FlowTable-owned container key -- never a raw pointer -- so ownership
// always lives in exactly one place.
class FlowKey {
public:
    // Original: just before inserting/looking up a flow, softflowd.c had a
    // comment explaining that "the numerically smaller address/port goes in
    // slot [0]" and normalized the fields by hand at every call site -- a
    // convention enforced only by a comment, not by the type system. Here,
    // make_canonical() is the *only* way to construct a FlowKey, so an
    // unnormalized FlowKey cannot exist. The implementation is a small pure
    // function that fits comfortably in the header, just as softflowd.h
    // itself had no corresponding .c file.
    static FlowKey make_canonical(IpAddress addr_a, IpAddress addr_b,
                                   std::uint16_t port_a, std::uint16_t port_b,
                                   std::uint8_t protocol, std::uint8_t tos,
                                   std::array<std::uint16_t, 2> vlanid) {
        FlowKey key;
        // Original used a hand-written memcmp-based comparison for the same
        // normalization. std::array's operator< is a guaranteed
        // element-wise lexicographic comparison, which is both clearer in
        // intent and has no possibility of an out-of-bounds read.
        const bool a_is_lower =
            (addr_a.bytes < addr_b.bytes) ||
            (addr_a.bytes == addr_b.bytes && port_a <= port_b);

        if (a_is_lower) {
            key.addr_ = {addr_a, addr_b};
            key.port_ = {port_a, port_b};
            key.vlanid_ = vlanid;
        } else {
            key.addr_ = {addr_b, addr_a};
            key.port_ = {port_b, port_a};
            key.vlanid_ = {vlanid[1], vlanid[0]};
        }
        key.protocol_ = protocol;
        key.tos_ = tos;
        return key;
    }

    const std::array<IpAddress, 2>& addr() const noexcept { return addr_; }
    const std::array<std::uint16_t, 2>& port() const noexcept { return port_; }
    std::uint8_t protocol() const noexcept { return protocol_; }
    std::uint8_t tos() const noexcept { return tos_; }
    const std::array<std::uint16_t, 2>& vlanid() const noexcept {
        return vlanid_;
    }

    // Defaulted <=> gives both operator== (used by the hash-based backend)
    // and a strict total order (used by the tree-based backend, in place of
    // the original's RB_GENERATE-produced comparison function). One
    // declaration serves both FlowTable backends described below.
    friend auto operator<=>(const FlowKey&, const FlowKey&) = default;
    friend bool operator==(const FlowKey&, const FlowKey&) = default;

private:
    FlowKey() = default;

    std::array<IpAddress, 2> addr_{};
    std::array<std::uint16_t, 2> port_{};
    std::array<std::uint16_t, 2> vlanid_{};
    std::uint8_t protocol_{0};
    std::uint8_t tos_{0};
};

// Original: struct FLOW's statistics fields. The `[2]` raw C arrays for
// tcp_flags/octets/packets become std::array; mplsLabels[10] +
// mplsLabelStackDepth becomes MplsLabelStack (a vector); ethermac[2][6]
// becomes std::array<std::array<uint8_t,6>,2>. In every case, an
// out-of-bounds index becomes an immediately detectable exception/assertion
// (std::array::at(), or a debug-build-checked operator[]) instead of silent
// memory corruption.
struct Flow {
    std::uint64_t flow_seq{0};
    TimePoint flow_start{};
    TimePoint flow_last{};

    std::array<std::uint64_t, 2> octets{};
    std::array<std::uint64_t, 2> packets{};
    std::array<std::uint8_t, 2> tcp_flags{};
    std::array<std::array<std::uint8_t, 6>, 2> ethermac{};

    std::uint32_t ip6_flowlabel_a{0};
    std::uint32_t ip6_flowlabel_b{0};

    MplsLabelStack mpls_labels;

    std::uint8_t flow_end_reason{0};
};

// Original: NetFlow/IPFIX/PSAMP export code (in softflowd.c and the various
// netflow*.c/ipfix.c/psamp.c files) worked directly off `struct FLOW`, which
// carried both the key fields (addr/port/protocol/...) and the value fields
// (octets/packets/...) together. Since this project splits those into
// FlowKey and Flow, exporters need both -- ExportRecord is what
// FlowTable::expire_flows()/force_expire_oldest() hand back, pairing a key
// with its accumulated statistics at the moment the flow was expired.
struct ExportRecord {
    FlowKey key;
    Flow flow;
};

// ---------------------------------------------------------------------
// ByteWriter (a shared serialization helper used by netflow1.*,
// netflow5.*, netflow9.*, ipfix.*, and psamp.*)
// ---------------------------------------------------------------------
//
// The original built export packets by populating `__packed` C structs
// (e.g. `struct NF5_HEADER`) with htons()/htonl() and then treating the
// struct's address as a byte buffer to send. Two portability/safety issues
// with that approach:
//   1. `__packed` (or `#pragma pack`) structs have members at potentially
//      under-aligned addresses; reading/writing through a typed pointer to
//      such a member is undefined behavior on architectures that don't
//      support unaligned access, even though it "works" on x86.
//   2. Every htons()/htonl() call is a place where it's easy to forget the
//      conversion, or apply it to the wrong field, with no compiler
//      diagnostic either way.
// ByteWriter appends fields one at a time as explicit big-endian byte
// sequences into a std::vector<std::uint8_t> -- there is no struct, no
// packing pragma, and no possibility of an unconverted or
// wrong-byte-order field compiling silently.
class ByteWriter {
public:
    void put_u8(std::uint8_t v) { buf_.push_back(v); }

    void put_u16(std::uint16_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v >> 8));
        buf_.push_back(static_cast<std::uint8_t>(v));
    }

    void put_u32(std::uint32_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v >> 24));
        buf_.push_back(static_cast<std::uint8_t>(v >> 16));
        buf_.push_back(static_cast<std::uint8_t>(v >> 8));
        buf_.push_back(static_cast<std::uint8_t>(v));
    }

    void put_u64(std::uint64_t v) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            buf_.push_back(
                static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
        }
    }

    void put_bytes(std::span<const std::uint8_t> bytes) {
        buf_.insert(buf_.end(), bytes.begin(), bytes.end());
    }

    // Appends the first 4 (IPv4) or 16 (IPv6) bytes of an IpAddress.
    void put_ipv4(const IpAddress& addr) {
        put_bytes(std::span<const std::uint8_t>(addr.bytes.data(), 4));
    }
    void put_ipv6(const IpAddress& addr) {
        put_bytes(std::span<const std::uint8_t>(addr.bytes.data(), 16));
    }

    std::size_t size() const noexcept { return buf_.size(); }

    // Overwrites 2 or 4 bytes previously written at `offset`, big-endian.
    // Used for length/count fields whose final value is only known after
    // the rest of the record has been serialized (e.g. a FlowSet length).
    // `offset` is bounds-checked, turning a would-be out-of-bounds write
    // into an exception rather than silent buffer corruption.
    void patch_u16(std::size_t offset, std::uint16_t v) {
        if (offset + 2 > buf_.size()) {
            throw std::out_of_range("ByteWriter::patch_u16: offset out of range");
        }
        buf_[offset] = static_cast<std::uint8_t>(v >> 8);
        buf_[offset + 1] = static_cast<std::uint8_t>(v);
    }
    void patch_u32(std::size_t offset, std::uint32_t v) {
        if (offset + 4 > buf_.size()) {
            throw std::out_of_range("ByteWriter::patch_u32: offset out of range");
        }
        buf_[offset] = static_cast<std::uint8_t>(v >> 24);
        buf_[offset + 1] = static_cast<std::uint8_t>(v >> 16);
        buf_[offset + 2] = static_cast<std::uint8_t>(v >> 8);
        buf_[offset + 3] = static_cast<std::uint8_t>(v);
    }

    const std::vector<std::uint8_t>& bytes() const noexcept { return buf_; }
    std::vector<std::uint8_t> take() { return std::move(buf_); }

private:
    std::vector<std::uint8_t> buf_;
};

} // namespace softflow

// Original: sys-tree.h's RB_GENERATE macro generated the FLOW/EXPIRY
// comparison functions (fl_compare/expiry_compare) with hand-rolled pointer
// arithmetic. All that's needed here for the hash-based backend is a
// std::hash<FlowKey> specialization; there is no hand-written comparator or
// tree-rotation logic to maintain at all.
template <>
struct std::hash<softflow::FlowKey> {
    std::size_t operator()(const softflow::FlowKey& k) const noexcept {
        std::size_t h = std::hash<std::uint8_t>{}(k.protocol());
        auto mix = [&h](std::size_t v) {
            h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        };
        for (const auto& a : k.addr()) {
            for (auto b : a.bytes) {
                mix(std::hash<std::uint8_t>{}(b));
            }
        }
        for (auto p : k.port()) {
            mix(std::hash<std::uint16_t>{}(p));
        }
        for (auto v : k.vlanid()) {
            mix(std::hash<std::uint16_t>{}(v));
        }
        mix(std::hash<std::uint8_t>{}(k.tos()));
        return h;
    }
};

namespace softflow {

// ---------------------------------------------------------------------
// FlowTable (original: struct FLOWTRACK + freelist.c + treetype.h +
//            sys-tree.h)
// ---------------------------------------------------------------------
//
// The original implementation combined three pieces of manual memory
// management:
//   1. freelist.c: a hand-rolled malloc/free wrapper (a separate free list
//      for flows and one for expiry events)
//   2. sys-tree.h: an intrusive red-black tree via the RB_HEAD/RB_ENTRY
//      macros (the FLOW struct itself doubled as a tree node, via
//      `FLOW_ENTRY(FLOW) trp;`)
//   3. Mutual raw pointers between FLOW and EXPIRY
//
// This design allowed for the classic bug patterns the article warns about:
//   - freeing a flow but forgetting to remove it from the expiry tree,
//     leaving a pointer to freed memory (dangling pointer / use-after-free)
//   - forgetting to return memory to the free list, or returning it twice
//     (double free)
//   - calling RB_INSERT/RB_REMOVE in the wrong order (corrupting the tree)
//
// In the modern C++ version, ownership of every flow lives in exactly one
// place: the associative container inside FlowTable. No free list is
// needed -- insertion/removal is the container's job, and a double free is
// structurally impossible. Expiry bookkeeping never touches a raw pointer;
// it maps "time -> FlowKey", and looking up an expired flow is just a
// lookup by key -- if that lookup somehow fails, find() returns "not
// found" instead of crashing.
//
// New in this revision: which associative container backs the primary flow
// index is a template parameter, so the same code that used to hard-code a
// red-black tree (sys-tree.h) in the original C project can now be selected
// explicitly:
//   - FlowIndexBackend::Hash -> std::unordered_map (average O(1) lookup)
//   - FlowIndexBackend::Tree -> std::map (a genuine red-black tree in
//     libstdc++/libc++, giving ordered iteration -- the closest modern
//     equivalent of the original's RB_HEAD/RB_ENTRY-based flow tree)
// FlowTable<Backend> selects the backend at compile time (zero overhead,
// the classic C++ template approach). FlowTableRuntime, defined further
// below, wraps both instantiations in a std::variant so the choice can also
// be made at run time (e.g. from a command-line flag).
enum class FlowIndexBackend {
    Hash, // std::unordered_map<FlowKey, Flow> -- closest to a hash table
    Tree, // std::map<FlowKey, Flow>           -- a genuine red-black tree
};

// Original: struct FLOWTRACKPARAMETERS' timeout fields. Plain `int` (in
// seconds) is replaced with std::chrono::seconds so that passing a value in
// the wrong unit (e.g. milliseconds by mistake) becomes a compile error
// rather than a runtime bug.
struct FlowTimeouts {
    std::chrono::seconds tcp{3600};
    std::chrono::seconds tcp_rst{120};
    std::chrono::seconds tcp_fin{300};
    std::chrono::seconds udp{300};
    std::chrono::seconds icmp{300};
    std::chrono::seconds general{3600};
    std::chrono::seconds maximum_lifetime{3600 * 24 * 7};
};

// Original: struct FLOWTRACKPARAMETERS' statistics fields. The original had
// a dozen-plus flat u_int64_t counters; only the subset needed so far is
// kept here (NetFlow export statistics will be added in a later stage).
struct FlowTableStats {
    std::uint64_t total_packets{0};
    std::uint64_t bad_packets{0};
    std::uint64_t flows_expired{0};
    std::uint64_t flows_force_expired{0};
};

// Original: struct FLOWTRACK as a whole, plus the functionality of
// freelist.c / sys-tree.h.
//
// Member function bodies are defined out-of-line in softflowd.cpp and
// explicitly instantiated for both FlowIndexBackend values (see the
// `extern template` declarations below), mirroring the original's
// declaration-in-.h / definition-in-.c split even though this is a
// template.
template <FlowIndexBackend Backend>
class FlowTable {
public:
    // Original: RB_HEAD(FLOWS, FLOW) flows; (an intrusive red-black tree
    // keyed by the FLOW struct itself), or with FlowIndexBackend::Hash, the
    // modern equivalent of a from-scratch hash table.
    using FlowMap =
        std::conditional_t<Backend == FlowIndexBackend::Hash,
                            std::unordered_map<FlowKey, Flow>,
                            std::map<FlowKey, Flow>>;

    explicit FlowTable(std::size_t max_flows,
                        TrackLevel track_level = TrackLevel::IpProtoPort,
                        FlowTimeouts timeouts = {});

    // Copying is deleted rather than left to the implicitly-generated
    // (and subtly wrong) default: expiry_lookup_ holds std::multimap
    // iterators that point into this object's own expiry_index_. A
    // member-wise *copy* would copy those iterator values verbatim, so the
    // copy's expiry_lookup_ would end up pointing into the *original's*
    // expiry_index_ rather than its own -- silently corrupting the
    // invariant the moment either object is destroyed or modified. Moving
    // does not have this problem: per the standard, moving a container
    // preserves the validity of iterators into it, so a moved-from
    // FlowTable's expiry_lookup_ iterators remain correctly associated with
    // the moved-to object's expiry_index_.
    FlowTable(const FlowTable&) = delete;
    FlowTable& operator=(const FlowTable&) = delete;
    FlowTable(FlowTable&&) noexcept = default;
    FlowTable& operator=(FlowTable&&) noexcept = default;
    ~FlowTable() = default;

    // Original: the "look up the flow, update it if found, otherwise
    // allocate + RB_INSERT" sequence that softflowd.c performed for every
    // packet in process_packet(). Here, unordered_map/map::try_emplace does
    // "construct if absent, otherwise return the existing entry" in a
    // single lookup.
    //
    // Returns: a reference to the updated Flow. The reference is valid only
    // while this FlowTable is alive and the flow has not yet been expired
    // (by design, this reference is meant to be used immediately by the
    // caller rather than stored, so no raw pointer needs to be handed out).
    Flow& record_packet(const FlowKey& key, TimePoint now,
                         std::uint8_t direction, std::uint64_t octet_delta,
                         bool is_tcp_syn, bool is_tcp_fin_or_rst);

    // Original: softflowd.c's check_expired(), which walked the EXPIRIES
    // tree from its smallest element removing anything past its expiry
    // time. Here that becomes iterating the ordered expiry index from the
    // beginning. Expired flows are returned as ExportRecord values (each a
    // copy of its key and its accumulated Flow), so the caller's copies are
    // independent of FlowTable's internal lifetime -- no risk of a
    // dangling reference even after the FlowTable is destroyed.
    std::vector<ExportRecord> expire_flows(TimePoint now);

    // Explicit forced eviction (original: softflowd.c's handling of
    // exceeding the configured maximum flow count with -m). Evicts the
    // flows with the nearest expiry first (i.e. the least recently active).
    std::vector<ExportRecord> force_expire_oldest(std::size_t count);

    // Original: softflowctl(8)'s dump-flows command. Returns a copy of
    // every currently tracked flow *without* removing or expiring any of
    // them (unlike expire_flows()/force_expire_oldest()) -- purely a
    // read-only snapshot for diagnostic reporting.
    std::vector<ExportRecord> snapshot() const;

    std::size_t size() const noexcept { return flows_.size(); }
    std::size_t max_flows() const noexcept { return max_flows_; }
    const FlowTableStats& stats() const noexcept { return stats_; }
    TrackLevel track_level() const noexcept { return track_level_; }
    const FlowTimeouts& timeouts() const noexcept { return timeouts_; }
    static constexpr FlowIndexBackend backend() noexcept { return Backend; }

private:
    TimePoint compute_expiry(const Flow& flow, bool is_tcp_syn,
                              bool is_tcp_fin_or_rst) const;
    void reschedule_expiry(const FlowKey& key, TimePoint new_expiry);

    std::size_t max_flows_;
    TrackLevel track_level_;
    FlowTimeouts timeouts_;
    FlowTableStats stats_;

    FlowMap flows_;

    // Original: RB_HEAD(EXPIRIES, EXPIRY) expiries; (an intrusive red-black
    // tree whose EXPIRY nodes pointed back to a FLOW via a raw pointer).
    // Here it's a "expiry time -> flow key" map -- the expiry index never
    // holds the flow itself or a pointer to it. Kept as std::multimap
    // (i.e. always tree-backed) regardless of the primary FlowMap backend,
    // because ordered iteration by time is fundamental to expiry
    // processing either way.
    std::multimap<TimePoint, FlowKey> expiry_index_;

    // Auxiliary index used to look up a flow's current position in
    // expiry_index_ by FlowKey, so that rescheduling (extending a timeout
    // when new traffic arrives) can be done in O(log n) instead of a linear
    // scan. This holds std::multimap iterators, not raw pointers; inserting
    // or erasing *other* elements of a std::map/std::multimap never
    // invalidates the iterators to elements that remain (a guarantee of the
    // standard library's map family), so holding on to them here is safe.
    std::unordered_map<FlowKey, std::multimap<TimePoint, FlowKey>::iterator>
        expiry_lookup_;
};

// Explicit instantiation declarations: tells any translation unit that
// includes this header not to implicitly instantiate FlowTable<Hash> /
// FlowTable<Tree> itself, but to expect the definitions from softflowd.cpp
// at link time. This keeps the (fairly large) template body out of every
// including file's compiled output, exactly as if FlowTable were a plain
// non-template class declared in a .h and defined once in a .c file.
extern template class FlowTable<FlowIndexBackend::Hash>;
extern template class FlowTable<FlowIndexBackend::Tree>;

// A non-template wrapper that allows the backend to be chosen at run time
// (e.g. from a command-line flag) rather than fixed at compile time. This
// directly answers "should flow tracking use a tree or a hash table" as a
// runtime decision, the same way the original build could be configured
// with -DFLOW_RB or an equivalent choice at build time -- except here it's
// a single binary that can do either.
//
// Internally this simply holds a std::variant of the two FlowTable
// instantiations and forwards every call through std::visit. There is no
// dynamic dispatch / vtable overhead beyond what std::variant already adds
// (a single tag check per call), and no raw pointers or manual ownership
// are introduced by this wrapper.
class FlowTableRuntime {
public:
    FlowTableRuntime(FlowIndexBackend backend, std::size_t max_flows,
                      TrackLevel track_level = TrackLevel::IpProtoPort,
                      FlowTimeouts timeouts = {});

    Flow& record_packet(const FlowKey& key, TimePoint now,
                         std::uint8_t direction, std::uint64_t octet_delta,
                         bool is_tcp_syn, bool is_tcp_fin_or_rst);
    std::vector<ExportRecord> expire_flows(TimePoint now);
    std::vector<ExportRecord> force_expire_oldest(std::size_t count);
    std::vector<ExportRecord> snapshot() const;

    const FlowTimeouts& timeouts() const noexcept;

    std::size_t size() const noexcept;
    std::size_t max_flows() const noexcept;
    const FlowTableStats& stats() const noexcept;
    TrackLevel track_level() const noexcept;
    FlowIndexBackend backend() const noexcept;

private:
    std::variant<FlowTable<FlowIndexBackend::Hash>,
                 FlowTable<FlowIndexBackend::Tree>>
        table_;
};

// ---------------------------------------------------------------------
// PacketParser (original: softflowd.c's ipv4_to_flowrec() /
//               ipv6_to_flowrec() / transport_to_flowrec())
// ---------------------------------------------------------------------
//
// The original code cast raw byte buffers directly onto <netinet/ip.h>'s
// struct ip / struct ip6_hdr / struct tcphdr etc. (a form of type punning
// that is a strict-aliasing violation -- technically undefined behavior
// that merely "happens to work" on most platforms/compilers). No casts are
// used here; every field is read a byte at a time out of a std::span via
// the read_be16/read_be32 helpers defined in softflowd.cpp. Because those
// helpers always read explicitly as big-endian, byte-order bugs from a
// missing ntohs/ntohl are structurally impossible.
//
// The original's ipv6_to_flowrec() also contained a real bug worth noting:
//   eh6 = (const struct ip6_ext *) pkt + size;
// Due to cast binding tighter than +, this advances the pointer by `size *
// sizeof(struct ip6_ext)` bytes, not `size` bytes as intended -- a classic
// "pointer arithmetic unit mismatch after a cast" bug that's easy to write
// in C and easy to miss in review. Using std::span::subspan(), which is
// unambiguously byte-oriented by its type signature, makes this entire bug
// class impossible to reintroduce by accident.
struct ParsedPacket {
    IpAddress src{};
    IpAddress dst{};
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    std::uint8_t protocol{0};
    std::uint8_t tos{0};
    std::uint8_t tcp_flags{0};
    std::uint32_t ip6_flowlabel{0};
    bool is_fragment{false};
    bool is_first_fragment{true};
};

// Original: process_packet()'s PP_BAD_PACKET / PP_MALLOC_FAIL integer
// return codes. A caller that forgets to check them gets no help from the
// compiler. std::optional<ParsedPacket> encodes "may not have a value" in
// the type itself. (It's still possible to call .value() unconditionally,
// so this isn't a hard guarantee -- but the return type alone now signals
// that failure is possible, which the original's plain `int` did not.)
class PacketParser {
public:
    explicit PacketParser(TrackLevel track_level) : track_level_(track_level) {}

    // Original: ipv4_to_flowrec() / ipv6_to_flowrec()
    // ip_payload is the IP packet with the data-link layer header already
    // stripped off.
    std::optional<ParsedPacket> parse(std::span<const std::uint8_t> ip_payload,
                                       AddressFamily af) const;

    TrackLevel track_level() const noexcept { return track_level_; }

private:
    std::optional<ParsedPacket>
    parse_ipv4(std::span<const std::uint8_t> data) const;
    std::optional<ParsedPacket>
    parse_ipv6(std::span<const std::uint8_t> data) const;

    // Original: transport_to_flowrec()
    void parse_transport(ParsedPacket& packet,
                          std::span<const std::uint8_t> transport_payload,
                          std::uint8_t protocol) const;

    TrackLevel track_level_;
};

// Original: the "decide addr[ndx] vs addr[ndx^1] ordering" step that
// preceded FlowKey construction (a memcmp inside ipv4_to_flowrec) is now
// just a call into FlowKey::make_canonical from a ParsedPacket.
FlowKey make_flow_key(const ParsedPacket& packet, TrackLevel track_level,
                      std::array<std::uint16_t, 2> vlanid = {0, 0});

// ---------------------------------------------------------------------
// PcapHandle (original: softflowd.c's main(), where pcap_t* was managed
//             by hand across several possible exit paths)
// ---------------------------------------------------------------------
//
// The original declared `pcap_t *pcap;` in main() and reused it across
// several exit paths (an error exit(1), a signal-driven shutdown, etc.),
// risking a forgotten pcap_close() on at least one path.
//
// Here, ownership of the pcap_t is expressed with std::unique_ptr and a
// custom deleter. Regardless of which function returns, or whether an
// exception propagates, the destructor is guaranteed to call pcap_close()
// exactly once when the handle goes out of scope -- eliminating the whole
// class of "forgot to close it" bugs. This is the most basic application of
// RAII, and mirrors the article's SocketHandle example.
class PcapError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Original: softflowd.c's DATALINK table (`static const struct DATALINK
// lt[]`). For each known link-layer type, it hand-maintained the number of
// bytes to skip to reach the IP header (skiplen) and how to determine the
// EtherType. Ethernet / Linux SLL / RAW / NULL-LOOP are supported here
// (PPP/PFLOG from the original can be added in a later stage).
enum class DatalinkKind {
    Ethernet,
    LinuxSll,
    Raw,
    NullLoop,
    Unsupported,
};

DatalinkKind classify_datalink(int pcap_dlt);
std::size_t datalink_header_len(DatalinkKind kind);

// Original: the result of pcap_next_ex(), i.e. the pair of
// `const u_char *frame` + `struct pcap_pkthdr *phdr`. The constraint that
// the span is valid only until the next call to next_packet() comes from
// libpcap's zero-copy design and can't be fully hidden, but combining
// "pointer" and "another, separate length variable" into a single type
// still prevents the class of bug where the length gets mismatched against
// the wrong pointer.
struct CapturedPacket {
    std::span<const std::uint8_t> data; // the bytes actually captured
    std::uint32_t original_length;      // on-the-wire length before any truncation (phdr->len)
    TimePoint timestamp;                // this process's monotonic clock at the moment of capture
    std::chrono::system_clock::time_point wall_timestamp; // libpcap's own recorded timestamp (phdr->ts)
};

class PcapHandle {
public:
    // Original: softflowd.c called pcap_open_live() directly, which offers
    // no control over the capture buffer size or "immediate mode" (how
    // promptly a captured packet is handed to the application versus
    // waiting for internal buffering/timeout). This project instead uses
    // the pcap_create()/pcap_activate() sequence, which allows setting
    // both -- buffer_bytes maps to the original's -B option, and
    // immediate mode (always enabled here) meaningfully improves how
    // quickly a live-captured packet becomes visible to next_packet(),
    // which in turn keeps the control-socket/signal-handling side of the
    // daemon's event loop responsive under load (see run_live_capture()
    // in softflowd.cpp).
    static PcapHandle open_live(const std::string& device, int snaplen,
                                 bool promiscuous,
                                 std::chrono::milliseconds read_timeout,
                                 std::size_t buffer_bytes = 0);
    static PcapHandle open_offline(const std::string& path);

    PcapHandle(const PcapHandle&) = delete;
    PcapHandle& operator=(const PcapHandle&) = delete;
    PcapHandle(PcapHandle&&) noexcept = default;
    PcapHandle& operator=(PcapHandle&&) noexcept = default;
    ~PcapHandle() = default; // the unique_ptr's deleter calls pcap_close()

    int datalink() const noexcept { return pcap_datalink(handle_.get()); }
    DatalinkKind datalink_kind() const { return classify_datalink(datalink()); }

    // Original: softflowd.c's main loop polled/selected on pcap's file
    // descriptor (via pcap_get_selectable_fd()) alongside its control
    // socket so it could react promptly to both packets and control
    // commands without a busy-wait. Exposed here so a live daemon loop can
    // add this fd to the same poll() set as the control socket and signal
    // pipe. Returns -1 if the platform/capture mode doesn't support a
    // selectable descriptor (notably, this is generally not meaningful
    // for offline pcap files, only live captures).
    int selectable_fd() const noexcept {
        return pcap_get_selectable_fd(handle_.get());
    }

    // Original: softflowd.c's pcap_compile()/pcap_setfilter() calls. The
    // original only passed pcap_geterr()'s string to logit() on a compile
    // failure, which the caller had no way to observe. Here it's an
    // exception, so it cannot be silently ignored.
    void set_filter(const std::string& bpf_expression);

    // Original: a thin wrapper over pcap_next_ex().
    // Returns: a CapturedPacket if one was available; std::nullopt on a
    // read timeout (live capture) or EOF (offline file).
    std::optional<CapturedPacket> next_packet();

private:
    explicit PcapHandle(pcap_t* handle) : handle_(handle) {}

    struct PcapCloser {
        void operator()(pcap_t* p) const noexcept {
            if (p != nullptr) {
                pcap_close(p);
            }
        }
    };
    std::unique_ptr<pcap_t, PcapCloser> handle_;
};

// ---------------------------------------------------------------------
// ExportDestination / ExportDestinationSet (original: softflowd.c's -n
// destination handling and send_multi_destinations())
// ---------------------------------------------------------------------
//
// Original: softflowd.c resolved each -n host:port with getaddrinfo(),
// opened a UDP socket per destination, and sent each export packet with
// sendto(). The socket file descriptors lived for the daemon's entire
// runtime as plain ints in a global-ish destinations array; nothing
// enforced that every one of them got closed on every exit path.
//
// ExportDestination wraps one such socket in RAII (closed by the
// destructor, matching PcapHandle and PidFile elsewhere in this project).
// The socket is connect()-ed to its destination up front, which both
// simplifies sending (plain send() instead of sendto() + a sockaddr each
// time) and lets the kernel report certain errors (e.g. ICMP port
// unreachable for a UDP send to a closed collector port) back to this
// process instead of silently discarding them.
class ExportError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Original: -P transport_protocol. udp and tcp are both fully implemented
// here; sctp is attempted using IPPROTO_SCTP if the platform's headers
// declare it (Linux with the kernel SCTP module loaded typically does),
// and otherwise ExportDestination's constructor throws ExportError, which
// main() reports as a fallback-to-udp warning rather than a hard failure
// -- see softflowd.cpp.
enum class TransportKind {
    Udp,
    Tcp,
    Sctp,
};

class ExportDestination {
public:
    // host/port are resolved via getaddrinfo(), so host may be a hostname
    // or a numeric IPv4/IPv6 address, and port may be a numeric port or a
    // services(5) name. ttl, if set, configures the original's -L
    // (IPv4 TTL / IPv6 hop limit). source_address and send_interface
    // correspond to the original's -e and -S respectively.
    //
    // Original: with tcp or sctp, the original opened one long-lived
    // connection per destination and streamed export packets over it
    // back-to-back with no additional framing -- the same approach taken
    // here, since every one of this project's export formats already
    // carries its own self-describing length in its header (a NetFlow v9/
    // IPFIX collector reading a TCP stream reads that header, learns the
    // message's length, reads that many bytes, and repeats).
    ExportDestination(const std::string& host, const std::string& port,
                       TransportKind transport = TransportKind::Udp,
                       std::optional<int> ttl = std::nullopt,
                       const std::string& source_address = "",
                       const std::string& send_interface = "");
    ~ExportDestination();

    ExportDestination(const ExportDestination&) = delete;
    ExportDestination& operator=(const ExportDestination&) = delete;
    ExportDestination(ExportDestination&&) noexcept;
    ExportDestination& operator=(ExportDestination&&) noexcept;

    // Sends one already-serialized export packet (e.g. from
    // Netflow5Exporter::build_packets()) to this destination. For
    // stream-oriented transports (tcp, sctp), this loops until every byte
    // is written, since a single send()/write() call over a stream socket
    // is not guaranteed to consume the whole buffer at once the way a UDP
    // datagram send is.
    void send_packet(const std::vector<std::uint8_t>& packet) const;

    const std::string& description() const noexcept { return description_; }

private:
    int fd_{-1};
    bool stream_oriented_{false};
    std::string description_;
};

// Original: softflowd.c's -n (comma-separated multiple destinations) and
// -l (load-balance across them, sending each successive export packet to
// the next destination in round-robin order, instead of the default of
// sending every packet to every destination).
class ExportDestinationSet {
public:
    void add(ExportDestination destination);

    bool empty() const noexcept { return destinations_.empty(); }
    std::size_t size() const noexcept { return destinations_.size(); }

    // Sends `packet` according to `load_balance`: to every configured
    // destination if false (the original's default), or to just the next
    // destination in round-robin order if true (the original's -l).
    void send_packet(const std::vector<std::uint8_t>& packet, bool load_balance);

private:
    std::vector<ExportDestination> destinations_;
    std::size_t next_index_{0};
};

} // namespace softflow

#endif // SOFTFLOWD_HPP
