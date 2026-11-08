/**
 * @file softflowd.hpp
 * @brief The types that the parts of softflowd+ share: the clock, the addresses, the flow key, the flow, the export record and the byte writer.
 *
 * The flow table is in flow.hpp, the packet parser, the link-layer types and the
 * captured packet are in packet.hpp, the libpcap handle is in capture.hpp, and
 * the export destinations are in netsock.hpp. They follow the files of the C
 * version, where softflowd.h keeps the structures that the other files share.
 * The types here apply the memory-safety practices described in the
 * accompanying article
 * (https://mecanik.dev/ja/posts/c++-vs-rust-memory-safety-practical-examples-with-modern-c++/).
 *
 * @original softflowd.h (struct FLOW and EXPIRY) and common.h.
 */
#ifndef SOFTFLOWD_HPP
#define SOFTFLOWD_HPP

#include <array>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace softflowd_cpp {

// ---------------------------------------------------------------------
// Common types (original: common.h, and the top of softflowd.h)
// ---------------------------------------------------------------------

/**
 * @brief The monotonic clock on which the times of the flows are recorded.
 */
using Clock = std::chrono::steady_clock;
/**
 * @brief A point in time on Clock.
 */
using TimePoint = Clock::time_point;
/**
 * @brief A span of time on Clock.
 */
using Duration = Clock::duration;

/**
 * @brief The address family of a flow: IPv4 or IPv6.
 *
 * @original struct FLOW used a raw int / u_int8_t for protocol, tcp_flags,
 * etc. enum class gives these fields compile-time type safety.
 */
enum class AddressFamily : std::uint8_t {
  IPv4,  ///< An IPv4 address (4 octets).
  IPv6,  ///< An IPv6 address (16 octets).
};

/**
 * @brief How much of a packet identifies a flow, selected with -T.
 *
 * The levels are ordered: a higher level tells more packets apart (the code
 * compares them with >=). The flow table, the exporters and the packet parser
 * use the level to decide which fields belong to a flow and are exported.
 *
 * @original TRACK_IP_ONLY .. TRACK_FULL_VLAN_ETHER (softflowd.h), and -T
 * track_level, exactly five levels named "ip", "proto", "full" (the default),
 * "vlan", and "ether". An earlier revision of this project had a spurious
 * sixth level between IpProtoPort and FullVlan (used only to gate ToS
 * capture); that distinction doesn't exist in the original and has been
 * removed so -T's five values map onto this enum one-to-one. The level "port"
 * (the original's TRACK_IP_PROTO_PORT) and "full-tos" are additions of this
 * project, as the enumerators describe.
 */
enum class TrackLevel : std::uint8_t {
  IpOnly,   ///< "ip": source/destination address only.
  IpProto,  ///< "proto": the addresses and the protocol.
  /** "port": the addresses, the protocol and the source/destination port,
   *  and no ToS in the flow (the original's TRACK_IP_PROTO_PORT). */
  Port,
  /** "full": the addresses, the protocol and the source/destination port (the
   *  default). ToS is deliberately *not* part of flow identity at this level,
   *  matching the reference implementation's actual flow_compare() behavior
   *  (see FlowKey's own comment) -- despite softflowd.h describing "full" as
   *  a 6-tuple that includes ToS, the real comparison function never touches
   *  it. */
  IpProtoPort,
  /** "full-tos": adds ToS. Opt-in: makes ToS part of flow identity too,
   *  matching what softflowd.h *documents* (but the reference C implementation
   *  doesn't actually do). Two packets identical except for ToS become
   *  separate flows at this level. */
  FullTos,
  FullVlan,       ///< "vlan": adds the VLAN ID.
  FullVlanEther,  ///< "ether": adds the source/destination Ethernet address.
};

/**
 * @brief An IPv4 or IPv6 address, with its family.
 *
 * @original
 *   union { struct in_addr v4; struct in6_addr v6; } addr[2];
 * A union plus a separate "which member is active" flag requires the
 * programmer to remember which member is valid; accessing the wrong one
 * (type punning) is undetected undefined behavior. Here a single fixed-size
 * array is used, and AddressFamily only changes how many of the bytes are
 * meaningful. (std::variant would be even safer, but this packet-processing
 * hot path favors a representation with low copy/branch overhead.)
 */
struct IpAddress {
  AddressFamily family{AddressFamily::IPv4};  ///< The family, which decides how many of #bytes are meaningful.
  std::array<std::uint8_t, 16> bytes{};       ///< The address in network byte order; only the first 4 bytes are used for IPv4.

  /**
     * @brief Compares two addresses, by family and then by bytes.
     *
     * A defaulted three-way comparison gives us both operator== (needed for
     * the hash-based backend) and a strict total order (needed for the
     * tree-based backend) for free, with no hand-written comparator that
     * could get out of sync between the two.
     *
     * @return The three-way ordering.
     */
  friend auto
  operator<=> (const IpAddress &, const IpAddress &) = default;
  /**
     * @brief Compares two addresses for equality.
     *
     * @return true when the family and the bytes are equal.
     */
  friend bool
  operator== (const IpAddress &, const IpAddress &) = default;
};

/**
 * @brief The MPLS label stack of a packet, one element per label.
 *
 * @original struct FLOW's mplsLabelStackDepth + mplsLabels[10] -- a fixed
 * buffer with its length tracked in a *separate* variable. Any place that
 * forgets to keep the two in sync is a buffer overrun / uninitialized read
 * waiting to happen (this is exactly the pattern in the article's second
 * example). std::vector ties the length to the data itself.
 * Each element is the top 3 octets of one MPLS shim header --
 * label(20 bits) | EXP(3 bits) | S(1 bit), i.e. bits 31-8 of the 4-byte
 * shim, TTL octet dropped -- stored verbatim rather than decomposed, so
 * it can be passed straight through to the IPFIX
 * mplsTopLabelStackSectionN field unchanged. See
 * packet.cpp's MplsShimEntry and export.cpp's write_mpls_labels().
 */
using MplsLabelStack = std::vector<std::uint32_t>;

// ---------------------------------------------------------------------
// FlowKey / Flow (original: struct FLOW in softflowd.h)
// ---------------------------------------------------------------------

/**
 * @brief The key that identifies a flow: its two endpoints in canonical order, the protocol and, depending on the track level, ToS, the VLAN IDs and the Ethernet addresses.
 *
 * @original struct FLOW mixed two responsibilities in one struct:
 *   (a) the fields used as a lookup key (addr/port/protocol/tos/vlanid...)
 *   (b) the fields updated as a result of a lookup (octets/packets/flow_seq)
 * It also carried an `EXPIRY *expiry` raw pointer to a matching EXPIRY
 * struct, and EXPIRY carried a `FLOW *flow` raw pointer back. This mutual
 * raw-pointer relationship is exactly the dangling-pointer / use-after-free
 * pattern called out in the article: freeing one side without updating the
 * other leaves a dangling pointer on the other side.
 *
 * Here the lookup key (FlowKey) and the value (Flow) are separate types, and
 * any association between a flow and its expiry bookkeeping is made through
 * a FlowTable-owned container key -- never a raw pointer -- so ownership
 * always lives in exactly one place.
 */
class FlowKey {
public:
  /**
   * @brief Makes the key of a flow from the two ends of a packet, in canonical order.
   *
   * @param addr_a The address of the first end.
   * @param addr_b The address of the second end.
   * @param port_a The port of the first end.
   * @param port_b The port of the second end.
   * @param protocol The IP protocol number.
   * @param tos The type of service; 0 unless the track level asks for it.
   * @param vlanid The VLAN IDs of the two ends, in the order of @p addr_a and @p addr_b.
   * @param ethermac The Ethernet addresses of the two ends, in the order of @p addr_a and @p addr_b.
   * @return The key; the numerically smaller address (then port) is in slot 0, and the VLAN IDs and Ethernet addresses are swapped with it.
   *
   * @original just before inserting/looking up a flow, softflowd.c had a
   * comment explaining that "the numerically smaller address/port goes in
   * slot [0]" and normalized the fields by hand at every call site -- a
   * convention enforced only by a comment, not by the type system. Here,
   * make_canonical() is the *only* way to construct a FlowKey, so an
   * unnormalized FlowKey cannot exist. The implementation is a small pure
   * function that fits comfortably in the header, just as softflowd.h
   * itself had no corresponding .c file.
   */
  static FlowKey
  make_canonical (IpAddress addr_a, IpAddress addr_b,
                  std::uint16_t port_a, std::uint16_t port_b,
                  std::uint8_t protocol, std::uint8_t tos,
                  std::array<std::uint16_t, 2> vlanid,
                  std::array<std::array<std::uint8_t, 6>, 2>
                    ethermac = {}) {
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
      key.ethermac_ = ethermac;
    } else {
      key.addr_ = {addr_b, addr_a};
      key.port_ = {port_b, port_a};
      key.vlanid_ = {vlanid[1], vlanid[0]};
      key.ethermac_ = {ethermac[1], ethermac[0]};
    }
    key.protocol_ = protocol;
    key.tos_ = tos;
    return key;
  }

  /**
     * @brief The addresses of the two ends.
     *
     * @return The addresses, in canonical order.
     */
  const std::array<IpAddress, 2> &
  addr () const noexcept {
    return addr_;
  }
  /**
     * @brief The ports of the two ends.
     *
     * @return The ports, in canonical order.
     */
  const std::array<std::uint16_t, 2> &
  port () const noexcept {
    return port_;
  }
  /**
     * @brief The IP protocol number.
     *
     * @return The protocol.
     */
  std::uint8_t
  protocol () const noexcept {
    return protocol_;
  }
  /**
     * @brief The type of service.
     *
     * @return The ToS; 0 unless the track level asks for it.
     */
  std::uint8_t
  tos () const noexcept {
    return tos_;
  }
  /**
     * @brief The VLAN IDs of the two ends.
     *
     * @return The VLAN IDs, in canonical order.
     */
  const std::array<std::uint16_t, 2> &
  vlanid () const noexcept {
    return vlanid_;
  }
  /**
     * @brief The Ethernet addresses of the two ends.
     *
     * @return The addresses, in canonical order.
     */
  const std::array<std::array<std::uint8_t, 6>, 2> &
  ethermac () const noexcept {
    return ethermac_;
  }

  /**
     * @brief Orders two keys; with operator== it serves both backends of the flow table.
     *
     * Defaulted \<=\> gives both operator== (used by the hash-based backend)
     * and a strict total order (used by the tree-based backend, in place of
     * the original's RB_GENERATE-produced comparison function). One
     * declaration serves both FlowTable backends described below.
     *
     * Original: softflowd.c's flow_compare() -- compares af/addr/protocol/
     * port(/vlanid/ethermac when tracked) only; ToS is *not* part of flow
     * identity there by default (see TrackLevel::IpProtoPort's comment).
     * tos_ is always a member of FlowKey (so it participates in this
     * defaulted comparison uniformly), but callers below only pass a real
     * ToS value in when TrackLevel::FullTos or above is selected --
     * otherwise they always pass 0, which makes tos_ a constant that never
     * differentiates any flow, functionally identical to excluding it.
     *
     * @return The three-way ordering.
     */
  friend auto
  operator<=> (const FlowKey &, const FlowKey &) = default;
  /**
     * @brief Compares two keys for equality.
     *
     * @return true when all the fields are equal.
     */
  friend bool
  operator== (const FlowKey &, const FlowKey &) = default;

private:
  /**
     * @brief Creates an empty key; make_canonical() is the only way to make a usable one.
     */
  FlowKey () = default;

  std::array<IpAddress, 2> addr_{};                        ///< The addresses of the two ends.
  std::array<std::uint16_t, 2> port_{};                    ///< The ports of the two ends.
  std::array<std::uint16_t, 2> vlanid_{};                  ///< The VLAN IDs of the two ends.
  std::array<std::array<std::uint8_t, 6>, 2> ethermac_{};  ///< The Ethernet addresses of the two ends.
  std::uint8_t protocol_{0};                               ///< The IP protocol number.
  std::uint8_t tos_{0};                                    ///< The type of service.
};

/**
 * @brief Why a flow was removed from the table, for the statistics.
 *
 * @original struct FLOW's statistics fields. The `[2]` raw C arrays for
 * tcp_flags/octets/packets become std::array; mplsLabels[10] +
 * mplsLabelStackDepth becomes MplsLabelStack (a vector); ethermac[2][6]
 * becomes std::array\<std::array\<uint8_t,6\>,2\>. In every case, an
 * out-of-bounds index becomes an immediately detectable exception/assertion
 * (std::array::at(), or a debug-build-checked operator[]) instead of silent
 * memory corruption.
 * Original: softflowd.h's R_GENERAL .. R_FLUSH expiry-reason enum, used to
 * classify why a flow was removed from the table for statistics purposes.
 */
enum class ExpiryReason : std::uint8_t {
  General,    ///< Expired by the general timeout.
  Tcp,        ///< Expired by the TCP timeout.
  TcpRst,     ///< Expired by the timeout after a TCP RST.
  TcpFin,     ///< Expired by the timeout after a TCP FIN.
  Udp,        ///< Expired by the UDP timeout.
  Icmp,       ///< Expired by the ICMP timeout.
  MaxLife,    ///< Lived as long as the maximum lifetime.
  OverBytes,  ///< Counted over 2 GiB and exported at once.
  OverFlows,  ///< Evicted because there were more flows than -m allows.
  Flush,      ///< Flushed on shutdown or by expire-all.
  Collision   ///< Evicted by a flow that hashed to the same slot (-F hash).
};

/**
 * @brief The state of a flow that changes while packets arrive: the counters, the times and the flags of both directions.
 *
 * Index 0 and 1 of the arrays are the two ends of the key, in canonical order.
 */
struct Flow {
  std::uint64_t flow_seq{0};  ///< The sequence number of the flow: how many flows were created before it, plus one.
  TimePoint flow_start{};     ///< The time of the first packet.
  TimePoint flow_last{};      ///< The time of the last packet.
  // Wall-clock counterparts of flow_start/flow_last, for -D debug
  // logging (format_flow()) and anything else that needs an actual
  // calendar date/time -- flow_start/flow_last above are on the
  // monotonic Clock (see softflowd.hpp's `using Clock =
  // std::chrono::steady_clock`), which has no fixed relationship to
  // wall-clock time on its own. In the original, flow->flow_start IS
  // the real wall-clock pcap-recorded time (see PCAP_TS_TO_TIMEVAL），
  // so these are populated alongside flow_start/flow_last in
  // record_packet() from the packet's own wall_timestamp.
  std::chrono::system_clock::time_point wall_start{};  ///< Wall-clock counterpart of #flow_start.
  std::chrono::system_clock::time_point wall_last{};   ///< Wall-clock counterpart of #flow_last.

  std::array<std::uint64_t, 2> octets{};                  ///< The octets seen from each end.
  std::array<std::uint64_t, 2> packets{};                 ///< The packets seen from each end.
  std::array<std::uint8_t, 2> tcp_flags{};                ///< The TCP flags seen from each end (ORed together).
  std::array<std::uint8_t, 2> tos{};                      ///< The type of service of the first packet, in the slot of its direction; the other slot stays 0.
  std::array<std::array<std::uint8_t, 6>, 2> ethermac{};  ///< The Ethernet addresses of each end.

  std::uint32_t ip6_flowlabel_a{0};  ///< The IPv6 flow label of the first end; never recorded, so 0 (dump-flows prints it).
  std::uint32_t ip6_flowlabel_b{0};  ///< The IPv6 flow label of the second end; never recorded, so 0 (dump-flows prints it).

  MplsLabelStack mpls_labels;  ///< The MPLS labels of the flow.

  std::uint8_t flow_end_reason{0};             ///< The flowEndReason that IPFIX reports (1 idle timeout, 2 active timeout, 3 end of flow, 5 lack of resource).
  ExpiryReason reason{ExpiryReason::General};  ///< Why the flow expired, once it did.
};

/**
 * @brief A flow as an exporter takes it: its key with the statistics at the moment it expired.
 *
 * @original NetFlow/IPFIX/PSAMP export code (in softflowd.c, export.c,
 * export_common.c, psamp.c and the files in compat/) worked directly off
 * `struct FLOW`, which carried both the key fields (addr/port/protocol/...)
 * and the value fields (octets/packets/...) together. Since this project
 * splits those into FlowKey and Flow, exporters need both -- ExportRecord is
 * what FlowTable::expire_flows()/force_expire_oldest() hand back, pairing a
 * key with its accumulated statistics at the moment the flow was expired.
 */
struct ExportRecord {
  FlowKey key;  ///< The key of the flow.
  Flow flow;    ///< The statistics of the flow.
};

/**
 * @brief A flow with its expiry event, as dump-flows shows it.
 *
 * @original the EXPIRY event of a flow (expiry-\>expires_at), as dump-flows
 * shows it next to the flow.
 */
struct ExpiryEntry {
  ExportRecord record;   ///< The flow.
  TimePoint expires_at;  ///< When the flow expires.
};

/**
 * @brief The time when a flow expires, in whole seconds since the epoch.
 *
 * @param flow The flow.
 * @param expires_at The time on Clock when it expires.
 * @return 0 for a flow that is due at once, otherwise the expiry time as seconds since the epoch.
 *
 * @original expiry-\>expires_at, a time_t. A flow that is over 2 GiB or over
 * its maximum lifetime has 0, which is due at once; any other flow has the
 * whole second of its expiry time.
 */
inline long long
expiry_epoch_seconds (const Flow &flow, TimePoint expires_at) {
  if (flow.reason == ExpiryReason::OverBytes || flow.reason == ExpiryReason::MaxLife) {
    return 0;
  }
  const auto wall = flow.wall_last +
                    std::chrono::duration_cast<std::chrono::system_clock::duration> (
                      expires_at - flow.flow_last);
  return std::chrono::duration_cast<std::chrono::seconds> (wall.time_since_epoch()).count();
}

/**
 * @brief Appends the fields of a packet as big-endian bytes to a buffer.
 *
 * It is the serialization helper that the exporters of NetFlow v1, v5, v9, IPFIX and PSAMP share.
 *
 * The original built export packets by populating `__packed` C structs
 * (e.g. `struct NF5_HEADER`) with htons()/htonl() and then treating the
 * struct's address as a byte buffer to send. Two portability/safety issues
 * with that approach:
 *   1. `__packed` (or `#pragma pack`) structs have members at potentially
 *      under-aligned addresses; reading/writing through a typed pointer to
 *      such a member is undefined behavior on architectures that don't
 *      support unaligned access, even though it "works" on x86.
 *   2. Every htons()/htonl() call is a place where it's easy to forget the
 *      conversion, or apply it to the wrong field, with no compiler
 *      diagnostic either way.
 * ByteWriter appends fields one at a time as explicit big-endian byte
 * sequences into a std::vector\<std::uint8_t\> -- there is no struct, no
 * packing pragma, and no possibility of an unconverted or
 * wrong-byte-order field compiling silently.
 *
 * @original ByteWriter (a shared serialization helper used by netflow1.*, netflow5.*, netflow9.*, ipfix.*, and psamp.*)
 */
class ByteWriter {
public:
  /**
     * @brief Appends one byte.
     *
     * @param v The value.
     */
  void
  put_u8 (std::uint8_t v) {
    buf_.push_back (v);
  }

  /**
     * @brief Appends a 16-bit value, big-endian.
     *
     * @param v The value.
     */
  void
  put_u16 (std::uint16_t v) {
    buf_.push_back (static_cast<std::uint8_t> (v >> 8));
    buf_.push_back (static_cast<std::uint8_t> (v));
  }

  /**
     * @brief Appends a 32-bit value, big-endian.
     *
     * @param v The value.
     */
  void
  put_u32 (std::uint32_t v) {
    buf_.push_back (static_cast<std::uint8_t> (v >> 24));
    buf_.push_back (static_cast<std::uint8_t> (v >> 16));
    buf_.push_back (static_cast<std::uint8_t> (v >> 8));
    buf_.push_back (static_cast<std::uint8_t> (v));
  }

  /**
     * @brief Appends a 64-bit value, big-endian.
     *
     * @param v The value.
     */
  void
  put_u64 (std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
      buf_.push_back (
        static_cast<std::uint8_t> (v >> static_cast<unsigned> (shift)));
    }
  }

  /**
     * @brief Appends bytes as they are.
     *
     * @param bytes The bytes.
     */
  void
  put_bytes (std::span<const std::uint8_t> bytes) {
    buf_.insert (buf_.end(), bytes.begin(), bytes.end());
  }

  /**
     * @brief Appends the 4 octets of an IPv4 address.
     *
     * Appends the first 4 (IPv4) or 16 (IPv6) bytes of an IpAddress.
     *
     * @param addr The address.
     */
  void
  put_ipv4 (const IpAddress &addr) {
    put_bytes (std::span<const std::uint8_t> (addr.bytes.data(), 4));
  }
  /**
     * @brief Appends the 16 octets of an IPv6 address.
     *
     * @param addr The address.
     */
  void
  put_ipv6 (const IpAddress &addr) {
    put_bytes (std::span<const std::uint8_t> (addr.bytes.data(), 16));
  }

  /**
     * @brief The number of bytes written.
     *
     * @return The size.
     */
  std::size_t
  size () const noexcept {
    return buf_.size();
  }

  /**
     * @brief Overwrites 2 bytes that were written before, big-endian.
     *
     * Overwrites 2 or 4 bytes previously written at `offset`, big-endian.
     * Used for length/count fields whose final value is only known after
     * the rest of the record has been serialized (e.g. a FlowSet length).
     * `offset` is bounds-checked, turning a would-be out-of-bounds write
     * into an exception rather than silent buffer corruption.
     *
     * @param offset Where the 2 bytes start.
     * @param v The new value.
     * @throw std::out_of_range when @p offset is outside of what was written.
     */
  void
  patch_u16 (std::size_t offset, std::uint16_t v) {
    if (offset + 2 > buf_.size()) {
      throw std::out_of_range ("ByteWriter::patch_u16: offset out of range");
    }
    buf_[offset] = static_cast<std::uint8_t> (v >> 8);
    buf_[offset + 1] = static_cast<std::uint8_t> (v);
  }
  /**
     * @brief Overwrites 4 bytes that were written before, big-endian.
     *
     * @param offset Where the 4 bytes start.
     * @param v The new value.
     * @throw std::out_of_range when @p offset is outside of what was written.
     */
  void
  patch_u32 (std::size_t offset, std::uint32_t v) {
    if (offset + 4 > buf_.size()) {
      throw std::out_of_range ("ByteWriter::patch_u32: offset out of range");
    }
    buf_[offset] = static_cast<std::uint8_t> (v >> 24);
    buf_[offset + 1] = static_cast<std::uint8_t> (v >> 16);
    buf_[offset + 2] = static_cast<std::uint8_t> (v >> 8);
    buf_[offset + 3] = static_cast<std::uint8_t> (v);
  }

  /**
     * @brief The bytes written so far.
     *
     * @return The buffer.
     */
  const std::vector<std::uint8_t> &
  bytes () const noexcept {
    return buf_;
  }
  /**
     * @brief Hands over the buffer; the writer is left empty.
     *
     * @return The buffer.
     */
  std::vector<std::uint8_t>
  take () {
    return std::move (buf_);
  }

  /**
     * @brief Discards everything written after a size.
     *
     * Discards everything written after `new_size` bytes. Used to roll
     * back a Set/FlowSet header that was opened speculatively but turned
     * out to have no room for even a single record before a packet-size
     * budget was reached -- see e.g. export_common.c's `last_valid`
     * rollback in send_ipfix_flows().
     *
     * @param new_size The number of bytes to keep.
     * @throw std::out_of_range when @p new_size is more than what was written.
     */
  void
  truncate (std::size_t new_size) {
    if (new_size > buf_.size()) {
      throw std::out_of_range ("ByteWriter::truncate: new_size exceeds current size");
    }
    buf_.resize (new_size);
  }

private:
  std::vector<std::uint8_t> buf_;  ///< The bytes written so far.
};

}  // namespace softflowd_cpp

/**
 * @brief The hash of a FlowKey, for the hash-based backend of the flow table.
 *
 * @original sys-tree.h's RB_GENERATE macro generated the FLOW/EXPIRY
 * comparison functions (fl_compare/expiry_compare) with hand-rolled pointer
 * arithmetic. All that's needed here for the hash-based backend is a
 * std::hash\<FlowKey\> specialization; there is no hand-written comparator or
 * tree-rotation logic to maintain at all.
 */
template <>
struct std::hash<softflowd_cpp::FlowKey> {
  /**
     * @brief Hashes a flow key, over all its fields.
     *
     * @param k The key.
     * @return The hash.
     */
  std::size_t
  operator() (const softflowd_cpp::FlowKey &k) const noexcept {
    std::size_t h = std::hash<std::uint8_t>{}(k.protocol());
    auto mix = [&h] (std::size_t v) {
      h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    };
    for (const auto &a : k.addr()) {
      for (auto b : a.bytes) {
        mix (std::hash<std::uint8_t>{}(b));
      }
    }
    for (auto p : k.port()) {
      mix (std::hash<std::uint16_t>{}(p));
    }
    for (auto v : k.vlanid()) {
      mix (std::hash<std::uint16_t>{}(v));
    }
    for (const auto &mac : k.ethermac()) {
      for (auto b : mac) {
        mix (std::hash<std::uint8_t>{}(b));
      }
    }
    mix (std::hash<std::uint8_t>{}(k.tos()));
    return h;
  }
};

#endif  // SOFTFLOWD_HPP
