/**
 * @file packet.hpp
 * @brief What softflowd+ finds out about a captured packet before the flow table sees it: the IP and transport headers, the link layer, and the frame.
 *
 * Split from softflowd.hpp and softflowd.cpp. PacketParser decodes the IP and
 * the transport headers, DatalinkKind names the link-layer types that can be
 * read, CapturedPacket is what the capture hands over, and classify_frame ()
 * finds the IP header in a frame. The reading of a capture file and the live
 * capture share them. The member functions of PacketParser and classify_frame
 * () are defined in packet.cpp.
 *
 * @original ipv4_to_flowrec (), ipv6_to_flowrec (), transport_to_flowrec ()
 * and the DATALINK table, ether_to_flowrec () and process_packet () of
 * softflowd.c, and packet.h of the C version.
 */
#ifndef SOFTFLOWD_CPP_PACKET_HPP
#define SOFTFLOWD_CPP_PACKET_HPP

#include "softflowd_cpp/softflowd.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace softflowd_cpp {

/**
 * @brief What the packet parser reads from the headers of a packet.
 */
struct ParsedPacket {
  IpAddress src{};                 ///< The source address.
  IpAddress dst{};                 ///< The destination address.
  std::uint16_t src_port{0};       ///< The source port; the ICMP type for ICMP.
  std::uint16_t dst_port{0};       ///< The destination port; the ICMP code for ICMP.
  std::uint8_t protocol{0};        ///< The IP protocol number.
  std::uint8_t tos{0};             ///< The type of service.
  std::uint8_t tcp_flags{0};       ///< The TCP flags.
  std::uint32_t ip6_flowlabel{0};  ///< The IPv6 flow label.
  bool is_fragment{false};         ///< Whether the packet is a fragment.
  bool is_first_fragment{true};    ///< Whether the packet is the first fragment (or not fragmented); only then it has the transport header.
};

/**
 * @brief Reads the headers of an IPv4 or IPv6 packet into a ParsedPacket.
 *
 * The original code cast raw byte buffers directly onto \<netinet/ip.h\>'s
 * struct ip / struct ip6_hdr / struct tcphdr etc. (a form of type punning
 * that is a strict-aliasing violation -- technically undefined behavior
 * that merely "happens to work" on most platforms/compilers). No casts are
 * used here; every field is read a byte at a time out of a std::span via
 * the read_be16/read_be32 helpers defined in softflowd.cpp. Because those
 * helpers always read explicitly as big-endian, byte-order bugs from a
 * missing ntohs/ntohl are structurally impossible.
 *
 * The original's ipv6_to_flowrec() also contained a real bug worth noting:
 *   eh6 = (const struct ip6_ext *) pkt + size;
 * Due to cast binding tighter than +, this advances the pointer by `size *
 * sizeof(struct ip6_ext)` bytes, not `size` bytes as intended -- a classic
 * "pointer arithmetic unit mismatch after a cast" bug that's easy to write
 * in C and easy to miss in review. Using std::span::subspan(), which is
 * unambiguously byte-oriented by its type signature, makes this entire bug
 * class impossible to reintroduce by accident.
 *
 * Original: PacketParser (original: softflowd.c's ipv4_to_flowrec() / ipv6_to_flowrec() / transport_to_flowrec())
 *
 * @original process_packet()'s PP_BAD_PACKET / PP_MALLOC_FAIL integer
 * return codes. A caller that forgets to check them gets no help from the
 * compiler. std::optional\<ParsedPacket\> encodes "may not have a value" in
 * the type itself. (It's still possible to call .value() unconditionally,
 * so this isn't a hard guarantee -- but the return type alone now signals
 * that failure is possible, which the original's plain `int` did not.)
 */
class PacketParser {
public:
  /**
     * @brief Creates a parser.
     *
     * full_l4hdr_check: when false (the default), only the bytes that are
     * read are required in the transport header: the ports of TCP, UDP,
     * DCCP and SCTP, the TCP flags, and the ICMP/ICMPv6 type and code. When
     * true (-f), the whole TCP, UDP, DCCP, ICMP or ICMPv6 header is
     * required, as the reference C softflowd did before it relaxed this
     * check. This follows the C implementation's default.
     *
     * @param track_level The -T level.
     * @param full_l4hdr_check Require the whole transport header (-f).
     */
  explicit PacketParser (TrackLevel track_level,
                         bool full_l4hdr_check = false)
      : track_level_ (track_level),
        full_l4hdr_check_ (full_l4hdr_check) {
  }

  /**
     * @brief Parses one packet.
     *
     * @param ip_payload The IP packet, with the data-link header already stripped off.
     * @param af Whether it is IPv4 or IPv6.
     * @return The fields, or nullopt when the packet is too short or malformed.
     *
     * @original ipv4_to_flowrec() / ipv6_to_flowrec()
     * ip_payload is the IP packet with the data-link layer header already
     * stripped off.
     */
  std::optional<ParsedPacket>
  parse (std::span<const std::uint8_t> ip_payload,
         AddressFamily af) const;

  /**
     * @brief The -T level.
     *
     * @return The level.
     */
  TrackLevel
  track_level () const noexcept {
    return track_level_;
  }

private:
  /**
     * @brief Parses an IPv4 packet.
     *
     * @param data The packet.
     * @return The fields, or nullopt when the packet is malformed.
     */
  std::optional<ParsedPacket>
  parse_ipv4 (std::span<const std::uint8_t> data) const;
  /**
     * @brief Parses an IPv6 packet, with its extension headers.
     *
     * @param data The packet.
     * @return The fields, or nullopt when the packet is malformed.
     */
  std::optional<ParsedPacket>
  parse_ipv6 (std::span<const std::uint8_t> data) const;

  /**
     * @brief Reads the ports, the TCP flags or the ICMP type and code from the transport header.
     *
     * @param packet The parsed packet, which is filled in.
     * @param transport_payload The bytes after the IP header.
     * @param protocol The IP protocol of the packet.
     *
     * @original transport_to_flowrec()
     */
  void
  parse_transport (ParsedPacket &packet,
                   std::span<const std::uint8_t> transport_payload,
                   std::uint8_t protocol) const;

  TrackLevel track_level_;
  bool full_l4hdr_check_;  ///< Whether the whole transport header is required.
};

/**
 * @brief Makes the key of the flow that a packet belongs to.
 *
 * @param packet The parsed packet.
 * @param track_level The -T level, which decides the fields that belong to the key.
 * @param vlanid The VLAN IDs of the source and of the destination.
 * @param ethermac The Ethernet addresses of the source and of the destination.
 * @return The key.
 *
 * @original the "decide addr[ndx] vs addr[ndx^1] ordering" step that
 * preceded FlowKey construction (a memcmp inside ipv4_to_flowrec) is now
 * just a call into FlowKey::make_canonical from a ParsedPacket.
 * vlanid and ethermac are those of the packet's source (index 0) and
 * destination (index 1); they are part of the flow only at the tracking
 * levels that ask for them (-T vlan and -T ether).
 */
FlowKey
make_flow_key (const ParsedPacket &packet, TrackLevel track_level,
               std::array<std::uint16_t, 2> vlanid = {0, 0},
               std::array<std::array<std::uint8_t, 6>, 2> ethermac = {});

/**
 * @brief Tells which end of a flow the source of a packet is.
 *
 * Which of the two endpoints of the flow the source of the packet is (the
 * original's ndx): 0 for the first of the canonical order, the lower address
 * or, when both ends have the same address (RFC 5103: a Biflow of a loopback
 * conversation), the lower port; otherwise 1.
 *
 * @param key The key of the flow.
 * @param packet The parsed packet.
 * @return 0 for the first end of the canonical order; otherwise 1.
 */
std::uint8_t
flow_direction (const FlowKey &key, const ParsedPacket &packet);

/**
 * @brief The link-layer types that softflowd+ can read.
 *
 * @original softflowd.c's DATALINK table (`static const struct DATALINK
 * lt[]`). For each known link-layer type, it hand-maintained the number of
 * bytes to skip to reach the IP header (skiplen) and how to determine the
 * EtherType. Ethernet / Linux SLL / RAW / NULL-LOOP are supported here
 * (PPP/PFLOG from the original can be added in a later stage).
 */
enum class DatalinkKind {
  Ethernet,     ///< Ethernet.
  LinuxSll,     ///< Linux cooked capture.
  Raw,          ///< Raw IP.
  NullLoop,     ///< BSD loopback (null / loop).
  Unsupported,  ///< Any other link-layer type.
};

/**
 * @brief Classifies a libpcap link-layer type.
 *
 * @param pcap_dlt The DLT_ value.
 * @return The kind.
 */
DatalinkKind
classify_datalink (int pcap_dlt);
/**
 * @brief The size of the link-layer header that comes before the IP header.
 *
 * @param kind The kind.
 * @return The size in octets.
 */
std::size_t
datalink_header_len (DatalinkKind kind);

/**
 * @brief A captured packet with its lengths and times.
 *
 * @original the result of pcap_next_ex(), i.e. the pair of
 * `const u_char *frame` + `struct pcap_pkthdr *phdr`. The constraint that
 * the span is valid only until the next call to next_packet() comes from
 * libpcap's zero-copy design and can't be fully hidden, but combining
 * "pointer" and "another, separate length variable" into a single type
 * still prevents the class of bug where the length gets mismatched against
 * the wrong pointer.
 */
struct CapturedPacket {
  std::span<const std::uint8_t> data;                    ///< The bytes actually captured.
  std::uint32_t original_length;                         ///< The on-the-wire length before any truncation (phdr->len).
  TimePoint timestamp;                                   ///< This process's monotonic clock at the moment of capture.
  std::chrono::system_clock::time_point wall_timestamp;  ///< libpcap's own recorded timestamp (phdr->ts).
};

/**
 * @brief What classify_frame () finds out about a frame.
 */
struct FrameClassification {
  softflowd_cpp::AddressFamily af;                        ///< The family of the IP header.
  std::size_t ip_offset;                                  ///< The bytes to skip, from the start of ip_bytes, to reach the IP header.
  std::vector<std::uint32_t> mpls_labels;                 ///< The MPLS labels, outermost first; empty when the frame is not MPLS.
  std::size_t vlan_size = 0;                              ///< The size of the 802.1Q tag: 4 for a tagged Ethernet frame, otherwise 0.
  std::uint16_t vlanid = 0;                               ///< The VLAN ID without the priority bits; 0 for an untagged frame.
  std::array<std::array<std::uint8_t, 6>, 2> ethermac{};  ///< The source and the destination Ethernet address.
};

std::optional<FrameClassification>
classify_frame (const softflowd_cpp::CapturedPacket &pkt, softflowd_cpp::DatalinkKind dl_kind,
                std::span<const std::uint8_t> ip_bytes);

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_PACKET_HPP
