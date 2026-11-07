/**
 * @file packet.hpp
 * @brief What softflowd+ finds out about a captured frame before the flow table sees it.
 *
 * Split from softflowd.cpp. classify_frame () is shared by the reading of a
 * capture file and the live capture. The decoding of the IP and the
 * transport headers is in PacketParser (softflowd.hpp).
 *
 * @original The data-link part of ether_to_flowrec () and process_packet () in
 * softflowd.c, with the DATALINK table that gives the offsets.
 */
#ifndef SOFTFLOWD_CPP_PACKET_HPP
#define SOFTFLOWD_CPP_PACKET_HPP

#include "softflowd_cpp/softflowd.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace softflowd_cpp {

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
