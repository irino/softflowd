/**
 * @file export_internal.hpp
 * @brief What export.cpp and export_template.cpp share, for IpfixExporter only.
 *
 * Not to be included outside of these files: the exporters are declared in
 * export.hpp.
 */
#ifndef SOFTFLOWD_CPP_EXPORT_INTERNAL_HPP
#define SOFTFLOWD_CPP_EXPORT_INTERNAL_HPP

#include <cstddef>
#include <cstdint>

#include "softflowd_cpp/ipfix.hpp"
#include "softflowd_cpp/softflowd.hpp"

namespace softflowd_cpp {

/**
 * @brief The size in bytes of one directional data record of NetFlow v9 and IPFIX.
 *
 * Every record of the same family and of the same ICMP-ness has exactly this
 * size, since no field has a variable length, so the packing loop of
 * IpfixExporter::build_packets () budgets the space by arithmetic instead of
 * writing a record and rolling it back, as the return value of
 * ipfix_flow_to_flowset () does in the C version. It is defined next to the
 * templates, which it has to agree with.
 *
 * @param is_v6 True for an IPv6 record, false for an IPv4 record.
 * @param is_icmp True for a record of the ICMP template, false for a record of
 *        the one of the transport protocols.
 * @param time_format The -A time format.
 * @param mpls_label_count The number of MPLS labels that are exported (-x).
 * @param track_level -T: the VLAN and Ethernet fields that are exported.
 * @return The size of the record.
 */
std::size_t
record_size (bool is_v6, bool is_icmp, IpfixTimeFormat time_format,
             std::uint8_t mpls_label_count, TrackLevel track_level);

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_EXPORT_INTERNAL_HPP
