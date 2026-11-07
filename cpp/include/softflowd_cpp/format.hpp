/**
 * @file format.hpp
 * @brief Text of addresses, times and flows, for the debug output and the dump of the flows.
 *
 * Split from softflowd.cpp. The formats are those of the original, so that
 * the output of -D and of the dump-flows command stays the same.
 *
 * @original format.c, format_time (), format_flow () and format_flow_brief ()
 * of softflowd.c, and inet_ntop () for the addresses.
 */
#ifndef SOFTFLOWD_CPP_FORMAT_HPP
#define SOFTFLOWD_CPP_FORMAT_HPP

#include "softflowd_cpp/softflowd.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <string>

namespace softflowd_cpp {

std::string
format_ethermac (const std::array<std::uint8_t, 6> &mac);

std::string
format_time (std::chrono::system_clock::time_point t);

std::string
format_address (const softflowd_cpp::IpAddress &addr);

std::string
format_flow_brief (std::uint64_t flow_seq,
                   const softflowd_cpp::FlowKey &key);

std::string
format_flow (const softflowd_cpp::FlowKey &key,
             const softflowd_cpp::Flow &flow);

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_FORMAT_HPP
