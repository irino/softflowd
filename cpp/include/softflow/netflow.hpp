// Original files: netflow.h
//
// The fixed sizes of the NetFlow v1 and v5 packets.
#ifndef SOFTFLOW_NETFLOW_HPP
#define SOFTFLOW_NETFLOW_HPP

#include <cstddef>

namespace softflow {

// Original: NETFLOW1_MAXFLOWS in netflow.h -- the maximum number of flow
// records in one NetFlow v1 export packet, following Cisco's documentation.
inline constexpr std::size_t kNetflow1MaxRecordsPerPacket = 24;
inline constexpr std::size_t kNetflow1HeaderSize = 16;
inline constexpr std::size_t kNetflow1RecordSize = 48;

// Original: netflow.h's NETFLOW5_MAXFLOWS. (1500 - 24-byte header) / 48-byte
// record = 30.75, rounded down.
inline constexpr std::size_t kNetflow5MaxRecordsPerPacket = 30;
inline constexpr std::size_t kNetflow5HeaderSize = 24;
inline constexpr std::size_t kNetflow5RecordSize = 48;

}  // namespace softflow

#endif  // SOFTFLOW_NETFLOW_HPP
