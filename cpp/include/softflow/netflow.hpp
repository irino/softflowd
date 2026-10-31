/**
 * @file netflow.hpp
 * @brief The fixed sizes of the NetFlow v1 and v5 packets.
 *
 * @original netflow.h.
 */
#ifndef SOFTFLOW_NETFLOW_HPP
#define SOFTFLOW_NETFLOW_HPP

#include <cstddef>

namespace softflow {

/**
 * @brief The maximum number of flow records in one NetFlow v1 export packet.
 *
 * Follows Cisco's documentation.
 *
 * @original NETFLOW1_MAXFLOWS in netflow.h.
 */
inline constexpr std::size_t kNetflow1MaxRecordsPerPacket = 24;
/** @brief The size in octets of the header of a NetFlow v1 packet. */
inline constexpr std::size_t kNetflow1HeaderSize = 16;
/** @brief The size in octets of one flow record of NetFlow v1. */
inline constexpr std::size_t kNetflow1RecordSize = 48;

/**
 * @brief The maximum number of flow records in one NetFlow v5 export packet.
 *
 * (1500 - 24-byte header) / 48-byte record = 30.75, rounded down.
 *
 * @original NETFLOW5_MAXFLOWS in netflow.h.
 */
inline constexpr std::size_t kNetflow5MaxRecordsPerPacket = 30;
/** @brief The size in octets of the header of a NetFlow v5 packet. */
inline constexpr std::size_t kNetflow5HeaderSize = 24;
/** @brief The size in octets of one flow record of NetFlow v5. */
inline constexpr std::size_t kNetflow5RecordSize = 48;

}  // namespace softflow

#endif  // SOFTFLOW_NETFLOW_HPP
