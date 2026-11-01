/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 * Copyright 2019 Hitoshi Irino <irino@sfc.wide.ad.jp> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS    OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file netflow.h
 * @brief The layouts on the wire of the NetFlow v1, v5 and v9 headers and of the
 *   v1 and v5 flow records.
 */

#ifndef _NETFLOW_H
#define _NETFLOW_H

#include "softflowd.h"

/**
 * @brief Cisco NetFlow v1 header format (16 octets), the first
 * NETFLOW1_HEADER_SIZE octets of the v5 one.
 *
 * Shared by compat/netflow1.c and the ipfix.c exporter.
 */
struct NETFLOW1_HEADER {
  u_int16_t version;                 /**< NetFlow version */
  u_int16_t flows;                   /**< Number of flow records in the packet */
  u_int32_t sysUpTime;               /**< Milliseconds since the exporter started */
  u_int32_t export_time;             /**< Seconds since the epoch */
  u_int32_t export_time_nanoseconds; /**< Nanoseconds after export_time */
} __packed;

/**
 * @brief Cisco NetFlow v5 header format (shared with the default ipfix.c
 * exporter).
 *
 * NetFlow v1 shares the first 16 bytes (NETFLOW1_HEADER_SIZE).
 * Ref:
 * https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
 */
struct NETFLOW5_HEADER {
  u_int16_t version;                 /**< NetFlow version, same as netflow v1 */
  u_int16_t flows;                   /**< Number of flow records in the packet, same as netflow v1 */
  u_int32_t sysUpTime;               /**< Milliseconds since the exporter started, same as netflow v1 */
  u_int32_t export_time;             /**< Seconds since the epoch, same as netflow v1 */
  u_int32_t export_time_nanoseconds; /**< Nanoseconds after export_time, same as netflow v1 */
  u_int32_t sequence_number;         /**< Counter of the flows exported so far */
  u_int8_t engine_type;              /**< Type of the flow-switching engine */
  u_int8_t engine_id;                /**< Slot number of the flow-switching engine */
  u_int16_t sampling_interval;       /**< The sampling mode in the top 2 bits and the interval in the other 14 bits; 1 and the rate of -s with -s, otherwise 0 */
} __packed;

/** Size in octets of the NetFlow v1 header. */
#define NETFLOW1_HEADER_SIZE 16

/**
 * @brief Cisco NetFlow v5 flow record (48 octets); NetFlow v1 records are the
 * same size.
 */
struct NETFLOW5_FLOW {
  u_int32_t sourceIPv4Address;          /**< Source IPv4 address, same as netflow v1 */
  u_int32_t destinationIPv4Address;     /**< Destination IPv4 address, same as netflow v1 */
  u_int32_t ipNextHopIPv4Address;       /**< IPv4 address of the next hop, same as netflow v1 */
  u_int16_t ingressInterface;           /**< Index of the input interface, same as netflow v1 */
  u_int16_t egressInterface;            /**< Index of the output interface, same as netflow v1 */
  u_int32_t packetDeltaCount;           /**< Packets of the flow, same as netflow v1 */
  u_int32_t octetDeltaCount;            /**< Octets of the flow, same as netflow v1 */
  u_int32_t flowStartSysUpTime;         /**< SysUpTime in milliseconds at the first packet, same as netflow v1 */
  u_int32_t flowEndSysUpTime;           /**< SysUpTime in milliseconds at the last packet, same as netflow v1 */
  u_int16_t sourceTransportPort;        /**< Source port, same as netflow v1 */
  u_int16_t destinationTransportPort;   /**< Destination port, same as netflow v1 */
  u_int8_t pad1;                        /**< Padding */
  u_int8_t tcpControlBits;              /**< Cumulative OR of the TCP flags */
  u_int8_t protocolIdentifier;          /**< IP protocol number */
  u_int8_t ipClassOfService;            /**< IP type of service */
  u_int16_t bgpSourceAsNumber;          /**< Autonomous system number of the source */
  u_int16_t bgpDestinationAsNumber;     /**< Autonomous system number of the destination */
  u_int8_t sourceIPv4PrefixLength;      /**< Prefix length of the source address */
  u_int8_t destinationIPv4PrefixLength; /**< Prefix length of the destination address */
  u_int16_t pad2;                       /**< Padding */
};

/* Maximum number of flows per packet */
/** Largest number of flow records in a NetFlow v1 packet. */
#define NETFLOW1_MAXFLOWS 24
/** Largest number of flow records in a NetFlow v5 packet. */
#define NETFLOW5_MAXFLOWS 30
/**
 * Largest size in octets of a NetFlow v5 packet: the header and the
 * largest number of flow records.
 */
#define NETFLOW5_MAXPACKET_SIZE      \
  (sizeof (struct NETFLOW5_HEADER) + \
   (NETFLOW5_MAXFLOWS * sizeof (struct NETFLOW5_FLOW)))

/** Set ID of a template set of NetFlow v9. */
#define NETFLOW9_TEMPLATE_SET_ID 0
/** Set ID of an options template set of NetFlow v9. */
#define NETFLOW9_OPTION_TEMPLATE_SET_ID 1

/** @brief Cisco NetFlow v9 header format (20 octets). */
struct NETFLOW9_HEADER {
  u_int16_t version;               /**< NetFlow version */
  u_int16_t flows;                 /**< Number of records in the packet, template records included */
  u_int32_t sysUpTime;             /**< Milliseconds since the exporter started */
  u_int32_t export_time;           /**< Seconds since the epoch */
  u_int32_t sequence_number;       /**< Counter of the packets exported so far */
  u_int32_t observation_domain_id; /**< Identifies the exporter, the source ID of NetFlow v9 */
} __packed;

#if COMPAT_EXPORT == COMPAT_EXPORT_STATIC_SEPARATE
/* Force a resend of the flow template, from netflow9.c */
void
netflow9_resend_template (void);
#endif /* COMPAT_EXPORT == COMPAT_EXPORT_STATIC_SEPARATE */

#endif /* _NETFLOW_H */
