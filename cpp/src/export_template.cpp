// Original files: export_template.c (and compat/ipfix.c, compat/netflow9.c)
//
// The templates of NetFlow v9 and IPFIX: the header of a packet, the options
// template set and the template set. Split from export.cpp. What the
// exporters share is in export_common.cpp.
#include "softflowd_cpp/export.hpp"
#include "softflowd_cpp/export_internal.hpp"

#include <algorithm>
#include <unistd.h>  // getpid() -- see write_options_set()

namespace softflowd_cpp {

namespace {

/**
 * @brief The start and the end time fields of a template: the information element ID and the length of each.
 *
 * Returns the (start, end) Information Element (type, length) pair for
 * the configured -A time_format, and writes the corresponding (start,
 * end) values for one record. Keeping the "which fields" and "which
 * values" logic paired up like this (rather than as two separately
 * maintained switches) makes it structurally impossible for the template
 * to describe a different encoding than what's actually written.
 */
struct TimeFieldPair {
  IpfixFieldSpec start_field;  ///< The field of the start of the flow.
  IpfixFieldSpec end_field;    ///< The field of the end of the flow.
};

/**
 * @brief Gives the start and end time fields for a time format.
 *
 * @param format The time format of -A.
 * @return The fields; flowStartSysUpTime and flowEndSysUpTime for SysUpTime, and the Seconds, Milliseconds, Microseconds or Nanoseconds pairs of the other formats.
 *
 * @original ipfix_fields.h's field_timesec/field_timemsec/field_timeusec/
 * field_timensec/field_timesysup all declare the Start field before the
 * End field (and compat/ipfix.c's copy_data_time() writes dt-\>u32.start
 * before dt-\>u32.end, i.e. the same order) -- start-then-end, not
 * end-then-start.
 */
TimeFieldPair
time_field_pair (IpfixTimeFormat format) {
  switch (format) {
    case IpfixTimeFormat::SysUpTime:
      return {{22, 4}, {21, 4}};  // flowStartSysUpTime, flowEndSysUpTime
    case IpfixTimeFormat::Seconds:
      return {{150, 4}, {151, 4}};  // flowStartSeconds, flowEndSeconds
    case IpfixTimeFormat::Milliseconds:
      return {{152, 8}, {153, 8}};  // flowStartMilliseconds, flowEndMilliseconds
    case IpfixTimeFormat::Microseconds:
      return {{154, 8}, {155, 8}};  // flowStartMicroseconds, flowEndMicroseconds
    case IpfixTimeFormat::Nanoseconds:
      return {{156, 8}, {157, 8}};  // flowStartNanoseconds, flowEndNanoseconds
  }
  return {{22, 4}, {21, 4}};
}

/**
 * @brief Gives the size of the VLAN and Ethernet fields of a track level.
 *
 * @param level The track level.
 * @return 0 below FullVlan, 4 bytes (two VLAN IDs) from FullVlan, and 16 bytes (the VLAN IDs and two Ethernet addresses) from FullVlanEther.
 */
std::size_t
l2_size (TrackLevel level) {
  return (level >= TrackLevel::FullVlan ? std::size_t{4} : std::size_t{0}) +
         (level >= TrackLevel::FullVlanEther ? std::size_t{12} : std::size_t{0});
}

}  // namespace

void
IpfixExporter::write_header (
  ByteWriter &writer, std::uint16_t length_or_count, TimePoint now,
  std::chrono::system_clock::time_point wall_now) const {
  const auto export_time = std::chrono::system_clock::to_time_t (wall_now);

  if (version_ == MessageVersion::NetFlow9) {
    // Original: struct NETFLOW9_HEADER. The count is the number of data
    // records and the sequence number counts packets.
    writer.put_u16 (9);  // version
    writer.put_u16 (length_or_count);
    writer.put_u32 (uptime_ms_unclamped (boot_time_, now));
    writer.put_u32 (static_cast<std::uint32_t> (export_time));
    writer.put_u32 (v9_sequence_);
    writer.put_u32 (observation_domain_id_);
    return;
  }
  writer.put_u16 (10);  // version
  writer.put_u16 (length_or_count);
  writer.put_u32 (static_cast<std::uint32_t> (export_time));
  writer.put_u32 (sequence_);
  writer.put_u32 (observation_domain_id_);
}

void
IpfixExporter::write_options_set (ByteWriter &writer) const {
  if (version_ == MessageVersion::NetFlow9) {
    // Original: nflow9_init_option(). An Options Template FlowSet (ID 1)
    // whose scope is the interface (4 octets) and whose option
    // fields are samplingInterval, samplingAlgorithm and interfaceName,
    // followed by its data record. Neither is padded.
    constexpr std::uint16_t kOptionTemplateFlowSetId = 1;
    constexpr std::uint16_t kOptionDataSetId = 256;
    constexpr std::uint16_t kScopeInterface = 2;
    constexpr std::size_t kIfNameLength = 16;  // IFNAMSIZ
    {
      const std::size_t set_start = writer.size();
      writer.put_u16 (kOptionTemplateFlowSetId);
      writer.put_u16 (0);  // Length placeholder
      writer.put_u16 (kOptionDataSetId);
      writer.put_u16 (4);   // scope length in octets (one field)
      writer.put_u16 (12);  // option length in octets (three fields)
      writer.put_u16 (kScopeInterface);
      writer.put_u16 (4);
      writer.put_u16 (34);  // SAMPLING_INTERVAL
      writer.put_u16 (4);
      writer.put_u16 (35);  // SAMPLING_ALGORITHM
      writer.put_u16 (1);
      writer.put_u16 (82);  // IF_NAME
      writer.put_u16 (static_cast<std::uint16_t> (kIfNameLength));
      finish_set_unpadded (writer, set_start);
    }
    {
      const std::size_t set_start = writer.size();
      writer.put_u16 (kOptionDataSetId);
      writer.put_u16 (0);  // Length placeholder
      writer.put_u32 (if_index_);
      writer.put_u32 (sampling_rate_ > 1 ? sampling_rate_ : 1);
      writer.put_u8 (1);  // deterministic sampling
      // interfaceName: empty unless the original is built with
      // --enable-ifname, which is off by default.
      for (std::size_t i = 0; i < kIfNameLength; ++i) {
        writer.put_u8 (0);
      }
      finish_set_unpadded (writer, set_start);
    }
    return;
  }
  // Original: ipfix_init_option() -- an Options Template Set (RFC 7011
  // section 3.4.2.2, Set ID 3) followed by its one Options Data Record
  // (Set ID 256, this project's arbitrarily-chosen but fixed template
  // ID, matching IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID). Scope field is
  // meteringProcessId; option fields carry systemInitTimeMilliseconds
  // (the reference point IpfixTimeFormat::SysUpTime's Start/End fields
  // are relative to -- see time_field_pair()) plus sampling/exporter
  // metadata this project doesn't otherwise track (sent as zero/empty,
  // matching a default, unconfigured original).
  static const std::vector<IpfixFieldSpec> kScopeFields = {
    {143, 4},  // meteringProcessId
  };
  static const std::vector<IpfixFieldSpec> kOptionFields = {
    {160, 8},   // systemInitTimeMilliseconds
    {305, 4},   // samplingPacketInterval (PSAMP)
    {306, 4},   // samplingPacketSpace (PSAMP)
    {304, 2},   // selectorAlgorithm (PSAMP)
    {82, 16},   // interfaceName (IFNAMSIZ == 16 on Linux)
    {130, 4},   // exporterIPv4Address
    {131, 16},  // exporterIPv6Address
    {403, 4},   // originalExporterIPv4Address
    {404, 16},  // originalExporterIPv6Address
  };
  constexpr std::uint16_t kOptionTemplateSetId = 3;
  constexpr std::uint16_t kOptionDataSetId = 256;

  {
    const std::size_t set_start = writer.size();
    writer.put_u16 (kOptionTemplateSetId);
    writer.put_u16 (0);                 // Length placeholder
    writer.put_u16 (kOptionDataSetId);  // template_id
    writer.put_u16 (static_cast<std::uint16_t> (
      kScopeFields.size() + kOptionFields.size()));                     // count
    writer.put_u16 (static_cast<std::uint16_t> (kScopeFields.size()));  // scope_count
    for (const auto &f : kScopeFields) {
      writer.put_u16 (f.type);
      writer.put_u16 (f.length);
    }
    for (const auto &f : kOptionFields) {
      writer.put_u16 (f.type);
      writer.put_u16 (f.length);
    }
    finish_set_unpadded (writer, set_start);
  }
  {
    const std::size_t set_start = writer.size();
    writer.put_u16 (kOptionDataSetId);
    writer.put_u16 (0);                                      // Length placeholder
    writer.put_u32 (static_cast<std::uint32_t> (getpid()));  // scope_pid
    const auto boot_epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds> (
      boot_wall_time_.time_since_epoch());
    writer.put_u64 (static_cast<std::uint64_t> (
      std::max<std::int64_t> (0, boot_epoch_ms.count())));         // systemInitTimeMilliseconds
    writer.put_u32 (sampling_rate_ > 1 ? sampling_rate_ : 1);      // samplingPacketInterval
    writer.put_u32 (sampling_rate_ > 0 ? sampling_rate_ - 1 : 0);  // samplingPacketSpace
    writer.put_u16 (1);                                            // selectorAlgorithm (PSAMP_selectorAlgorithm_count)
    for (int i = 0; i < 16; ++i) {
      // interfaceName: empty unless the original is built with
      // --enable-ifname, which is off by default.
      writer.put_u8 (0);
    }
    // exporterIPv4/6Address and originalExporterIPv4/6Address all carry the
    // address of -e, or zero when there is none for the family.
    const std::array<std::uint8_t, 4> v4 =
      exporter_addresses_.v4.value_or (std::array<std::uint8_t, 4>{});
    const std::array<std::uint8_t, 16> v6 =
      exporter_addresses_.v6.value_or (std::array<std::uint8_t, 16>{});
    for (int i = 0; i < 2; ++i) {
      for (const std::uint8_t b : v4) {
        writer.put_u8 (b);
      }
      for (const std::uint8_t b : v6) {
        writer.put_u8 (b);
      }
    }
    finish_set_unpadded (writer, set_start);
  }
}

void
IpfixExporter::write_template_set (ByteWriter &writer) const {
  // Original: each entry in `templates[]` (compat/ipfix.c) is a self-contained
  // struct with its OWN Set header (IPFIX_SET_HEADER, Set ID 2) baked
  // in, and memcpy_template() copies each one out individually -- so on
  // the wire, four separate Template Sets are sent (one per template),
  // not one Set containing four Template Records. finish_set() pads
  // each to a 4-byte boundary and patches its own length, same as any
  // other Set.
  const auto write_template = [&] (std::uint16_t template_id,
                                   std::span<const IpfixFieldSpec> fields) {
    const std::size_t set_start = writer.size();
    // Set ID 2 identifies a Template Set (IPFIX; NetFlow v9 uses 0)
    writer.put_u16 (version_ == MessageVersion::Ipfix ? 2 : 0);
    writer.put_u16 (0);  // Length placeholder, patched by finish_set()
    writer.put_u16 (template_id);
    writer.put_u16 (static_cast<std::uint16_t> (fields.size()));
    for (const auto &f : fields) {
      if (f.enterprise == 0) {
        writer.put_u16 (f.type);
        writer.put_u16 (f.length);
      } else {
        // Enterprise-specific Information Element (RFC 7011
        // section 3.2): the top bit of the type field is set, and
        // a 4-byte Enterprise Number follows the normal 4-byte
        // (type, length) pair.
        writer.put_u16 (static_cast<std::uint16_t> (f.type | 0x8000u));
        writer.put_u16 (f.length);
        writer.put_u32 (f.enterprise);
      }
    }
    finish_set_unpadded (writer, set_start);
  };

  const auto [start_field, end_field] = time_field_pair (time_format_);

  // Original: field_common -- octetDeltaCount, packetDeltaCount,
  // ingressInterface, egressInterface, flowDirection, flowEndReason.
  // Shared by every non-biflow template between the timestamps and the
  // transport-or-ICMP fields; see write_common_fields().
  static const std::vector<IpfixFieldSpec> kCommonFields = {
    {1, 4},    // octetDeltaCount
    {2, 4},    // packetDeltaCount
    {10, 4},   // ingressInterface
    {14, 4},   // egressInterface
    {61, 1},   // flowDirection
    {136, 1},  // flowEndReason
  };

  if (!biflow_) {
    // Field order must exactly match write_v4_record()/write_v6_record()/
    // write_v4_icmp_record()/write_v6_icmp_record(): address, time,
    // common, then transport (ordinary flows) or icmpTypeCode (ICMP
    // flows) -- see compat/ipfix.c's ipfix_init_template_unity().
    std::vector<IpfixFieldSpec> v4_fields = {
      {8, 4},
      {12, 4},  // sourceIPv4Address, destinationIPv4Address
    };
    std::vector<IpfixFieldSpec> v6_fields = {
      {27, 16},
      {28, 16},  // sourceIPv6Address, destinationIPv6Address
    };
    for (auto *fields : {&v4_fields, &v6_fields}) {
      fields->push_back (start_field);
      fields->push_back (end_field);
      fields->insert (fields->end(), kCommonFields.begin(), kCommonFields.end());
    }
    std::vector<IpfixFieldSpec> v4_icmp_fields = v4_fields;
    std::vector<IpfixFieldSpec> v6_icmp_fields = v6_fields;

    v4_fields.push_back ({7, 2});   // sourceTransportPort
    v4_fields.push_back ({11, 2});  // destinationTransportPort
    v4_fields.push_back ({4, 1});   // protocolIdentifier
    v4_fields.push_back ({6, 1});   // tcpControlBits
    v4_fields.push_back ({60, 1});  // ipVersion
    v4_fields.push_back ({5, 1});   // ipClassOfService

    v6_fields.push_back ({7, 2});
    v6_fields.push_back ({11, 2});
    v6_fields.push_back ({4, 1});
    v6_fields.push_back ({6, 1});
    v6_fields.push_back ({60, 1});
    v6_fields.push_back ({5, 1});

    v4_icmp_fields.push_back ({32, 2});  // icmpTypeCodeIPv4
    v4_icmp_fields.push_back ({4, 1});   // protocolIdentifier
    v4_icmp_fields.push_back ({60, 1});  // ipVersion
    v4_icmp_fields.push_back ({5, 1});   // ipClassOfService

    v6_icmp_fields.push_back ({139, 2});  // icmpTypeCodeIPv6
    v6_icmp_fields.push_back ({4, 1});
    v6_icmp_fields.push_back ({60, 1});
    v6_icmp_fields.push_back ({5, 1});

    for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
      if (track_level_ >= TrackLevel::FullVlan) {
        fields->push_back ({58, 2});  // vlanId
        fields->push_back ({59, 2});  // postVlanId
      }
      if (track_level_ >= TrackLevel::FullVlanEther) {
        fields->push_back ({56, 6});  // sourceMacAddress
        fields->push_back ({57, 6});  // postDestinationMacAddress
      }
    }
    for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
      const IpfixFieldSpec mpls{static_cast<std::uint16_t> (70 + i), 3};
      for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
        fields->push_back (mpls);
      }
    }
    write_template (kIpfixTemplateIdV4, v4_fields);
    write_template (kIpfixTemplateIdIcmpV4, v4_icmp_fields);
    write_template (kIpfixTemplateIdV6, v6_fields);
    write_template (kIpfixTemplateIdIcmpV6, v6_icmp_fields);
  } else {
    // Field order must exactly match write_biflow_v4_record()/
    // write_biflow_v4_icmp_record()/write_biflow_v6_record()/
    // write_biflow_v6_icmp_record(): the SAME forward layout as the
    // non-biflow branch above (address, time, common, transport-or-
    // icmp), then MPLS, then the Reverse Information Elements (RFC
    // 5103): reverse octetDeltaCount/packetDeltaCount/
    // ipClassOfService [field_bicommon], then EITHER reverse
    // tcpControlBits [field_bitransport] OR reverse icmpTypeCode
    // [field_biicmp4/6].
    std::vector<IpfixFieldSpec> v4_fields = {
      {8, 4},
      {12, 4},  // sourceIPv4Address, destinationIPv4Address
    };
    std::vector<IpfixFieldSpec> v6_fields = {
      {27, 16},
      {28, 16},  // sourceIPv6Address, destinationIPv6Address
    };
    for (auto *fields : {&v4_fields, &v6_fields}) {
      fields->push_back (start_field);
      fields->push_back (end_field);
      fields->insert (fields->end(), kCommonFields.begin(), kCommonFields.end());
    }
    std::vector<IpfixFieldSpec> v4_icmp_fields = v4_fields;
    std::vector<IpfixFieldSpec> v6_icmp_fields = v6_fields;

    v4_fields.push_back ({7, 2});
    v4_fields.push_back ({11, 2});
    v4_fields.push_back ({4, 1});
    v4_fields.push_back ({6, 1});
    v4_fields.push_back ({60, 1});
    v4_fields.push_back ({5, 1});

    v6_fields.push_back ({7, 2});
    v6_fields.push_back ({11, 2});
    v6_fields.push_back ({4, 1});
    v6_fields.push_back ({6, 1});
    v6_fields.push_back ({60, 1});
    v6_fields.push_back ({5, 1});

    v4_icmp_fields.push_back ({32, 2});  // icmpTypeCodeIPv4
    v4_icmp_fields.push_back ({4, 1});
    v4_icmp_fields.push_back ({60, 1});
    v4_icmp_fields.push_back ({5, 1});

    v6_icmp_fields.push_back ({139, 2});  // icmpTypeCodeIPv6
    v6_icmp_fields.push_back ({4, 1});
    v6_icmp_fields.push_back ({60, 1});
    v6_icmp_fields.push_back ({5, 1});

    for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
      if (track_level_ >= TrackLevel::FullVlan) {
        fields->push_back ({58, 2});  // vlanId
        fields->push_back ({59, 2});  // postVlanId
      }
      if (track_level_ >= TrackLevel::FullVlanEther) {
        fields->push_back ({56, 6});  // sourceMacAddress
        fields->push_back ({57, 6});  // postDestinationMacAddress
      }
    }
    for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
      const IpfixFieldSpec mpls{static_cast<std::uint16_t> (70 + i), 3};
      for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
        fields->push_back (mpls);
      }
    }

    const IpfixFieldSpec reverse_octets{1, 4, kIpfixReversePen};
    const IpfixFieldSpec reverse_packets{2, 4, kIpfixReversePen};
    const IpfixFieldSpec reverse_tos{5, 1, kIpfixReversePen};
    const IpfixFieldSpec reverse_tcp_flags{6, 1, kIpfixReversePen};
    const IpfixFieldSpec reverse_icmp4{32, 2, kIpfixReversePen};
    const IpfixFieldSpec reverse_icmp6{139, 2, kIpfixReversePen};
    for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
      fields->push_back (reverse_octets);
      fields->push_back (reverse_packets);
      fields->push_back (reverse_tos);
    }
    v4_fields.push_back (reverse_tcp_flags);
    v6_fields.push_back (reverse_tcp_flags);
    v4_icmp_fields.push_back (reverse_icmp4);
    v6_icmp_fields.push_back (reverse_icmp6);

    write_template (kIpfixTemplateIdV4, v4_fields);
    write_template (kIpfixTemplateIdIcmpV4, v4_icmp_fields);
    write_template (kIpfixTemplateIdV6, v6_fields);
    write_template (kIpfixTemplateIdIcmpV6, v6_icmp_fields);
  }
}

// Total on-wire size, in bytes, of one directional record for a given
// (is-v6, is-ICMP) combination -- addr + time + common(18) +
// transport(8)-or-icmp(5) + MPLS labels. See export_internal.hpp.
std::size_t
record_size (bool is_v6, bool is_icmp, IpfixTimeFormat time_format,
             std::uint8_t mpls_label_count, TrackLevel track_level) {
  const auto [start_field, end_field] = time_field_pair (time_format);
  const std::size_t addr_size = is_v6 ? 32 : 8;
  const std::size_t time_size =
    static_cast<std::size_t> (start_field.length) + end_field.length;
  constexpr std::size_t kCommonSize = 18;
  const std::size_t transport_or_icmp_size = is_icmp ? 5 : 8;
  return addr_size + time_size + kCommonSize + transport_or_icmp_size +
         l2_size (track_level) + static_cast<std::size_t> (mpls_label_count) * 3;
}

}  // namespace softflowd_cpp
