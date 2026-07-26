#include "softflow/psamp.hpp"

#include <algorithm>

namespace softflow {

SampledPacket make_sampled_packet(const ParsedPacket& packet,
                                   std::uint32_t observed_length,
                                   TimePoint observed_at) {
    SampledPacket sample;
    sample.src = packet.src;
    sample.dst = packet.dst;
    sample.src_port = packet.src_port;
    sample.dst_port = packet.dst_port;
    sample.protocol = packet.protocol;
    sample.tos = packet.tos;
    sample.observed_length = observed_length;
    sample.observed_at = observed_at;
    return sample;
}

namespace {

void finish_set(ByteWriter& writer, std::size_t set_start) {
    const std::size_t raw_length = writer.size() - set_start;
    const std::size_t pad = (4 - (raw_length % 4)) % 4;
    for (std::size_t i = 0; i < pad; ++i) {
        writer.put_u8(0);
    }
    writer.patch_u16(set_start + 2, static_cast<std::uint16_t>(raw_length + pad));
}

// See ipfix.cpp's identically-named helpers for the rationale; duplicated
// here rather than shared, matching this project's file boundaries (see
// psamp.hpp's header comment on why PSAMP is its own file rather than
// folded into ipfix.*).
std::uint64_t epoch_ms(TimePoint now,
                        std::chrono::system_clock::time_point wall_now,
                        TimePoint t) {
    const auto age = now - t;
    const auto wall_t = wall_now - age;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        wall_t.time_since_epoch());
    return static_cast<std::uint64_t>(std::max<std::int64_t>(0, ms.count()));
}

std::uint64_t epoch_ms_to_ntp64(std::uint64_t epoch_ms_value) {
    constexpr std::uint64_t kNtpEpochOffsetSeconds = 2208988800ULL;
    const std::uint64_t seconds = epoch_ms_value / 1000;
    const std::uint64_t ms_remainder = epoch_ms_value % 1000;
    const auto ntp_seconds = static_cast<std::uint32_t>(seconds + kNtpEpochOffsetSeconds);
    const auto ntp_fraction =
        static_cast<std::uint32_t>((ms_remainder * 4294967296ULL) / 1000ULL);
    return (static_cast<std::uint64_t>(ntp_seconds) << 32) | ntp_fraction;
}

// Original: -A time_format. 322/323/324/325 = observationTimeSeconds/
// Milliseconds/Microseconds/Nanoseconds (the PSAMP/IPFIX Information
// Element registry's single-timestamp counterparts to flowStart*/
// flowEnd*; see ipfix.cpp's time_field_pair() for the two-timestamp
// version and the NTP-encoding rationale for micro/nano).
struct TimeField {
    std::uint16_t type;
    std::uint16_t length;
};

TimeField observation_time_field(IpfixTimeFormat format) {
    switch (format) {
    case IpfixTimeFormat::Seconds:
        return {322, 4};
    case IpfixTimeFormat::Milliseconds:
        return {323, 8};
    case IpfixTimeFormat::Microseconds:
        return {324, 8};
    case IpfixTimeFormat::Nanoseconds:
        return {325, 8};
    }
    return {323, 8};
}

void write_observation_time(ByteWriter& writer, IpfixTimeFormat format,
                             TimePoint now,
                             std::chrono::system_clock::time_point wall_now,
                             TimePoint observed_at) {
    const std::uint64_t ms = epoch_ms(now, wall_now, observed_at);
    switch (format) {
    case IpfixTimeFormat::Seconds:
        writer.put_u32(static_cast<std::uint32_t>(ms / 1000));
        break;
    case IpfixTimeFormat::Milliseconds:
        writer.put_u64(ms);
        break;
    case IpfixTimeFormat::Microseconds:
    case IpfixTimeFormat::Nanoseconds:
        writer.put_u64(epoch_ms_to_ntp64(ms));
        break;
    }
}

void write_v4_record(ByteWriter& writer, const SampledPacket& s,
                      IpfixTimeFormat time_format, TimePoint now,
                      std::chrono::system_clock::time_point wall_now) {
    write_observation_time(writer, time_format, now, wall_now, s.observed_at);
    writer.put_u8(4);                                        // ipVersion
    writer.put_u8(s.protocol);                                // protocolIdentifier
    writer.put_u8(s.tos);                                     // ipClassOfService
    writer.put_u16(s.src_port);                                // sourceTransportPort
    writer.put_ipv4(s.src);                                    // sourceIPv4Address
    writer.put_u16(s.dst_port);                                // destinationTransportPort
    writer.put_ipv4(s.dst);                                    // destinationIPv4Address
    writer.put_u32(s.observed_length);                         // octetDeltaCount (this packet's length)
}

void write_v6_record(ByteWriter& writer, const SampledPacket& s,
                      IpfixTimeFormat time_format, TimePoint now,
                      std::chrono::system_clock::time_point wall_now) {
    write_observation_time(writer, time_format, now, wall_now, s.observed_at);
    writer.put_u8(6); // ipVersion
    writer.put_u8(s.protocol);
    writer.put_u8(s.tos);
    writer.put_u16(s.src_port);
    writer.put_ipv6(s.src);
    writer.put_u16(s.dst_port);
    writer.put_ipv6(s.dst);
    writer.put_u32(s.observed_length);
}

} // namespace

void PsampExporter::write_header(
    ByteWriter& writer, std::uint16_t message_length,
    std::chrono::system_clock::time_point wall_now) const {
    const auto export_time = std::chrono::system_clock::to_time_t(wall_now);

    // PSAMP (RFC 5477) reuses the IPFIX message header verbatim.
    writer.put_u16(10); // version
    writer.put_u16(message_length);
    writer.put_u32(static_cast<std::uint32_t>(export_time));
    writer.put_u32(sequence_);
    writer.put_u32(observation_domain_id_);
}

void PsampExporter::write_template_set(ByteWriter& writer) const {
    const std::size_t set_start = writer.size();
    writer.put_u16(2); // IPFIX Template Set ID
    writer.put_u16(0); // Length placeholder

    const auto write_template = [&](std::uint16_t template_id,
                                     std::span<const TimeField> fields) {
        writer.put_u16(template_id);
        writer.put_u16(static_cast<std::uint16_t>(fields.size()));
        for (const auto& f : fields) {
            writer.put_u16(f.type);
            writer.put_u16(f.length);
        }
    };

    const auto time_field = observation_time_field(time_format_);

    // Field order must exactly match write_v4_record()/write_v6_record().
    // 60 = ipVersion, 4 = protocolIdentifier, 5 = ipClassOfService, 7/11 =
    // source/destination transport port, 8/12 = source/destination IPv4
    // address, 27/28 = source/destination IPv6 address, 1 =
    // octetDeltaCount (reused here to report this single sampled packet's
    // on-the-wire length -- see psamp.hpp's header comment on this
    // simplification).
    const TimeField kIpv4Fields[] = {
        time_field, {60, 1}, {4, 1}, {5, 1},
        {7, 2},     {8, 4},  {11, 2}, {12, 4},
        {1, 4},
    };
    write_template(kPsampTemplateIdV4, kIpv4Fields);

    const TimeField kIpv6Fields[] = {
        time_field, {60, 1}, {4, 1},   {5, 1},
        {7, 2},     {27, 16}, {11, 2}, {28, 16},
        {1, 4},
    };
    write_template(kPsampTemplateIdV6, kIpv6Fields);

    finish_set(writer, set_start);
}

std::vector<std::vector<std::uint8_t>>
PsampExporter::build_packets(
    std::span<const SampledPacket> samples, TimePoint now,
    std::chrono::system_clock::time_point wall_now) {
    std::vector<const SampledPacket*> v4, v6;
    for (const auto& s : samples) {
        if (s.src.family == AddressFamily::IPv4) {
            v4.push_back(&s);
        } else {
            v6.push_back(&s);
        }
    }

    std::vector<std::vector<std::uint8_t>> packets;
    std::size_t v4_idx = 0, v6_idx = 0;

    while (v4_idx < v4.size() || v6_idx < v6.size()) {
        ByteWriter body;
        std::uint32_t data_records_in_packet = 0;

        const bool send_template = (packets_since_template_ == 0);
        if (send_template) {
            write_template_set(body);
        }

        if (v4_idx < v4.size()) {
            const std::size_t chunk =
                std::min(kPsampMaxV4RecordsPerSet, v4.size() - v4_idx);
            const std::size_t set_start = body.size();
            body.put_u16(kPsampTemplateIdV4);
            body.put_u16(0);
            for (std::size_t i = 0; i < chunk; ++i) {
                write_v4_record(body, *v4[v4_idx + i], time_format_, now, wall_now);
            }
            finish_set(body, set_start);
            data_records_in_packet += static_cast<std::uint32_t>(chunk);
            v4_idx += chunk;
        }

        if (v6_idx < v6.size()) {
            const std::size_t chunk =
                std::min(kPsampMaxV6RecordsPerSet, v6.size() - v6_idx);
            const std::size_t set_start = body.size();
            body.put_u16(kPsampTemplateIdV6);
            body.put_u16(0);
            for (std::size_t i = 0; i < chunk; ++i) {
                write_v6_record(body, *v6[v6_idx + i], time_format_, now, wall_now);
            }
            finish_set(body, set_start);
            data_records_in_packet += static_cast<std::uint32_t>(chunk);
            v6_idx += chunk;
        }

        ByteWriter packet;
        const std::uint16_t message_length =
            static_cast<std::uint16_t>(16 + body.size());
        write_header(packet, message_length, wall_now);
        packet.put_bytes(body.bytes());
        packets.push_back(packet.take());

        sequence_ += data_records_in_packet;
        packets_since_template_ =
            send_template ? 1 : packets_since_template_ + 1;
        if (packets_since_template_ >= kPsampTemplateResendInterval) {
            packets_since_template_ = 0;
        }
    }

    return packets;
}

// =======================================================================
// PsampReceiver (original: -R receive_port)
// =======================================================================

namespace {

std::uint16_t read_u16_at(std::span<const std::uint8_t> data, std::size_t offset) {
    return static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
}

std::uint32_t read_u32_at(std::span<const std::uint8_t> data, std::size_t offset) {
    return (static_cast<std::uint32_t>(data[offset]) << 24) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
           static_cast<std::uint32_t>(data[offset + 3]);
}

std::uint64_t read_u64_at(std::span<const std::uint8_t> data, std::size_t offset) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | data[offset + static_cast<std::size_t>(i)];
    }
    return v;
}

// Inverse of ipfix.cpp's epoch_ms_to_ntp64(): recovers an epoch
// millisecond value from the 64-bit NTP short format.
std::uint64_t ntp64_to_epoch_ms(std::uint64_t ntp64) {
    constexpr std::uint64_t kNtpEpochOffsetSeconds = 2208988800ULL;
    const auto ntp_seconds = static_cast<std::uint32_t>(ntp64 >> 32);
    const auto ntp_fraction = static_cast<std::uint32_t>(ntp64 & 0xFFFFFFFFu);
    const std::uint64_t unix_seconds =
        static_cast<std::uint64_t>(ntp_seconds) - kNtpEpochOffsetSeconds;
    const std::uint64_t ms_remainder =
        (static_cast<std::uint64_t>(ntp_fraction) * 1000ULL) / 4294967296ULL;
    return unix_seconds * 1000 + ms_remainder;
}

// Converts an epoch-millisecond timestamp carried in a received record
// into a TimePoint in this process's own monotonic Clock domain, anchored
// at `received_at` (this process's monotonic time when the UDP datagram
// arrived) and the current wall-clock time (sampled fresh here, since
// decode_record() doesn't otherwise have access to the wall clock at the
// moment the datagram was received). This is the receive-side mirror of
// ipfix.cpp's epoch_ms() helper, which performs the equivalent conversion
// in the opposite direction when exporting.
TimePoint monotonic_time_for_epoch_ms(TimePoint received_at,
                                       std::uint64_t epoch_ms_value) {
    const auto wall_now = std::chrono::system_clock::now();
    const auto wall_now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        wall_now.time_since_epoch());
    const auto age_ms = wall_now_ms.count() - static_cast<std::int64_t>(epoch_ms_value);
    return received_at - std::chrono::duration_cast<Clock::duration>(
                              std::chrono::milliseconds(age_ms));
}

} // namespace

void PsampReceiver::decode_template_set(std::span<const std::uint8_t> set_body,
                                          const std::string& source_id) {
    std::size_t offset = 0;
    while (offset + 4 <= set_body.size()) {
        const std::uint16_t template_id = read_u16_at(set_body, offset);
        const std::uint16_t field_count = read_u16_at(set_body, offset + 2);
        offset += 4;

        std::vector<FieldInfo> fields;
        fields.reserve(field_count);
        for (std::uint16_t i = 0; i < field_count; ++i) {
            if (offset + 4 > set_body.size()) {
                return; // truncated template; stop decoding this message
            }
            std::uint16_t type = read_u16_at(set_body, offset);
            const std::uint16_t length = read_u16_at(set_body, offset + 2);
            offset += 4;
            if ((type & 0x8000u) != 0) {
                // Enterprise-specific Information Element: skip the
                // 4-byte Enterprise Number that follows. This receiver
                // doesn't interpret enterprise-specific fields
                // semantically (see decode_record()), only skips them by
                // their declared length, so the enterprise number itself
                // doesn't need to be retained.
                if (offset + 4 > set_body.size()) {
                    return;
                }
                offset += 4;
                type &= 0x7FFFu;
            }
            fields.push_back(FieldInfo{type, length});
        }
        // Scoped by source_id (see decode_message()'s header comment):
        // two different exporters are free to reuse the same numeric
        // template_id for entirely different record layouts, so the
        // template table must not conflate them.
        templates_[TemplateKey{source_id, template_id}] = std::move(fields);
    }
}

std::optional<SampledPacket>
PsampReceiver::decode_record(std::span<const std::uint8_t> record,
                              const std::vector<FieldInfo>& fields,
                              TimePoint received_at) {
    SampledPacket sample;
    sample.observed_at = received_at; // overwritten below if a time field is present
    bool have_src = false, have_dst = false;

    std::size_t offset = 0;
    for (const auto& field : fields) {
        if (offset + field.length > record.size()) {
            return std::nullopt; // record shorter than its template declares
        }
        const auto field_bytes = record.subspan(offset, field.length);

        switch (field.type) {
        case 8: // sourceIPv4Address
            sample.src.family = AddressFamily::IPv4;
            std::copy(field_bytes.begin(), field_bytes.end(), sample.src.bytes.begin());
            have_src = true;
            break;
        case 12: // destinationIPv4Address
            sample.dst.family = AddressFamily::IPv4;
            std::copy(field_bytes.begin(), field_bytes.end(), sample.dst.bytes.begin());
            have_dst = true;
            break;
        case 27: // sourceIPv6Address
            sample.src.family = AddressFamily::IPv6;
            std::copy(field_bytes.begin(), field_bytes.end(), sample.src.bytes.begin());
            have_src = true;
            break;
        case 28: // destinationIPv6Address
            sample.dst.family = AddressFamily::IPv6;
            std::copy(field_bytes.begin(), field_bytes.end(), sample.dst.bytes.begin());
            have_dst = true;
            break;
        case 7: // sourceTransportPort
            if (field.length == 2) sample.src_port = read_u16_at(record, offset);
            break;
        case 11: // destinationTransportPort
            if (field.length == 2) sample.dst_port = read_u16_at(record, offset);
            break;
        case 4: // protocolIdentifier
            if (field.length >= 1) sample.protocol = record[offset];
            break;
        case 5: // ipClassOfService
            if (field.length >= 1) sample.tos = record[offset];
            break;
        case 1: // octetDeltaCount (this project's stand-in for the sampled packet's length)
            if (field.length == 4) sample.observed_length = read_u32_at(record, offset);
            break;
        case 322: // observationTimeSeconds
            if (field.length == 4) {
                const std::uint64_t epoch_seconds = read_u32_at(record, offset);
                sample.observed_at = monotonic_time_for_epoch_ms(
                    received_at, epoch_seconds * 1000ULL);
            }
            break;
        case 323: // observationTimeMilliseconds
            if (field.length == 8) {
                const std::uint64_t epoch_ms_value = read_u64_at(record, offset);
                sample.observed_at =
                    monotonic_time_for_epoch_ms(received_at, epoch_ms_value);
            }
            break;
        case 324: // observationTimeMicroseconds
        case 325: // observationTimeNanoseconds
            if (field.length == 8) {
                const std::uint64_t ntp64 = read_u64_at(record, offset);
                sample.observed_at = monotonic_time_for_epoch_ms(
                    received_at, ntp64_to_epoch_ms(ntp64));
            }
            break;
        default:
            break; // unrecognized field: skip by length, decode what we do understand
        }
        offset += field.length;
    }

    if (!have_src || !have_dst) {
        return std::nullopt; // not enough information to be useful
    }
    return sample;
}

std::vector<SampledPacket>
PsampReceiver::decode_message(std::span<const std::uint8_t> data,
                                TimePoint received_at, const std::string& source_id) {
    std::vector<SampledPacket> samples;
    if (data.size() < 16) {
        return samples;
    }
    const std::uint16_t version = read_u16_at(data, 0);
    if (version != 10) {
        return samples; // not an IPFIX-framed message
    }
    const std::uint16_t message_length = read_u16_at(data, 2);
    const std::size_t effective_length = std::min<std::size_t>(message_length, data.size());

    std::size_t offset = 16;
    while (offset + 4 <= effective_length) {
        const std::uint16_t set_id = read_u16_at(data, offset);
        const std::uint16_t set_length = read_u16_at(data, offset + 2);
        if (set_length < 4 || offset + set_length > effective_length) {
            break; // malformed Set; stop decoding the rest of this message
        }
        const auto set_body = data.subspan(offset + 4, set_length - 4);

        if (set_id == 2) {
            decode_template_set(set_body, source_id);
        } else if (set_id >= 256) {
            const auto template_it = templates_.find(TemplateKey{source_id, set_id});
            if (template_it != templates_.end()) {
                std::size_t record_size = 0;
                for (const auto& f : template_it->second) {
                    record_size += f.length;
                }
                if (record_size > 0) {
                    std::size_t record_offset = 0;
                    while (record_offset + record_size <= set_body.size()) {
                        auto decoded = decode_record(
                            set_body.subspan(record_offset, record_size),
                            template_it->second, received_at);
                        if (decoded.has_value()) {
                            samples.push_back(*decoded);
                        }
                        record_offset += record_size;
                    }
                }
            }
            // An unknown template ID means this Data Set can't be decoded
            // (there's no way to know each field's meaning or even its
            // length without the template) -- it's skipped entirely
            // rather than guessed at.
        }

        offset += set_length;
    }

    return samples;
}

} // namespace softflow
