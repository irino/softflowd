// Original files: psamp.c, psamp.h
//
// PSAMP (RFC 5477) reports individual *sampled packets*, not aggregated
// flow statistics -- it reuses the IPFIX message framing (RFC 7011) but
// with a different set of Information Elements describing one observed
// packet at a time. This is a meaningfully different shape of input than
// the ExportRecord (aggregated Flow + FlowKey) used by netflow1/5/9.hpp
// and ipfix.hpp: PSAMP naturally consumes something closer to a
// ParsedPacket (see softflowd.hpp) plus its capture timestamp and
// on-the-wire length, taken directly from the packet-capture pipeline
// rather than from FlowTable.
//
// Simplification note: full RFC 5477 defines Information Elements for
// selector process identification, packet hashes, and raw packet content
// that this implementation does not attempt to reproduce. The template
// below reports a practically useful subset (timestamp, addresses, ports,
// protocol, ToS, observed length) sufficient to demonstrate PSAMP's
// per-packet (rather than per-flow) reporting model using genuine IPFIX
// framing and Information Elements from the IANA registry.
#ifndef SOFTFLOW_PSAMP_HPP
#define SOFTFLOW_PSAMP_HPP

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "softflow/ipfix.hpp"
#include "softflow/softflowd.hpp"

namespace softflow {

// Original: psamp.c's per-packet sample record, built from the same
// packet-parsing step that also feeds FlowTable::record_packet() (see
// PacketParser in softflowd.hpp). Kept separate from ParsedPacket itself
// since PSAMP additionally needs the capture timestamp and the packet's
// on-the-wire length (ParsedPacket only describes header fields).
struct SampledPacket {
    IpAddress src;
    IpAddress dst;
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    std::uint8_t protocol{0};
    std::uint8_t tos{0};
    std::uint32_t observed_length{0}; // on-the-wire length of this one packet
    TimePoint observed_at{};
};

// Original: the glue in softflowd.c that turned a just-parsed packet into
// a PSAMP sample record for selectors configured to sample-and-report
// (rather than only feed flow tracking).
SampledPacket make_sampled_packet(const ParsedPacket& packet,
                                   std::uint32_t observed_length,
                                   TimePoint observed_at);

inline constexpr std::uint16_t kPsampTemplateIdV4 = 512;
inline constexpr std::uint16_t kPsampTemplateIdV6 = 513;
inline constexpr std::size_t kPsampMaxV4RecordsPerSet = 25;
inline constexpr std::size_t kPsampMaxV6RecordsPerSet = 15;
inline constexpr std::uint32_t kPsampTemplateResendInterval = 20;

class PsampExporter {
public:
    // As with IpfixExporter, no boot_time is needed: PSAMP records here
    // carry an absolute observation time rather than a device-uptime-
    // relative one. time_format corresponds to the same -A option
    // IpfixExporter accepts (see ipfix.hpp's IpfixTimeFormat).
    explicit PsampExporter(std::uint32_t observation_domain_id = 0,
                            IpfixTimeFormat time_format = IpfixTimeFormat::Milliseconds)
        : observation_domain_id_(observation_domain_id), time_format_(time_format) {}

    // now/wall_now play the same role as in IpfixExporter::build_packets()
    // -- converting each sample's monotonic observed_at into an absolute
    // observationTimeMilliseconds value.
    std::vector<std::vector<std::uint8_t>>
    build_packets(std::span<const SampledPacket> samples, TimePoint now,
                  std::chrono::system_clock::time_point wall_now);

    std::uint32_t sequence() const noexcept { return sequence_; }

private:
    void write_header(ByteWriter& writer, std::uint16_t message_length,
                       std::chrono::system_clock::time_point wall_now) const;
    void write_template_set(ByteWriter& writer) const;

    std::uint32_t observation_domain_id_;
    IpfixTimeFormat time_format_;
    std::uint32_t sequence_{0};
    std::uint32_t packets_since_template_{0};
};

// Original: -R receive_port. softflowd can act as a PSAMP *collector*,
// receiving samples from another exporter (over UDP, in the same
// IPFIX/PSAMP message framing PsampExporter produces) and feeding them
// into local flow tracking as an alternative to -i/-r's own packet
// capture.
//
// Simplification note: this decoder handles the general IPFIX Template
// Set / Data Set structure (so it can, in principle, decode messages from
// any well-formed IPFIX-framed PSAMP exporter, not only this project's
// own PsampExporter), but only extracts the specific Information Elements
// this project's own template uses semantically (addresses, ports,
// protocol, ToS, observation time, and octetDeltaCount as a stand-in for
// packet length -- see PsampExporter's own header comment on this
// simplification). Fields it doesn't recognize are skipped over using
// their declared length rather than causing a decode failure, so a
// message with additional, unrecognized fields still decodes the fields
// this project does understand.
class PsampReceiver {
public:
    // Decodes one received UDP payload. `source_id` scopes this message's
    // Template Set / Data Set to whichever exporter sent it -- typically
    // the sender's address (and, since a NetFlow/IPFIX/PSAMP exporter
    // normally sends every packet from the same bound source port for its
    // whole lifetime, its port too), formatted as a string by the caller.
    // Without this, two different exporters happening to both use, say,
    // template ID 256 for two *different* record layouts (entirely
    // possible: template IDs only need to be unique per exporter, not
    // globally) would silently corrupt each other's decoded data. Pass an
    // empty string if only ever receiving from a single known exporter
    // and this scoping isn't needed.
    //
    // Returns any Data Records successfully decoded as SampledPacket
    // values (in the order they appeared); returns an empty vector for a
    // payload that isn't a recognizable IPFIX message, or one containing
    // only Template Sets. Malformed input never throws -- a single
    // corrupt or unrelated UDP datagram arriving on the receive port
    // shouldn't be able to crash a long-running daemon.
    std::vector<SampledPacket> decode_message(std::span<const std::uint8_t> data,
                                                TimePoint received_at,
                                                const std::string& source_id = "");

    // Number of distinct (source, template ID) pairs currently being
    // tracked -- exposed mainly for diagnostics/testing.
    std::size_t template_count() const noexcept { return templates_.size(); }

private:
    struct FieldInfo {
        std::uint16_t type;
        std::uint16_t length;
    };
    struct TemplateKey {
        std::string source_id;
        std::uint16_t template_id;

        friend bool operator==(const TemplateKey&, const TemplateKey&) = default;
    };
    struct TemplateKeyHash {
        std::size_t operator()(const TemplateKey& k) const noexcept {
            return std::hash<std::string>{}(k.source_id) ^
                   (std::hash<std::uint16_t>{}(k.template_id) << 1);
        }
    };

    void decode_template_set(std::span<const std::uint8_t> set_body,
                              const std::string& source_id);
    std::optional<SampledPacket>
    decode_record(std::span<const std::uint8_t> record,
                   const std::vector<FieldInfo>& fields, TimePoint received_at);

    std::unordered_map<TemplateKey, std::vector<FieldInfo>, TemplateKeyHash> templates_;
};

} // namespace softflow

#endif // SOFTFLOW_PSAMP_HPP
