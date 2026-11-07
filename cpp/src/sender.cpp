/**
 * @file sender.cpp
 * @brief The export of the flows that expired: the exporters, the destinations and the export thread of -M.
 *
 * Split from softflowd.cpp. See sender.hpp.
 */
#include "softflowd_cpp/sender.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace softflowd_cpp {

namespace {

/**
 * @brief Writes export packets to a file, each after its length as 4 bytes in big-endian order.
 *
 * A script can thus split the file into the packets without knowing the protocol. It is the --export-out file of this project; the original has no such file.
 *
 * Writes each export packet to `path` with a simple 4-byte big-endian
 * length prefix, so a human or a small script can split the file back
 * into individual UDP payloads without needing to parse each protocol's
 * framing just to find record boundaries. This is specific to this
 * project's own debug/demo output file, not part of any of the wire
 * protocols themselves, and not part of the original softflowd (which
 * only ever sends export packets over the network via -n).
 *
 * @param path The file.
 * @param packets The packets; nothing is written, and the file is not touched, when there are none.
 * @param append true to append to the file, and false to start it anew.
 * @throw std::runtime_error when the file cannot be opened.
 */
void
write_framed_packets (const std::string &path,
                      const std::vector<std::vector<std::uint8_t>> &packets,
                      bool append) {
  if (packets.empty()) {
    return;
  }
  std::FILE *f = std::fopen (path.c_str(), append ? "ab" : "wb");
  if (f == nullptr) {
    throw std::runtime_error ("failed to open '" + path + "' for writing");
  }
  struct FileCloser {
    std::FILE *file;
    ~FileCloser () {
      if (file != nullptr) {
        std::fclose (file);
      }
    }
  } closer{f};

  for (const auto &pkt : packets) {
    const std::uint32_t len = static_cast<std::uint32_t> (pkt.size());
    const std::uint8_t len_be[4] = {
      static_cast<std::uint8_t> (len >> 24),
      static_cast<std::uint8_t> (len >> 16),
      static_cast<std::uint8_t> (len >> 8),
      static_cast<std::uint8_t> (len),
    };
    std::fwrite (len_be, 1, sizeof (len_be), f);
    std::fwrite (pkt.data(), 1, pkt.size(), f);
  }
}

}  // namespace

ExportPipeline::ExportPipeline (const DaemonConfig &config, softflowd_cpp::TimePoint boot_time)
    : format_ (config.export_format), gauge_clock_ (config.gauge_clock),
      multithread_ (config.multithread),
      biflow_ (config.bidirectional_ipfix) {
  const auto transport_kind = [&] {
    switch (config.transport) {
      case TransportProtocol::Udp:
        return softflowd_cpp::TransportKind::Udp;
      case TransportProtocol::Tcp:
        return softflowd_cpp::TransportKind::Tcp;
      case TransportProtocol::Sctp:
        return softflowd_cpp::TransportKind::Sctp;
    }
    return softflowd_cpp::TransportKind::Udp;
  }();

  if (format_ == ExportFormat::Ntopng) {
    // Original: connect_ntopng () for every -n destination, in place of
    // the datagram sockets.
    ntopng_.emplace (config.track_level);
#ifdef SOFTFLOWD_CPP_HAVE_ZMQ
    for (const auto &[host, port] : config.destinations) {
      ntopng_sinks_.emplace_back (host, port);
    }
#endif
  }
  for (const auto &[host, port] : format_ == ExportFormat::Ntopng
                                    ? decltype (config.destinations){}
                                    : config.destinations) {
    try {
      destinations_.add (softflowd_cpp::ExportDestination (
        host, port, transport_kind, config.ttl,
        config.source_address, config.send_interface));
    } catch (const softflowd_cpp::ExportError &e) {
      if (config.transport == TransportProtocol::Sctp) {
        // Original: -P sctp. SCTP support depends on kernel
        // module availability, which isn't guaranteed, so a
        // failure here falls back to UDP rather than
        // preventing the daemon from starting at all.
        std::fprintf (stderr,
                      "warning: SCTP export to '%s:%s' failed "
                      "(%s); falling back to udp\n",
                      host.c_str(), port.c_str(), e.what());
        destinations_.add (softflowd_cpp::ExportDestination (
          host, port, softflowd_cpp::TransportKind::Udp, config.ttl,
          config.source_address, config.send_interface));
      } else {
        throw;
      }
    }
  }
  load_balance_ = config.load_balance;

  if (!config.export_out.empty()) {
    export_out_ = config.export_out;
    write_framed_packets (export_out_, {}, /*append=*/false);  // truncate/create
  }

  switch (format_) {
    case ExportFormat::Netflow1:
      netflow1_.emplace (boot_time, config.debug, config.if_index);
      break;
    case ExportFormat::Netflow5:
      netflow5_.emplace (boot_time, config.debug, config.sampling_rate,
                         config.if_index);
      break;
    case ExportFormat::Netflow9:
    case ExportFormat::Ipfix:
      // Original: send_netflow_v9() and send_ipfix() share
      // send_ipfix_flows().
      ipfix_.emplace (/*observation_domain_id=*/0,
                      static_cast<std::uint8_t> (config.mpls_labels),
                      to_ipfix_time_format (config.time_format),
                      config.bidirectional_ipfix, boot_time,
                      std::chrono::system_clock::now(),
                      format_ == ExportFormat::Netflow9
                        ? softflowd_cpp::MessageVersion::NetFlow9
                        : softflowd_cpp::MessageVersion::Ipfix,
                      config.if_index, config.sampling_rate, config.track_level);
      if (config.direction_mac.has_value() &&
          config.track_level >= softflowd_cpp::TrackLevel::FullVlanEther) {
        ipfix_->set_direction_mac (*config.direction_mac);
      }
      if (!config.source_address.empty()) {
        ipfix_->set_exporter_addresses (
          softflowd_cpp::resolve_exporter_addresses (config.source_address));
      }
      break;
    case ExportFormat::Psamp:
      psamp_.emplace (/*observation_domain_id=*/0);
      break;
    case ExportFormat::Ntopng:  // set up above
    case ExportFormat::None:
      break;
  }
}

ExportPipeline::~ExportPipeline () {
  // Original: wait_for_export_threads () before the process exits.
  if (worker_.joinable()) {
    {
      std::lock_guard<std::mutex> lock (queue_mutex_);
      stop_ = true;
    }
    queue_cv_.notify_all();
    worker_.join();
  }
}

std::size_t
ExportPipeline::ntopng_sink_count () const noexcept {
#ifdef SOFTFLOWD_CPP_HAVE_ZMQ
  return ntopng_sinks_.size();
#else
  return 0;
#endif
}

bool
ExportPipeline::resend_template () {
  std::lock_guard<std::mutex> state_lock (state_mutex_);
  if (ipfix_.has_value()) {
    ipfix_->force_template_resend();
    return true;
  }
  return false;
}

void
ExportPipeline::reinit_boot_time (softflowd_cpp::TimePoint now,
                                  std::chrono::system_clock::time_point wall_now) {
  std::lock_guard<std::mutex> state_lock (state_mutex_);
  if (netflow1_.has_value())
    netflow1_->set_boot_time (now);
  if (netflow5_.has_value())
    netflow5_->set_boot_time (now);
  if (ipfix_.has_value()) {
    ipfix_->set_boot_time (now, wall_now);
  }
}

ExportPipeline::ExportOutcome
ExportPipeline::export_flows (const std::vector<softflowd_cpp::ExportRecord> &records,
                              softflowd_cpp::TimePoint now,
                              std::chrono::system_clock::time_point wall_now) {
  if (!multithread_) {
    return export_now (records, now, wall_now);
  }
  if (records.empty() || !wants_flows()) {
    return {};
  }
  {
    std::lock_guard<std::mutex> lock (queue_mutex_);
    if (!worker_.joinable()) {
      worker_ = std::thread ([this] { export_thread(); });
    }
    queue_.push_back (Job{records, now, wall_now});
  }
  queue_cv_.notify_one();
  return {};
}

void
ExportPipeline::export_thread () {
  std::unique_lock<std::mutex> lock (queue_mutex_);
  for (;;) {
    queue_cv_.wait (lock, [&] { return stop_ || !queue_.empty(); });
    if (queue_.empty()) {
      return;  // stopped and drained
    }
    Job job = std::move (queue_.front());
    queue_.pop_front();
    busy_ = true;
    lock.unlock();
    const ExportOutcome o = export_now (job.records, job.now, job.wall_now);
    lock.lock();
    async_outcome_.flows += o.flows;
    async_outcome_.records += o.records;
    async_outcome_.packets += o.packets;
    async_outcome_.failures += o.failures;
    busy_ = false;
    idle_cv_.notify_all();
  }
}

ExportPipeline::ExportOutcome
ExportPipeline::export_ntopng (const std::vector<softflowd_cpp::ExportRecord> &records,
                               softflowd_cpp::TimePoint now,
                               std::chrono::system_clock::time_point wall_now) {
  const auto messages = ntopng_->build_messages (records, now, wall_now);
  ExportOutcome outcome;
  outcome.records = records.size();
  outcome.packets = messages.size();
#ifdef SOFTFLOWD_CPP_HAVE_ZMQ
  for (const auto &message : messages) {
    for (auto &sink : ntopng_sinks_) {
      sink.send (message);
    }
  }
#endif
  return outcome;
}

ExportPipeline::ExportOutcome
ExportPipeline::export_now (const std::vector<softflowd_cpp::ExportRecord> &records,
                            softflowd_cpp::TimePoint now,
                            std::chrono::system_clock::time_point wall_now) {
  std::lock_guard<std::mutex> state_lock (state_mutex_);
  if (records.empty() || !wants_flows()) {
    return {};
  }
  // Original: -g also reports the CPU clocks spent in the export function.
  struct ExportClock {
    bool enabled;
    std::clock_t &total;
    unsigned long &calls;
    std::clock_t start;
    ~ExportClock () {
      if (enabled) {
        total += std::clock() - start;
        ++calls;
      }
    }
  } export_clock{gauge_clock_, export_clocks_, export_calls_,
                 gauge_clock_ ? std::clock() : 0};
  if (format_ == ExportFormat::Ntopng) {
    return export_ntopng (records, now, wall_now);
  }
  std::vector<std::vector<std::uint8_t>> packets;
  std::vector<std::size_t> template_only;
  switch (format_) {
    case ExportFormat::Netflow1:
      packets = netflow1_->build_packets (records, now, wall_now);
      break;
    case ExportFormat::Netflow5:
      packets = netflow5_->build_packets (records, now, wall_now);
      break;
    case ExportFormat::Netflow9:
    case ExportFormat::Ipfix:
      // Original: with -l and several destinations the templates go to
      // all of them in a packet of their own.
      packets = ipfix_->build_packets (
        records, now, wall_now,
        load_balance_ && destinations_.size() > 1 ? &template_only : nullptr);
      break;
    case ExportFormat::Psamp:
    case ExportFormat::Ntopng:
    case ExportFormat::None:
      break;
  }
  dispatch (packets, template_only);
  // Original: NetFlow v1/v5/v9 and IPFIX (non-biflow) each split a
  // single (bidirectional) internal flow into up to two exported
  // records -- one per direction that actually carried traffic
  // (softflowd.c's `if (flows[i]->octets[0] > 0) {...}` /
  // `octets[1] > 0` in compat/netflow5.c, mirrored by this project's own
  // flatten() helpers in export.cpp). So "records sent" is *not* the same as the number
  // of input flows -- count directions with packets independently.
  // Original: with -b, bidir_func () makes one record of each flow.
  std::uint64_t record_count = 0;
  for (const auto &r : records) {
    record_count += biflow_ && format_ == ExportFormat::Ipfix
                      ? 1u
                      : (r.flow.packets[0] > 0 ? 1u : 0u) +
                          (r.flow.packets[1] > 0 ? 1u : 0u);
  }
  // No per-record encoding failures are currently detectable, and
  // send_packet() doesn't report per-destination failures -- so
  // failures is always 0 for now.
  //
  // Original: compat/netflow5.c's send_netflow_v5_v1() (used for both -v1
  // and -v5) increments *both* `flows_exported` and `records_sent`
  // via the *same* per-record `j++` -- i.e. for those two formats,
  // "flows exported" and "records sent" are identical counts, not
  // flows-before-splitting vs records-after.
  //
  // compat/netflow9.c's send_netflow_v9() and export_common.c's
  // send_ipfix_flows() do NOT follow this: their outer packing
  // loop does `j += i;` where `i` is the index over the *original*
  // (pre-split) flows array, while `records_sent`/`nf9->flows`
  // separately accumulate the actual per-direction record count
  // returned by nf_flow_to_flowset()/ipfix_flow_to_flowset(). So
  // for v9/IPFIX, "flows exported" counts original flows and
  // "records sent" counts post-split records -- these two counts
  // genuinely differ whenever any flow has traffic in both
  // directions, unlike v1/v5.
  const bool flows_equals_records =
    format_ == ExportFormat::Netflow1 || format_ == ExportFormat::Netflow5;
  const std::uint64_t flow_count =
    flows_equals_records ? record_count : records.size();
  return ExportOutcome{flow_count, record_count, packets.size(), 0};
}

void
ExportPipeline::export_psamp (const softflowd_cpp::PsampSample &sample, bool adjust_time) {
  std::lock_guard<std::mutex> state_lock (state_mutex_);
  if (!wants_samples()) {
    return;
  }
  std::vector<std::size_t> template_only;
  const auto packets = psamp_->build_packets (
    sample, std::chrono::system_clock::now(), adjust_time, &template_only);
  dispatch (packets, template_only);
}

void
ExportPipeline::dispatch (const std::vector<std::vector<std::uint8_t>> &packets,
                          const std::vector<std::size_t> &to_all_destinations) {
  if (packets.empty()) {
    return;
  }
  for (std::size_t i = 0; i < packets.size(); ++i) {
    // A template-only packet goes to every destination even with -l.
    const bool to_all =
      std::find (to_all_destinations.begin(), to_all_destinations.end(), i) !=
      to_all_destinations.end();
    destinations_.send_packet (packets[i], load_balance_ && !to_all);
  }
  if (!export_out_.empty()) {
    write_framed_packets (export_out_, packets, /*append=*/true);
  }
}

}  // namespace softflowd_cpp
