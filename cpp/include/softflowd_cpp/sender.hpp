/**
 * @file sender.hpp
 * @brief The export of the flows that expired: the exporters, the destinations and the export thread of -M.
 *
 * Split from softflowd.cpp. ExportPipeline gives the records of the expired
 * flows to the exporter of the chosen format and sends the packets to the
 * destinations, to the --export-out file, or to the ntopng sinks.
 *
 * @original send_multi_destinations (), send_threaded () and threaded_send ()
 * of softflowd.c, with the state of the export threads that sender.c keeps
 * private in the C version.
 */
#ifndef SOFTFLOWD_CPP_SENDER_HPP
#define SOFTFLOWD_CPP_SENDER_HPP

#include "softflowd_cpp/export.hpp"
#include "softflowd_cpp/netsock.hpp"
#include "softflowd_cpp/ntopng.hpp"
#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/psamp.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace softflowd_cpp {

/**
 * @brief Exports flows and PSAMP samples to the destinations, the --export-out file and ntopng, with the one exporter that -v chose.
 *
 * Owns exactly one of the five Stage 3 exporters (selected by -v),
 * this run's -n destinations (if any), and this project's own
 * --export-out file (if requested). Every place that needs to export
 * flows or PSAMP samples goes through this one object instead of
 * repeating the "which exporter, which destinations, which file" dispatch
 * logic at each call site.
 *
 * @original ExportPipeline (original: softflowd.c's per-destination NetFlow/IPFIX/ PSAMP state and send_multi_destinations())
 */
class ExportPipeline {
public:
  /**
   * @brief Makes the exporter of the format that -v chose, and opens the destinations (or the ntopng sinks) and the --export-out file.
   *
   * A destination that cannot be opened throws a softflowd_cpp::ExportError; for -P sctp it only prints a warning and falls back to UDP.
   *
   * @param config The settings.
   * @param boot_time The time when the exporter started, which SysUpTime counts from.
   */
  ExportPipeline (const DaemonConfig &config, softflowd_cpp::TimePoint boot_time);

  ExportPipeline (const ExportPipeline &) = delete;
  ExportPipeline &
  operator= (const ExportPipeline &) = delete;

  ~ExportPipeline ();

  /**
   * @brief Waits until every export that -M queued has been sent.
   *
   * @original wait_for_export_threads (). Blocks until every export that
   * was queued by -M has been sent.
   */
  void
  wait_idle () {
    std::unique_lock<std::mutex> lock (queue_mutex_);
    idle_cv_.wait (lock, [&] { return queue_.empty() && !busy_; });
  }

  /**
   * @brief Adds what the export thread has sent since the last call to the statistics of a flow table.
   *
   * Without -M there is nothing to add.
   *
   * Moves what the export thread has sent since the last call into the
   * statistics of the flow table; a no-op without -M.
   *
   * @param table The flow table; it provides record_export_stats ().
   * @tparam Table The type of the flow table.
   */
  template <typename Table>
  void
  sync_stats (Table &table) {
    ExportOutcome o;
    {
      std::lock_guard<std::mutex> lock (queue_mutex_);
      o = async_outcome_;
      async_outcome_ = {};
    }
    if (o.flows != 0 || o.records != 0 || o.packets != 0 || o.failures != 0) {
      table.record_export_stats (o.flows, o.records, o.packets, o.failures);
    }
  }

  /**
   * @brief Gives the number of ntopng destinations.
   *
   * @return The number; 0 when built without ZeroMQ.
   */
  std::size_t
  ntopng_sink_count () const noexcept;

  /**
   * @brief Tells whether the export packets have anywhere to go.
   *
   * @return true when there is a destination, an ntopng sink or the --export-out file.
   *
   * @original with no -n, softflowd runs in "statistics gathering
   * mode only" -- flows are still tracked and expired, but no export
   * packets are built or sent at all.
   */
  bool
  has_sink () const noexcept {
    return !destinations_.empty() || !export_out_.empty() ||
           ntopng_sink_count() != 0;
  }

  /**
   * @brief Tells whether the format exports flows.
   *
   * @return true for every format except PSAMP and None.
   */
  bool
  wants_flows () const noexcept {
    // Original: without a destination the packets are made, counted as
    // exported and sent nowhere.
    return format_ != ExportFormat::Psamp && format_ != ExportFormat::None;
  }
  /**
   * @brief Tells whether the format exports sampled packets.
   *
   * @return true for PSAMP.
   */
  bool
  wants_samples () const noexcept {
    return format_ == ExportFormat::Psamp;
  }

  /**
   * @brief Makes the exporter send its templates again; it is the send-template command.
   *
   * @return true when the format has templates (NetFlow v9 or IPFIX), and otherwise false.
   *
   * @original softflowctl(8)'s send-template ("Has no effect for other
   * flow export versions" besides NetFlow v9). Returns true if this
   * pipeline was actually able to honor the request (i.e. is running
   * NetFlow v9), so the control-command handler can report accurately
   * whether anything happened.
   */
  bool
  resend_template ();

  /**
   * @brief Sets the boot time of the exporters again (-I).
   *
   * @param now The new boot time on Clock.
   * @param wall_now The wall-clock time that corresponds to @p now; the current time by default.
   *
   * @original -I boot_time_reinit periodic reset, driven by the main
   * loop's expiry-check cadence. No-op for exporters that don't use
   * boot_time (PSAMP; IPFIX's SysUpTime encoding uses it too, but is
   * reinitialized here alongside the others).
   */
  void
  reinit_boot_time (softflowd_cpp::TimePoint now,
                    std::chrono::system_clock::time_point wall_now =
                      std::chrono::system_clock::now());

  /**
   * @brief What an export sent, to be added to the statistics of the flow table.
   *
   * flows/records/packets/failures actually sent, so the caller can
   * report them into FlowTableStats (see FlowTable::record_export_stats).
   */
  struct ExportOutcome {
    std::uint64_t flows = 0;     ///< The flows exported.
    std::uint64_t records = 0;   ///< The records sent.
    std::uint64_t packets = 0;   ///< The packets sent; for ntopng, the messages.
    std::uint64_t failures = 0;  ///< The failures to send; none is detected now, so it is 0.
  };

  /**
   * @brief Gives the CPU clock ticks that the export has taken (-g).
   *
   * @return The ticks.
   */
  std::clock_t
  export_clocks () const {
    return export_clocks_;
  }

  /**
   * @brief Gives the number of exports whose clock ticks are counted (-g).
   *
   * @return The number.
   */
  unsigned long
  export_calls () const {
    return export_calls_;
  }

  /**
   * @brief Exports expired flows, at once or, with -M, on the export thread.
   *
   * @param records The flows.
   * @param now The current time on Clock.
   * @param wall_now The wall-clock time that corresponds to @p now.
   * @return What was sent. With -M it is empty, and sync_stats () reports it later.
   *
   * @original with -M the expired flows are copied and sent by another
   * thread. A single export thread keeps the packets, and so the sequence
   * numbers, in order. The outcome is then reported later, by sync_stats ().
   */
  ExportOutcome
  export_flows (const std::vector<softflowd_cpp::ExportRecord> &records,
                softflowd_cpp::TimePoint now,
                std::chrono::system_clock::time_point wall_now);

  /**
   * @brief Expired flows that wait in the queue of the export thread (-M).
   */
  struct Job {
    std::vector<softflowd_cpp::ExportRecord> records;  ///< The flows.
    softflowd_cpp::TimePoint now;                      ///< The current time on Clock when they expired.
    std::chrono::system_clock::time_point wall_now;    ///< The wall-clock time that corresponds to #now.
  };

  /**
   * @brief The body of the export thread of -M: it exports the jobs of the queue until it is stopped and the queue is empty.
   */
  void
  export_thread ();

  /**
   * @brief Makes the ntopng messages of flows and sends every message to every destination.
   *
   * @param records The flows.
   * @param now The current time on Clock.
   * @param wall_now The wall-clock time that corresponds to @p now.
   * @return The records and the messages that were made; the flows are not counted.
   *
   * @original send_ntopng (). Every message goes to every destination. As in
   * the original the flows are not counted as exported, only the records
   * and the messages are.
   */
  ExportOutcome
  export_ntopng (const std::vector<softflowd_cpp::ExportRecord> &records,
                 softflowd_cpp::TimePoint now,
                 std::chrono::system_clock::time_point wall_now);

  /**
   * @brief Makes the packets of flows in the format of -v, sends them, and counts what was sent.
   *
   * With -g, the CPU clock ticks of the call are added to export_clocks ().
   *
   * @param records The flows.
   * @param now The current time on Clock.
   * @param wall_now The wall-clock time that corresponds to @p now.
   * @return What was sent. The flows are the flows that were given, but for NetFlow v1 and v5 they are the records; failures is 0. Nothing is sent when there are no flows or the format does not export flows.
   */
  ExportOutcome
  export_now (const std::vector<softflowd_cpp::ExportRecord> &records,
              softflowd_cpp::TimePoint now,
              std::chrono::system_clock::time_point wall_now);

  /**
   * @brief Sends one PSAMP message for a sampled packet.
   *
   * @param sample The sampled packet.
   * @param adjust_time true with -a; it is handed to the exporter as it is.
   *
   * @original send_psamp (). One message per sampled packet, sent at once.
   * The template message goes to every destination, whatever -l says.
   */
  void
  export_psamp (const softflowd_cpp::PsampSample &sample, bool adjust_time);

private:
  void
  dispatch (const std::vector<std::vector<std::uint8_t>> &packets,
            const std::vector<std::size_t> &to_all_destinations = {});

  ExportFormat format_;
  bool gauge_clock_;
  bool multithread_;
  bool biflow_;  // -b: a flow is one record of IPFIX, whatever its directions
  std::clock_t export_clocks_ = 0;
  unsigned long export_calls_ = 0;
  std::string export_out_;

  // -M: the queue of the export thread. state_mutex_ protects the exporters
  // against the template and boot time requests of the main thread.
  std::mutex state_mutex_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::condition_variable idle_cv_;
  std::deque<Job> queue_;
  ExportOutcome async_outcome_;
  bool stop_ = false;
  bool busy_ = false;
  std::thread worker_;
  softflowd_cpp::ExportDestinationSet destinations_;
  bool load_balance_ = false;
  std::optional<softflowd_cpp::Netflow1Exporter> netflow1_;
  std::optional<softflowd_cpp::Netflow5Exporter> netflow5_;
  std::optional<softflowd_cpp::IpfixExporter> ipfix_;
  std::optional<softflowd_cpp::PsampExporter> psamp_;
  std::optional<softflowd_cpp::NtopngExporter> ntopng_;
#ifdef SOFTFLOWD_CPP_HAVE_ZMQ
  std::vector<softflowd_cpp::NtopngSink> ntopng_sinks_;
#endif
};

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_SENDER_HPP
