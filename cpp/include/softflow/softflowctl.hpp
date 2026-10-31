/**
 * @file softflowctl.hpp
 * @brief The protocol of the control socket that softflowd and softflowctl share.
 *
 * This header captures that shared protocol explicitly as named constants and
 * helper functions, used by both this project's softflowctl.cpp (the client)
 * and softflowd.cpp's control-socket server loop (see softflowd.cpp for the
 * server side, matching the original's file boundary: softflowd.c owned the
 * listening/accepting code, softflowctl.c only ever behaved as a client).
 * This implementation supports the full command set of softflowctl(8).
 *
 * @original softflowctl.c. softflowctl had no separate .h in the original; the
 * client and daemon simply agreed on the same commands and socket path by
 * convention. The commands are those of the manual page of softflowctl(8):
 * shutdown, exit, expire-all, delete-all, statistics, debug+, debug-,
 * stop-gather, start-gather, dump-flows, timeouts, send-template.
 */
#ifndef SOFTFLOW_SOFTFLOWCTL_HPP
#define SOFTFLOW_SOFTFLOWCTL_HPP

#include <stdexcept>
#include <string>

namespace softflow {

/** @brief The default path of the control socket. */
inline constexpr const char* kDefaultControlSocketPath = "/var/run/softflowd.ctl";
/** @brief The default path of the pid file. */
inline constexpr const char* kDefaultPidFilePath = "/var/run/softflowd.pid";

/** @brief The words of the commands that softflowctl sends to the daemon. */
namespace control_commands {
inline constexpr const char *kHelp = "help";                   ///< List the valid control words.
inline constexpr const char *kShutdown = "shutdown";           ///< Graceful exit: expire + export, then quit.
inline constexpr const char *kExit = "exit";                   ///< Immediate exit: no expiry/export.
inline constexpr const char *kExpireAll = "expire-all";        ///< Force-expire every tracked flow now.
inline constexpr const char *kDeleteAll = "delete-all";        ///< Drop every tracked flow, no expiry/export.
inline constexpr const char *kStatistics = "statistics";       ///< Report FlowTableStats + tracked-flow count.
inline constexpr const char *kDebugPlus = "debug+";            ///< Increase the daemon's debug verbosity.
inline constexpr const char *kDebugMinus = "debug-";           ///< Decrease the daemon's debug verbosity.
inline constexpr const char *kStopGather = "stop-gather";      ///< Pause packet processing.
inline constexpr const char *kStartGather = "start-gather";    ///< Resume packet processing.
inline constexpr const char *kDumpFlows = "dump-flows";        ///< Report info on every currently tracked flow.
inline constexpr const char *kTimeouts = "timeouts";           ///< Report configured flow timeout parameters.
inline constexpr const char *kSendTemplate = "send-template";  ///< Resend NetFlow v9 template before next export.
} // namespace control_commands

/** @brief An error on the control socket (connecting, reading or writing). */
class ControlSocketError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * @brief Reads one newline-terminated line from a connected socket.
 *
 * Blocks until either a full line or EOF is seen.
 *
 * @param fd The connected socket.
 * @return The line without its trailing newline.
 *
 * @original softflowctl.c/softflowd.c presumably used a fixed-size buffer with
 * read(); this reads one byte at a time into a std::string instead, which
 * cannot overflow a fixed buffer no matter how long the peer's line is (a
 * std::string grows as needed) and needs no separate "did the line get
 * truncated" bookkeeping.
 */
std::string read_line(int fd);

/**
 * @brief Reads everything available from a connected socket until the peer
 * closes its end (EOF), blocking until then.
 *
 * Used for reading a response that may span multiple lines (e.g. dump-flows,
 * one line per tracked flow) -- read_line() intentionally stops at the *first*
 * newline, which would silently truncate a multi-line response, so this is a
 * distinct function rather than a variant of it. The daemon's control-socket
 * server (softflowd.cpp) always closes the connection immediately after
 * writing its complete response, so "read until EOF" correctly captures the
 * whole thing, single-line or not.
 *
 * @param fd The connected socket.
 * @return The response.
 */
std::string read_until_eof(int fd);

/**
 * @brief Reads the raw reply: read_until_eof() without the stripped trailing newline.
 *
 * @param fd The connected socket.
 * @return The reply as the daemon wrote it.
 *
 * @original softflowctl.c copies the reply to stdout as it is.
 */
std::string read_all(int fd);
/**
 * @brief Reads the command that a client sent.
 *
 * @param fd The connected socket.
 * @param[out] command The command, without its newline, of at most 63 bytes.
 * @return false when the peer closed without sending anything.
 *
 * @original softflowd.c reads a command with fgets (buf, 64, ...).
 */
bool read_command(int fd, std::string& command);

/**
 * @brief Writes @p text as it is (write_line() without the added newline).
 *
 * @param fd The connected socket.
 * @param text The text.
 */
void write_all(int fd, const std::string& text);

/**
 * @brief Writes @p line followed by a single newline to a connected socket.
 *
 * @param fd The connected socket.
 * @param line The line, without a newline.
 */
void write_line(int fd, const std::string& line);

/**
 * @brief The client side of the control socket.
 *
 * Wrapping the socket file descriptor in a class means it is closed via the
 * destructor on every exit path (including an exception thrown by
 * send_command()), rather than needing an explicit close() before each of
 * main()'s return statements.
 *
 * @original The client-side connection logic embedded directly in
 * softflowctl.c's main().
 */
class ControlClient {
public:
  /**
     * @brief Connects to the control socket.
     * @param socket_path The path of the socket.
     * @throw ControlSocketError when it cannot connect.
     */
  explicit ControlClient (
    const std::string &socket_path = kDefaultControlSocketPath);
  /** @brief Closes the connection. */
  ~ControlClient();

  ControlClient (const ControlClient &) = delete;
  ControlClient &
  operator= (const ControlClient &) = delete;

  /**
     * @brief Sends a command and returns the daemon's single-line response.
     * @param command The command, one of control_commands.
     * @return The response, without its trailing newline.
     */
  std::string
  send_command (const std::string &command);

  /**
     * @brief Sends a command and returns the reply as the daemon wrote it.
     * @param command The command, one of control_commands.
     * @return The reply, which may span several lines.
     */
  std::string
  send_command_raw (const std::string &command);

private:
  int fd_{-1};  ///< The connected socket.
};

} // namespace softflow

#endif // SOFTFLOW_SOFTFLOWCTL_HPP
