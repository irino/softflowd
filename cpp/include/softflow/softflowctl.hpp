// Original files: softflowctl.c (softflowctl had no separate .h in the
// original; the client and daemon simply agreed on the same commands and
// socket path by convention). This header captures that shared protocol
// explicitly as named constants and helper functions, used by both this
// project's softflowctl.cpp (the client) and softflowd.cpp's control-socket
// server loop (see softflowd.cpp for the server side, matching the
// original's file boundary: softflowd.c owned the listening/accepting
// code, softflowctl.c only ever behaved as a client).
//
// Original: softflowctl(8) commands, per its manual page: shutdown, exit,
// expire-all, delete-all, statistics, debug+, debug-, stop-gather,
// start-gather, dump-flows, timeouts, send-template. This implementation
// supports the full command set.
#ifndef SOFTFLOW_SOFTFLOWCTL_HPP
#define SOFTFLOW_SOFTFLOWCTL_HPP

#include <stdexcept>
#include <string>

namespace softflow {

inline constexpr const char* kDefaultControlSocketPath = "/var/run/softflowd.ctl";
inline constexpr const char* kDefaultPidFilePath = "/var/run/softflowd.pid";

namespace control_commands {
inline constexpr const char* kShutdown = "shutdown";       // graceful exit: expire + export, then quit
inline constexpr const char* kExit = "exit";                // immediate exit: no expiry/export
inline constexpr const char* kExpireAll = "expire-all";     // force-expire every tracked flow now
inline constexpr const char* kDeleteAll = "delete-all";     // drop every tracked flow, no expiry/export
inline constexpr const char* kStatistics = "statistics";    // report FlowTableStats + tracked-flow count
inline constexpr const char* kDebugPlus = "debug+";          // increase the daemon's debug verbosity
inline constexpr const char* kDebugMinus = "debug-";         // decrease the daemon's debug verbosity
inline constexpr const char* kStopGather = "stop-gather";    // pause packet processing
inline constexpr const char* kStartGather = "start-gather";  // resume packet processing
inline constexpr const char* kDumpFlows = "dump-flows";      // report info on every currently tracked flow
inline constexpr const char* kTimeouts = "timeouts";         // report configured flow timeout parameters
inline constexpr const char* kSendTemplate = "send-template"; // resend NetFlow v9 template before next export
} // namespace control_commands

class ControlSocketError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Reads one newline-terminated line from a connected socket, blocking
// until either a full line or EOF is seen. Returns the line without its
// trailing newline. Original: softflowctl.c/softflowd.c presumably used a
// fixed-size buffer with read(); this reads one byte at a time into a
// std::string instead, which cannot overflow a fixed buffer no matter how
// long the peer's line is (a std::string grows as needed) and needs no
// separate "did the line get truncated" bookkeeping.
std::string read_line(int fd);

// Reads everything available from a connected socket until the peer
// closes its end (EOF), blocking until then. Used for reading a
// response that may span multiple lines (e.g. dump-flows, one line per
// tracked flow) -- read_line() above intentionally stops at the *first*
// newline, which would silently truncate a multi-line response, so this
// is a distinct function rather than a variant of it. The daemon's
// control-socket server (softflowd.cpp) always closes the connection
// immediately after writing its complete response, so "read until EOF"
// correctly captures the whole thing, single-line or not.
std::string read_until_eof(int fd);

// Writes `line` followed by a single newline to a connected socket.
void write_line(int fd, const std::string& line);

// Original: the client-side connection logic embedded directly in
// softflowctl.c's main(). Wrapping the socket file descriptor in a class
// means it is closed via the destructor on every exit path (including an
// exception thrown by send_command()), rather than needing an explicit
// close() before each of main()'s return statements.
class ControlClient {
public:
    explicit ControlClient(
        const std::string& socket_path = kDefaultControlSocketPath);
    ~ControlClient();

    ControlClient(const ControlClient&) = delete;
    ControlClient& operator=(const ControlClient&) = delete;

    // Sends `command` and returns the daemon's single-line response.
    std::string send_command(const std::string& command);

private:
    int fd_{-1};
};

} // namespace softflow

#endif // SOFTFLOW_SOFTFLOWCTL_HPP
