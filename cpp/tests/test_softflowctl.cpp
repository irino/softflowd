// Tests the control-socket wire protocol (read_line/write_line/
// ControlClient) without needing a second OS process: a std::thread plays
// the role of softflowd's control-socket server, accepting one connection
// on a real Unix domain socket and responding according to a tiny script.
// This exercises the exact same code path ControlClient uses against the
// real softflowd_cpp daemon, just without needing to spawn and manage a
// second process from the test itself.
#include <cassert>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <thread>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "softflow/softflowctl.hpp"

using namespace softflow;

namespace {

std::string temp_socket_path(const char* suffix) {
    std::ostringstream oss;
    oss << "/tmp/softflow_test_ctl_" << getpid() << suffix;
    return oss.str();
}

// Minimal control-socket server: binds, listens, accepts exactly one
// connection, reads one command line, and writes back `response`.
class OneShotServer {
public:
    explicit OneShotServer(const std::string& path) : path_(path) {
        ::unlink(path_.c_str());
        fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        assert(fd_ >= 0);

        struct sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
        const int bind_result =
            bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        assert(bind_result == 0);
        const int listen_result = listen(fd_, 1);
        assert(listen_result == 0);
    }

    ~OneShotServer() {
        if (fd_ >= 0) {
            close(fd_);
        }
        ::unlink(path_.c_str());
    }

    // Runs in a background thread: accepts one connection, records the
    // command it received, and sends back `response`.
    void serve_once(const std::string& response) {
        thread_ = std::thread([this, response] {
            const int client_fd = accept(fd_, nullptr, nullptr);
            assert(client_fd >= 0);
            received_command_ = read_line(client_fd);
            write_line(client_fd, response);
            close(client_fd);
        });
    }

    void join() {
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    const std::string& received_command() const noexcept {
        return received_command_;
    }

private:
    std::string path_;
    int fd_{-1};
    std::thread thread_;
    std::string received_command_;
};

void test_read_write_line_round_trip_over_a_socketpair() {
    int fds[2];
    const int result = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(result == 0);

    write_line(fds[0], "hello world");
    const std::string received = read_line(fds[1]);
    assert(received == "hello world");

    // An empty line is a valid (if unusual) line.
    write_line(fds[0], "");
    assert(read_line(fds[1]).empty());

    close(fds[0]);
    close(fds[1]);
}

void test_read_line_returns_partial_data_on_eof_without_trailing_newline() {
    int fds[2];
    const int result = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(result == 0);

    // Write raw bytes with no trailing '\n', then close the write end,
    // simulating a peer that disconnects mid-line.
    const std::string raw = "no newline here";
    ssize_t written = write(fds[0], raw.data(), raw.size());
    assert(written == static_cast<ssize_t>(raw.size()));
    close(fds[0]);

    const std::string received = read_line(fds[1]);
    assert(received == raw);

    close(fds[1]);
}

void test_control_client_sends_command_and_receives_response() {
    const auto path = temp_socket_path("_1");
    OneShotServer server(path);
    server.serve_once("OK tracked=42 backend=hash");

    ControlClient client(path);
    const std::string response = client.send_command(control_commands::kStatistics);

    server.join();
    assert(server.received_command() == control_commands::kStatistics);
    assert(response == "OK tracked=42 backend=hash");
}

void test_control_client_throws_when_socket_does_not_exist() {
    const auto path = temp_socket_path("_nonexistent");
    ::unlink(path.c_str()); // make sure nothing is actually listening here

    bool threw = false;
    try {
        ControlClient client(path);
    } catch (const ControlSocketError&) {
        threw = true;
    }
    assert(threw);
}

void test_all_known_commands_round_trip() {
    // Exercises every command name softflowd_cpp's control loop
    // recognizes (see handle_control_command() in softflowd.cpp), purely
    // at the wire-protocol level -- this test doesn't link against
    // softflowd.cpp itself, only softflowctl's client/protocol code, so it
    // can't verify the *daemon's* handling of each command, only that the
    // command names themselves are sent byte-for-byte as expected.
    const char* commands[] = {
        control_commands::kShutdown, control_commands::kExit,
        control_commands::kExpireAll, control_commands::kDeleteAll,
        control_commands::kStatistics, control_commands::kDebugPlus,
        control_commands::kDebugMinus, control_commands::kStopGather,
        control_commands::kStartGather, control_commands::kDumpFlows,
        control_commands::kTimeouts, control_commands::kSendTemplate,
    };

    for (const char* command : commands) {
        const auto path = temp_socket_path("_cmd");
        OneShotServer server(path);
        server.serve_once("OK");

        ControlClient client(path);
        const std::string response = client.send_command(command);
        server.join();

        assert(server.received_command() == command);
        assert(response == "OK");
    }
}

} // namespace

int main() {
    test_read_write_line_round_trip_over_a_socketpair();
    test_read_line_returns_partial_data_on_eof_without_trailing_newline();
    test_control_client_sends_command_and_receives_response();
    test_control_client_throws_when_socket_does_not_exist();
    test_all_known_commands_round_trip();
    std::puts("all softflowctl tests passed");
    return 0;
}
