#include "softflow/softflowctl.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace softflow {

std::string read_line(int fd) {
    std::string line;
    char c;
    for (;;) {
        const ssize_t n = read(fd, &c, 1);
        if (n == 0) {
            break; // EOF: peer closed the connection
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw ControlSocketError(std::string("read() failed: ") +
                                      std::strerror(errno));
        }
        if (c == '\n') {
            break;
        }
        line.push_back(c);
    }
    return line;
}

std::string read_until_eof(int fd) {
    std::string result;
    char buf[4096];
    for (;;) {
        const ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) {
            break; // EOF: peer closed the connection
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw ControlSocketError(std::string("read() failed: ") +
                                      std::strerror(errno));
        }
        result.append(buf, static_cast<std::size_t>(n));
    }
    // The server always terminates its response with a trailing newline
    // (see write_line()); strip exactly one so callers see the same
    // "no trailing newline" shape read_line() produces for a single-line
    // response.
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

void write_line(int fd, const std::string& line) {
    std::string buf = line;
    buf.push_back('\n');
    std::size_t offset = 0;
    while (offset < buf.size()) {
        const ssize_t n =
            write(fd, buf.data() + offset, buf.size() - offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw ControlSocketError(std::string("write() failed: ") +
                                      std::strerror(errno));
        }
        offset += static_cast<std::size_t>(n);
    }
}

ControlClient::ControlClient(const std::string& socket_path) {
    fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0) {
        throw ControlSocketError(std::string("socket() failed: ") +
                                  std::strerror(errno));
    }

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        close(fd_);
        fd_ = -1;
        throw ControlSocketError("control socket path too long: " + socket_path);
    }
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        const std::string err = std::strerror(errno);
        close(fd_);
        fd_ = -1;
        throw ControlSocketError("connect() to '" + socket_path +
                                  "' failed: " + err);
    }
}

ControlClient::~ControlClient() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

std::string ControlClient::send_command(const std::string& command) {
    write_line(fd_, command);
    return read_until_eof(fd_);
}

} // namespace softflow

// =======================================================================
// main() (original: softflowctl.c's main())
// =======================================================================
#ifndef SOFTFLOW_NO_MAIN

namespace {

void print_usage(const char* argv0) {
    std::fprintf(stderr,
                 "usage: %s [-c ctl_sock] command\n"
                 "commands: shutdown, exit, expire-all, delete-all, "
                 "statistics, debug+, debug-,\n"
                 "          stop-gather, start-gather, dump-flows, "
                 "timeouts, send-template\n"
                 "default ctl_sock: %s\n",
                 argv0, softflow::kDefaultControlSocketPath);
}

} // namespace

int main(int argc, char** argv) {
    std::string socket_path = softflow::kDefaultControlSocketPath;
    std::string command;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-c" && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (command.empty()) {
            command = arg;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (command.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    try {
        softflow::ControlClient client(socket_path);
        const std::string response = client.send_command(command);
        std::printf("%s\n", response.c_str());
        return response.rfind("ERROR", 0) == 0 ? 1 : 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s: %s\n", argv[0], e.what());
        return 1;
    }
}

#endif // SOFTFLOW_NO_MAIN
