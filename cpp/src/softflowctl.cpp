#include "softflow/softflowctl.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace softflow {

std::string
read_line (int fd) {
  std::string line;
  char c;
  for (;;) {
    const ssize_t n = read (fd, &c, 1);
    if (n == 0) {
      break;  // EOF: peer closed the connection
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw ControlSocketError (std::string ("read() failed: ") +
                                std::strerror (errno));
    }
    if (c == '\n') {
      break;
    }
    line.push_back (c);
  }
  return line;
}

std::string
read_all (int fd) {
  std::string result;
  char buf[4096];
  for (;;) {
    const ssize_t n = read (fd, buf, sizeof (buf));
    if (n == 0) {
      break;  // EOF: peer closed the connection
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw ControlSocketError (std::string ("read() failed: ") +
                                std::strerror (errno));
    }
    result.append (buf, static_cast<std::size_t> (n));
  }
  return result;
}

std::string
read_until_eof (int fd) {
  std::string result = read_all (fd);
  // The server always terminates its response with a trailing newline
  // (see write_line()); strip exactly one so callers see the same
  // "no trailing newline" shape read_line() produces for a single-line
  // response.
  if (!result.empty() && result.back() == '\n') {
    result.pop_back();
  }
  return result;
}

bool
read_command (int fd, std::string &command) {
  // Original: fgets (buf, 64, ctlf); the command is what was read up to the
  // newline, at most 63 bytes.
  command.clear();
  char c;
  bool any = false;
  while (command.size() < 63) {
    const ssize_t n = read (fd, &c, 1);
    if (n == 0) {
      break;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw ControlSocketError (std::string ("read() failed: ") +
                                std::strerror (errno));
    }
    any = true;
    if (c == '\n') {
      break;
    }
    command.push_back (c);
  }
  return any;
}

void
write_line (int fd, const std::string &line) {
  write_all (fd, line + "\n");
}

void
write_all (int fd, const std::string &buf) {
  std::size_t offset = 0;
  while (offset < buf.size()) {
    const ssize_t n =
      write (fd, buf.data() + offset, buf.size() - offset);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw ControlSocketError (std::string ("write: ") +
                                std::strerror (errno));
    }
    offset += static_cast<std::size_t> (n);
  }
}

ControlClient::ControlClient (const std::string &socket_path) {
  fd_ = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd_ < 0) {
    throw ControlSocketError (std::string ("ctl socket() error: ") +
                              std::strerror (errno));
  }

  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (socket_path.size() >= sizeof (addr.sun_path)) {
    close (fd_);
    fd_ = -1;
    throw ControlSocketError ("Control socket path too long.");
  }
  std::strncpy (addr.sun_path, socket_path.c_str(), sizeof (addr.sun_path) - 1);

  if (connect (fd_, reinterpret_cast<struct sockaddr *> (&addr), sizeof (addr)) < 0) {
    const std::string err = std::strerror (errno);
    close (fd_);
    fd_ = -1;
    throw ControlSocketError ("ctl connect(\"" + socket_path +
                              "\") error: " + err);
  }
}

ControlClient::~ControlClient () {
  if (fd_ >= 0) {
    close (fd_);
  }
}

std::string
ControlClient::send_command (const std::string &command) {
  write_line (fd_, command);
  return read_until_eof (fd_);
}

std::string
ControlClient::send_command_raw (const std::string &command) {
  write_line (fd_, command);
  return read_all (fd_);
}

}  // namespace softflow

// =======================================================================
// main() (original: softflowctl.c's main())
// =======================================================================
#ifndef SOFTFLOW_NO_MAIN

namespace {

// Original: softflowctl.c's usage ().
void
print_usage () {
  std::fprintf (stderr, "Usage: [-c ctlsock] softflowctl [command]\n");
}

}  // namespace

// Original: softflowctl.c's main (): the command is sent as it is, the reply
// is copied to stdout as it is, and the exit status is 0 once connected.
int
main (int argc, char **argv) {
  std::string socket_path = softflow::kDefaultControlSocketPath;
  int ch;
  while ((ch = getopt (argc, argv, "hc:")) != -1) {
    switch (ch) {
      case 'h':
        print_usage();
        return 0;
      case 'c':
        socket_path = optarg;
        break;
      default:
        std::fprintf (stderr, "Invalid commandline option.\n");
        print_usage();
        return 1;
    }
  }

  // Accept only one argument
  if (optind != argc - 1) {
    print_usage();
    return 1;
  }

  try {
    softflow::ControlClient client (socket_path);
    const std::string reply = client.send_command_raw (argv[optind]);
    std::fwrite (reply.data(), 1, reply.size(), stdout);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf (stderr, "%s\n", e.what());
    return 1;
  }
}

#endif  // SOFTFLOW_NO_MAIN
