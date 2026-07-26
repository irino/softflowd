#include "softflow/daemon.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace softflow {

void daemonize() {
    const pid_t pid = fork();
    if (pid < 0) {
        throw std::system_error(errno, std::generic_category(), "fork() failed");
    }
    if (pid > 0) {
        // Original: the parent process in a forking daemon exits
        // immediately, so a shell launching it returns right away instead
        // of blocking for the daemon's entire lifetime. _exit() (not
        // exit()) is used deliberately: it skips atexit()/destructor-style
        // cleanup that belongs to the child's copy of any RAII state (a
        // FlowTable, open sockets, etc.), none of which the parent
        // actually owns after fork() -- running that cleanup here would
        // be acting on resources the child still needs.
        _exit(0);
    }

    if (setsid() < 0) {
        throw std::system_error(errno, std::generic_category(), "setsid() failed");
    }

    // Original: chdir("/") so the daemon doesn't pin whatever directory it
    // happened to be launched from (which could, e.g., prevent that
    // filesystem from being unmounted later). Non-fatal if it fails.
    if (chdir("/") != 0) {
        // Nothing meaningful to do differently; daemonization continues
        // with the current working directory instead.
    }

    const int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) {
            close(devnull);
        }
    }
}

PidFile::PidFile(std::string path) : path_(std::move(path)) {
    if (std::FILE* existing = std::fopen(path_.c_str(), "r")) {
        long existing_pid = 0;
        const int scanned = std::fscanf(existing, "%ld", &existing_pid);
        std::fclose(existing);
        if (scanned == 1 && existing_pid > 0) {
            // kill(pid, 0) sends no actual signal; it only checks whether
            // the process exists and this process has permission to
            // signal it. ESRCH specifically means "no such process",
            // i.e. the old pidfile is stale and safe to overwrite.
            if (kill(static_cast<pid_t>(existing_pid), 0) == 0 || errno != ESRCH) {
                throw std::runtime_error(
                    "pidfile '" + path_ + "' names a process (" +
                    std::to_string(existing_pid) +
                    ") that appears to still be running");
            }
        }
    }

    std::FILE* f = std::fopen(path_.c_str(), "w");
    if (f == nullptr) {
        throw std::system_error(errno, std::generic_category(),
                                 "failed to open pidfile '" + path_ + "'");
    }
    std::fprintf(f, "%ld\n", static_cast<long>(getpid()));
    std::fclose(f);
    owns_ = true;
}

PidFile::~PidFile() {
    if (owns_) {
        // Best-effort: a destructor cannot usefully report failure here,
        // and an admin can always clean up a leftover pidfile by hand if
        // this does fail (e.g. the containing directory became
        // read-only mid-run).
        std::remove(path_.c_str());
    }
}

PidFile::PidFile(PidFile&& other) noexcept
    : path_(std::move(other.path_)), owns_(other.owns_) {
    other.owns_ = false;
}

PidFile& PidFile::operator=(PidFile&& other) noexcept {
    if (this != &other) {
        if (owns_) {
            std::remove(path_.c_str());
        }
        path_ = std::move(other.path_);
        owns_ = other.owns_;
        other.owns_ = false;
    }
    return *this;
}

std::atomic<int> SignalPipe::write_fd_{-1};

void SignalPipe::handler(int sig) {
    // Everything called here must be async-signal-safe: no malloc, no
    // iostream, no std::string. write() is on POSIX's async-signal-safe
    // function list; std::atomic<int>::load with relaxed ordering compiles
    // to a plain load instruction with no locking, which is safe to
    // execute from a handler on every platform this project targets, even
    // though the C++ standard itself does not formally guarantee
    // signal-handler safety for std::atomic.
    const int fd = write_fd_.load(std::memory_order_relaxed);
    if (fd >= 0) {
        const char byte = static_cast<char>(sig);
        // The return value is intentionally ignored: there is nothing
        // useful a signal handler could do differently based on write()
        // failing (e.g. EAGAIN because the pipe is momentarily full just
        // means this particular signal notification is dropped, which is
        // acceptable -- drain() will still see every *other* pending
        // signal, and repeated identical signals carry no new
        // information anyway).
        const ssize_t write_result = write(fd, &byte, 1);
        if (write_result < 0) {
            // Nothing to do: see the comment above.
        }
    }
}

SignalPipe::SignalPipe() {
    int fds[2];
    if (pipe(fds) != 0) {
        throw std::system_error(errno, std::generic_category(), "pipe() failed");
    }
    read_fd_ = fds[0];
    write_fd_local_ = fds[1];

    // Both ends are non-blocking: the write end so the handler's write()
    // never blocks (it could otherwise deadlock the process if the pipe
    // filled up while signals were being delivered faster than drain()
    // could keep up), and the read end so drain() can safely loop "until
    // there's nothing left" without blocking on the last read.
    fcntl(read_fd_, F_SETFL, fcntl(read_fd_, F_GETFL) | O_NONBLOCK);
    fcntl(write_fd_local_, F_SETFL, fcntl(write_fd_local_, F_GETFL) | O_NONBLOCK);

    write_fd_.store(write_fd_local_, std::memory_order_relaxed);

    struct sigaction sa {};
    sa.sa_handler = &SignalPipe::handler;
    sigemptyset(&sa.sa_mask);
    // Deliberately *not* SA_RESTART: this project's main event loop is
    // built entirely around poll() returning promptly (with EINTR) the
    // moment a signal arrives, so it can react to a shutdown request
    // without waiting out however much of the current poll() timeout
    // remains. SA_RESTART would have the kernel transparently resume an
    // interrupted poll() with its timeout adjusted, which is usually
    // desirable for simple programs but works against the responsiveness
    // this project's daemon loop depends on.
    sa.sa_flags = 0;
    for (int sig : {SIGTERM, SIGINT, SIGHUP, SIGUSR1}) {
        sigaction(sig, &sa, nullptr);
    }
}

SignalPipe::~SignalPipe() {
    write_fd_.store(-1, std::memory_order_relaxed);
    for (int sig : {SIGTERM, SIGINT, SIGHUP, SIGUSR1}) {
        signal(sig, SIG_DFL);
    }
    if (read_fd_ >= 0) {
        close(read_fd_);
    }
    if (write_fd_local_ >= 0) {
        close(write_fd_local_);
    }
}

std::vector<int> SignalPipe::drain() {
    std::vector<int> signals;
    char byte;
    while (read(read_fd_, &byte, 1) == 1) {
        signals.push_back(static_cast<int>(static_cast<unsigned char>(byte)));
    }
    return signals;
}

} // namespace softflow
