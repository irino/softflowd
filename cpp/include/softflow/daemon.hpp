/**
 * @file daemon.hpp
 * @brief Running as a daemon: backgrounding, the pid file and the signals.
 *
 * The original used this file for the process-backgrounding logic (fork +
 * setsid + redirecting stdio) that turns a foreground process into a Unix
 * daemon. This project keeps that same responsibility here, plus two related
 * pieces of daemon infrastructure that the original handled less formally
 * inline in softflowd.c: pidfile management and signal handling.
 *
 * Signal handling deserves a specific memory-safety note. A signal handler
 * can interrupt the program at any point, including in the middle of a
 * non-reentrant libc call (malloc, printf, std::cout, etc.). Calling such
 * functions from a handler is undefined behavior -- a classic, easy-to-miss
 * bug in daemons that try to do "a little cleanup" directly inside a SIGTERM
 * handler. This project uses the standard self-pipe trick instead: the
 * handler does nothing but write one byte (using the raw,
 * async-signal-safe write() syscall) to a pipe; all the real handling
 * (expiring flows, exporting, exiting) happens later in the normal control
 * flow of the main loop, once it observes the pipe is readable.
 *
 * @original daemon.c, daemon.h.
 */
#ifndef SOFTFLOW_DAEMON_HPP
#define SOFTFLOW_DAEMON_HPP

#include <atomic>
#include <string>
#include <vector>

namespace softflow {

/**
 * @brief Turns the foreground process into a daemon.
 *
 * Does fork(), setsid(), chdir("/") and redirects the standard streams to
 * /dev/null. Must be called before any threads are started and before any
 * file descriptors that must survive are opened relative to a relative path
 * (chdir("/") changes the process's working directory).
 *
 * On success, the parent process has already called _exit() (so this function
 * does not return in the parent); only the backgrounded child returns.
 *
 * @throw std::system_error if fork()/setsid() fail.
 *
 * @original The fork()+setsid()+chdir("/")+redirect-stdio-to-/dev/null
 * sequence historically found in daemon.c.
 */
void daemonize();

/**
 * @brief The pid file, which is removed when the object is destroyed.
 *
 * RAII replaces the original's "write it near the top of main(), and hope
 * every exit path remembers to unlink() it" pattern (a leak of a stale
 * pidfile is exactly the kind of resource-cleanup bug this project's other
 * RAII wrappers, like PcapHandle, target too). The file is removed when the
 * PidFile object is destroyed, on every path -- normal return, exception, or
 * (via the SignalPipe-driven shutdown path) a caught signal. A daemon that
 * has changed its root directory and its user cannot remove it any more.
 *
 * @original The PID file softflowd.c wrote to /var/run/softflowd.pid (or -p's
 * argument) so that init scripts and admins could find the running daemon's
 * process ID.
 */
class PidFile {
public:
  /**
     * @brief Writes the pid file.
     *
     * This is the "don't start two daemons against the same control socket"
     * safety check that the original relied on operators to do by hand.
     *
     * @param path The path of the pid file.
     * @throw std::runtime_error if a pidfile already exists at @p path and the
     *        PID it names belongs to a still-running process (checked via
     *        kill(pid, 0)).
     */
  explicit PidFile (std::string path);
  /** @brief Removes the pid file, when this object owns it. */
  ~PidFile();

  PidFile (const PidFile &) = delete;
  PidFile &
  operator= (const PidFile &) = delete;
  /**
     * @brief Takes over the pid file of @p other, which no longer owns it.
     * @param other The pid file to take over.
     */
  PidFile (PidFile &&other) noexcept;
  /**
     * @brief Takes over the pid file of @p other, which no longer owns it.
     * @param other The pid file to take over.
     * @return This object.
     */
  PidFile &
  operator= (PidFile &&other) noexcept;

  /**
     * @brief The path of the pid file.
     * @return The path.
     */
  const std::string &
  path () const noexcept {
    return path_; }

private:
  std::string path_;  ///< The path of the pid file.
  bool owns_{false};  ///< Whether this object removes the file.
};

/**
 * @brief Turns the signals into bytes of a pipe that the main loop polls.
 *
 * SignalPipe exposes a pollable file descriptor (read_fd()); the main event
 * loop adds it to the same poll()/select() set as the pcap and control-socket
 * file descriptors, and calls drain() once it becomes readable to find out
 * which signals arrived since the last check. This keeps all of the actual
 * signal *handling* logic in ordinary, non-signal-handler code, where it's
 * safe to call whatever functions it needs to.
 *
 * Only one SignalPipe may exist in the process at a time (the signal handler
 * itself must be a plain function, not a member function, so it can only
 * forward to one instance's pipe -- tracked via a static file descriptor).
 * This is not a limitation in practice: a daemon only needs one.
 *
 * @original softflowd.c installed signal() handlers for SIGTERM/SIGINT
 * (graceful shutdown) and SIGHUP/SIGUSR1 (various runtime controls),
 * presumably touching global state directly from within the handler.
 */
class SignalPipe {
public:
  /** @brief Creates the pipe and installs the signal handler. */
  SignalPipe();
  /** @brief Closes the pipe. */
  ~SignalPipe();

  SignalPipe (const SignalPipe &) = delete;
  SignalPipe &
  operator= (const SignalPipe &) = delete;

  /**
     * @brief The read end of the pipe, to be added to the poll() set.
     * @return The file descriptor.
     */
  int
  read_fd () const noexcept {
    return read_fd_; }

  /**
     * @brief Reads every signal number written to the pipe since the last call.
     *
     * This function does not block.
     *
     * @return The signal numbers, in the order they were received; empty if
     *         none are currently pending.
     */
  std::vector<int>
  drain ();

private:
  /** @brief The signal handler: writes the signal number to the pipe, and does nothing else. */
  static void
  handler (int sig);

  /**
     * @brief The currently-registered SignalPipe's write end, if any.
     *
     * Accessed from handler() (a plain, async-signal-safe write of an int) and
     * from the constructor/destructor of whichever SignalPipe is "live".
     */
  static std::atomic<int> write_fd_;

  int read_fd_{-1};         ///< The read end of the pipe.
  int write_fd_local_{-1};  ///< The write end of the pipe of this object.
};

} // namespace softflow

#endif // SOFTFLOW_DAEMON_HPP
