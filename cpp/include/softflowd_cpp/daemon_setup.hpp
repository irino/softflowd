/**
 * @file daemon_setup.hpp
 * @brief The set-up of the daemon: the drop of privileges.
 *
 * Split from softflowd.cpp, as daemon_setup.c is from softflowd.c in the C
 * version. The signal handlers of daemon_setup.c are SignalPipe of
 * daemon.hpp, and its ZeroMQ sockets are NtopngSink of ntopng.hpp.
 *
 * @original drop_privs () of daemon_setup.c.
 */
#ifndef SOFTFLOWD_CPP_DAEMON_SETUP_HPP
#define SOFTFLOWD_CPP_DAEMON_SETUP_HPP

namespace softflowd_cpp {

/**
 * @brief Changes the root directory of a daemon to an empty one, and its user to an unprivileged one.
 *
 * It exits with 1 when it fails.
 */
void
drop_privs ();

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_DAEMON_SETUP_HPP
