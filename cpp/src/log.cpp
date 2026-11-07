/**
 * @file log.cpp
 * @brief The messages of softflowd+: to the standard error or to syslog.
 *
 * Split from softflowd.cpp. See log.hpp.
 */
#include "softflowd_cpp/log.hpp"

#include <cstdarg>
#include <cstdio>

#include <syslog.h>

namespace softflowd_cpp {

namespace {

/**
 * @brief Where the messages go: true for the standard error, false for syslog.
 *
 * @original log.c. A process that is not a daemon logs to the standard error,
 * a daemon to syslog (LOG_DAEMON, with the PID, and the connection opened at
 * once, as it can not be after the chroot of the privilege drop).
 */
bool log_to_stderr = true;

}  // namespace

/**
 * @brief Chooses where the messages go, and opens syslog when they go there.
 *
 * @param ident The name that syslog shows.
 * @param to_stderr true for the standard error, false for syslog.
 */
void
loginit (const char *ident, bool to_stderr) {
  log_to_stderr = to_stderr;
  if (!to_stderr) {
    openlog (ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
  }
}

/**
 * @brief Logs a message: a line on the standard error, or a message to syslog.
 *
 * @param level The syslog level; the standard error has no levels.
 * @param fmt The format of the message, as for printf().
 * @param ... The values for the format.
 */
void
logit (int level, const char *fmt, ...) {
  va_list ap;
  va_start (ap, fmt);
  if (log_to_stderr) {
    std::vfprintf (stderr, fmt, ap);
    std::fputs ("\n", stderr);
  } else {
    vsyslog (level, fmt, ap);
  }
  va_end (ap);
}

}  // namespace softflowd_cpp
