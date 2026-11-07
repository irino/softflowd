/**
 * @file log.hpp
 * @brief The messages of softflowd+: to the standard error or to syslog.
 *
 * Split from softflowd.cpp. The level of logit () is a syslog level (LOG_ERR,
 * LOG_NOTICE and so on), so the users of this header can name the levels
 * without including <syslog.h>.
 *
 * @original log.c
 */
#ifndef SOFTFLOWD_CPP_LOG_HPP
#define SOFTFLOWD_CPP_LOG_HPP

#include <syslog.h>

namespace softflowd_cpp {

void
loginit (const char *ident, bool to_stderr);

void
logit (int level, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_LOG_HPP
