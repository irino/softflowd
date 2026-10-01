/*
 * Copyright 2004 Damien Miller <djm@mindrot.org> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#include "log.h"
#include <stdarg.h>

/** Non-zero if messages go to stderr instead of syslog; set by loginit(). */
static int logstderr = 0;

/**
 * @brief Select where log messages go.
 *
 * @param ident     Currently unused (the syslog identity is always PROGNAME).
 * @param to_stderr Non-zero to log to stderr, zero to log to syslog (LOG_DAEMON, with PID).
 */
void
loginit(const char *ident, int to_stderr)
{
	(void) ident;
	if (to_stderr)
		logstderr = 1;
	else
		openlog(PROGNAME, LOG_PID|LOG_NDELAY, LOG_DAEMON);
}

/**
 * @brief Log a printf-style message to stderr or syslog, depending on loginit().
 *
 * @param level syslog priority (LOG_ERR, LOG_DEBUG, ...); ignored when logging to stderr.
 * @param fmt   printf-style format string, followed by its arguments.
 */
void
logit(int level, const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);

	if (logstderr) {
		vfprintf(stderr, fmt, args);
		fputs("\n", stderr);
	} else
		vsyslog(level, fmt, args);

	va_end(args);
}

