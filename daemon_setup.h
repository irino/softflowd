/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 * Copyright 2026 Hitoshi Irino <irino@sfc.wide.ad.jp> All rights reserved.
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

/**
 * @file daemon_setup.h
 * @brief Declarations of daemon_setup.c: the signal handlers and their flags,
 *   the drop of privileges and the ZeroMQ sockets of -v ntopng. This file was
 *   split from softflowd.c.
 */

#ifndef _DAEMON_SETUP_H
#define _DAEMON_SETUP_H
#include "softflowd.h"

extern volatile sig_atomic_t
  stats_log_request; /**< Set by SIGUSR1: log the statistics */
extern volatile sig_atomic_t
  hup_log_request; /**< Set by SIGHUP: log that there is no reload */

void
sighand_graceful_shutdown (int signum);
void
sighand_log_stats (int signum);
void
sighand_hup (int signum);
void
sighand_other (int signum);
void
drop_privs (void);
#ifdef ENABLE_NTOPNG
void
connect_ntopng_destinations (struct NETFLOW_TARGET *target);
#endif /* ENABLE_NTOPNG */

#endif /* _DAEMON_SETUP_H */
