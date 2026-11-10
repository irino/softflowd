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
 * @file daemon_setup.c
 * @brief The set-up of the daemon: the signal handlers and their flags, the
 *   drop of privileges and the ZeroMQ sockets of -v ntopng. This file was split
 *   from softflowd.c.
 */

#include "softflowd.h"
#include "daemon_setup.h"
#include "common.h"
#include "globals.h"
#include "log.h"
#include "sender.h"

/* Signal handler flags */
/** Set by the signal handler to the received signal number to request a
 * graceful shutdown. */
volatile sig_atomic_t graceful_shutdown_request = 0;
/** Set by SIGUSR1: log the number of the tracked flows and of the packets. */
volatile sig_atomic_t stats_log_request = 0;
/** Set by SIGHUP: log that a reload of the configuration is not implemented. */
volatile sig_atomic_t hup_log_request = 0;

/**
 * @brief Signal handler that requests a graceful shutdown.
 *
 * @param signum Signal number; stored in graceful_shutdown_request.
 */
void
sighand_graceful_shutdown (int signum) {
  graceful_shutdown_request = signum;
}

/**
 * @brief Signal handler of SIGUSR1: request the log of the statistics.
 *
 * @param signum Signal number; not used.
 */
void
sighand_log_stats (int signum) {
  (void) signum;
  stats_log_request = 1;
}

/**
 * @brief Signal handler of SIGHUP: request the log that there is no reload.
 *
 * @param signum Signal number; not used.
 */
void
sighand_hup (int signum) {
  (void) signum;
  hup_log_request = 1;
}

/**
 * @brief Signal handler for unexpected signals: log and exit immediately.
 *
 * @param signum Signal number.
 */
void
sighand_other (int signum) {
  /* XXX: this may not be completely safe */
  logit (LOG_WARNING, "Exiting immediately on unexpected signal %d", signum);
  _exit (0);
}

/**
 * @brief Drop privileges and chroot; exits on failure.
 */
void
drop_privs (void) {
  struct passwd *pw;

  if ((pw = getpwnam (PRIVDROP_USER)) == NULL) {
    logit (LOG_ERR, "Unable to find unprivileged user \"%s\"", PRIVDROP_USER);
    exit (1);
  }
  if (chdir (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, strerror (errno));
    exit (1);
  }
  if (chroot (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chroot to directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, strerror (errno));
    exit (1);
  }
  if (chdir ("/") != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot root: %s", strerror (errno));
    exit (1);
  }
  if (setgroups (1, &pw->pw_gid) != 0) {
    logit (LOG_ERR, "Couldn't setgroups (%u): %s", (unsigned int) pw->pw_gid,
           strerror (errno));
    exit (1);
  }
#if defined(HAVE_SETRESGID)
  if (setresgid (pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
#elif defined(HAVE_SETREGID)
  if (setregid (pw->pw_gid, pw->pw_gid) == -1)
#else
  if (setegid (pw->pw_gid) == -1 || setgid (pw->pw_gid) == -1)
#endif
  {
    logit (LOG_ERR, "Couldn't set gid (%u): %s", (unsigned int) pw->pw_gid,
           strerror (errno));
    exit (1);
  }
#if defined(HAVE_SETRESUID)
  if (setresuid (pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
#elif defined(HAVE_SETREUID)
  if (setreuid (pw->pw_uid, pw->pw_uid) == -1)
#else
  if (seteuid (pw->pw_uid) == -1 || setuid (pw->pw_uid) == -1)
#endif
  {
    logit (LOG_ERR, "Couldn't set uid (%u): %s", (unsigned int) pw->pw_uid,
           strerror (errno));
    exit (1);
  }
}

#ifdef ENABLE_NTOPNG
/**
 * @brief Create the ZeroMQ sockets of the -n destinations of -v ntopng.
 *
 * ZeroMQ starts its I/O threads in the process that makes the socket, and a
 * fork () does not carry them to the child: the sockets are made after
 * daemon (), and before drop_privs ().  Exits on failure.
 *
 * @param target Export target; the destinations are numeric (getnameinfo ()).
 */
void
connect_ntopng_destinations (struct NETFLOW_TARGET *target) {
  int dest_idx, rc;
  struct DESTINATION *dest;

  if (target->dialect->version != SOFTFLOWD_NF_VERSION_NTOPNG
#ifdef ENABLE_NTOPNG_JSON
      && target->dialect->version != SOFTFLOWD_NF_VERSION_NTOPNG_JSON
#endif
  )
    return;
  for (dest_idx = 0; dest_idx < target->num_destinations; dest_idx++) {
    dest = &target->destinations[dest_idx];
    if (dest->ss.ss_family == 0)
      continue;
    if ((rc = connect_ntopng (dest->hostname, dest->servname, &dest->zmq)) !=
        0) {
      logit (LOG_ERR, "Could not create ZeroMQ socket for %s:%s: (%d) %s",
             dest->hostname, dest->servname, rc, strerror (rc));
      exit (1);
    }
  }
}
#endif /* ENABLE_NTOPNG */
