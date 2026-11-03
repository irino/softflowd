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
 * @file control.c
 * @brief The control socket: the listener on the unix domain socket and the
 *   processing of the commands that softflowctl sends. This file was
 *   split from softflowd.c.
 */

#include "softflowd.h"
#include "control.h"
#include "expire.h"
#include "export_common.h"
#include "format.h"
#include "globals.h"
#include "log.h"
#include "netflow.h"
#include "stats.h"

/**
 * @brief Accept one connection on the control socket and run its command.
 *
 * Commands: help, shutdown, exit, expire-all, send-template, delete-all,
 * statistics, debug+, debug-, stop-gather, start-gather, dump-flows and
 * timeouts.
 *
 * @param lsock                Listening control socket.
 * @param target               Export target (for "send-template").
 * @param ft                   Flow tracking state.
 * @param pcap                 Capture handle (for "statistics").
 * @param exit_request         Set to 1 by the "exit" command.
 * @param stop_collection_flag Set by "stop-gather" and "start-gather".
 * @return 0 if the command was handled, 1 if softflowd should stop ("shutdown"
 * and "exit"), -1 on error or for an unknown command.
 */
int
accept_control (int lsock, struct NETFLOW_TARGET *target,
                struct FLOWTRACK *ft, pcap_t *pcap, int *exit_request,
                int *stop_collection_flag) {
  char buf[64], *p;
  FILE *ctlf;
  int fd, ret = 0, cmd;
  /* A command's position in control_words[] is its number in the switch */
  enum { CTL_HELP,
         CTL_SHUTDOWN,
         CTL_EXIT,
         CTL_EXPIRE_ALL,
         CTL_SEND_TEMPLATE,
         CTL_DELETE_ALL,
         CTL_STATISTICS,
         CTL_DEBUG_ON,
         CTL_DEBUG_OFF,
         CTL_STOP_GATHER,
         CTL_START_GATHER,
         CTL_DUMP_FLOWS,
         CTL_TIMEOUTS,
         CTL_UNKNOWN };
  static const char *const control_words[] = {
    "help", "shutdown", "exit", "expire-all", "send-template", "delete-all",
    "statistics", "debug+", "debug-", "stop-gather", "start-gather",
    "dump-flows", "timeouts"};

  if ((fd = accept (lsock, NULL, NULL)) == -1) {
    logit (LOG_ERR, "ctl accept: %s - exiting", strerror (errno));
    return (-1);
  }
  if ((ctlf = fdopen (fd, "r+")) == NULL) {
    logit (LOG_ERR, "fdopen: %s - exiting\n", strerror (errno));
    close (fd);
    return (-1);
  }
  setlinebuf (ctlf);

  if (fgets (buf, sizeof (buf), ctlf) == NULL) {
    logit (LOG_ERR, "Control socket yielded no data");
    return (0);
  }
  if ((p = strchr (buf, '\n')) != NULL)
    *p = '\0';

  if (verbose_flag)
    logit (LOG_DEBUG, "Control socket \"%s\"", buf);

  for (cmd = 0; cmd < CTL_UNKNOWN && strcmp (buf, control_words[cmd]) != 0;
       cmd++)
    ;
  /* Every reply except help and the unknown command starts with the pid */
  if (cmd != CTL_HELP && cmd != CTL_UNKNOWN)
    fprintf (ctlf, "softflowd[%u]: ", (unsigned int) getpid());
  if (cmd == CTL_EXPIRE_ALL || cmd == CTL_SEND_TEMPLATE)
#if COMPAT_EXPORT == COMPAT_EXPORT_STATIC_SEPARATE
    netflow9_resend_template();
#else  /* COMPAT_EXPORT != COMPAT_EXPORT_STATIC_SEPARATE */
    ipfix_resend_template();
#endif /* COMPAT_EXPORT == COMPAT_EXPORT_STATIC_SEPARATE */
  switch (cmd) {
    case CTL_HELP:
      fprintf (ctlf, "Valid control words are:\n"
                     "\tdebug+ debug- delete-all dump-flows exit expire-all\n"
                     "\tshutdown start-gather statistics stop-gather timeouts\n"
                     "\tsend-template\n");
      break;
    case CTL_SHUTDOWN:
      fprintf (ctlf, "Shutting down gracefully...\n");
      graceful_shutdown_request = 1;
      ret = 1;
      break;
    case CTL_EXIT:
      fprintf (ctlf, "Exiting now...\n");
      *exit_request = 1;
      ret = 1;
      break;
    case CTL_EXPIRE_ALL:
      fprintf (ctlf, "Expired %d flows.\n",
               check_expired (ft, target, CE_EXPIRE_ALL));
      break;
    case CTL_SEND_TEMPLATE:
      fprintf (ctlf, "Template will be sent at next flow export\n");
      break;
    case CTL_DELETE_ALL:
      fprintf (ctlf, "Deleted %d flows.\n", delete_all_flows (ft));
      break;
    case CTL_STATISTICS:
      fprintf (ctlf, "Accumulated statistics since %s UTC:\n",
               format_time (ft->param.system_boot_time.tv_sec));
      statistics (ft, ctlf, pcap);
      break;
    case CTL_DEBUG_ON:
      fprintf (ctlf, "Debug level increased.\n");
      verbose_flag = 1;
      break;
    case CTL_DEBUG_OFF:
      fprintf (ctlf, "Debug level decreased.\n");
      verbose_flag = 0;
      break;
    case CTL_STOP_GATHER:
      fprintf (ctlf, "Data collection stopped.\n");
      *stop_collection_flag = 1;
      break;
    case CTL_START_GATHER:
      fprintf (ctlf, "Data collection resumed.\n");
      *stop_collection_flag = 0;
      break;
    case CTL_DUMP_FLOWS:
      fprintf (ctlf, "Dumping flow data:\n");
      dump_flows (ft, ctlf);
      break;
    case CTL_TIMEOUTS:
      fprintf (ctlf, "Printing timeouts:\n");
      print_timeouts (ft, ctlf);
      break;
    default:
      fprintf (ctlf, "Unknown control command \"%s\"\n", buf);
  }

  fclose (ctlf);
  close (fd);

  return (ret);
}

/**
 * @brief Create the listening UNIX-domain socket for the control interface.
 *
 * @param path Socket path; an existing file at that path is removed first.
 * @return The listening socket. Exits the process on error.
 */
int
unix_listener (const char *path) {
  struct sockaddr_un addr;
  socklen_t addrlen;
  int s;

  memset (&addr, '\0', sizeof (addr));
  addr.sun_family = AF_UNIX;

  if (strlcpy (addr.sun_path, path, sizeof (addr.sun_path)) >=
      sizeof (addr.sun_path)) {
    fprintf (stderr, "control socket path too long\n");
    exit (1);
  }

  addr.sun_path[sizeof (addr.sun_path) - 1] = '\0';

  addrlen = offsetof (struct sockaddr_un, sun_path) + strlen (path) + 1;
#ifdef SOCK_HAS_LEN
  addr.sun_len = addrlen;
#endif

  if ((s = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
    fprintf (stderr, "unix domain socket() error: %s\n", strerror (errno));
    exit (1);
  }
  unlink (path);
  if (bind (s, (struct sockaddr *) &addr, addrlen) == -1) {
    fprintf (stderr, "unix domain bind(\"%s\") error: %s\n", addr.sun_path,
             strerror (errno));
    exit (1);
  }
  if (listen (s, 64) == -1) {
    fprintf (stderr, "unix domain listen() error: %s\n", strerror (errno));
    exit (1);
  }

  return (s);
}
