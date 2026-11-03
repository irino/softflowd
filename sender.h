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
 * @file sender.h
 * @brief Declarations of sender.c: export senders: the table of the export
 *   versions, sending a packet to the destinations, and the threaded
 *   export (-M). This file was split from softflowd.c.
 */

#ifndef _SENDER_H
#define _SENDER_H
#include "softflowd.h"

/* Netflow send functions */
/**
 * Type of the functions that export the flows of one version of NetFlow
 * or IPFIX; the argument holds the flows to send.
 */
typedef int (netflow_send_func_t) (struct SENDPARAMETER);

/** @brief An export version and the functions that send it. */
struct NETFLOW_SENDER {
  int version;                     /**< The version, as -v gives it */
  netflow_send_func_t *func;       /**< Sends the flows of the version */
  netflow_send_func_t *bidir_func; /**< Sends biflow records (-b); NULL when the version has no such function */
  int v6_capable;                  /**< Non-zero when the version can carry IPv6 flows */
};

const struct NETFLOW_SENDER *
lookup_netflow_sender (int version);
#ifdef ENABLE_PTHREAD
void
wait_for_export_threads (void);
int
send_threaded (struct SENDPARAMETER sp, netflow_send_func_t *func);
#endif /* ENABLE_PTHREAD */
/** The versions that can be exported; nf[0] is the default. */
extern const struct NETFLOW_SENDER nf[];

#endif /* _SENDER_H */
