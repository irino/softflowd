/*
 * Copyright 2019 Hitoshi Irino <irino@sfc.wide.ad.jp> All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS    OR
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

#ifndef _NETFLOW9_H
#define _NETFLOW9_H

#include "softflowd.h"

#define NFLOW9_TEMPLATE_SET_ID          0
#define NFLOW9_OPTION_TEMPLATE_SET_ID   1

/* Information Elements */
#define NFLOW9_SAMPLING_INTERVAL        34
#define NFLOW9_SAMPLING_ALGORITHM       35

#define NFLOW9_OPTION_SCOPE_INTERFACE           2
#define NFLOW9_SAMPLING_ALGORITHM_DETERMINISTIC 1

struct NFLOW9_HEADER {
  u_int16_t version, flows;
  u_int32_t uptime_ms;
  u_int32_t export_time;        // in seconds
  u_int32_t sequence, od_id;
} __packed;

#ifdef LEGACY
/* Prototypes for functions to send NetFlow packets, from netflow*.c */
int send_netflow_v9 (struct SENDPARAMETER sp);
/* Force a resend of the flow template */
void netflow9_resend_template (void);
#endif /* LEGACY */

#endif /* _NETFLOW9_H */
