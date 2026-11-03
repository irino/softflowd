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
 * @file flow.h
 * @brief Declarations of flow.c: the flow table: comparing, hashing, looking
 *   up, inserting and removing flows, the free lists of flows and
 *   expiries, and the initial state of the flow tracker. This file was
 *   split from softflowd.c.
 */

#ifndef _FLOW_H
#define _FLOW_H
#include "softflowd.h"

int
flow_compare (struct FLOW *a, struct FLOW *b);
int
expiry_compare (struct EXPIRY *a, struct EXPIRY *b);
const char *
flow_lookup_name (enum FLOW_LOOKUP mode);
int
flow_table_init (struct FLOWTRACK *ft);
u_int32_t
flow_index (const struct FLOWTRACK *ft,
            const struct FLOW *flow);
struct FLOW *
flow_table_find (struct FLOWTRACK *ft, struct FLOW *key,
                 u_int32_t idx);
void
flow_table_insert (struct FLOWTRACK *ft, struct FLOW *flow,
                   u_int32_t idx);
void
flow_table_remove (struct FLOWTRACK *ft, struct FLOW *flow);
void
flow_table_report (const struct FLOWTRACK *ft);
void
flow_table_usage (struct FLOWTRACK *ft, u_int32_t *used,
                  u_int32_t *maxdepth);
struct FLOW *
flow_get (struct FLOWTRACK *ft);
void
flow_put (struct FLOWTRACK *ft, struct FLOW *flow);
struct EXPIRY *
expiry_get (struct FLOWTRACK *ft);
void
expiry_put (struct FLOWTRACK *ft, struct EXPIRY *expiry);
void
init_flowtrack (struct FLOWTRACK *ft);

FLOW_PROTOTYPE (FLOWS, FLOW, trp, flow_compare);
EXPIRY_PROTOTYPE (EXPIRIES, EXPIRY, trp, expiry_compare);

#endif /* _FLOW_H */
