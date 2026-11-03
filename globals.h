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
 * @file globals.h
 * @brief Declarations of the global state of softflowd.c: the flags, counters
 *   and levels that the other parts of softflowd share. This file was
 *   split from softflowd.c.
 */

#ifndef _GLOBALS_H
#define _GLOBALS_H
#include "softflowd.h"

extern int verbose_flag;           /**< Debugging flag */
extern u_int16_t if_index;         /**< "manual" interface index */
extern int track_level;            /**< Flow tracking level (TRACK_*) */
extern int snaplen;                /**< Capture length; 0 selects a default */
extern int gauge_clock;            /**< -g: report cpu clocks */
extern clock_t export_clocks;      /**< cpu clocks spent in the export function */
extern unsigned long export_calls; /**< Number of calls to the export function */
extern volatile sig_atomic_t
  graceful_shutdown_request; /**< Set by the signal handler to request a
                                graceful shutdown */

#endif /* _GLOBALS_H */
