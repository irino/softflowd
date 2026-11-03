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
 * @file options.h
 * @brief Declarations of options.c: command line support: the usage message
 *   and the parsing of timeouts, host:port arguments and MAC addresses.
 *   This file was split from softflowd.c.
 */

#ifndef _OPTIONS_H
#define _OPTIONS_H
#include "softflowd.h"

/* Empty fallback where common.h does not define __dead (non-GNU C, non-BSD). */
#ifndef __dead
/**
 * Marks a function that does not return; empty where common.h does not
 * define it.
 */
#define __dead
#endif
char *
argv_join (int argc, char **argv);
void
usage (void);
__dead void
die_usage (const char *fmt, ...);
void
set_timeout (struct FLOWTRACK *ft, const char *to_spec);
int
parse_hostports (char *s, struct DESTINATION *dest,
                 int max_dest);
int
parse_mac_address (const char *str, u_int8_t mac[6]);

#endif /* _OPTIONS_H */
