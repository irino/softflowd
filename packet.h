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
 * @file packet.h
 * @brief Declarations of packet.c: packet parsing: decode the datalink, IP
 *   and transport headers of a captured packet into a flow record and
 *   add it to the flow table. This file was split from softflowd.c.
 */

#ifndef _PACKET_H
#define _PACKET_H
#include "softflowd.h"

int
process_packet (struct CB_CTXT *cb_ctxt,
                const struct pcap_pkthdr *phdr, const u_char *frame,
                int datalink_size, int af, u_int16_t vlanid,
                u_int8_t num_label);
int
datalink_check (int linktype, const u_int8_t *pkt, u_int32_t caplen,
                int *af, u_int16_t *vlanid, u_int8_t *num_label);

#endif /* _PACKET_H */
