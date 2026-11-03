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
 * @file format.c
 * @brief Formatting of times and flows for log and debug output. This file
 *   was split from softflowd.c.
 */

#include "softflowd.h"
#include "format.h"
#include "log.h"

#if 0
/* Dump a packet */
static void
dump_packet (const u_int8_t *p, int len) {
  char buf[1024], tmp[3];
  int i;

  for (*buf = '\0', i = 0; i < len; i++) {
    snprintf (tmp, sizeof (tmp), "%02x%s", p[i], i % 2 ? " " : "");
    if (strlcat (buf, tmp, sizeof (buf) - 4) >= sizeof (buf) - 4) {
      strlcat (buf, "...", sizeof (buf));
      break;
    }
  }
  logit (LOG_INFO, "packet len %d: %s", len, buf);
}
#endif

/**
 * @brief Format a time in an ISO-like format.
 *
 * @param t Time to format.
 * @return Pointer to a string valid until the next call.
 */
const char *
format_time (time_t t) {
  struct tm *tm;
  static char buf[32];

  tm = gmtime (&t);
  strftime (buf, sizeof (buf), "%Y-%m-%dT%H:%M:%S", tm);

  return (buf);
}

/**
 * @brief Format a flow in a verbose form for logging.
 *
 * @param flow Flow to format.
 * @return Pointer to a string valid until the next call.
 */
const char *
format_flow (struct FLOW *flow) {
  char addr1[64], addr2[64], start_time[32], fin_time[32];
  static char buf[4096];

  inet_ntop (flow->af, &flow->addr[0], addr1, sizeof (addr1));
  inet_ntop (flow->af, &flow->addr[1], addr2, sizeof (addr2));

  snprintf (start_time, sizeof (start_time), "%s",
            format_time (flow->flow_start.tv_sec));
  snprintf (fin_time, sizeof (fin_time), "%s",
            format_time (flow->flow_last.tv_sec));

  snprintf (buf, sizeof (buf),
            "seq:%" PRIu64 " [%s]:%hu <> [%s]:%hu proto:%u "
            "octets>:%u packets>:%u octets<:%u packets<:%u "
            "start:%s.%03lld finish:%s.%03lld tcp>:%02x tcp<:%02x "
            "flowlabel>:%08x flowlabel<:%08x "
            "vlan>:%u vlan<:%u ether:" PRI_ETHERMAC " <> " PRI_ETHERMAC,
            flow->flow_seq, addr1, ntohs (flow->port[0]), addr2,
            ntohs (flow->port[1]), (int) flow->protocol, flow->octets[0],
            flow->packets[0], flow->octets[1], flow->packets[1], start_time,
            (long long) ((flow->flow_start.tv_usec + 500) / 1000), fin_time,
            (long long) ((flow->flow_last.tv_usec + 500) / 1000),
            flow->tcp_flags[0], flow->tcp_flags[1], flow->ip6_flowlabel[0],
            flow->ip6_flowlabel[1], flow->vlanid[0], flow->vlanid[1],
            FORMAT_ETHERMAC (flow->ethermac[0]),
            FORMAT_ETHERMAC (flow->ethermac[1]));

  return (buf);
}

/**
 * @brief Format a flow in a brief form for logging.
 *
 * @param flow Flow to format.
 * @return Pointer to a string valid until the next call.
 */
const char *
format_flow_brief (struct FLOW *flow) {
  char addr1[64], addr2[64];
  static char buf[4096];

  inet_ntop (flow->af, &flow->addr[0], addr1, sizeof (addr1));
  inet_ntop (flow->af, &flow->addr[1], addr2, sizeof (addr2));

  snprintf (buf, sizeof (buf),
            "seq:%" PRIu64 " [%s]:%hu <> [%s]:%hu proto:%u "
            "vlan>:%u vlan<:%u  ether:" PRI_ETHERMAC " <> " PRI_ETHERMAC " ",
            flow->flow_seq, addr1, ntohs (flow->port[0]), addr2,
            ntohs (flow->port[1]), (int) flow->protocol, flow->vlanid[0],
            flow->vlanid[1], FORMAT_ETHERMAC (flow->ethermac[0]),
            FORMAT_ETHERMAC (flow->ethermac[1]));

  return (buf);
}
