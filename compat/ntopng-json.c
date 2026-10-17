/*
 * Copyright 2018 Alastair D'Silva <alastair@d-silva.org> All rights reserved.
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

#include "common.h"
#include "log.h"
#include "treetype.h"
#include "softflowd.h"
#include <stdbool.h>

/*
 * JSON export for ntopng up to 5.x (struct zmq_msg_hdr, version 2).
 * ntopng 6.0 and later ignore JSON flows in the Community edition: use the
 * TLV export in ntopng.c for those versions.
 */
struct NTOPNG_MSG_HEADER {
  char url[16];
  u_int8_t version, source_id;
  u_int16_t size;
  u_int32_t msg_id;
} __attribute__ ((packed));

static int
add_json_flow (struct SENDPARAMETER *sp, struct FLOW *flow, char *buf,
               size_t len) {
  int size;

  if (len < 2)
    return (int) len + 1;
  size = snprintf (buf, len,
                   "{"
                   "\"7\": %d,"    /* src port */
                   "\"11\": %d,"   /* dst port */
                   "\"1\": %u,"    /* in octets (src -> dst) */
                   "\"2\": %u,"    /* in packets (src -> dst) */
                   "\"23\": %u,"   /* out octets (dst -> src) */
                   "\"24\": %u,"   /* out packets (dst -> src) */
                   "\"22\": %lld," /* start timestamp (epoch sec) */
                   "\"21\": %lld," /* last timestamp (epoch sec) */
                   "\"6\": %d,"    /* tcp flags */
                   "\"4\": %d",    /* protocol */
                   ntohs (flow->port[0]),
                   ntohs (flow->port[1]),
                   flow->octets[0],
                   flow->packets[0],
                   flow->octets[1],
                   flow->packets[1],
                   (long long) flow->flow_start.tv_sec,
                   (long long) flow->flow_last.tv_sec,
                   flow->tcp_flags[0],
                   flow->protocol);

  if (size < 0 || (size_t) size > len - 1)
    return (int) len + 1;

  if (flow->af == AF_INET) {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    /* safe to ignore errors, neither error case can occur */
    inet_ntop (AF_INET, &flow->addr[0].v4, src, sizeof (src));
    inet_ntop (AF_INET, &flow->addr[1].v4, dst, sizeof (dst));

    size += snprintf (buf + size, len - size, ",\"8\":\"%s\"," /* ipv4 src addr */
                                              "\"12\":\"%s\"", /* ipv4 dst addr */
                      src, dst);
  } else {
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];

    /* safe to ignore errors, neither error case can occur */
    inet_ntop (AF_INET6, &flow->addr[0].v6, src, sizeof (src));
    inet_ntop (AF_INET6, &flow->addr[1].v6, dst, sizeof (dst));

    size += snprintf (buf + size, len - size, ",\"27\":\"%s\"," /* ipv6 src addr */
                                              "\"28\":\"%s\"",  /* ipv6 dst addr */
                      src, dst);
  }
  if (size < 0 || (size_t) size > len - 1)
    return (int) len + 1;

  if (sp->param->track_level >= TRACK_FULL_VLAN) {
    size += snprintf (buf + size, len - size, ",\"58\":%d," /* vlan src */
                                              "\"59\":%d",  /* vlan dst */
                      flow->vlanid[0], flow->vlanid[1]);

    if (size < 0 || (size_t) size > len - 1)
      return (int) len + 1;
  }

  if (sp->param->track_level >= TRACK_FULL_VLAN_ETHER) {
    size += snprintf (buf + size, len - size, ",\"56\":\"%x:%x:%x:%x:%x:%x\"," /* ether mac src */
                                              "\"57\":\"%x:%x:%x:%x:%x:%x\"",  /* ether mac dst */
                      flow->ethermac[0][0], flow->ethermac[0][1],
                      flow->ethermac[0][2], flow->ethermac[0][3],
                      flow->ethermac[0][4], flow->ethermac[0][5],
                      flow->ethermac[1][0], flow->ethermac[1][1],
                      flow->ethermac[1][2], flow->ethermac[1][3],
                      flow->ethermac[1][4], flow->ethermac[1][5]);
  }

  if (size < 0 || (size_t) size > len - 1)
    return (int) len + 1;

  size += snprintf (buf + size, len - size, "}");

  return size;
}

#define MAX_JSON_SIZE 7168

static int
send_ntopng_message (struct SENDPARAMETER *sp, int start_at_flow) {
  struct NTOPNG_MSG_HEADER header;
  static uint32_t msg_id = 0;
  char json[MAX_JSON_SIZE];
  int json_used = 0;
  int flow = start_at_flow;
  bool first = true;
  int target = 0;

  memset (&header, 0, sizeof (header));
  memcpy (header.url, "flow", 4);
  header.version = 2;
  header.msg_id = htonl (msg_id++);

  json_used += snprintf (json + json_used, MAX_JSON_SIZE - json_used, "[");

  while (flow < sp->num_flows) {
    int separator = 0;
    int size;

    if (!first)
      separator =
        snprintf (json + json_used, MAX_JSON_SIZE - json_used, ",\n");
    size = add_json_flow (sp, sp->flows[flow],
                          json + json_used + separator,
                          MAX_JSON_SIZE - json_used - separator);
    if (size > MAX_JSON_SIZE - json_used - separator - 2) { /* "]\0" */
      if (!first)
        break; /* the separator is not committed, so no trailing comma */
      /* A single flow never fits: skip it, otherwise we would loop forever */
      logit (LOG_WARNING, "ntopng: flow too large for a JSON message");
      flow++;
      continue;
    }
    json_used += separator + size;
    first = false;
    flow++;
  }
  if (first) /* nothing to send */
    return flow;
  json_used += snprintf (json + json_used, MAX_JSON_SIZE - json_used, "]");

  header.size = htons (json_used);

  for (target = 0; target < sp->target->num_destinations; target++) {
    void *socket = sp->target->destinations[target].zmq.socket;

    if (zmq_send (socket, &header, sizeof (header), ZMQ_SNDMORE) < 0 ||
        zmq_send (socket, json, json_used, 0) < 0)
      logit (LOG_WARNING, "ntopng: zmq_send failed: %s",
             zmq_strerror (errno));
  }

  return flow;
}

int
send_ntopng_json (struct SENDPARAMETER sp) {
  int flow = 0;
  int packets = 0;

  while (flow < sp.num_flows) {
    flow = send_ntopng_message (&sp, flow);
    packets++;
  }

  sp.param->records_sent += flow;
  sp.param->packets_sent += packets;

  return packets;
}
