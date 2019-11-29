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


struct NTOPNG_MSG_HEADER {
  char url[16];
  u_int8_t version, source_id;
  u_int16_t size;
  u_int32_t msg_id;
} __attribute__((packed));

/*
 * Connect to NTOPNG collector
 */
int
connect_ntopng(const char *host, const char *port, struct ZMQ *zmq) {
  void *context = zmq_ctx_new();
  void *pub_socket = zmq_socket(context, ZMQ_PUB);
  char connect_str[6 + NI_MAXHOST + 1 + NI_MAXSERV + 1];  /* "tcp://hostname:port" */

  if (!context)
    return errno;

  if (!pub_socket) {
    zmq_ctx_destroy(context);
    return errno;
  }

  snprintf(connect_str, sizeof(connect_str), "tcp://%s:%s", host, port);
  fprintf(stderr, "Connecting ZMQ socket '%s'\n", connect_str);
  if (zmq_connect (pub_socket, connect_str)) {
    zmq_close(pub_socket);
    zmq_ctx_destroy(context);
    return errno;
  }

  zmq->context = context;
  zmq->socket = pub_socket;
  return 0;
}

static int
add_json_flow (struct SENDPARAMETER *sp, struct FLOW *flow, char *buf, size_t len)
{
  int size = snprintf(buf, len,
    "{"
      "\"7\": %d," /* src port */
      "\"11\": %d," /* dst port */
      "\"1\": %d," /* in octets */
      "\"2\": %d," /* in packets */
      "\"23\": %d," /* out octets */
      "\"24\": %d," /* out packets */
      "\"22\": %d," /* start timestamp */
      "\"21\": %d," /* last timestamp */
      "\"6\": %d," /* tcp flags */
      "\"4\": %d", /* protocol */
    flow->port[0],
    flow->port[1],
    flow->octets[1],
    flow->packets[1],
    flow->octets[0],
    flow->packets[0],
    timeval_sub_ms (&flow->flow_start, &sp->param->system_boot_time),
    timeval_sub_ms (&flow->flow_last, &sp->param->system_boot_time),
    flow->tcp_flags[0],
    flow->protocol
  );

  if (size > (len - 1))
    return size;

  if (flow->af == AF_INET) {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    /* safe to ignore errors, neither error case can occur */
    inet_ntop(AF_INET, &flow->addr[0].v4, src, sizeof(src));
    inet_ntop(AF_INET, &flow->addr[1].v4, dst, sizeof(dst));

    size += snprintf(buf + size, len - size,
        ",\"8\":\"%s\"," /* ipv4 src addr */
        "\"12\":\"%s\"", /* ipv4 dst addr */
        src,
        dst
    );
  } else {
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];

    /* safe to ignore errors, neither error case can occur */
    inet_ntop(AF_INET6, &flow->addr[0].v6, src, sizeof(src));
    inet_ntop(AF_INET6, &flow->addr[1].v6, dst, sizeof(dst));

    size += snprintf(buf + size, len - size,
        ",\"27\":\"%s\"," /* ipv6 src addr */
        "\"28\":\"%s\"", /* ipv6 dst addr */
        src,
        dst
    );
  }
  if (size > (len - 1))
    return size;

  if (sp->param->track_level >= TRACK_FULL_VLAN) {
    size += snprintf(buf + size, len - size,
        ",\"58\":%d," /* vlan src */
        "\"59\":%d", /* vlan dst */
        flow->vlanid[0],
        flow->vlanid[1]
    );

    if (size > (len - 1))
      return size;
  }

  if (sp->param->track_level >= TRACK_FULL_VLAN_ETHER) {
    size += snprintf(buf + size, len - size,
        ",\"56\":\"%x:%x:%x:%x:%x:%x\"," /* ether mac src */
        "\"57\":\"%x:%x:%x:%x:%x:%x\"", /* ether mac dst */
        flow->ethermac[0][0],flow->ethermac[0][1],flow->ethermac[0][2],
        flow->ethermac[0][3],flow->ethermac[0][4],flow->ethermac[0][5],
        flow->ethermac[1][0],flow->ethermac[1][1],flow->ethermac[1][2],
        flow->ethermac[1][3],flow->ethermac[1][4],flow->ethermac[1][5]
    );
  }

  if (size > (len - 1))
    return size;

  size += snprintf(buf + size, len - size, "}");

  return size;
}

#define MAX_JSON_SIZE 7168

int
send_ntopng_message (struct SENDPARAMETER *sp, int start_at_flow) {
  struct NTOPNG_MSG_HEADER header;
  static uint32_t msg_id = 0;
  char json[MAX_JSON_SIZE];
  int json_used = 0;
  int flow = start_at_flow;
  bool first = true;
  int target = 0;

  header.url[0] = 'f';
  header.url[1] = 'l';
  header.url[2] = 'o';
  header.url[3] = 'w';
  memset(header.url + 4, 0, sizeof(header.url) - 4);

  header.version = 2;
  header.msg_id = htonl(msg_id++);

  json_used += snprintf(json + json_used, MAX_JSON_SIZE - json_used, "[");

  while (flow < sp->num_flows) {
    int size = 0;
    if (first) {
      first = false;
    } else {
      json_used += snprintf (json + json_used, MAX_JSON_SIZE - json_used, ",\n");
    }

    size = add_json_flow (sp, sp->flows[flow], json + json_used, MAX_JSON_SIZE - json_used);
    if (size > (MAX_JSON_SIZE - json_used - 2 -2)) { /* space for "]\0" and next ",\n"*/
      break;
    }

    json_used += size;
    flow++;
  }
  json_used += snprintf (json + json_used, MAX_JSON_SIZE - json_used, "]");

  header.size = htons(json_used);

  for (target = 0; target < sp->target->num_destinations; target++) {
    zmq_send(sp->target->destinations[target].zmq.socket, &header, sizeof(header), ZMQ_SNDMORE);
    zmq_send(sp->target->destinations[target].zmq.socket, json, json_used, 0);
  }

  return flow;
}

int
send_ntopng(struct SENDPARAMETER sp) {
  int flow = 0;
  int packets = 0;

  while (flow < sp.num_flows) {
    flow = send_ntopng_message(&sp, flow);
    packets++;
  }

  sp.param->records_sent += flow;
  sp.param->packets_sent += packets;

#ifdef ENABLE_PTHREAD
  if (use_thread)
    free (sp.flows);
#endif /* ENABLE_PTHREAD */

  return packets;
}
