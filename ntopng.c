/*
 * Copyright 2018 Alastair D'Silva <alastair@d-silva.org> All rights reserved.
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

#include "common.h"
#include "log.h"
#include "treetype.h"
#include "softflowd.h"

/*
 * TLV export for ntopng 6.0 and later (tested against the 7.0 sources).
 *
 * Message header: struct zmq_msg_hdr_v4 of ntopng (ZMQ_MSG_VERSION 4).
 * Payload: nDPI serializer in TLV format, see ndpi_serializer.c:
 *   2 bytes   serializer version (1) and format (1 = TLV)
 *   per item  1 byte (key type << 4 | value type), key, value
 *   per flow  1 byte end of record (1)
 * Integers are big endian and use the smallest of 1, 2, 4 or 8 bytes,
 * strings are a 2 byte length followed by the characters.
 * Older ntopng (up to 5.x) can be fed with the JSON export in
 * compat/ntopng-json.c.
 */
#define NTOPNG_MSG_VERSION 4
#define NTOPNG_FLAG_IS_TLV (1 << 1)
#define NTOPNG_MAX_TLV_SIZE 16384 /* ntopng accepts up to 128 KB */
#define NTOPNG_LINGER_MS 3000     /* wait for the queued messages at exit */

#define TLV_VERSION 1
#define TLV_FORMAT_TLV 1
#define TLV_END_OF_RECORD 1
#define TLV_UINT8 2
#define TLV_UINT16 3
#define TLV_UINT32 4
#define TLV_UINT64 5
#define TLV_STRING 11

/* NetFlow v9 element ids understood by ntopng */
#define NTOPNG_IN_BYTES 1
#define NTOPNG_IN_PKTS 2
#define NTOPNG_PROTOCOL 4
#define NTOPNG_TCP_FLAGS 6
#define NTOPNG_L4_SRC_PORT 7
#define NTOPNG_IPV4_SRC_ADDR 8
#define NTOPNG_L4_DST_PORT 11
#define NTOPNG_IPV4_DST_ADDR 12
#define NTOPNG_LAST_SWITCHED 21
#define NTOPNG_FIRST_SWITCHED 22
#define NTOPNG_OUT_BYTES 23
#define NTOPNG_OUT_PKTS 24
#define NTOPNG_IPV6_SRC_ADDR 27
#define NTOPNG_IPV6_DST_ADDR 28
#define NTOPNG_IN_SRC_MAC 56
#define NTOPNG_OUT_DST_MAC 57
#define NTOPNG_SRC_VLAN 58
#define NTOPNG_DST_VLAN 59

/* struct zmq_msg_hdr_v4: 36 bytes, the two bytes after flags are padding */
struct NTOPNG_MSG_HEADER {
  char url[16];
  u_int8_t version, flags;
  u_int8_t pad[2];
  u_int32_t uncompressed_size; /* network byte order */
  u_int32_t compressed_size;   /* network byte order */
  u_int32_t msg_id;            /* network byte order */
  u_int32_t source_id;         /* host byte order, read as is by ntopng */
} __attribute__ ((packed));

typedef char
  ntopng_msg_header_size_check[(sizeof (struct NTOPNG_MSG_HEADER) == 36) ? 1
                                                                         : -1];

struct TLV {
  u_int8_t *buf;
  size_t size; /* capacity of buf */
  size_t len;  /* bytes used */
};

/*
 * Connect to NTOPNG collector
 */
int
connect_ntopng (const char *host, const char *port, struct ZMQ *zmq) {
  void *context = zmq_ctx_new();
  void *pub_socket;
  char connect_str[6 + NI_MAXHOST + 1 + NI_MAXSERV + 1]; /* "tcp://hostname:port" */

  if (!context)
    return errno;
  pub_socket = zmq_socket (context, ZMQ_PUB);
  if (!pub_socket) {
    zmq_ctx_destroy (context);
    return errno;
  }

  snprintf (connect_str, sizeof (connect_str), "tcp://%s:%s", host, port);
  fprintf (stderr, "Connecting ZMQ socket '%s'\n", connect_str);

  if (zmq_connect (pub_socket, connect_str)) {
    zmq_close (pub_socket);
    zmq_ctx_destroy (context);
    return errno;
  }

  zmq->context = context;
  zmq->socket = pub_socket;

  return 0;
}

/*
 * Close the ZMQ socket. zmq_ctx_destroy waits until the queued messages are
 * sent, but at most for the linger time: without it the flows exported at
 * shutdown are lost when the process exits.
 */
void
close_ntopng (struct ZMQ *zmq) {
  int linger = NTOPNG_LINGER_MS;

  zmq_setsockopt (zmq->socket, ZMQ_LINGER, &linger, sizeof (linger));
  zmq_close (zmq->socket);
  zmq_ctx_destroy (zmq->context);
  zmq->socket = NULL;
  zmq->context = NULL;
}

static void
tlv_init (struct TLV *t, u_int8_t *buf, size_t size) {
  t->buf = buf;
  t->size = size;
  buf[0] = TLV_VERSION;
  buf[1] = TLV_FORMAT_TLV;
  t->len = 2;
}

static void
tlv_put_be (struct TLV *t, u_int64_t v, int bytes) {
  int i;

  for (i = bytes - 1; i >= 0; i--)
    t->buf[t->len++] = (v >> (8 * i)) & 0xff;
}

/* Smallest of 1, 2, 4 or 8 bytes holding v, as the nDPI serializer does */
static int
tlv_uint_bytes (u_int64_t v) {
  return v <= 0xff ? 1 : v <= 0xffff        ? 2
                       : v <= 0xffffffffULL ? 4
                                            : 8;
}

static u_int8_t
tlv_uint_type (int bytes) {
  return bytes == 1   ? TLV_UINT8
         : bytes == 2 ? TLV_UINT16
         : bytes == 4 ? TLV_UINT32
                      : TLV_UINT64;
}

/* Returns 0 on success, -1 if the item does not fit in the buffer */
static int
tlv_put_uint (struct TLV *t, u_int32_t key, u_int64_t value) {
  int kb = tlv_uint_bytes (key);
  int vb = tlv_uint_bytes (value);

  if (t->size - t->len < (size_t) (1 + kb + vb))
    return -1;
  t->buf[t->len++] = (tlv_uint_type (kb) << 4) | tlv_uint_type (vb);
  tlv_put_be (t, key, kb);
  tlv_put_be (t, value, vb);
  return 0;
}

static int
tlv_put_string (struct TLV *t, u_int32_t key, const char *value) {
  size_t slen = strlen (value);
  int kb = tlv_uint_bytes (key);

  if (slen > 0xffff || t->size - t->len < 1 + kb + 2 + slen)
    return -1;
  t->buf[t->len++] = (tlv_uint_type (kb) << 4) | TLV_STRING;
  tlv_put_be (t, key, kb);
  tlv_put_be (t, slen, 2);
  memcpy (t->buf + t->len, value, slen);
  t->len += slen;
  return 0;
}

static int
tlv_end_record (struct TLV *t) {
  if (t->len >= t->size)
    return -1;
  t->buf[t->len++] = TLV_END_OF_RECORD;
  return 0;
}

/*
 * Append one flow as a TLV record. Ports and counters are plain integers
 * in host byte order, addresses and MAC addresses are strings.
 * Returns 0 on success, -1 if the record does not fit in the buffer.
 */
static int
add_tlv_flow (struct SENDPARAMETER *sp, struct FLOW *flow, struct TLV *t) {
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  char mac[2][3 * 6];
  int i;

  if (tlv_put_uint (t, NTOPNG_L4_SRC_PORT, ntohs (flow->port[0])) ||
      tlv_put_uint (t, NTOPNG_L4_DST_PORT, ntohs (flow->port[1])) ||
      /* IN is source -> destination, OUT is destination -> source */
      tlv_put_uint (t, NTOPNG_IN_BYTES, flow->octets[0]) ||
      tlv_put_uint (t, NTOPNG_IN_PKTS, flow->packets[0]) ||
      tlv_put_uint (t, NTOPNG_OUT_BYTES, flow->octets[1]) ||
      tlv_put_uint (t, NTOPNG_OUT_PKTS, flow->packets[1]) ||
      /* epoch seconds */
      tlv_put_uint (t, NTOPNG_FIRST_SWITCHED, flow->flow_start.tv_sec) ||
      tlv_put_uint (t, NTOPNG_LAST_SWITCHED, flow->flow_last.tv_sec) ||
      tlv_put_uint (t, NTOPNG_TCP_FLAGS, flow->tcp_flags[0]) ||
      tlv_put_uint (t, NTOPNG_PROTOCOL, flow->protocol))
    return -1;

  if (flow->af == AF_INET) {
    inet_ntop (AF_INET, &flow->addr[0].v4, src, sizeof (src));
    inet_ntop (AF_INET, &flow->addr[1].v4, dst, sizeof (dst));
    if (tlv_put_string (t, NTOPNG_IPV4_SRC_ADDR, src) ||
        tlv_put_string (t, NTOPNG_IPV4_DST_ADDR, dst))
      return -1;
  } else {
    inet_ntop (AF_INET6, &flow->addr[0].v6, src, sizeof (src));
    inet_ntop (AF_INET6, &flow->addr[1].v6, dst, sizeof (dst));
    if (tlv_put_string (t, NTOPNG_IPV6_SRC_ADDR, src) ||
        tlv_put_string (t, NTOPNG_IPV6_DST_ADDR, dst))
      return -1;
  }

  if (sp->param->track_level >= TRACK_FULL_VLAN) {
    if (tlv_put_uint (t, NTOPNG_SRC_VLAN, flow->vlanid[0]) ||
        tlv_put_uint (t, NTOPNG_DST_VLAN, flow->vlanid[1]))
      return -1;
  }

  if (sp->param->track_level >= TRACK_FULL_VLAN_ETHER) {
    for (i = 0; i < 2; i++)
      snprintf (mac[i], sizeof (mac[i]), "%02x:%02x:%02x:%02x:%02x:%02x",
                flow->ethermac[i][0], flow->ethermac[i][1],
                flow->ethermac[i][2], flow->ethermac[i][3],
                flow->ethermac[i][4], flow->ethermac[i][5]);
    if (tlv_put_string (t, NTOPNG_IN_SRC_MAC, mac[0]) ||
        tlv_put_string (t, NTOPNG_OUT_DST_MAC, mac[1]))
      return -1;
  }

  return tlv_end_record (t);
}

static int
send_ntopng_message (struct SENDPARAMETER *sp, int start_at_flow) {
  struct NTOPNG_MSG_HEADER header;
  static uint32_t msg_id = 0;
  u_int8_t payload[NTOPNG_MAX_TLV_SIZE];
  struct TLV t;
  int flow = start_at_flow;
  int added = 0;
  int target;

  tlv_init (&t, payload, sizeof (payload));

  while (flow < sp->num_flows) {
    size_t mark = t.len;

    if (add_tlv_flow (sp, sp->flows[flow], &t) < 0) {
      t.len = mark; /* drop the partial record */
      if (added)
        break; /* continue in the next message */
      /* A single flow never fits: skip it, otherwise we would loop forever */
      logit (LOG_WARNING, "ntopng: flow too large for a TLV message");
    } else
      added++;
    flow++;
  }
  if (!added)
    return flow;

  memset (&header, 0, sizeof (header));
  memcpy (header.url, "flow", 4);
  header.version = NTOPNG_MSG_VERSION;
  header.flags = NTOPNG_FLAG_IS_TLV;
  header.uncompressed_size = header.compressed_size = htonl (t.len);
  header.msg_id = htonl (msg_id++);
  header.source_id = 0;

  for (target = 0; target < sp->target->num_destinations; target++) {
    void *socket = sp->target->destinations[target].zmq.socket;

    if (zmq_send (socket, &header, sizeof (header), ZMQ_SNDMORE) < 0 ||
        zmq_send (socket, t.buf, t.len, 0) < 0)
      logit (LOG_WARNING, "ntopng: zmq_send failed: %s",
             zmq_strerror (errno));
  }

  return flow;
}

int
send_ntopng (struct SENDPARAMETER sp) {
  int flow = 0;
  int packets = 0;

  while (flow < sp.num_flows) {
    flow = send_ntopng_message (&sp, flow);
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
