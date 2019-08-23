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

#include "common.h"
#include "log.h"
#include "ipfix.h"
#include "psamp.h"
#include <pcap.h>

#define PSAMP_SOFTFLOWD_TEMPLATE_ID       3072
#define PSAMP_SOFTFLOWD_TEMPLATE_NRECORDS 4

#define PSAMP_DATALINKFRAME_SIZE IPFIX_SOFTFLOWD_MAX_PACKET_SIZE - \
  sizeof(struct IPFIX_HEADER) - sizeof(struct IPFIX_SET_HEADER) - 8 - 8 -2

const struct IPFIX_FIELD_SPECIFIER field_psamp[] = {
  {PSAMP_selectionSequenceId, 8},
  {PSAMP_observationTimeMicroseconds, 8},
  {PSAMP_sectionExportedOctets, 2},
  {PSAMP_dataLinkFrameSection, PSAMP_DATALINKFRAME_SIZE}
};

struct PSAMP_SOFTFLOWD_TEMPLATE {
  struct IPFIX_TEMPLATE_SET_HEADER h;
  struct IPFIX_FIELD_SPECIFIER r[PSAMP_SOFTFLOWD_TEMPLATE_NRECORDS];
} __packed;
struct PSAMP_SOFTFLOWD_TEMPLATE template;
static int psamp_pkts_until_template = -1;

static void
psamp_init_template (struct PSAMP_SOFTFLOWD_TEMPLATE *template_p) {
  u_int index = 0;
  memset (template_p, 0, sizeof (*template_p));
  template_p->h.c.set_id = htons (IPFIX_TEMPLATE_SET_ID);
  template_p->h.c.length = htons (sizeof (struct PSAMP_SOFTFLOWD_TEMPLATE));
  template_p->h.r.template_id = htons (PSAMP_SOFTFLOWD_TEMPLATE_ID);
  template_p->h.r.count = htons (PSAMP_SOFTFLOWD_TEMPLATE_NRECORDS);
  ipfix_init_fields (template_p->r, &index, field_psamp,
                     PSAMP_SOFTFLOWD_TEMPLATE_NRECORDS);
}

int
send_psamp (const u_char * pkt, int caplen, struct timeval tv,
            struct NETFLOW_TARGET *target, uint64_t total_packets) {
  u_char packet[IPFIX_SOFTFLOWD_MAX_PACKET_SIZE];
  struct IPFIX_HEADER *ipfix = (struct IPFIX_HEADER *) packet;
  struct IPFIX_SET_HEADER *dh;
  u_int64_t *sequenceId;
  struct ntp_time_t *ntptime;
  u_int16_t *exportedOctets;
  int offset = sizeof (struct IPFIX_HEADER);
  int copysize =
    caplen < PSAMP_DATALINKFRAME_SIZE ? caplen : PSAMP_DATALINKFRAME_SIZE;

  ipfix->version = htons (NF_VERSION_IPFIX);    // PSAMP uses IPFIX
  ipfix->export_time = htonl (tv.tv_sec);
  ipfix->sequence = htonl ((u_int32_t) (total_packets & 0x00000000ffffffff));
  ipfix->od_id = 0;

  if (psamp_pkts_until_template == -1) {
    psamp_init_template (&template);
    psamp_pkts_until_template = 0;
    memcpy (&packet[offset], &template, sizeof (template));
    ipfix->length = htons (offset + sizeof (template));
    if (send_multi_destinations
        (target->num_destinations, target->destinations, 0, packet,
         offset + sizeof (template)) < 0)
      return (-1);
  }

  dh = (struct IPFIX_SET_HEADER *) &packet[offset];
  dh->set_id = htons (PSAMP_SOFTFLOWD_TEMPLATE_ID);
  dh->length =
    htons (IPFIX_SOFTFLOWD_MAX_PACKET_SIZE - sizeof (struct IPFIX_HEADER));
  offset += sizeof (struct IPFIX_SET_HEADER);

  sequenceId = (u_int64_t *) & packet[offset];
  *sequenceId = htobe64 (total_packets);
  offset += sizeof (u_int64_t);

  ntptime = (struct ntp_time_t *) &packet[offset];
  conv_unix_to_ntp (tv, ntptime);
  ntptime->second = htonl (ntptime->second);
  ntptime->fraction = htonl (ntptime->fraction);
  offset += sizeof (struct ntp_time_t);

  exportedOctets = (u_int16_t *) & packet[offset];
  *exportedOctets = htons (copysize);
  offset += sizeof (u_int16_t);

  memset (&packet[offset], 0, IPFIX_SOFTFLOWD_MAX_PACKET_SIZE - offset);
  memcpy (&packet[offset], pkt, copysize);
  ipfix->length = htons (IPFIX_SOFTFLOWD_MAX_PACKET_SIZE);
  if (send_multi_destinations (target->num_destinations, target->destinations,
                               target->is_loadbalance,
                               packet, IPFIX_SOFTFLOWD_MAX_PACKET_SIZE) < 0)
    return (-1);
  return 1;
}

// This function only process softflowd orignate psamp data record.
int
recv_psamp (int rsock, struct CB_CTXT *cb_ctxt) {
  char buf[IPFIX_SOFTFLOWD_MAX_PACKET_SIZE];
  struct IPFIX_HEADER *ipfix = (struct IPFIX_HEADER *) buf;
  struct ntp_time_t ntptime;
  struct pcap_pkthdr pkthdr;
  int recvsize = 0;
  int offset = 0;
  memset (buf, 0, sizeof (buf));
  recvsize = recv (rsock, buf, sizeof (buf), 0);
  if (recvsize < 0) {
    perror ("recv");
    return -1;
  } else if (recvsize <
             (sizeof (struct IPFIX_HEADER) +
              sizeof (struct IPFIX_SET_HEADER) + sizeof (uint64_t) +
              sizeof (struct ntp_time_t) + sizeof (uint16_t))) {
    logit (LOG_DEBUG, "recv_psamp: recvsize: %d is shorter than needed size",
           recvsize);
    return -1;
  }
  offset = sizeof (struct IPFIX_HEADER);
  struct IPFIX_SET_HEADER *sh = (struct IPFIX_SET_HEADER *) &buf[offset];
  offset += sizeof (struct IPFIX_SET_HEADER);
  if (ntohs (ipfix->version) != NF_VERSION_IPFIX)
    return -1;
  if (ntohs (sh->set_id) != PSAMP_SOFTFLOWD_TEMPLATE_ID)
    return 0;                   // This function only process softflowd orignate psamp data record.

  // disrgard selectionSequenceId
  offset += sizeof (uint64_t);

  // observationTimeMicroseconds
  ntptime = *((struct ntp_time_t *) &buf[offset]);
  offset += sizeof (struct ntp_time_t);
  ntptime.second = ntohl (ntptime.second);
  ntptime.fraction = ntohl (ntptime.fraction);
  pkthdr.ts = conv_ntp_to_unix (ntptime);

  //sectionExportedOctets
  pkthdr.caplen = pkthdr.len = ntohs (*((uint16_t *) & buf[offset]));
  offset += sizeof (uint16_t);
  pkthdr.caplen =
    pkthdr.caplen <
    sizeof (buf) - offset ? pkthdr.caplen : sizeof (buf) - offset;

  flow_cb ((u_char *) cb_ctxt, &pkthdr, (const u_char *) &buf[offset]);
  return 1;
}
