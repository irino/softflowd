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

#ifndef _IPFIX_H
#define _IPFIX_H

#include "softflowd.h"

#define IPFIX_TEMPLATE_SET_ID           2
#define IPFIX_OPTION_TEMPLATE_SET_ID    3
#define IPFIX_MIN_RECORD_SET_ID         256

/* Flowset record ies the we care about */
#define IPFIX_octetDeltaCount           1
#define IPFIX_packetDeltaCount          2
/* ... */
#define IPFIX_protocolIdentifier        4
#define IPFIX_ipClassOfService          5
/* ... */
#define IPFIX_tcpControlBits            6
#define IPFIX_sourceTransportPort       7
#define IPFIX_sourceIPv4Address         8
/* ... */
#define IPFIX_ingressInterface          10
#define IPFIX_destinationTransportPort  11
#define IPFIX_destinationIPv4Address    12
/* ... */
#define IPFIX_egressInterface           14
/* ... */
#define IPFIX_flowEndSysUpTime          21
#define IPFIX_flowStartSysUpTime        22
/* ... */
#define IPFIX_sourceIPv6Address         27
#define IPFIX_destinationIPv6Address    28
/* ... */
#define IPFIX_icmpTypeCodeIPv4          32
/* ... */
#define IPFIX_sourceMacAddress          56
#define IPFIX_postDestinationMacAddress 57
#define IPFIX_vlanId                    58
#define IPFIX_postVlanId                59

#define IPFIX_ipVersion                     60
/* ... */
#define IPFIX_interfaceName                 82
/* ... */
#define IPFIX_icmpTypeCodeIPv6              139
/* ... */
#define IPFIX_meteringProcessId             143
/* ... */
#define IPFIX_flowStartSeconds              150
#define IPFIX_flowEndSeconds                151
#define IPFIX_flowStartMilliSeconds         152
#define IPFIX_flowEndMilliSeconds           153
#define IPFIX_flowStartMicroSeconds         154
#define IPFIX_flowEndMicroSeconds           155
#define IPFIX_flowStartNanoSeconds          156
#define IPFIX_flowEndNanoSeconds            157
/* ... */
#define IPFIX_systemInitTimeMilliseconds    160
/* ... */


#define IPFIX_SOFTFLOWD_MAX_PACKET_SIZE     1428
struct IPFIX_HEADER {
  u_int16_t version, length;
  u_int32_t export_time;        /* in seconds */
  u_int32_t sequence, od_id;
} __packed;
struct IPFIX_SET_HEADER {
  u_int16_t set_id, length;
} __packed;
struct IPFIX_TEMPLATE_RECORD_HEADER {
  u_int16_t template_id, count;
} __packed;
struct IPFIX_TEMPLATE_SET_HEADER {
  struct IPFIX_SET_HEADER c;
  struct IPFIX_TEMPLATE_RECORD_HEADER r;
} __packed;

struct IPFIX_FIELD_SPECIFIER {
  u_int16_t ie, length;
} __packed;

struct IPFIX_OPTION_TEMPLATE_SET_HEADER {
  struct IPFIX_SET_HEADER c;
  union {
    struct {
      struct IPFIX_TEMPLATE_RECORD_HEADER r;
      u_int16_t scope_count;
    } i;
    struct {
      u_int16_t template_id;
      u_int16_t scope_length;
      u_int16_t option_length;
    } n;
  } u;
} __packed;

struct IPFIX_VENDOR_FIELD_SPECIFIER {
  u_int16_t ie, length;
  u_int32_t pen;
} __packed;
#define REVERSE_PEN 29305

struct ntp_time_t {
  uint32_t second;
  uint32_t fraction;
};

/* Prototypes for functions to send NetFlow packets */
int send_nflow9 (struct SENDPARAMETER sp);
int send_ipfix (struct SENDPARAMETER sp);
int send_ipfix_bi (struct SENDPARAMETER sp);
/* Force a resend of the flow template */
void ipfix_resend_template (void);
int ipfix_init_fields (struct IPFIX_FIELD_SPECIFIER *dst, u_int * index,
                       const struct IPFIX_FIELD_SPECIFIER *src,
                       u_int field_number);
void conv_unix_to_ntp (struct timeval tv, struct ntp_time_t *ntp);
struct timeval conv_ntp_to_unix (struct ntp_time_t ntp);
#endif /* _IPFIX_H */
