/*
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

/**
 * @file export_template.c
 * @brief The template-based part of the encoder-based exporter: the templates
 *   and the options template of NetFlow v9 and IPFIX, and the encoding of
 *   their data records. Split from export.c.
 */

#include "export.h"
#include "export_common.h"
#include "ipfix.h"
#include "ipfix_fields.h"
#include "common.h"
#include "netflow.h"
#include "psamp.h"
#include "softflowd.h"

/** A NetFlow v9 / IPFIX template (struct IPFIX_SOFTFLOWD_TEMPLATE) together
 * with the encoders used to fill its data records. */
struct EXPORT_TEMPLATE {
  /** Template as sent, in network byte order. */
  struct IPFIX_SOFTFLOWD_TEMPLATE t;
  /** Encoders of the fields of a data record. */
  struct EXPORT_FIELD_SPECIFIER_ENCODER hr[IPFIX_SOFTFLOWD_TEMPLATE_NRECORDS];
  /** Encoders of the reverse-direction fields; t.bi_count of them are used. */
  struct EXPORT_FIELD_SPECIFIER_ENCODER
    hbi[IPFIX_SOFTFLOWD_TEMPLATE_BI_NRECORDS];
  u_int hr_count; /**< Number of entries of hr[] in use */
};

/** Templates indexed by TMPLV4, TMPLICMPV4, TMPLV6 and TMPLICMPV6. */
static struct EXPORT_TEMPLATE templates[TMPLMAX];

/**
 * @brief Emits NFv9/IPFIX Options Templates and Data Records using
 * export_emit_group_enc().
 *
 * Reuses struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE to avoid duplicate padded
 * declarations.
 */
struct EXPORT_OPTION_TEMPLATE {
  /** Options template as sent on the wire. */
  struct IPFIX_SOFTFLOWD_OPTION_TEMPLATE tmpl;
  /* Host-order copies for the Data Record -- see EXPORT_TEMPLATE.hr[]. */
  /** Encoders of the scope fields. */
  struct EXPORT_FIELD_SPECIFIER_ENCODER
    hs[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS];
  /** Encoders of the option fields. */
  struct EXPORT_FIELD_SPECIFIER_ENCODER
    hr[IPFIX_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];
  u_int hs_count;      /**< Number of entries in hs[] */
  u_int hr_count;      /**< Number of entries in hr[] */
  u_int16_t total_len; /**< Bytes of tmpl.h+s+r actually in use */
};

/** The options template and data record, built once by ipfix_init_option(). */
static struct EXPORT_OPTION_TEMPLATE option_template;
/** Non-zero once option_template has been built. */
static int option_initialized = 0;

/**
 * @brief Build the options template for the given version into option_template.
 *
 * @param version Export version: 9 or 10.
 */
static void
ipfix_init_option (u_int16_t version) {
  const struct EXPORT_FIELD_SPECIFIER_ENCODER *scope_src, *opt_src;
  u_int scope_n, opt_n, i, scope_speclen, opt_speclen;

  memset (&option_template, 0, sizeof (option_template));
  if (version == 10) {
    scope_src = field_scope;
    scope_n = EXPORT_NFIELDS_ENC (field_scope);
    opt_src = field_option;
    opt_n = EXPORT_NFIELDS_ENC (field_option);
  } else {
    scope_src = field_nf9scope;
    scope_n = EXPORT_NFIELDS_ENC (field_nf9scope);
    opt_src = field_nf9option;
    opt_n = EXPORT_NFIELDS_ENC (field_nf9option);
  }

  for (i = 0; i < scope_n; i++) {
    option_template.tmpl.s[i].ie = htons (scope_src[i].field.ie);
    option_template.tmpl.s[i].length = htons (scope_src[i].field.length);
    option_template.hs[i] = scope_src[i];
  }
  option_template.hs_count = scope_n;
  for (i = 0; i < opt_n; i++) {
    option_template.tmpl.r[i].ie = htons (opt_src[i].field.ie);
    option_template.tmpl.r[i].length = htons (opt_src[i].field.length);
    option_template.hr[i] = opt_src[i];
  }
  option_template.hr_count = opt_n;

  /* scope_speclen/opt_speclen: byte length of the field-specifier
   * lists themselves (4 octets/entry), not of the data they describe. */
  scope_speclen = scope_n * sizeof (struct IPFIX_FIELD_SPECIFIER);
  opt_speclen = opt_n * sizeof (struct IPFIX_FIELD_SPECIFIER);

  option_template.tmpl.h.c.set_id =
    htons (version == 10 ? IPFIX_OPTION_TEMPLATE_SET_ID
                         : NETFLOW9_OPTION_TEMPLATE_SET_ID);
  option_template.tmpl.h.c.length =
    htons (sizeof (option_template.tmpl.h) + scope_speclen + opt_speclen);
  if (version == 10) {
    option_template.tmpl.h.u.i.r.template_id =
      htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    option_template.tmpl.h.u.i.r.count = htons (scope_n + opt_n);
    option_template.tmpl.h.u.i.scope_count = htons (scope_n);
  } else {
    option_template.tmpl.h.u.n.template_id =
      htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
    option_template.tmpl.h.u.n.scope_length = htons (scope_speclen);
    option_template.tmpl.h.u.n.option_length = htons (opt_speclen);
  }
  option_template.total_len =
    sizeof (option_template.tmpl.h) + scope_speclen + opt_speclen;
  option_initialized = 1;
}

/**
 * @brief Append the options template set and its data record to a packet.
 *
 * The data record is emitted through export_emit_group_enc() like a standard
 * record.
 *
 * @param packet  Packet buffer.
 * @param offset  Offset to write at; advanced past the appended data.
 * @param version Export version: 9 or 10.
 * @param sp      Send parameters; the option values are taken from sp->param.
 */
static void
ipfix_send_option (u_char *packet, u_int *offset, u_int16_t version,
                   const struct SENDPARAMETER *sp) {
  struct IPFIX_SET_HEADER *c;
  u_int doff;
  u_int scope_speclen, opt_speclen;

  if (!option_initialized)
    ipfix_init_option (version);

  /* Copies template header, s[], and r[] in 3 separate blocks to skip unused
   * tail bytes caused by IPFIX's max-sized field array backing in
   * option_template. */
  scope_speclen =
    option_template.hs_count * sizeof (struct IPFIX_FIELD_SPECIFIER);
  opt_speclen = option_template.hr_count * sizeof (struct IPFIX_FIELD_SPECIFIER);
  memcpy (packet + *offset, &option_template.tmpl.h,
          sizeof (option_template.tmpl.h));
  *offset += sizeof (option_template.tmpl.h);
  memcpy (packet + *offset, option_template.tmpl.s, scope_speclen);
  *offset += scope_speclen;
  memcpy (packet + *offset, option_template.tmpl.r, opt_speclen);
  *offset += opt_speclen;

  c = (struct IPFIX_SET_HEADER *) (packet + *offset);
  doff = sizeof (*c);
  struct EXPORT_CTX ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.sp = sp;
  doff = export_emit_group_enc (option_template.hs, option_template.hs_count,
                                packet + *offset, doff, &ctx);
  doff = export_emit_group_enc (option_template.hr, option_template.hr_count,
                                packet + *offset, doff, &ctx);
  c->set_id = htons (IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID);
  c->length = htons (doff);
  *offset += doff;
}

/**
 * @brief Add fields to a template and remember their encoders.
 *
 * Fields that do not fit in the template arrays are dropped.
 *
 * @param tmpl         Template to extend.
 * @param index        Position to start at; advanced by the number of fields
 * added.
 * @param src          Field table with encoders.
 * @param field_number Number of fields to add.
 * @param bi_flag      IPFIX_BIFLAG_ON to add reverse-direction (enterprise)
 * fields.
 * @return Sum of the lengths of the added fields.
 */
static u_int
ipfix_init_template_fields (struct EXPORT_TEMPLATE *tmpl, u_int *index,
                            const struct EXPORT_FIELD_SPECIFIER_ENCODER *src,
                            u_int field_number, int bi_flag) {
  u_int i, length = 0;
  u_int max_fields = bi_flag ? sizeof (tmpl->t.v) / sizeof (tmpl->t.v[0])
                             : sizeof (tmpl->t.r) / sizeof (tmpl->t.r[0]);
  for (i = 0; i < field_number && *index + i < max_fields; i++) {
    if (bi_flag) {
      tmpl->t.v[*index + i].ie = htons (src[i].field.ie | 0x8000);
      tmpl->t.v[*index + i].length = htons (src[i].field.length);
      tmpl->t.v[*index + i].pen = htonl (REVERSE_PEN);
      tmpl->hbi[*index + i] = src[i];
    } else {
      tmpl->t.r[*index + i].ie = htons (src[i].field.ie);
      tmpl->t.r[*index + i].length = htons (src[i].field.length);
      tmpl->hr[*index + i] = src[i];
    }
    length += src[i].field.length;
  }
  if (!bi_flag)
    tmpl->hr_count = *index + i;
  *index += i;
  return length;
}

/**
 * @brief Add the flow start/end time fields chosen by the time format option
 * (-A).
 *
 * @param param   Tracking parameters (time_format).
 * @param tmpl    Template to extend.
 * @param index   Position to start at; advanced.
 * @param version Export version: only IPFIX (10) supports absolute time
 * formats.
 * @return Sum of the lengths of the added fields.
 */
static u_int
ipfix_init_template_time (struct FLOWTRACKPARAMETERS *param,
                          struct EXPORT_TEMPLATE *tmpl, u_int *index,
                          u_int16_t version) {
  /* Absolute (calendar) timestamps are IPFIX-only
   * NetFlow v9 always uses the relative sysUpTime form. */
  if (version == 10 && param->time_format == 's')
    return ipfix_init_template_fields (tmpl, index, field_timesec, 2,
                                       IPFIX_BIFLAG_OFF);
  if (version == 10 && param->time_format == 'm')
    return ipfix_init_template_fields (tmpl, index, field_timemsec, 2,
                                       IPFIX_BIFLAG_OFF);
  if (version == 10 && param->time_format == 'M')
    return ipfix_init_template_fields (tmpl, index, field_timeusec, 2,
                                       IPFIX_BIFLAG_OFF);
  if (version == 10 && param->time_format == 'n')
    return ipfix_init_template_fields (tmpl, index, field_timensec, 2,
                                       IPFIX_BIFLAG_OFF);
  return ipfix_init_template_fields (tmpl, index, field_timesysup, 2,
                                     IPFIX_BIFLAG_OFF);
}

/**
 * @brief Build one complete template.
 *
 * @param param       Tracking parameters.
 * @param tmpl        Template to build.
 * @param template_id Template id.
 * @param v6_flag     Non-zero for IPv6.
 * @param icmp_flag   Non-zero for the ICMP variant.
 * @param bi_flag     IPFIX_BIFLAG_ON for biflow (reverse fields).
 * @param version     Export version.
 */
static void
ipfix_init_template_unity (struct FLOWTRACKPARAMETERS *param,
                           struct EXPORT_TEMPLATE *tmpl,
                           u_int template_id, u_int8_t v6_flag,
                           u_int8_t icmp_flag, u_int8_t bi_flag,
                           u_int16_t version) {
  u_int index = 0, bi_index = 0, length = 0;
  memset (tmpl, 0, sizeof (*tmpl));
  tmpl->t.h.c.set_id =
    htons (version == 10 ? IPFIX_TEMPLATE_SET_ID : NETFLOW9_TEMPLATE_SET_ID);
  tmpl->t.h.r.template_id = htons (template_id);

  if (v6_flag)
    length += ipfix_init_template_fields (tmpl, &index, field_v6,
                                          EXPORT_NFIELDS_ENC (field_v6),
                                          IPFIX_BIFLAG_OFF);
  else
    length += ipfix_init_template_fields (tmpl, &index, field_v4,
                                          EXPORT_NFIELDS_ENC (field_v4),
                                          IPFIX_BIFLAG_OFF);
  length += ipfix_init_template_time (param, tmpl, &index, version);
  length += ipfix_init_template_fields (tmpl, &index, field_common,
                                        EXPORT_NFIELDS_ENC (field_common),
                                        IPFIX_BIFLAG_OFF);
  if (icmp_flag) {
    if (v6_flag)
      length += ipfix_init_template_fields (tmpl, &index, field_icmp6,
                                            EXPORT_NFIELDS_ENC (field_icmp6),
                                            IPFIX_BIFLAG_OFF);
    else
      length += ipfix_init_template_fields (tmpl, &index, field_icmp4,
                                            EXPORT_NFIELDS_ENC (field_icmp4),
                                            IPFIX_BIFLAG_OFF);
  } else {
    length += ipfix_init_template_fields (tmpl, &index, field_transport,
                                          EXPORT_NFIELDS_ENC (field_transport),
                                          IPFIX_BIFLAG_OFF);
  }
  if (param->track_level >= TRACK_FULL_VLAN)
    length += ipfix_init_template_fields (tmpl, &index, field_vlan,
                                          EXPORT_NFIELDS_ENC (field_vlan),
                                          IPFIX_BIFLAG_OFF);
  if (param->track_level >= TRACK_FULL_VLAN_ETHER)
    length += ipfix_init_template_fields (tmpl, &index, field_ether,
                                          EXPORT_NFIELDS_ENC (field_ether),
                                          IPFIX_BIFLAG_OFF);
  if (bi_flag && version == 10) {
    length += ipfix_init_template_fields (tmpl, &bi_index, field_bicommon,
                                          EXPORT_NFIELDS_ENC (field_bicommon),
                                          IPFIX_BIFLAG_ON);
    if (icmp_flag) {
      if (v6_flag)
        length += ipfix_init_template_fields (
          tmpl, &bi_index, field_biicmp6,
          EXPORT_NFIELDS_ENC (field_biicmp6), IPFIX_BIFLAG_ON);
      else
        length += ipfix_init_template_fields (
          tmpl, &bi_index, field_biicmp4,
          EXPORT_NFIELDS_ENC (field_biicmp4), IPFIX_BIFLAG_ON);
    } else {
      length += ipfix_init_template_fields (
        tmpl, &bi_index, field_bitransport,
        EXPORT_NFIELDS_ENC (field_bitransport), IPFIX_BIFLAG_ON);
    }
  }
  tmpl->t.bi_count = bi_index;
  tmpl->t.h.r.count = htons (index + bi_index + param->max_num_label);
  tmpl->t.h.c.length =
    htons (sizeof (struct IPFIX_TEMPLATE_SET_HEADER) +
           index * sizeof (struct IPFIX_FIELD_SPECIFIER) +
           bi_index * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) +
           param->max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER));
  tmpl->t.data_len =
    length + param->max_num_label * IPFIX_mplsLabelStackSection_SIZE;
}

/**
 * @brief Build the IPv4, ICMPv4, IPv6 and ICMPv6 templates into templates.
 *
 * @param param   Tracking parameters.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow.
 * @param version Export version: 9 or 10.
 */
static void
ipfix_init_templates (struct FLOWTRACKPARAMETERS *param,
                      u_int8_t bi_flag, u_int16_t version) {
  u_int8_t v6_flag = 0, icmp_flag = 0;
  u_int16_t template_id = 0;
  int i;
  for (i = 0; i < TMPLMAX; i++) {
    switch (i) {
      case TMPLV4:
        v6_flag = 0;
        icmp_flag = 0;
        template_id = IPFIX_SOFTFLOWD_V4_TEMPLATE_ID;
        break;
      case TMPLICMPV4:
        v6_flag = 0;
        icmp_flag = 1;
        template_id = IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID;
        break;
      case TMPLV6:
        v6_flag = 1;
        icmp_flag = 0;
        template_id = IPFIX_SOFTFLOWD_V6_TEMPLATE_ID;
        break;
      case TMPLICMPV6:
        v6_flag = 1;
        icmp_flag = 1;
        template_id = IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID;
        break;
    }
    ipfix_init_template_unity (param, &templates[i], template_id, v6_flag,
                               icmp_flag, bi_flag, version);
  }
}

/**
 * @brief Append a template to a packet, including reverse fields and the MPLS
 * label fields.
 *
 * @param packet        Packet buffer.
 * @param offset        Offset to write at; advanced.
 * @param tmpl          Template to copy.
 * @param bi_flag       Non-zero to append the reverse-direction fields.
 * @param max_num_label Number of MPLS label fields to append.
 */
static void
ipfix_memcpy_template (u_char *packet, u_int *offset,
                       struct EXPORT_TEMPLATE *tmpl, u_int8_t bi_flag,
                       u_int8_t max_num_label) {
  u_int i, size = ntohs (tmpl->t.h.c.length) -
                  tmpl->t.bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER) -
                  max_num_label * sizeof (struct IPFIX_FIELD_SPECIFIER);
  memcpy (packet + *offset, &tmpl->t, size);
  *offset += size;
  if (bi_flag) {
    size = tmpl->t.bi_count * sizeof (struct IPFIX_VENDOR_FIELD_SPECIFIER);
    memcpy (packet + *offset, tmpl->t.v, size);
    *offset += size;
  }
  for (i = 0; i < max_num_label; i++) {
    struct IPFIX_FIELD_SPECIFIER *mpls_fs =
      (struct IPFIX_FIELD_SPECIFIER *) &packet[*offset];
    mpls_fs->ie = htons (IPFIX_mplsTopLabelStackSection + i);
    mpls_fs->length = htons (IPFIX_mplsLabelStackSection_SIZE);
    *offset += sizeof (struct IPFIX_FIELD_SPECIFIER);
  }
}

/**
 * @brief Encode the data records of one flow (standard or biflow) using the
 * template field list.
 *
 * Dynamic counterpart of the record loop in send_fixed_flow().
 *
 * @param flow     Flow to encode.
 * @param packet   Output buffer.
 * @param len      Space available in packet.
 * @param sp       Send parameters: flows, target, interface index, tracking
 * parameters and verbosity.
 * @param len_used Receives the number of bytes written.
 * @param bi_flag  Non-zero to emit one biflow record instead of one per
 * direction.
 * @param version  Export version.
 * @return Number of records written, or -1 if the buffer is too small.
 */
int
ipfix_flow_to_flowset (const struct FLOW *flow, u_char *packet,
                       u_int len, const struct SENDPARAMETER *sp,
                       u_int *len_used, u_int8_t bi_flag,
                       u_int16_t version) {
  u_int tmplindex = ipfix_flow_to_template_index (flow);
  struct EXPORT_TEMPLATE *tmpl = &templates[tmplindex];
  u_int offset = 0, nflows = 0, k;
  u_int frecnum = bi_flag ? 1 : 2;
  struct EXPORT_CTX ctx = {.sp = sp, .flow = flow, .i = 0};

  (void) version; /* only used to size frecnum via bi_flag */
  if (len < tmpl->t.data_len * frecnum)
    return (-1);

  for (ctx.i = 0; ctx.i < frecnum; ctx.i++) {
    if (bi_flag == 0 && flow->octets[ctx.i] == 0)
      continue;
    nflows++;
    offset =
      export_emit_group_enc (tmpl->hr, tmpl->hr_count, packet, offset, &ctx);
    if (bi_flag && ctx.i == 0) {
      struct EXPORT_CTX bictx = ctx;
      bictx.i = 1; /* reverse direction */
      offset = export_emit_group_enc (tmpl->hbi, tmpl->t.bi_count, packet, offset,
                                      &bictx);
    }
    for (k = 0; k < sp->param->max_num_label; k++) {
      memcpy (&packet[offset], &flow->mplsLabels[k],
              IPFIX_mplsLabelStackSection_SIZE);
      offset += IPFIX_mplsLabelStackSection_SIZE;
    }
  }
  *len_used = offset;
  return (nflows);
}

/**
 * @brief Build the templates and the option record on the first export.
 *
 * @param sp      Send parameters; the tracking parameters are taken from
 * sp->param.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow export.
 * @param version Export version: 9 or 10.
 */
void
ipfix_init_exporter (const struct SENDPARAMETER *sp,
                     u_int8_t bi_flag, u_int16_t version) {
  ipfix_init_templates (sp->param, bi_flag, version);
  ipfix_init_option (version);
}

/**
 * @brief Append the templates and the option record to a packet.
 *
 * @param packet  Packet buffer.
 * @param offset  Offset in the packet to append at; updated.
 * @param bi_flag IPFIX_BIFLAG_ON for biflow export.
 * @param version Export version: 9 or 10.
 * @param sp      Send parameters; the option values are taken from sp->param.
 */
void
ipfix_put_templates (u_char *packet, u_int *offset, u_int8_t bi_flag,
                     u_int16_t version,
                     const struct SENDPARAMETER *sp) {
  u_int i;

  for (i = 0; i < TMPLMAX; i++)
    ipfix_memcpy_template (packet, offset, &templates[i], bi_flag,
                           sp->param->max_num_label);
  ipfix_send_option (packet, offset, version, sp);
}

/**
 * @brief Set ID of the data set that uses a template.
 *
 * @param tmplindex TMPLV4, TMPLICMPV4, TMPLV6 or TMPLICMPV6.
 * @return Template ID in network byte order.
 */
u_int16_t
ipfix_template_set_id (u_int tmplindex) {
  return templates[tmplindex].t.h.r.template_id;
}
