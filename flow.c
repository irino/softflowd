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
 * @file flow.c
 * @brief The flow table: comparing, hashing, looking up, inserting and
 *   removing flows, the free lists of flows and expiries, and the
 *   initial state of the flow tracker. This file was split from
 *   softflowd.c.
 */

#include "softflowd.h"
#include "flow.h"
#include "format.h"
#include "globals.h"
#include "ipfix.h"
#include "log.h"
#ifdef HAVE_XXHASH
#include <xxhash.h>
#endif /* HAVE_XXHASH */

/** Upper limit of the number of buckets of the flow table. */
#define FLOW_MAX_BUCKETS (1U << 24) /* upper bound of the flow table size */

/**
 * @brief Comparison function of the flow tree.
 *
 * Flows are compared on their identity fields, which depend on the tracking
 * level.
 *
 * @param a First flow.
 * @param b Second flow.
 * @return Negative, zero or positive, as for memcmp().
 */
int
flow_compare (struct FLOW *a, struct FLOW *b) {
  /* Be careful to avoid signed vs unsigned issues here */
  int r;
  u_int32_t i;
  if (track_level == TRACK_FULL_VLAN || track_level == TRACK_FULL_VLAN_ETHER) {
    if (a->vlanid[0] != b->vlanid[0])
      return (a->vlanid[0] > b->vlanid[0] ? 1 : -1);

    if (a->vlanid[1] != b->vlanid[1])
      return (a->vlanid[1] > b->vlanid[1] ? 1 : -1);
  }

  if (track_level == TRACK_FULL_VLAN_ETHER) {
    if ((r = memcmp (&a->ethermac[0], &b->ethermac[0], 6)) != 0)
      return (r > 0 ? 1 : -1);

    if ((r = memcmp (&a->ethermac[1], &b->ethermac[1], 6)) != 0)
      return (r > 0 ? 1 : -1);
  }

  if (a->af != b->af)
    return (a->af > b->af ? 1 : -1);

  if ((r = memcmp (&a->addr[0], &b->addr[0], sizeof (a->addr[0]))) != 0)
    return (r > 0 ? 1 : -1);

  if ((r = memcmp (&a->addr[1], &b->addr[1], sizeof (a->addr[1]))) != 0)
    return (r > 0 ? 1 : -1);

#ifdef notyet
  if (a->ip6_flowlabel[0] != 0 && b->ip6_flowlabel[0] != 0 &&
      a->ip6_flowlabel[0] != b->ip6_flowlabel[0])
    return (a->ip6_flowlabel[0] > b->ip6_flowlabel[0] ? 1 : -1);

  if (a->ip6_flowlabel[1] != 0 && b->ip6_flowlabel[1] != 0 &&
      a->ip6_flowlabel[1] != b->ip6_flowlabel[1])
    return (a->ip6_flowlabel[1] > b->ip6_flowlabel[1] ? 1 : -1);
#endif

  if (a->protocol != b->protocol)
    return (a->protocol > b->protocol ? 1 : -1);

  if (a->port[0] != b->port[0])
    return (ntohs (a->port[0]) > ntohs (b->port[0]) ? 1 : -1);

  if (a->port[1] != b->port[1])
    return (ntohs (a->port[1]) > ntohs (b->port[1]) ? 1 : -1);

  if (a->mplsLabelStackDepth != b->mplsLabelStackDepth)
    return (a->mplsLabelStackDepth > b->mplsLabelStackDepth ? 1 : -1);
  for (i = 0; i < a->mplsLabelStackDepth; i++) {
    if (a->mplsLabels[i] != b->mplsLabels[i])
      return (a->mplsLabels[i] > b->mplsLabels[i] ? 1 : -1);
  }

  return (0);
}

/* Generate functions for flow tree */
FLOW_GENERATE (FLOWS, FLOW, trp, flow_compare);

/**
 * @brief Comparison function of the expiry tree.
 *
 * Ordered by expiry time; ties are broken by flow sequence number so entries
 * are unique.
 *
 * @param a First expiry event.
 * @param b Second expiry event.
 * @return -1, 0 or 1.
 */
int
expiry_compare (struct EXPIRY *a, struct EXPIRY *b) {
  if (a->expires_at != b->expires_at)
    return (a->expires_at > b->expires_at ? 1 : -1);

  /* Make expiry entries unique by comparing flow sequence */
  if (a->flow->flow_seq != b->flow->flow_seq)
    return (a->flow->flow_seq > b->flow->flow_seq ? 1 : -1);

  return (0);
}

/* Generate functions for flow tree */
EXPIRY_GENERATE (EXPIRIES, EXPIRY, trp, expiry_compare);

/**
 * @brief Hash the identity fields of a flow.
 *
 * Uses exactly the fields flow_compare() looks at (and only those), so flows
 * that compare equal always hash equal. The fields are packed into one buffer
 * first, so padding and the unused part of the address union cannot influence
 * the result.
 *
 * @param flow Flow to hash.
 * @return 32-bit hash value.
 */
static u_int32_t
flow_hash (const struct FLOW *flow) {
  u_int8_t key[sizeof (flow->vlanid) + sizeof (flow->ethermac) +
               sizeof (flow->af) + sizeof (flow->addr) + sizeof (flow->protocol) +
               sizeof (flow->port) + sizeof (flow->mplsLabelStackDepth) +
               sizeof (flow->mplsLabels)];
  size_t len = 0, n;
  u_int32_t depth = flow->mplsLabelStackDepth;
#ifdef HAVE_XXHASH
  XXH64_hash_t h;
#else  /* HAVE_XXHASH */
  u_int32_t h = 2166136261U; /* FNV-1a */
  size_t i;
#endif /* HAVE_XXHASH */

#define KEY_ADD(p, size)             \
  do {                               \
    memcpy (key + len, (p), (size)); \
    len += (size);                   \
  } while (0)
  if (track_level == TRACK_FULL_VLAN || track_level == TRACK_FULL_VLAN_ETHER)
    KEY_ADD (flow->vlanid, sizeof (flow->vlanid));
  if (track_level == TRACK_FULL_VLAN_ETHER)
    KEY_ADD (flow->ethermac, sizeof (flow->ethermac));
  KEY_ADD (&flow->af, sizeof (flow->af));
  KEY_ADD (flow->addr, sizeof (flow->addr));
  KEY_ADD (&flow->protocol, sizeof (flow->protocol));
  KEY_ADD (flow->port, sizeof (flow->port));
  KEY_ADD (&flow->mplsLabelStackDepth, sizeof (flow->mplsLabelStackDepth));
  if (depth > sizeof (flow->mplsLabels) / sizeof (flow->mplsLabels[0]))
    depth = sizeof (flow->mplsLabels) / sizeof (flow->mplsLabels[0]);
  n = depth * sizeof (flow->mplsLabels[0]);
  if (n > 0)
    KEY_ADD (flow->mplsLabels, n);
#undef KEY_ADD

#ifdef HAVE_XXHASH
  h = XXH64 (key, len, 0);
  return ((u_int32_t) (h ^ (h >> 32)));
#else  /* HAVE_XXHASH */
  for (i = 0; i < len; i++) {
    h ^= key[i];
    h *= 16777619U;
  }
  return (h);
#endif /* HAVE_XXHASH */
}

/**
 * @brief Name of a flow lookup mode, as given to --flow-lookup.
 *
 * @param mode Lookup mode.
 * @return Name of the mode.
 */
const char *
flow_lookup_name (enum FLOW_LOOKUP mode) {
  switch (mode) {
    case FLOW_LOOKUP_HASH_TREE:
      return ("hash-tree");
    case FLOW_LOOKUP_HASH:
      return ("hash");
    default:
      return ("tree");
  }
}

/**
 * @brief Allocate the flow table according to the lookup mode and max_flows.
 *
 * Tree mode uses a single bucket. The hash modes use a power of two number of
 * buckets (at least max_flows, twice that in hash mode, capped at
 * FLOW_MAX_BUCKETS). Call after the options are parsed.
 *
 * @param ft Flow tracking state.
 * @return 0 on success, -1 if the allocation failed.
 */
int
flow_table_init (struct FLOWTRACK *ft) {
  u_int64_t want, n;
  u_int32_t i;

  n = 1;
  if (ft->flow_lookup != FLOW_LOOKUP_TREE) {
    want = ft->param.max_flows;
    if (ft->flow_lookup == FLOW_LOOKUP_HASH)
      want *= 2;
    while (n < want && n < FLOW_MAX_BUCKETS)
      n <<= 1;
  }
  ft->flow_nbuckets = (u_int32_t) n;

  if (ft->flow_lookup == FLOW_LOOKUP_HASH) {
    ft->flow_table_bytes = ft->flow_nbuckets * sizeof (*ft->flow_slots);
    ft->flow_slots = calloc (ft->flow_nbuckets, sizeof (*ft->flow_slots));
    return (ft->flow_slots == NULL ? -1 : 0);
  }
  ft->flow_table_bytes = ft->flow_nbuckets * sizeof (*ft->flow_buckets);
  ft->flow_buckets = calloc (ft->flow_nbuckets, sizeof (*ft->flow_buckets));
  if (ft->flow_buckets == NULL)
    return (-1);
  for (i = 0; i < ft->flow_nbuckets; i++)
    FLOW_INIT (&ft->flow_buckets[i]);
  return (0);
}

/**
 * @brief Bucket index of a flow.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow (only its identity fields are used).
 * @return Index into the flow table.
 */
u_int32_t
flow_index (const struct FLOWTRACK *ft,
            const struct FLOW *flow) {
  if (ft->flow_nbuckets == 1)
    return (0);
  return (flow_hash (flow) & (ft->flow_nbuckets - 1));
}

/**
 * @brief Look up a flow in the flow table.
 *
 * @param ft  Flow tracking state.
 * @param key Flow holding the identity to look for.
 * @param idx Bucket index of key, from flow_index().
 * @return Matching flow, or NULL.
 */
struct FLOW *
flow_table_find (struct FLOWTRACK *ft, struct FLOW *key,
                 u_int32_t idx) {
  struct FLOW *resident;

  if (ft->flow_lookup == FLOW_LOOKUP_HASH) {
    resident = ft->flow_slots[idx];
    return (resident != NULL && flow_compare (resident, key) == 0 ? resident
                                                                  : NULL);
  }
  return (FLOW_FIND (FLOWS, &ft->flow_buckets[idx], key));
}

/**
 * @brief Insert a new flow into the flow table.
 *
 * In hash mode a flow already resident in the bucket is taken out of the table
 * and scheduled for immediate expiry (R_COLLISION); it is exported by the next
 * expiry scan.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow to insert.
 * @param idx  Bucket index of flow, from flow_index().
 */
void
flow_table_insert (struct FLOWTRACK *ft, struct FLOW *flow,
                   u_int32_t idx) {
  struct FLOW *victim;
  struct EXPIRY *expiry;

  if (ft->flow_lookup != FLOW_LOOKUP_HASH) {
    FLOW_INSERT (FLOWS, &ft->flow_buckets[idx], flow);
    return;
  }

  if ((victim = ft->flow_slots[idx]) != NULL) {
    expiry = victim->expiry;
    /* Keep the reason of a flow that is already due for expiry */
    if (expiry != NULL && expiry->expires_at != 0) {
      EXPIRY_REMOVE (EXPIRIES, &ft->expiries, expiry);
      expiry->expires_at = 0;
      expiry->reason = R_COLLISION;
      victim->flowEndReason = IPFIX_flowEndReason_lackOfResource;
      EXPIRY_INSERT (EXPIRIES, &ft->expiries, expiry);
    }
    if (verbose_flag)
      logit (LOG_DEBUG, "COLLISION %s", format_flow_brief (victim));
  }
  ft->flow_slots[idx] = flow;
}

/**
 * @brief Remove a flow from the flow table.
 *
 * A flow that was evicted by a collision (hash mode) is no longer in the table;
 * this is detected by comparing the resident of the bucket with the flow.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow to remove.
 */
void
flow_table_remove (struct FLOWTRACK *ft, struct FLOW *flow) {
  u_int32_t idx = flow_index (ft, flow);

  if (ft->flow_lookup == FLOW_LOOKUP_HASH) {
    if (ft->flow_slots[idx] == flow)
      ft->flow_slots[idx] = NULL;
    return;
  }
  FLOW_REMOVE (FLOWS, &ft->flow_buckets[idx], flow);
}

/**
 * @brief Print how the flow table was allocated (debug mode).
 *
 * Shows the number of buckets, the memory of the bucket array (also relative to
 * tree mode, which has a single bucket) and, for scale, the memory flows take
 * at max_flows.
 *
 * @param ft Flow tracking state.
 */
void
flow_table_report (const struct FLOWTRACK *ft) {
  size_t tree_bytes = sizeof (struct FLOWS);

  fprintf (stderr, "Flow table: mode=%s buckets=%u (max_flows=%u%s)\n",
           flow_lookup_name (ft->flow_lookup), ft->flow_nbuckets,
           ft->param.max_flows,
           ft->flow_nbuckets == FLOW_MAX_BUCKETS ? ", at the cap" : "");
  fprintf (stderr,
           "Flow table: bucket array %zu bytes (%zu bytes/bucket), %+lld bytes "
           "vs tree mode\n",
           ft->flow_table_bytes, ft->flow_table_bytes / ft->flow_nbuckets,
           (long long) ft->flow_table_bytes - (long long) tree_bytes);
  fprintf (stderr,
           "Flow table: flows at max_flows: %zu bytes (FLOW %zu + EXPIRY %zu "
           "each)\n",
           (size_t) ft->param.max_flows *
             (sizeof (struct FLOW) + sizeof (struct EXPIRY)),
           sizeof (struct FLOW), sizeof (struct EXPIRY));
}

/**
 * @brief Measure how the active flows are spread over the buckets.
 *
 * Walks every bucket, so it is meant for statistics only.
 *
 * @param ft       Flow tracking state.
 * @param used     Receives the number of non-empty buckets.
 * @param maxdepth Receives the largest number of flows in one bucket.
 */
void
flow_table_usage (struct FLOWTRACK *ft, u_int32_t *used,
                  u_int32_t *maxdepth) {
  struct FLOW *flow;
  u_int32_t i, depth;

  *used = *maxdepth = 0;
  for (i = 0; i < ft->flow_nbuckets; i++) {
    depth = 0;
    if (ft->flow_lookup == FLOW_LOOKUP_HASH)
      depth = ft->flow_slots[i] != NULL;
    else
      for (flow = FLOW_MIN (FLOWS, &ft->flow_buckets[i]); flow != NULL;
           flow = FLOW_NEXT (FLOWS, &ft->flow_buckets[i], flow))
        depth++;
    if (depth > 0)
      (*used)++;
    if (depth > *maxdepth)
      *maxdepth = depth;
  }
}

/**
 * @brief Allocate a flow record from the flow freelist.
 *
 * @param ft Flow tracking state.
 * @return New flow record, or NULL if out of memory.
 */
struct FLOW *
flow_get (struct FLOWTRACK *ft) {
  return freelist_get (&ft->flow_freelist);
}

/**
 * @brief Return a flow record to the flow freelist.
 *
 * @param ft   Flow tracking state.
 * @param flow Flow record to release.
 */
void
flow_put (struct FLOWTRACK *ft, struct FLOW *flow) {
  return freelist_put (&ft->flow_freelist, flow);
}

/**
 * @brief Allocate an expiry event from the expiry freelist.
 *
 * @param ft Flow tracking state.
 * @return New expiry event, or NULL if out of memory.
 */
struct EXPIRY *
expiry_get (struct FLOWTRACK *ft) {
  return freelist_get (&ft->expiry_freelist);
}

/**
 * @brief Return an expiry event to the expiry freelist.
 *
 * @param ft     Flow tracking state.
 * @param expiry Expiry event to release.
 */
void
expiry_put (struct FLOWTRACK *ft, struct EXPIRY *expiry) {
  return freelist_put (&ft->expiry_freelist, expiry);
}

/**
 * @brief Initialise the flow tracking state with the default limits and
 * timeouts.
 *
 * @param ft Flow tracking state.
 */
void
init_flowtrack (struct FLOWTRACK *ft) {
  /* Set up flow-tracking structure */
  memset (ft, '\0', sizeof (*ft));
  ft->param.next_flow_seq = 1;
  ft->flow_lookup = FLOW_LOOKUP_HASH_TREE; /* default; -F selects another */
  EXPIRY_INIT (&ft->expiries);

  freelist_init (&ft->flow_freelist, sizeof (struct FLOW));
  freelist_init (&ft->expiry_freelist, sizeof (struct EXPIRY));

  ft->param.max_flows = DEFAULT_MAX_FLOWS;

  track_level = ft->param.track_level = TRACK_FULL;

  ft->param.tcp_timeout = DEFAULT_TCP_TIMEOUT;
  ft->param.tcp_rst_timeout = DEFAULT_TCP_RST_TIMEOUT;
  ft->param.tcp_fin_timeout = DEFAULT_TCP_FIN_TIMEOUT;
  ft->param.udp_timeout = DEFAULT_UDP_TIMEOUT;
  ft->param.icmp_timeout = DEFAULT_ICMP_TIMEOUT;
  ft->param.general_timeout = DEFAULT_GENERAL_TIMEOUT;
  ft->param.maximum_lifetime = DEFAULT_MAXIMUM_LIFETIME;
  ft->param.expiry_interval = DEFAULT_EXPIRY_INTERVAL;
}
