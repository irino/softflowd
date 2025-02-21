/*
 * Copyright (c) 2002 Damien Miller.  All rights reserved.
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

#ifndef _SFD_COMMON_H
#define _SFD_COMMON_H

#include "config.h"

#define _BSD_SOURCE             /* Needed for BSD-style struct ip,tcp,udp on Linux */
#define _DEFAULT_SOURCE         /* It is recommended to use instead of _BSD_SOURCE on Linux */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <netdb.h>

#if defined(HAVE_NET_BPF_H)
#include <net/bpf.h>
#elif defined(HAVE_PCAP_BPF_H)
#include <pcap-bpf.h>
#endif
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif

#if defined(HAVE_SYS_ENDIAN_H)
#include <sys/endian.h>
#elif defined(HAVE_ENDIAN_H)
#include <endian.h>
#endif

/* The name of the program */
#define PROGNAME		"softflowd"

/* The name of the program */
#define PROGVER			"1.1.1"

/* Default pidfile */
#define DEFAULT_PIDFILE		"/var/run/" PROGNAME ".pid"

/* Default control socket */
#define DEFAULT_CTLSOCK		"/var/run/" PROGNAME ".ctl"

#define RCSID(msg) \
	static /**/const char *const flowd_rcsid[] =		\
	    { (const char *)flowd_rcsid, "\100(#)" msg }	\

#ifndef IP_OFFMASK
#define IP_OFFMASK		0x1fff  /* mask for fragmenting bits */
#endif
#ifndef IPV6_VERSION
#define IPV6_VERSION		0x60
#endif
#ifndef IPV6_VERSION_MASK
#define IPV6_VERSION_MASK	0xf0
#endif
#ifndef IPV6_FLOWINFO_MASK
#define IPV6_FLOWINFO_MASK	ntohl(0x0fffffff)
#endif
#ifndef IPV6_FLOWLABEL_MASK
#define IPV6_FLOWLABEL_MASK	ntohl(0x000fffff)
#endif

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL		"/dev/null"
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#if defined(__GNUC__)
#ifndef __dead
#define __dead                __attribute__((__noreturn__))
#endif
#ifndef __packed
#define __packed              __attribute__((__packed__))
#endif
#endif

#if !defined(HAVE_INT8_T) && defined(OUR_CFG_INT8_T)
typedef OUR_CFG_INT8_T int8_t;
#endif
#if !defined(HAVE_INT16_T) && defined(OUR_CFG_INT16_T)
typedef OUR_CFG_INT16_T int16_t;
#endif
#if !defined(HAVE_INT32_T) && defined(OUR_CFG_INT32_T)
typedef OUR_CFG_INT32_T int32_t;
#endif
#if !defined(HAVE_INT64_T) && defined(OUR_CFG_INT64_T)
typedef OUR_CFG_INT64_T int64_t;
#endif
#if !defined(HAVE_U_INT8_T) && defined(OUR_CFG_U_INT8_T)
typedef OUR_CFG_U_INT8_T u_int8_t;
#endif
#if !defined(HAVE_U_INT16_T) && defined(OUR_CFG_U_INT16_T)
typedef OUR_CFG_U_INT16_T u_int16_t;
#endif
#if !defined(HAVE_U_INT32_T) && defined(OUR_CFG_U_INT32_T)
typedef OUR_CFG_U_INT32_T u_int32_t;
#endif
#if !defined(HAVE_U_INT64_T) && defined(OUR_CFG_U_INT64_T)
typedef OUR_CFG_U_INT64_T u_int64_t;
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy (char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat (char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_CLOSEFROM
void closefrom (int lowfd);
#endif

#ifndef HAVE_STRUCT_IP6_EXT
struct ip6_ext {
  u_int8_t ip6e_nxt;
  u_int8_t ip6e_len;
} __packed;
#endif


/* following lines are copy from unistd.h in Linux for avoidance warnings in compilation */
#if defined(HAVE_SETRESGID) && !defined(_GNU_SOURCE)
extern int setresgid (uid_t __ruid, uid_t __euid, uid_t __suid);
#endif
#if defined(HAVE_SETRESUID) && !defined(_GNU_SOURCE)
extern int setresuid (uid_t __ruid, uid_t __euid, uid_t __suid);
#endif

#if defined (HAVE_DECL_HTONLL) && !defined (HAVE_DECL_HTOBE64)
#define htobe64     htonll
#endif

#ifndef ETH_ALEN
// https://cdn.kernel.org/pub/linux/kernel/people/marcelo/linux-2.4/include/linux/if_ether.h
#define ETH_ALEN	6       /* Octets in one ethernet addr   */
#endif /* ETH_ALEN */

#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC	0x8847  /* MPLS Unicast traffic         */
#endif /* ETH_P_MPLS_UC */
#ifndef MPLS_LS_S_MASK
#define MPLS_LS_S_MASK          0x00000100
#endif /* MPLS_LS_S_MASK */
#ifndef MPLS_LS_S_SHIFT
#define MPLS_LS_S_SHIFT         8
#endif /* MPLS_LS_S_SHIFT */
#ifndef IFNAMSIZ                /* defined in <net/if.h> in linux */
#define IFNAMSIZ 16
#endif /* IFNAMSIZ */

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#endif /* __APPLE__ */

#endif /* _SFD_COMMON_H */
