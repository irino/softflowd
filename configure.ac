# Copyright (c) 2004 Damien Miller
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

AC_INIT([softflowd],[1.1.1])
AC_CONFIG_SRCDIR([softflowd.c])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_INSTALL

# Optional verbose warnings for gcc, see below
WFLAGS="-Wall -Waggregate-return -Wcast-align -Wcast-qual"
WFLAGS="$WFLAGS -Wmissing-declarations -Wmissing-prototypes"
WFLAGS="$WFLAGS -Wno-conversion -Wpointer-arith -Wshadow"
WFLAGS="$WFLAGS -Wuninitialized -Wcast-align -Wcast-qual"
WFLAGS="$WFLAGS -Wformat=2 -Wformat-nonliteral -Wwrite-strings"

# Process flag arguments early, so they are available for tests later
AC_ARG_ENABLE(cpp,
              AS_HELP_STRING([--enable-cpp],[build the C++ reimplementation (softflowd+/softflowctl+) under cpp/ (default NO)]),
              [cpp=yes],[cpp=no])
AC_ARG_ENABLE(rust,
              AS_HELP_STRING([--enable-rust],[build the Rust reimplementation (rsoftflowd/rsoftctl) under rust/ (default NO)]),
              [rust=yes],[rust=no])

# AC_PROG_CXX must be called unconditionally (not inside a shell "if"),
# because it registers Automake's per-language dependency-tracking
# conditional (am__fastdepCXX). Wrapping it in a runtime shell
# conditional leaves that AM_CONDITIONAL undefined whenever --enable-cpp
# isn't given, which breaks every build. AC_CHECK_PROG is a plain
# runtime check (no AM_CONDITIONAL involved), so it's fine to leave
# inside the conditional below.
AC_PROG_CXX

if test "x$cpp" = "xyes"; then
  AC_CHECK_PROG([CMAKE], [cmake], [cmake], [no])
  if test "x$CXX" = "x"; then
    AC_MSG_ERROR([--enable-cpp was given but no g++/C++ compiler was found])
  fi
  if test "x$CMAKE" = "xno"; then
    AC_MSG_ERROR([--enable-cpp was given but cmake was not found])
  fi
fi
AM_CONDITIONAL([ENABLE_CPP], [test x$cpp = xyes])

if test "x$rust" = "xyes"; then
  AC_CHECK_PROG([RUSTC], [rustc], [rustc], [no])
  AC_CHECK_PROG([CARGO], [cargo], [cargo], [no])
  if test "x$RUSTC" = "xno"; then
    AC_MSG_ERROR([--enable-rust was given but rustc was not found])
  fi
  if test "x$CARGO" = "xno"; then
    AC_MSG_ERROR([--enable-rust was given but cargo was not found])
  fi
fi
AM_CONDITIONAL([ENABLE_RUST], [test x$rust = xyes])

AC_ARG_ENABLE(gcc-warnings,
	[  --enable-gcc-warnings   Enable verbose warnings (only for gcc)],
	[ if test "x$enableval" = "xyes" ; then CFLAGS="$CFLAGS $WFLAGS"; fi ]
)
AC_ARG_ENABLE(legacy,
              AS_HELP_STRING([--enable-legacy],[(deprecated; use --enable-unified-export-type=none) enable legacy NetFlow implementation (default NO)]),
              [legacy=$enableval],[legacy=])
AC_ARG_ENABLE(unified-export,
              AS_HELP_STRING([--enable-unified-export],[(deprecated; use --enable-unified-export-type=full) enable single switch/if-else based NetFlow v1/v5/v9/IPFIX exporter in ipfix.c (default NO)]),
              [unified_export=$enableval],[unified_export=])
AC_ARG_ENABLE(unified-export-type,
              AS_HELP_STRING([--enable-unified-export-type=full|partial|none],
                             [choose the NetFlow v1/v5/v9/IPFIX exporter architecture in ipfix.c: full (single switch/if-else based unified exporter for all versions), partial (default; per-version exporters that share unified field tables), or none (fully separate legacy NetFlow v9 exporter in netflow9.c)]),
              [unified_export_type=$enableval],[unified_export_type=])
if test -n "$unified_export_type" ; then
  dnl New-style option was given: it decides, and wins over the
  dnl deprecated flags below if both happen to be present.
  case "$unified_export_type" in
    full|partial|none) ;;
    *) AC_MSG_ERROR([--enable-unified-export-type must be one of: full, partial, none (got: $unified_export_type)]) ;;
  esac
  if test -n "$legacy" -o -n "$unified_export" ; then
    AC_MSG_WARN([--enable-unified-export-type=$unified_export_type overrides the deprecated --enable-legacy/--enable-unified-export options])
  fi
  legacy=no
  unified_export=no
  case "$unified_export_type" in
    full) unified_export=yes ;;
    none) legacy=yes ;;
  esac
else
  dnl Only the deprecated flags (or neither) were given: keep their
  dnl old, independent-boolean behavior exactly as before, including
  dnl the (functionally redundant but previously allowed) case of
  dnl both being enabled together.
  test -z "$legacy" && legacy=no
  test -z "$unified_export" && unified_export=no
  if test "x$legacy" = "xyes" -o "x$unified_export" = "xyes" ; then
    AC_MSG_WARN([--enable-legacy/--enable-unified-export are deprecated; use --enable-unified-export-type=full|partial|none instead])
  fi
fi
AC_ARG_ENABLE(pthread,
              AS_HELP_STRING([--enable-pthread],[enable pthread (default NO) (experimental, unstable)]),
              [pthread=yes],[pthread=no])
AC_ARG_ENABLE(ntopng,
              AS_HELP_STRING([--enable-ntopng],[enable flow sending to ntopng with zeromq (default NO)]),
              [ntopng=yes],[ntopng=no])
AC_ARG_ENABLE(ifname,
              AS_HELP_STRING([--enable-ifname],[enable flow reporting iface name in normal data of v9 and IPFIX (default NO)]),
              [ifname=yes],[ifname=no])
AC_ARG_ENABLE(flow-spray,
              AS_HELP_STRING([--enable-flow-spray],[enable spray as flow tree type(default is RB)]),
              AC_DEFINE([FLOW_SPRAY], 1, [enable spray as flow tree type]),
	      AC_DEFINE([FLOW_RB], 1, [enable RB(red-black) as flow tree type]))
AC_ARG_ENABLE(expiry-spray,
              AS_HELP_STRING([--enable-expiry-spray],[enable spray as expiry tree type (default is RB)]),
              AC_DEFINE([EXPIRY_SPRAY], 1, [enable spray as flow tree type]),
	      AC_DEFINE([EXPIRY_RB], 1, [enable RB(red-black) as flow tree type]))

AC_ARG_WITH(cflags,
	[  --with-cflags           Specify additional compiler flags],
	[ if test "x$withval" != "xno" ; then CFLAGS="$CFLAGS $withval"; fi ]
)
AC_ARG_WITH(cppflags,
	[  --with-cppflags         Specify additional preprocessor flags] ,
	[ if test "x$withval" != "xno"; then CPPFLAGS="$CPPFLAGS $withval"; fi ]
)
AC_ARG_WITH(ldflags,
	[  --with-ldflags          Specify additional linker flags],
	[ if test "x$withval" != "xno" ; then LDFLAGS="$LDFLAGS $withval"; fi ]
)
AC_ARG_WITH(libs,
	[  --with-libs             Specify additional libraries to link with],
	[ if test "x$withval" != "xno" ; then LIBS="$LIBS $withval"; fi ]
)
AC_ARG_WITH(chrootdir,
	[  --with-chrootdir        Specify chroot directory],
	[ AC_DEFINE_UNQUOTED([PRIVDROP_CHROOT_DIR], ["${withval}"], [privdrop chroot directory]) ]
)

AC_DEFINE([_BSD_SOURCE], [], [Define BSD SOURCE for Linux])
AC_CHECK_HEADERS(net/bpf.h pcap.h pcap-bpf.h sys/endian.h endian.h)
AC_CHECK_HEADERS(ifaddrs.h net/if_arp.h net/if_ether.h net/ethernet.h)
dnl netinet/if_ether.h (OpenBSD) requires net/if_arp.h (for struct
dnl arphdr) and net/if.h to be included first; the default
dnl AC_CHECK_HEADERS prologue does not include these, so it must be
dnl checked separately with explicit prerequisite headers.
AC_CHECK_HEADERS([netinet/if_ether.h], [], [],
[[#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#if HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif
]])
dnl AC_CHECK_HEADERS(netinet/in_systm.h netinet/tcp.h netinet/udp.h)
dnl
dnl # This ugliness is because of autoconf's stupid default include list
dnl AC_CHECK_HEADERS([netinet/ip.h],
dnl 	[AC_DEFINE([HAVE_HAVE_NETINET_IP_H], 1, [has netinet/ip.h])], [],
dnl 	[
dnl #include <sys/types.h>
dnl #include <netinet/in.h>
dnl #if HAVE_NETINET_IN_SYSTM_H
dnl #include <netinet/in_systm.h>
dnl #endif
dnl 	])

AC_CHECK_MEMBER([struct sockaddr.sa_len],
	[AC_DEFINE([SOCK_HAS_LEN], 1, [struct sockaddr contains length])], ,
	[#include <sys/types.h>
	 #include <sys/socket.h>])

AC_CHECK_MEMBER(struct ip6_ext.ip6e_nxt,
	[AC_DEFINE([HAVE_STRUCT_IP6_EXT], 1, [struct ip6_ext.ip6e_nxt exists])],
	[],
	[
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <netinet/in.h>
		#include <netinet/ip6.h>
	])

AC_SEARCH_LIBS(daemon, bsd)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket)
AC_CHECK_LIB(pcap, pcap_open_live)

dnl pcap_set_immediate_mode() appeared in libpcap 1.5; guard its use so the
dnl build still works against older libpcap.
AC_CHECK_LIB(pcap, pcap_set_immediate_mode,
	[AC_DEFINE([HAVE_PCAP_SET_IMMEDIATE_MODE], 1,
		[libpcap provides pcap_set_immediate_mode()])])

AC_CHECK_FUNCS(closefrom daemon setresuid setreuid setresgid setgid strlcpy strlcat strsep)
AC_CHECK_DECLS([htobe64, htonll])

AC_CHECK_TYPES([u_int64_t, int64_t, uint64_t, u_int32_t, int32_t, uint32_t])
AC_CHECK_TYPES([u_int16_t, int16_t, uint16_t, u_int8_t, int8_t, uint8_t])
AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(short int, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long int, 4)
AC_CHECK_SIZEOF(long long int, 8)

dnl Resolve legacy/unified_export flags into a single tri-state macro.
dnl 'unified_export=yes' overrides legacy to avoid compiling unreachable
dnl legacy exporter code (netflow1.c / netflow9.c).
if test "x$unified_export" = "xyes" ; then
  resolved_export_type=full
elif test "x$legacy" = "xyes" ; then
  resolved_export_type=none
else
  resolved_export_type=partial
fi
AC_DEFINE([ENABLE_UNIFIED_EXPORT_TYPE_FULL], [1],
          [sentinel value: single switch/if-else based unified NetFlow v1/v5/v9/IPFIX exporter in ipfix.c])
AC_DEFINE([ENABLE_UNIFIED_EXPORT_TYPE_PARTIAL], [2],
          [sentinel value: per-version NetFlow v1/v5/v9/IPFIX exporters in ipfix.c sharing unified field tables (default)])
AC_DEFINE([ENABLE_UNIFIED_EXPORT_TYPE_NONE], [3],
          [sentinel value: fully separate legacy NetFlow v9 exporter in netflow9.c])
case "$resolved_export_type" in
  full)    AC_DEFINE([ENABLE_UNIFIED_EXPORT_TYPE], [ENABLE_UNIFIED_EXPORT_TYPE_FULL],
                      [which NetFlow v1/v5/v9/IPFIX exporter architecture ipfix.c etc. build: one of the ENABLE_UNIFIED_EXPORT_TYPE_* sentinels above]) ;;
  none)    AC_DEFINE([ENABLE_UNIFIED_EXPORT_TYPE], [ENABLE_UNIFIED_EXPORT_TYPE_NONE],
                      [which NetFlow v1/v5/v9/IPFIX exporter architecture ipfix.c etc. build: one of the ENABLE_UNIFIED_EXPORT_TYPE_* sentinels above])
           LEGACY='netflow9.$(OBJEXT) netflow1.$(OBJEXT)'
           AC_SUBST([LEGACY]) ;;
  partial) AC_DEFINE([ENABLE_UNIFIED_EXPORT_TYPE], [ENABLE_UNIFIED_EXPORT_TYPE_PARTIAL],
                      [which NetFlow v1/v5/v9/IPFIX exporter architecture ipfix.c etc. build: one of the ENABLE_UNIFIED_EXPORT_TYPE_* sentinels above]) ;;
esac
AM_CONDITIONAL([UNIFIED_EXPORT_TYPE_NONE], [test "x$resolved_export_type" = xnone])
AM_CONDITIONAL([UNIFIED_EXPORT_TYPE_FULL], [test "x$resolved_export_type" = xfull])
if test "x$pthread" = "xyes" ; then
  AC_DEFINE([ENABLE_PTHREAD], 1, [enable pthread])
  AC_CHECK_LIB(pthread, pthread_create, [],[AC_MSG_ERROR([pthread.h not found])])
  AC_CHECK_HEADERS(pthread.h, [],[AC_MSG_ERROR([pthread.h not found])])
fi
if test "x$ntopng" = "xyes" ; then
  AC_DEFINE([ENABLE_NTOPNG], 1, [enable ntopng])
   AC_CHECK_LIB(zmq, zmq_connect, [],[AC_MSG_ERROR([libzmq not found])])
   AC_CHECK_HEADERS(zmq.h, [],[AC_MSG_ERROR([zmq.h not found])])
  NTOPNG='ntopng.$(OBJEXT)'
  AC_SUBST([NTOPNG])
fi
AM_CONDITIONAL([ENABLE_NTOPNG], [test x$ntopng = xyes])
if test "x$ifname" = "xyes" ; then
  AC_DEFINE([ENABLE_IFNAME], 1, [enable reporting iface name])
fi
if test "x$ac_cv_type_uint8_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT8_T], [uint8_t], [8-bit unsigned int])
elif test "x$ac_cv_sizeof_char" = "x1" ; then
	AC_DEFINE([OUR_CFG_U_INT8_T], [unsigned char], [8-bit unsigned int])
else
	AC_MSG_ERROR([No 8-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_char" = "x1" ; then
	AC_DEFINE([OUR_CFG_INT8_T], [signed char], [8-bit signed int])
else
	AC_MSG_ERROR([No 8-bit signed int type found])
fi

if test "x$ac_cv_type_uint16_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT16_T], [uint16_t], [16-bit unsigned int])
elif test "x$ac_cv_sizeof_short_int" = "x2" ; then
	AC_DEFINE([OUR_CFG_U_INT16_T], [unsigned short int], [16-bit unsigned int])
else
	AC_MSG_ERROR([No 16-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_short_int" = "x2" ; then
	AC_DEFINE([OUR_CFG_INT16_T], [short int], [16-bit signed int])
else
	AC_MSG_ERROR([No 16-bit signed int type found])
fi

if test "x$ac_cv_type_uint32_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT32_T], [uint32_t], [32-bit unsigned int])
elif test "x$ac_cv_sizeof_int" = "x4" ; then
	AC_DEFINE([OUR_CFG_U_INT32_T], [unsigned int], [32-bit unsigned int])
else
	AC_MSG_ERROR([No 32-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_int" = "x4" ; then
	AC_DEFINE([OUR_CFG_INT32_T], [int], [32-bit signed int])
else
	AC_MSG_ERROR([No 32-bit signed int type found])
fi

if test "x$ac_cv_type_uint64_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT64_T], [uint64_t], [64-bit unsigned int])
elif test "x$ac_cv_sizeof_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_U_INT64_T], [unsigned long int], [64-bit unsigned int])
elif test "x$ac_cv_sizeof_long_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_U_INT64_T], [unsigned long long int], [64-bit unsigned int])
else
	AC_MSG_ERROR([No 64-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_INT64_T], [long int], [64-bit signed int])
elif test "x$ac_cv_sizeof_long_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_INT64_T], [long long int], [64-bit signed int])
else
	AC_MSG_ERROR([No 64-bit signed int type found])
fi

if test "x$ac_cv_header_pcap_bpf_h" != "xyes" && \
   test "x$ac_cv_header_net_bpf_h" != "xyes" ; then
	AC_MSG_ERROR([No BPF header found])
fi
if test "x$ac_cv_header_pcap_h" != "xyes" ; then
	AC_MSG_ERROR([No pcap.h header found])
fi
if test "x$ac_cv_lib_pcap_pcap_open_live" != "xyes" ; then
	AC_MSG_ERROR([libpcap not found])
fi

AC_CANONICAL_HOST
case "$host_os" in
 linux-gnu*)
	AC_DEFINE([LINUX], [], [Linux OS])
 ;;
esac

AC_EXEEXT
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
