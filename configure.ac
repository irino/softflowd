# $Id$
#
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

AC_INIT
AC_CONFIG_SRCDIR([softflowd.c])

AC_CONFIG_HEADER(config.h)
AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_HEADERS(net/bpf.h pcap-bpf.h)

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

AC_CHECK_LIB(pcap, pcap_open_live)

AC_CHECK_TYPES([u_int64_t, int64_t, uint64_t, u_int32_t, int32_t, uint32_t])
AC_CHECK_TYPES([u_int16_t, int16_t, uint16_t, u_int8_t, int8_t, uint8_t])
AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(short int, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long int, 4)
AC_CHECK_SIZEOF(long long int, 8)

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

AC_EXEEXT
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

