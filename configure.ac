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

AC_EXEEXT
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

