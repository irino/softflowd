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
 * @file netsock.c
 * @brief Network sockets: the UDP receive and export sockets and the binding
 *   of a socket to a device. This file was split from softflowd.c.
 */

#include "softflowd.h"
#include "netsock.h"
#include "log.h"
#ifdef LINUX
#include <net/if.h>
#endif /* LINUX */

/**
 * @brief Create a UDP socket bound to a local port on all IPv4 addresses.
 *
 * @param portnumber Port to bind, in host order.
 * @return The socket, or a negative value on error.
 */
int
recvsock (uint16_t portnumber) {
  struct sockaddr_in addr;
  int rsock = socket (AF_INET, SOCK_DGRAM, 0);
  if (rsock < 0) {
    perror ("socket");
    return rsock;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons (portnumber);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind (rsock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    fprintf (stderr, "bind to UDP port %u failed: %s\n", (unsigned) portnumber,
             strerror (errno));
    close (rsock);
    return -1;
  }
  return rsock;
}

#ifdef LINUX
/**
 * @brief Bind a socket to a network interface (SO_BINDTODEVICE, Linux only).
 *
 * @param sock   Socket to bind.
 * @param ifname Interface name.
 */
void
bind_device (int sock, char *ifname) {
  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
  if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) <
      0) {
    perror ("SO_BINDTODEVICE failed");
  }
}
#endif /* LINUX */

/**
 * @brief Create a socket connected to an export destination.
 *
 * @param addr         Destination address.
 * @param len          Length of addr.
 * @param hoplimit     Multicast TTL / hop limit, or -1 for the default (1 for
 * multicast addresses).
 * @param protocol     IPPROTO_UDP or another IP protocol for a stream socket.
 * @param exporterAddr Optional local exporter addresses to bind to (-e); may be
 * NULL.
 * @return The connected socket. Exits the process on error.
 */
int
connsock (struct sockaddr_storage *addr, socklen_t len, int hoplimit,
          int protocol, struct addrinfo *exporterAddr) {
  int s;
  unsigned int h6;
  unsigned char h4;
  struct sockaddr_in *in4 = (struct sockaddr_in *) addr;
  struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) addr;
  struct addrinfo *rp = NULL;

  if ((s = socket (addr->ss_family,
                   protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
                   protocol)) == -1) {
    fprintf (stderr, "socket() error: %s\n", strerror (errno));
    exit (1);
  }
  if (exporterAddr != NULL) {
    for (rp = exporterAddr; rp != NULL; rp = rp->ai_next) {
      if (bind (s, rp->ai_addr, rp->ai_addrlen) == 0) {
        break;
      }
    }
    exporterAddr = rp;
  }
  if (connect (s, (struct sockaddr *) addr, len) == -1) {
    fprintf (stderr, "connect() error: %s\n", strerror (errno));
    exit (1);
  }

  switch (addr->ss_family) {
    case AF_INET:
      /* Default to link-local TTL for multicast addresses */
      if (hoplimit == -1 && IN_MULTICAST (in4->sin_addr.s_addr))
        hoplimit = 1;
      if (hoplimit == -1)
        break;
      h4 = hoplimit;
      if (setsockopt (s, IPPROTO_IP, IP_MULTICAST_TTL, &h4, sizeof (h4)) == -1) {
        fprintf (stderr,
                 "setsockopt(IP_MULTICAST_TTL, "
                 "%u): %s\n",
                 h4, strerror (errno));
        exit (1);
      }
      break;
    case AF_INET6:
      /* Default to link-local hoplimit for multicast addresses */
      if (hoplimit == -1 && IN6_IS_ADDR_MULTICAST (&in6->sin6_addr))
        hoplimit = 1;
      if (hoplimit == -1)
        break;
      h6 = hoplimit;
      if (setsockopt (s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &h6, sizeof (h6)) ==
          -1) {
        fprintf (stderr,
                 "setsockopt(IPV6_MULTICAST_HOPS, %u): "
                 "%s\n",
                 h6, strerror (errno));
        exit (1);
      }
  }

  return (s);
}
