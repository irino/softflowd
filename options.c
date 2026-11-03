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
 * @file options.c
 * @brief Command line support: the usage message and the parsing of timeouts,
 *   host:port arguments and MAC addresses. This file was split from
 *   softflowd.c.
 */

#include "softflowd.h"
#include "options.h"
#include "convtime.h"
#include "log.h"
#include <stdarg.h> /* va_start and va_end for die_usage() */

/**
 * @brief Join command line arguments into one space-separated string.
 *
 * @param argc Number of arguments.
 * @param argv Arguments to join.
 * @return Newly allocated string (used for the BPF filter). Exits on
 * out-of-memory.
 */
char *
argv_join (int argc, char **argv) {
  int i;
  size_t ret_len;
  char *ret;

  ret_len = 0;
  ret = NULL;
  for (i = 0; i < argc; i++) {
    ret_len += strlen (argv[i]);
    if ((ret = realloc (ret, ret_len + 2)) == NULL) {
      fprintf (stderr, "Memory allocation failed.\n");
      exit (1);
    }
    if (i == 0)
      ret[0] = '\0';
    else {
      ret_len++; /* Make room for ' ' */
      strlcat (ret, " ", ret_len + 1);
    }

    strlcat (ret, argv[i], ret_len + 1);
  }

  return (ret);
}

/**
 * @brief Display commandline usage information.
 */
void
usage (void) {
  fprintf (
    stderr,
    "Usage: %s [options] [bpf_program]\n"
    "This is %s version %s. Valid commandline options:\n"
    "  -i, --interface [idx:]interface\n"
    "                          Specify interface to listen on\n"
    "  -r, --read pcap_file    Specify packet capture file to read\n"
    "  -t, --timeout timeout=time\n"
    "                          Specify named timeout\n"
    "  -m, --max-flows max_flows\n"
    "                          Specify maximum number of flows to track (1 "
    "or more, default %d)\n"
    "  -n, --netflow-dest host:port\n"
    "                          Send Cisco NetFlow(tm)-compatible packets to "
    "host:port\n"
    "  -p, --pidfile pidfile   Record pid in specified file\n"
    "                          (default: %s)\n"
    "  -c, --control-socket socketfile\n"
    "                          Location of control socket\n"
    "                          (default: %s)\n"
    "  -v, --netflow-version 1|5|9|10|psamp\n"
    "                          NetFlow export packet version\n"
    "                          10 means IPFIX and psamp means PSAMP (packet "
    "sampling)\n"
#ifdef ENABLE_NTOPNG
    "     ntopng               ntopng means direct injection to NTOPNG (if "
    "supported, ntopng 6.0 or later).\n"
#ifdef ENABLE_NTOPNG_JSON
    "     ntopng-json          ntopng-json means direct injection to NTOPNG "
    "5.x or earlier\n"
    "                          using JSON\n"
#endif
#endif
    "  -L, --hoplimit hoplimit Set TTL/hoplimit for export datagrams\n"
    "  -T, --track full|port|proto|ip|\n"
    "                          Set flow tracking level (default: full)\n"
    "                          vlan                 (\"vlan\" tracking means "
    "\"full\" tracking with vlanid)\n"
    "                          ether                (\"ether\" tracking "
    "means \"vlan\" tracking with ether header)\n"
    "  -H, --direction-mac MAC Specify MAC Address to determine direction "
    "(requires -T ether)\n"
    "  -6, --track-ipv6        Track IPv6 flows, regardless of whether "
    "selected \n"
    "                          NetFlow export protocol supports it\n"
    "  -d, --foreground        Don't daemonise (run in foreground)\n"
    "  -D, --debug             Debug mode: foreground + verbosity + track v6 "
    "flows\n"
    "  -P, --export-protocol udp|tcp|sctp\n"
    "                          Specify transport layer protocol for "
    "exporting packets\n"
    "  -A, --absolute-time sec|milli|micro|nano\n"
    "                          Specify absolute time format form exporting "
    "records\n"
    "  -s, --sampling-rate rate\n"
    "                          Specify periodical sampling rate "
    "(denominator)\n"
    "  -B, --pcap-buffer-size bytes\n"
    "                          Libpcap buffer size in bytes\n"
    "  -b, --bidirectional     Bidirectional mode in IPFIX (-b work with -v "
    "10)\n"
    "  -a, --adjust-time       Adjusting time for reading pcap file (-a work "
    "with -r)\n"
    "  -C, --snaplen capture_length\n"
    "                          Specify length for packet capture (snaplen)\n"
    "  -l, --load-balance      Load balancing mode for multiple "
    "destinations\n"
    "  -R, --psamp-port receive_port\n"
    "                          Specify port number for PSAMP receive mode\n"
#ifdef ENABLE_PTHREAD
    "  -M, --multithread       Enable multithread\n"
#endif /* ENABLE_PTHREAD */
    "  -N, --no-promisc        Disable promiscuous mode\n"
#ifdef LINUX
    "  -S, --send-interface send_interface_name\n"
    "                          Specify send interface name\n"
#endif /* LINUX */
    "  -x, --mpls-labels labels\n"
    "                          Specify number of MPLS labels (1 to 10)\n"
    "  -I, --reinit-interval seconds\n"
    "                          Specify seconds for reinitialize boot time\n"
    "  -g, --gauge-cpu-clock   Gauge cpu clock (total and export) for "
    "benchmark\n"
    "  -e, --exporter-ip address\n"
    "                          Specify Exporter IP (IPv4 or IPv6) address\n"
    "  -f, --full-transport-header-check\n"
    "                          Require the whole TCP/UDP/ICMP header instead "
    "of\n"
    "                          only the fields used (ports, TCP flags, ICMP "
    "type/code)\n"
    "  -F, --flow-lookup mode  Flow table lookup: tree, hash-tree (default) "
    "or hash\n"
    "                          (hash: a colliding flow expires the resident "
    "one)\n"
    "  -h, --help              Display this help\n"
    "\n"
    "Valid timeout names and default values:\n"
    "  tcp     (default %6d)"
    "  tcp.rst (default %6d)"
    "  tcp.fin (default %6d)\n"
    "  udp     (default %6d)"
    "  icmp    (default %6d)"
    "  general (default %6d)\n"
    "  maxlife (default %6d)"
    "  expint  (default %6d)\n"
    "\n",
    PROGNAME, PROGNAME, PROGVER, DEFAULT_MAX_FLOWS, DEFAULT_PIDFILE,
    DEFAULT_CTLSOCK, DEFAULT_TCP_TIMEOUT, DEFAULT_TCP_RST_TIMEOUT,
    DEFAULT_TCP_FIN_TIMEOUT, DEFAULT_UDP_TIMEOUT, DEFAULT_ICMP_TIMEOUT,
    DEFAULT_GENERAL_TIMEOUT, DEFAULT_MAXIMUM_LIFETIME,
    DEFAULT_EXPIRY_INTERVAL);
}
/**
 * @brief Print an error message and the usage text to stderr, then exit(1).
 *
 * @param fmt printf-style error message, written to stderr before the usage.
 */
__dead void
die_usage (const char *fmt, ...) {
  va_list ap;

  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  usage();
  exit (1);
}

/**
 * @brief Parse a "-t name=time" argument and set that timeout.
 *
 * Exits with a usage message on a malformed argument.
 *
 * @param ft      Flow tracking state.
 * @param to_spec Argument of the form name=time; name is tcp, tcp.rst, tcp.fin,
 * udp, icmp, general, maxlife or expint.
 */
void
set_timeout (struct FLOWTRACK *ft, const char *to_spec) {
  char *name, *value;
  long secs;
  int timeout;

  if ((name = strdup (to_spec)) == NULL) {
    fprintf (stderr, "Out of memory\n");
    exit (1);
  }
  if ((value = strchr (name, '=')) == NULL || *(++value) == '\0') {
    die_usage ("Invalid -t option \"%s\".\n", name);
  }
  *(value - 1) = '\0';
  secs = convtime (value);
  /* The timeouts are kept in an int; a longer one must not be truncated. */
  if (secs < 0 || secs > INT_MAX) {
    die_usage ("Invalid -t timeout.\n");
  }
  timeout = (int) secs;
  if (strcmp (name, "tcp") == 0)
    ft->param.tcp_timeout = timeout;
  else if (strcmp (name, "tcp.rst") == 0)
    ft->param.tcp_rst_timeout = timeout;
  else if (strcmp (name, "tcp.fin") == 0)
    ft->param.tcp_fin_timeout = timeout;
  else if (strcmp (name, "udp") == 0)
    ft->param.udp_timeout = timeout;
  else if (strcmp (name, "icmp") == 0)
    ft->param.icmp_timeout = timeout;
  else if (strcmp (name, "general") == 0)
    ft->param.general_timeout = timeout;
  else if (strcmp (name, "maxlife") == 0)
    ft->param.maximum_lifetime = timeout;
  else if (strcmp (name, "expint") == 0)
    ft->param.expiry_interval = timeout;
  else {
    die_usage ("Invalid -t name.\n");
  }

  if (ft->param.general_timeout == 0) {
    fprintf (stderr, "\"general\" flow timeout must be "
                     "greater than zero\n");
    exit (1);
  }

  free (name);
}

/**
 * @brief Resolve one "host:port" (or "[v6addr]:port") argument.
 *
 * Exits with a message on error.
 *
 * @param s    Argument to parse.
 * @param addr Receives the resolved address.
 * @param len  On entry the size of addr, on return the address length.
 */
static void
parse_hostport (const char *s, struct sockaddr *addr,
                socklen_t *len) {
  char *orig, *host, *port;
  struct addrinfo hints, *res;
  int herr;

  if ((host = orig = strdup (s)) == NULL) {
    fprintf (stderr, "Out of memory\n");
    exit (1);
  }
  if ((port = strrchr (host, ':')) == NULL || *(++port) == '\0' ||
      *host == '\0') {
    die_usage ("Invalid -n argument.\n");
  }
  *(port - 1) = '\0';
  /* getaddrinfo () cuts a numeric port to 16 bits: refuse one that is too big */
  if (*port >= '0' && *port <= '9') {
    char *end;
    unsigned long portnum;
    errno = 0;
    portnum = strtoul (port, &end, 10);
    if (*end == '\0' && (errno == ERANGE || portnum > 65535)) {
      die_usage ("Invalid -n argument.\n");
    }
  }

  /* Accept [host]:port for numeric IPv6 addresses */
  if (*host == '[' && *(port - 2) == ']') {
    host++;
    *(port - 2) = '\0';
  }

  memset (&hints, '\0', sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  /* getaddrinfo () returns a non-zero EAI_* code on failure, not -1 only */
  if ((herr = getaddrinfo (host, port, &hints, &res)) != 0 || res == NULL ||
      res->ai_addr == NULL) {
    fprintf (stderr, "No addresses found for [%s]:%s\n", host, port);
    exit (1);
  }
  if (res->ai_addrlen > *len) {
    fprintf (stderr, "Address too long\n");
    exit (1);
  }
  memcpy (addr, res->ai_addr, res->ai_addrlen);
  free (orig);
  *len = res->ai_addrlen;
}

/**
 * @brief Resolve a comma-separated list of host:port destinations.
 *
 * @param s        Comma-separated list.
 * @param dest     Destination array to fill.
 * @param max_dest Size of dest.
 * @return Number of destinations parsed.
 */
int
parse_hostports (const char *s, struct DESTINATION *dest,
                 int max_dest) {
  int i = 0;
  char *hostport;
  for (hostport = strsep ((char **) &s, ","); hostport != NULL && i < max_dest;
       hostport = strsep ((char **) &s, ",")) {
    dest[i].sslen = sizeof (dest[i].ss);
    parse_hostport (hostport, (struct sockaddr *) &dest[i].ss, &dest[i].sslen);
    i++;
  }
  return i;
}
/**
 * @brief Parse a MAC address string into a 6-octet array.
 *
 * @param str Address as aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff.
 * @param mac Receives the address.
 * @return 0 on success, -1 on error.
 */
int
parse_mac_address (const char *str, u_int8_t mac[6]) {
  unsigned int b[6];
  int i;

  if (sscanf (str, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3], &b[4],
              &b[5]) != 6 &&
      sscanf (str, "%2x-%2x-%2x-%2x-%2x-%2x", &b[0], &b[1], &b[2], &b[3], &b[4],
              &b[5]) != 6)
    return (-1);

  for (i = 0; i < 6; i++) {
    if (b[i] > 0xff)
      return (-1);
    mac[i] = (u_int8_t) b[i];
  }
  return (0);
}
