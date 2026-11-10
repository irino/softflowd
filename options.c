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
 * @brief Command line support: the usage message, the parsing of the options
 *   and of timeouts, host:port arguments and MAC addresses. This file was split
 *   from softflowd.c.
 */

#include "softflowd.h"
#include "options.h"
#include "convtime.h"
#include "globals.h"
#include "ipfix.h"
#include "log.h"
#include "netsock.h"
#include "sender.h"
#include <getopt.h>
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
 * @param s        Comma-separated list; it is modified (strsep).
 * @param dest     Destination array to fill.
 * @param max_dest Size of dest.
 * @return Number of destinations parsed.
 */
int
parse_hostports (char *s, struct DESTINATION *dest,
                 int max_dest) {
  int i = 0;
  char *hostport;
  for (hostport = strsep (&s, ","); hostport != NULL && i < max_dest;
       hostport = strsep (&s, ",")) {
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

/**
 * @brief Parse the command line: the short options and their long names.
 *
 * Sets *cfg to the defaults first. The options act in the order they are
 * given, as -e and -P do, so a later option overrides an earlier one. The
 * settings of the flow table and of the export target are stored in
 * *flowtrack and *target, those of main () in *cfg. Exits on an invalid
 * option, and, for -h, after the usage message. The caller reads the BPF
 * expression from the arguments after optind.
 *
 * @param argc Argument count.
 * @param argv Arguments.
 * @param cfg Receives the settings that main () uses.
 * @param flowtrack Flow table; initialised by init_flowtrack ().
 * @param target Export target; initialised by the caller.
 */
void
parse_command_line (int argc, char **argv, struct DAEMON_CONFIG *cfg,
                    struct FLOWTRACK *flowtrack, struct NETFLOW_TARGET *target) {
  int ch;
  int recvport = IPFIX_PORT;
  int version = 0;
  char *timeunit;
  static const struct option long_options[] = {
    {"track-ipv6", no_argument, NULL, '6'},
    {"adjust-time", no_argument, NULL, 'a'},
    {"absolute-time", required_argument, NULL, 'A'},
    {"bidirectional", no_argument, NULL, 'b'},
    {"pcap-buffer-size", required_argument, NULL, 'B'},
    {"control-socket", required_argument, NULL, 'c'},
    {"snaplen", required_argument, NULL, 'C'},
    {"foreground", no_argument, NULL, 'd'},
    {"debug", no_argument, NULL, 'D'},
    {"exporter-ip", required_argument, NULL, 'e'},
    {"full-transport-header-check", no_argument, NULL, 'f'},
    {"flow-lookup", required_argument, NULL, 'F'},
    {"gauge-cpu-clock", no_argument, NULL, 'g'},
    {"help", no_argument, NULL, 'h'},
    {"direction-mac", required_argument, NULL, 'H'},
    {"interface", required_argument, NULL, 'i'},
    {"reinit-interval", required_argument, NULL, 'I'},
    {"load-balance", no_argument, NULL, 'l'},
    {"hoplimit", required_argument, NULL, 'L'},
    {"max-flows", required_argument, NULL, 'm'},
#ifdef ENABLE_PTHREAD
    {"multithread", no_argument, NULL, 'M'},
#endif /* ENABLE_PTHREAD */
    {"netflow-dest", required_argument, NULL, 'n'},
    {"no-promisc", no_argument, NULL, 'N'},
    {"pidfile", required_argument, NULL, 'p'},
    {"export-protocol", required_argument, NULL, 'P'},
    {"read", required_argument, NULL, 'r'},
    {"psamp-port", required_argument, NULL, 'R'},
    {"sampling-rate", required_argument, NULL, 's'},
#ifdef LINUX
    {"send-interface", required_argument, NULL, 'S'},
#endif /* LINUX */
    {"timeout", required_argument, NULL, 't'},
    {"track", required_argument, NULL, 'T'},
    {"netflow-version", required_argument, NULL, 'v'},
    {"mpls-labels", required_argument, NULL, 'x'},
    {NULL, 0, NULL, 0}};

  memset (cfg, '\0', sizeof (*cfg));
  cfg->hoplimit = -1;
  cfg->protocol = IPPROTO_UDP;
  cfg->use_promisc = 1;
  cfg->pidfile_path = DEFAULT_PIDFILE;
  cfg->ctlsock_path = DEFAULT_CTLSOCK;

  while (
    (ch = getopt_long (argc, argv,
                       "6aA:bB:c:C:dDe:fF:ghH:i:I:lL:m:Mn:Np:P:r:R:s:S:t:T:v:x:",
                       long_options, NULL)) != -1) {
    switch (ch) {
      case '6':
        cfg->always_v6 = 1;
        break;
      case 'a':
        flowtrack->param.adjust_time = 1;
        break;
      case 'A':
        if (strcasecmp (optarg, "sec") == 0)
          flowtrack->param.time_format = 's';
        else if (strcasecmp (optarg, "milli") == 0)
          flowtrack->param.time_format = 'm';
        else if (strcasecmp (optarg, "micro") == 0)
          flowtrack->param.time_format = 'M';
        else if (strcasecmp (optarg, "nano") == 0)
          flowtrack->param.time_format = 'n';
        else {
          die_usage ("Unknown time format\n");
        }
        break;
      case 'b':
        flowtrack->param.bidirection = 1;
        break;
      case 'B':
        cfg->pcap_override_buffer_size = atoi (optarg);
        break;
      case 'c':
        if (strcmp (optarg, "none") == 0)
          cfg->ctlsock_path = NULL;
        else
          cfg->ctlsock_path = optarg;
        break;
      case 'C': /* Capture Length */
        snaplen = atoi (optarg);
        break;
      case 'd':
        cfg->dontfork_flag = 1;
        break;
      case 'D':
        verbose_flag = 1;
        cfg->always_v6 = 1;
        cfg->dontfork_flag = 1;
        break;
      case 'e':
        if (optarg != NULL) {
          struct addrinfo hints;
          int gai_err;
          memset (&hints, '\0', sizeof (hints));
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = cfg->protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
          hints.ai_flags = 0;
          hints.ai_protocol = cfg->protocol;
          /* getaddrinfo() does not set errno; report its own error code. */
          if ((gai_err = getaddrinfo (optarg, NULL, &hints,
                                      &flowtrack->param.option.exporterAddr)) !=
              0) {
            fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (gai_err));
            break;
          }
        }
        break;
      case 'f':
        flowtrack->param.full_l4hdr_check = 1;
        break;
      case 'F':
        if (strcmp (optarg, "tree") == 0)
          flowtrack->flow_lookup = FLOW_LOOKUP_TREE;
        else if (strcmp (optarg, "hash-tree") == 0)
          flowtrack->flow_lookup = FLOW_LOOKUP_HASH_TREE;
        else if (strcmp (optarg, "hash") == 0)
          flowtrack->flow_lookup = FLOW_LOOKUP_HASH;
        else {
          die_usage ("Invalid flow lookup mode\n\n");
        }
        break;
      case 'g':
        gauge_clock = 1;
        break;
      case 'h':
        usage();
        exit (0);
      case 'H':
        if (optarg != NULL) {
          if (parse_mac_address (optarg, flowtrack->param.direction_mac) != 0) {
            fprintf (stderr, "Invalid MAC address %s\n", optarg);
            exit (1);
          }
          flowtrack->param.direction_mac_set = 1;
        }
        break;
      case 'i':
        if (cfg->capfile != NULL || cfg->dev != NULL) {
          die_usage ("Packet source already specified.\n\n");
        }
#if defined(HAVE_STRSEP)
        cfg->dev = strsep (&optarg, ":");
#else  /* defined(HAVE_STRSEP) */
        cfg->dev = strtok (optarg, ":");
#endif /* defined(HAVE_STRSEP) */
        if (optarg != NULL) {
          if (strlen (cfg->dev) > 0) {
            if_index = (u_int16_t) atoi (cfg->dev);
          }
          cfg->dev = optarg;
          cfg->user_ifindex_flag = 1;
        }
        if (strlen (cfg->dev) == 0) {
          die_usage ("Wrong interface is specified.\n\n");
        }
        if (verbose_flag)
          fprintf (stderr, "Using %s (idx: %d)\n", cfg->dev, if_index);
        strlcpy (flowtrack->param.option.interfaceName, cfg->dev,
                 sizeof (flowtrack->param.option.interfaceName));
        break;
      case 'I':
        errno = 0; /* strtol() sets errno on error only */
        cfg->boot_time_reinit_sec = strtol (optarg, &timeunit, 10);
        if ((errno == ERANGE && (cfg->boot_time_reinit_sec == LONG_MAX ||
                                 cfg->boot_time_reinit_sec == LONG_MIN)) ||
            (errno != 0 && cfg->boot_time_reinit_sec == 0)) {
          perror ("strtol");
          usage();
          exit (EXIT_FAILURE);
        }
        if (timeunit == optarg) {
          die_usage ("No digits were found in boot_time_reinit\n");
        }
        if (*timeunit == 'd' || *timeunit == 'D') { /* days */
          if (cfg->boot_time_reinit_sec > BOOTTIME_MAX_DAY) {
            cfg->boot_time_reinit_sec = BOOTTIME_MAX_DAY;
          }
          cfg->boot_time_reinit_sec *= (24 * 60 * 60);     /* convert to seconds */
        } else if (*timeunit == 'h' || *timeunit == 'H') { /* hours */
          if (cfg->boot_time_reinit_sec > BOOTTIME_MAX_HOUR) {
            cfg->boot_time_reinit_sec = BOOTTIME_MAX_HOUR;
          }
          cfg->boot_time_reinit_sec *= (60 * 60);          /* convert to seconds */
        } else if (*timeunit == 'm' || *timeunit == 'M') { /* minutes */
          if (cfg->boot_time_reinit_sec > BOOTTIME_MAX_MIN) {
            cfg->boot_time_reinit_sec = BOOTTIME_MAX_MIN;
          }
          cfg->boot_time_reinit_sec *= 60; /* convert to seconds */
        } else {
          if (cfg->boot_time_reinit_sec > BOOTTIME_MAX_SEC) { /* seconds */
            cfg->boot_time_reinit_sec = BOOTTIME_MAX_SEC;
          }
        }
        if (verbose_flag) {
          fprintf (stderr, "boot_time_reinit is %ld seconds.\n",
                   cfg->boot_time_reinit_sec);
        }
        break;
      case 'l':  // load balancing
        target->is_loadbalance = 1;
        break;
      case 'L':
        cfg->hoplimit = atoi (optarg);
        if (cfg->hoplimit < 0 || cfg->hoplimit > 255) {
          die_usage ("Invalid hop limit\n\n");
        }
        break;
      case 'm': {
        /* Range check on an int: max_flows is unsigned and would wrap. */
        int max_flows = atoi (optarg);
        if (max_flows < 1) {
          die_usage ("Invalid maximum flows\n\n");
        }
        flowtrack->param.max_flows = max_flows;
      } break;
      case 'M':
#ifdef ENABLE_PTHREAD
        use_thread = 1;
#endif /* ENABLE_PTHREAD */
        break;
      case 'n':
        /* Will exit on failure */
        target->num_destinations = parse_hostports (optarg, target->destinations,
                                                    SOFTFLOWD_MAX_DESTINATIONS);
        break;
      case 'N':
        cfg->use_promisc = 0;
        break;
      case 'p':
        cfg->pidfile_path = optarg;
        break;
      case 'P':
        if (strcasecmp (optarg, "udp") == 0)
          cfg->protocol = IPPROTO_UDP;
        else if (strcasecmp (optarg, "tcp") == 0)
          cfg->protocol = IPPROTO_TCP;
#ifdef IPPROTO_SCTP
        else if (strcasecmp (optarg, "sctp") == 0)
          cfg->protocol = IPPROTO_SCTP;
#endif
        else {
          die_usage ("Unknown transport layer protocol\n");
        }
        break;
      case 'r':
        if (cfg->capfile != NULL || cfg->dev != NULL) {
          die_usage ("Packet source already specified.\n\n");
        }
        cfg->capfile = optarg;
        cfg->dontfork_flag = 1;
        cfg->ctlsock_path = NULL;
        strlcpy (flowtrack->param.option.interfaceName, cfg->capfile,
                 sizeof (flowtrack->param.option.interfaceName));
        break;
      case 'R':
        recvport = atoi (optarg);
        if (recvport < 0 || recvport > 65535) {
          /* Say so with the usage, and go on with the default port */
          fprintf (stderr, "Invalid -R port, using the default %d.\n",
                   IPFIX_PORT);
          usage();
          recvport = IPFIX_PORT;
        }
        cfg->rsock = recvsock ((uint16_t) recvport);
        if (cfg->rsock < 0)
          exit (1);
        break;
      case 's':
        flowtrack->param.option.sample = atoi (optarg);
        if (flowtrack->param.option.sample < 2) {
          flowtrack->param.option.sample = 0;
        }
        break;
#ifdef LINUX
      case 'S':
        cfg->send_ifname = optarg;
        break;
#endif /* LINUX */
      case 't':
        /* Will exit on failure */
        set_timeout (flowtrack, optarg);
        break;
      case 'T':
        if (strcasecmp (optarg, "full") == 0)
          flowtrack->param.track_level = TRACK_FULL;
        else if (strcasecmp (optarg, "port") == 0)
          flowtrack->param.track_level = TRACK_IP_PROTO_PORT;
        else if (strcasecmp (optarg, "proto") == 0)
          flowtrack->param.track_level = TRACK_IP_PROTO;
        else if (strcasecmp (optarg, "ip") == 0)
          flowtrack->param.track_level = TRACK_IP_ONLY;
        else if (strcasecmp (optarg, "vlan") == 0)
          flowtrack->param.track_level = TRACK_FULL_VLAN;
        else if (strcasecmp (optarg, "ether") == 0)
          flowtrack->param.track_level = TRACK_FULL_VLAN_ETHER;

        else {
          die_usage ("Unknown flow tracking level\n");
        }
        track_level = flowtrack->param.track_level;
        break;
      case 'v':
        if (!strncmp (optarg, "psamp", sizeof ("psamp"))) {
          flowtrack->param.is_psamp = 1;
          break;
        }
#ifdef ENABLE_NTOPNG
        if (!strncmp (optarg, SOFTFLOWD_NF_VERSION_NTOPNG_STRING,
                      sizeof (SOFTFLOWD_NF_VERSION_NTOPNG_STRING))) {
          version = SOFTFLOWD_NF_VERSION_NTOPNG;
        }
#ifdef ENABLE_NTOPNG_JSON
        if (!strncmp (optarg, SOFTFLOWD_NF_VERSION_NTOPNG_JSON_STRING,
                      sizeof (SOFTFLOWD_NF_VERSION_NTOPNG_JSON_STRING))) {
          version = SOFTFLOWD_NF_VERSION_NTOPNG_JSON;
        }
#endif /* ENABLE_NTOPNG_JSON */
#endif /* ENABLE_NTOPNG */
        version = version ? version : atoi (optarg);
        target->dialect = lookup_netflow_sender (version);
        if (target->dialect == NULL) {
          fprintf (stderr, "Invalid NetFlow version\n");
          exit (1);
        }
        break;
      case 'x': {
        /* Range check on an int: max_num_label is u_int8_t and would wrap. */
        int num_label = atoi (optarg);
        if (num_label < 1 || num_label > 10) {
          die_usage ("Invalid number of MPLS label (1 to 10)\n\n");
        }
        flowtrack->param.max_num_label = num_label;
      } break;
      default:
        die_usage ("Invalid commandline option.\n");
    }
  }
}
