#define _BSD_SOURCE /* Needed for BSD-style struct ip,tcp,udp on Linux */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/bpf.h>

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>

/* XXX: this check probably isn't sufficient for all systems */
#ifndef __GNU_LIBRARY__ 
# define SOCK_HAS_LEN 
#endif

/* The name of the program */
#define PROGNAME		"softflowd"

/* The name of the program */
#define PROGVER			"0.8"

/* Default pidfile */
#define DEFAULT_PIDFILE		"/var/run/" PROGNAME ".pid"

/* Default control socket */
#define DEFAULT_CTLSOCK		"/var/run/" PROGNAME ".ctl"

#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

