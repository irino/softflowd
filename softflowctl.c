#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#define DEFAULT_CTLSOCK "/var/run/softflowd.ctl"

int
main(int argc, char **argv)
{
	const char *ctlsock_path;
	char buf[8192], *command;
	struct sockaddr_un ctl;
	socklen_t ctllen;
	int ctlsock;
	FILE *ctlf;

	/* XXX: use getopt */
	if (argc != 2) {
		fprintf(stderr, "Usage: softflowctl [command]\n");
		exit(1);
	}
	command = argv[1];

	ctlsock_path = DEFAULT_CTLSOCK;

	memset(&ctl, '\0', sizeof(ctl));
	strncpy(ctl.sun_path, ctlsock_path, sizeof(ctl.sun_path));
	ctl.sun_path[sizeof(ctl.sun_path) - 1] = '\0';
	ctl.sun_family = AF_UNIX;
	ctllen = offsetof(struct sockaddr_un, sun_path) +
            strlen(ctlsock_path) + 1;
#ifdef SOCK_HAS_LEN 
	ctl.sun_len = socklen;
#endif
	if ((ctlsock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "ctl socket() error: %s\n", 
		    strerror(errno));
		exit(1);
	}
	if (connect(ctlsock, (struct sockaddr*)&ctl, sizeof(ctl)) == -1) {
		fprintf(stderr, "ctl bind(\"%s\") error: %s\n",
		    ctl.sun_path, strerror(errno));
		exit(1);
	}
	
	if ((ctlf = fdopen(ctlsock, "r+")) == NULL) {
		fprintf(stderr, "fdopen: %s\n", strerror(errno));
		exit(1);
	}
	setlinebuf(ctlf);
	if (fprintf(ctlf, "%s\n", command) < 0) {
		fprintf(stderr, "write: %s\n", strerror(errno));
		exit(1);
	}

	while((fgets(buf, sizeof(buf), ctlf)) != NULL) {
		printf("REPLY: %s", buf);
	}	

	exit(0);
}
