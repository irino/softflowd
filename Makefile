WARNFLAGS=\
	-Wall -Waggregate-return -Wcast-align -Wcast-qual \
	-Wmissing-declarations -Wmissing-prototypes -Wno-conversion \
	-Wpointer-arith -Wshadow -Wuninitialized -Wcast-align \
	-Wcast-qual -WformatC=2 -Wformat-nonliteral -Wwrite-strings \
	-Werror

LIBS=-lpcap #-lefence
LDFLAGS=-g

CFLAGS=-g -O $(WARNFLAGS) -I/usr/include/pcap

TARGETS=softflowd softflowctl

all: $(TARGETS)

softflowd: convtime.o softflowd.o
	$(CC) $(LDFLAGS) -o $@ softflowd.o convtime.o $(LIBS)

softflowctl: convtime.o softflowctl.o
	$(CC) $(LDFLAGS) -o $@ softflowctl.o convtime.o $(LIBS)

clean:
	rm -f $(TARGETS) *.o core *.core

strip:
	strip $(TARGETS)
