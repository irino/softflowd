WARNFLAGS=\
	-Wall -Waggregate-return -Wcast-align -Wcast-qual \
	-Wmissing-declarations -Wmissing-prototypes -Wno-conversion \
	-Wpointer-arith -Wshadow -Wuninitialized -Wcast-align \
	-Wcast-qual -WformatC=2 -Wformat-nonliteral -Wwrite-strings \
	-Wconversion \
	-Werror

LIBS=-lpcap #-lefence
LDFLAGS=-g

CFLAGS=-g -O $(WARNFLAGS)

TARGETS=softflowd

all: $(TARGETS)

softflowd: softflowd.o
	$(CC) $(LDFLAGS) -o $@ softflowd.o $(LIBS)

clean:
	rm -f $(TARGETS) *.o core *.core

