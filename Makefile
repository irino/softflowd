WARNFLAGS=\
	-Wall \
	-Waggregate-return \
	-Wcast-align \
	-Wcast-qual \
	-Werror \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wno-conversion \
	-Wpointer-arith \
	-Wshadow \
	-Wuninitialized \
	-Wcast-align \
	-Wcast-qual \
	-WformatC=2-security \
	-Wformat-nonliteral \
	-Wwrite-strings \
	-Wconversion \
	-Winline \
#	-Wunreachable-code \
#	-Wredundant-decls \
#	-Wpadded 	

LIBS=-lpcap

CFLAGS=-g -O $(WARNFLAGS)

TARGETS=softflowd

all: $(TARGETS)

softflowd: softflowd.o
	$(CC) -o $@ softflowd.o $(LIBS)

clean:
	rm -f $(TARGETS) *.o core *.core
