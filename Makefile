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
	-Wuninitialized

LIBS=-lpcap

CFLAGS=-g -O $(WARNFLAGS)

fakeflowd: fakeflowd.o
	$(CC) -o $@ fakeflowd.o $(LIBS)

clean:
	rm -f fakeflowd fakeflowd.o core *.core
