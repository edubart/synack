CC=gcc
CFLAGS=-Wall -Wextra -Wno-unused-parameter -Wno-unused-result -O2
LDFLAGS=-s -lm -pthread
prefix=/usr/local

.PHONY: all clean distclean install
all: synack sniffer

synack: leef.o synack.o
	${CC} -o synack $^ ${LDFLAGS}

sniffer: leef.o sniffer.o
	${CC} -o sniffer $^ ${LDFLAGS}

${OBJS}: %.o: %.c *.h
	${CC} ${CFLAGS} -o $@ -c $<

clean:
	rm -f *.o synack sniffer

distclean: clean

install:
	mkdir -p $(prefix)/bin
	install -m 4755 synack $(prefix)/bin/
