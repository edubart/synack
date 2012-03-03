CC=gcc
CFLAGS=-Wall -O3 -fomit-frame-pointer
LDFLAGS=-s -pthread -lm
prefix=/usr/local

.PHONY: all clean distclean install
all: synack sniffer

synack: leef.o synack.o
	${CC} ${LDFLAGS} -o synack $^

sniffer: leef.o sniffer.o
	${CC} ${LDFLAGS} -o sniffer $^

${OBJS}: %.o: %.c *.h
	${CC} ${CFLAGS} -o $@ -c $<

clean:
	rm -f *.o synack sniffer

distclean: clean

install:
	mkdir -p $(prefix)/bin
	install -m 4755 ${TARGET} $(prefix)/bin/