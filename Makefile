TARGET=synack
SRCS=leef.c synack.c
OBJS=${SRCS:.c=.o}
CC=gcc
CFLAGS=-Wall -O2 -D_REENTRANT
LDFLAGS=-s -lm
LIBS=-lpthread
prefix=/usr/local

.PHONY: all clean distclean install
all: ${TARGET}

${TARGET}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

${OBJS}: %.o: %.c
	${CC} ${CFLAGS} -o $@ -c $<

clean:
	-rm -f *.o ${TARGET}

distclean: clean

install:
	mkdir -p $(prefix)/bin
	install -m 4755 ${TARGET} $(prefix)/bin/