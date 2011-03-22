TARGET=synack
SRCS=leef.c main.c
OBJS=${SRCS:.c=.o}
CCFLAGS=-Wall -O2 -D_REENTRANT
LDFLAGS=-s
LIBS=-lpthread
prefix=/usr/local

.PHONY: all clean distclean install
all: ${TARGET}

${TARGET}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

${OBJS}: %.o: %.c
	${CC} ${CCFLAGS} -o $@ -c $<

clean:
	-rm -f *.o ${TARGET}

distclean: clean

install:
	install -m 4755 synack $(prefix)/bin