TARGET=synack
SRCS=leef.c main.c
OBJS=${SRCS:.c=.o}
CCFLAGS=-Wall -O2
LDFLAGS=-s
LIBS=

.PHONY: all clean distclean
all: ${TARGET}

${TARGET}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

${OBJS}: %.o: %.c
	${CC} ${CCFLAGS} -o $@ -c $<

clean:
	-rm -f *.o ${TARGET}

distclean: clean
