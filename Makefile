CFLAGS= -I. -Wall
SRCS=	bin2hex.c endian.c aout16.c aout32.c bin.c com.c elf.c exe.c rel.c sav.c
OBJS=	bin2hex.o endian.o aout16.o aout32.o bin.o com.o elf.o exe.o rel.o sav.o

all:	bin2hex

bin2hex: ${OBJS}
	${CC} ${CFLAGS}  -o bin2hex ${OBJS}

clean:
	rm -f ${OBJS} bin2hex .depend

depend:	${SRCS}
	mkdep ${CFLAGS} ${SRCS}
