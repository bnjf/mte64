
CFLAGS?=-g -pg -DDEBUG -Wall -pedantic-errors -O
LDFLAGS?=-pg

all: demo

clean:
	rm -f demo.o mte64.o mte64.h

demo: mte64.o demo.o

demo.o: mte64.o

mte64.h:	mte64.c
	#makeheaders -v -local mte64.c
	makeheaders -v mte64.c
	touch mte64.h

mte64.o:	mte64.c mte64.h

tags: mte64.c
	ctags mte64.c

