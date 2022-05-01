
CFLAGS?=-g -DDEBUG -Wall -pedantic-errors -Wno-unused-function \
	-O9 -march=native
LDFLAGS?=

all: tags headers demo

clean:
	rm -f demo.o mte64.o mte64.h

demo: mte64.o demo.o op_tree.o rnd.o

headers:
	makeheaders -v *.[ch]

tags:
	ctags *.c

