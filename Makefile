
CFLAGS?=-g -DDEBUG -Wall -pedantic-errors -Wno-unused-function \
	-O -march=native
LDFLAGS?=

all: tags headers demo

clean:
	rm -f *.[oh]

demo: mte64.o demo.o op_tree.o rnd.o

headers:
	makeheaders -v *.[ch]

tags:
	ctags *.c

