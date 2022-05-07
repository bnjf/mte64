
CFLAGS?=-g -DDEBUG \
	-Wall \
	-Wno-unused-function \
	-Wno-unused-variable \
	-Wno-unused-but-set-variable \
	-pedantic-errors \
	-O -march=native
LDFLAGS?=-lefence

all: tags headers demo

clean:
	rm -f *.[oh] tags

demo: mte64.o demo.o op_tree.o rnd.o

headers:
	makeheaders -v *.[ch]

tags:
	ctags *.c

