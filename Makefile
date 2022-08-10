
CFLAGS?=-g -DDEBUG \
	-Wall \
	-Wno-unused-function \
	-Wno-unused-variable \
	-Wno-unused-but-set-variable \
	-Wimplicit-fallthrough \
	-pedantic-errors \
	-O -march=native
LDFLAGS?=-lefence

all: tags headers demo

clean:
	rm -f *.o tags demo

demo: mte64.o demo.o op_tree.o rnd.o integer_inverse.o generate.o

headers:
	makeheaders -v *.[ch]

tags:
	ctags -R .

