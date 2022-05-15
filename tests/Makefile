
CFLAGS?=-g -DDEBUG \
	-Wall \
	-Wno-unused-function \
	-Wno-unused-variable \
	-Wno-unused-but-set-variable \
	-Wimplicit-fallthrough \
	-pedantic-errors \
	-O -march=native
LDFLAGS?=-lefence
CPPFLAGS+=-I../ 

op_tree: op_tree.o ../testdata/tree/t_work.o ../testdata/tree/t_workinv.o ../rnd.o ../op_tree.o ../integer_inverse.o
op_tree.o: op_tree.c op_tree.h
op_tree.h: op_tree.c ../testdata/tree/t_work.c ../testdata/tree/t_workinv.c ../*.c
	makeheaders $^
	touch op_tree.h

../testdata/tree/t_work.o ../testdata/tree/t_workinv.o:
	$(MAKE) -C ../testdata/tree $(notdir $@)
../rnd.o ../op_tree.o ../integer_inverse.o:
	$(MAKE) -C ../ $(notdir $@)

clean:
	rm -f *.[oh] op_tree ../testdata/tree/t_work.o ../testdata/tree/t_workinv.o ../rnd.o ../op_tree.o ../integer_inverse.o
