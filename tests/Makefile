
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

op_tree: op_tree.o data/tree/t_work.o data/tree/t_workinv.o rnd_mock.o ../op_tree.o ../integer_inverse.o
op_tree.o: op_tree.c op_tree.h
op_tree.h: op_tree.c data/tree/t_work.c data/tree/t_workinv.c ../*.c
	makeheaders $^
	touch op_tree.h

data/tree/t_work.c data/tree/t_workinv.c:
	@echo manually run make in data/tree
	@false
data/tree/t_work.o data/tree/t_workinv.o:
	$(MAKE) -C data/tree $(notdir $@)
../op_tree.o ../integer_inverse.o:
	$(MAKE) -C ../ $(notdir $@)

clean:
	@rm -f *.[oh] op_tree data/tree/t_work.o data/tree/t_workinv.o rnd_mock.o ../op_tree.o ../integer_inverse.o
	$(MAKE) -C data/tree clean
