
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

op_tree: op_tree.o data/tree/t_work.o data/tree/t_workinv.o mock/rnd.o ../op_tree.o ../integer_inverse.o
op_tree.o: op_tree.c op_tree.h
op_tree.h: op_tree.c data/tree/t_work.c data/tree/t_workinv.c ../*.c
	makeheaders $^
	touch op_tree.h

data/tree/t_work.c data/tree/t_workinv.c:
	$(error ... make the target ``testdata'' first)
testdata: data/tree/t_work.o data/tree/t_workinv.o

data/tree/t_work.o data/tree/t_workinv.o:
	$(MAKE) -C data/tree $(notdir $@)
../op_tree.o ../integer_inverse.o:
	$(MAKE) -C ../ $(notdir $@)

clean:
	$(MAKE) -C data/tree clean
	$(RM) op_tree op_tree.h op_tree.o data/tree/t_work.o data/tree/t_workinv.o mock/rnd.o ../op_tree.o ../integer_inverse.o
