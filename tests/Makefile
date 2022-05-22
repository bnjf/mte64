
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

compare_original_trees: compare_original_trees.o data/tree/t_work.o data/tree/t_workinv.o mock/rnd.o ../op_tree.o ../integer_inverse.o
compare_original_trees.o: compare_original_trees.c compare_original_trees.h
compare_original_trees.h: compare_original_trees.c data/tree/t_work.c data/tree/t_workinv.c ../*.c ../common.h
	makeheaders $^
	touch compare_original_trees.h

find_x_bump: find_x_bump.o ../op_tree.o ../integer_inverse.o mock/rnd.o
find_x_bump.o: find_x_bump.c find_x_bump.h
find_x_bump.h: find_x_bump.c ../op_tree.c ../integer_inverse.c mock/rnd.c ../mte64.c ../common.h
	makeheaders $^
	touch $@

print_ops: print_ops.o ../op_tree.o ../integer_inverse.o mock/rnd.o
print_ops.o: print_ops.c print_ops.h
print_ops.h: print_ops.c ../op_tree.c ../integer_inverse.c mock/rnd.c ../mte64.c ../common.h
	makeheaders $^
	touch $@

data/tree/t_work.c data/tree/t_workinv.c:
	$(error ... make the target ``testdata'' first)
testdata: data/tree/t_work.o data/tree/t_workinv.o

data/tree/t_work.o data/tree/t_workinv.o:
	$(MAKE) -C data/tree $(notdir $@)
../op_tree.o ../integer_inverse.o:
	$(MAKE) -C ../ $(notdir $@)

clean:
	$(MAKE) -C data/tree clean
	$(RM) compare_original_trees compare_original_trees.h compare_original_trees.o data/tree/t_work.o data/tree/t_workinv.o mock/rnd.o ../compare_original_trees.o ../integer_inverse.o
	$(RM) find_x_bump.o ../op_tree.o ../integer_inverse.o mock/rnd.o
	$(RM) find_x_bump.h ../op_tree.h ../integer_inverse.h mock/rnd.h ../mte64.h
