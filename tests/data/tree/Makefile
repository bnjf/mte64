
CFLAGS?=-g -DDEBUG \
	-Wall \
	-Wno-unused-function \
	-Wno-unused-variable \
	-Wno-unused-but-set-variable \
	-Wimplicit-fallthrough \
	-pedantic-errors \
	-O -march=native

CPPFLAGS+=-I../../

all:	munge t_work.o t_workinv.o
munge:	munge.c ../../mut_work16.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<
clean:
	$(RM) \
		t_work.[cho] \
		t_workinv.[cho] \
		munge 

# generated files
t_work.o: t_work.c t_work.h
t_work.c: work.bin.gz munge
	zcat $< | ./munge $* > $@
t_work.h:
	makeheaders t_work.c
t_workinv.o: t_workinv.c t_workinv.h
t_workinv.c: workinv.bin.gz munge
	zcat $< | ./munge $* > $@
t_workinv.h:
	makeheaders t_workinv.c

