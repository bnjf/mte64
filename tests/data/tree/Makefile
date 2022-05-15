
CPPFLAGS+=-I../../../
CFLAGS?=-O -Wall

all:	munge t_work.o t_workinv.o
munge:	munge.c
clean:
	@rm -f t_work.c t_work.o t_workinv.c t_workinv.o munge

# generated files
t_work.o: t_work.c
t_work.c: work.bin.gz munge
	zcat $< | ./munge $* > $@
t_workinv.o: t_workinv.c
t_workinv.c: workinv.bin.gz munge
	zcat $< | ./munge $* > $@

