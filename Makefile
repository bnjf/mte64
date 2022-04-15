
all: mte64.h mte64.o

mte64.h:	mte64.c
	makeheaders -v -local mte64.c
	touch mte64.h

mte64.o: 	mte64.c

