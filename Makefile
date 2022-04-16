
all: demo

demo: demo.o mte64.o

mte64.h:	mte64.c
	makeheaders -v -local mte64.c
	touch mte64.h

mte64.o:	mte64.c mte64.h

