#!/bin/sh

set -eu

makeheaders find_x_bump.c  ../op_tree.c ../integer_inverse.c ../rnd.c ../mte64.c ../common.h
clang find_x_bump.c -o find_x_bump ../op_tree.c ../integer_inverse.c mock/rnd.c -O0 -Wall -g -Wno-unused-variable

exit

exec 1>/dev/null

./find_x_bump 1000000 0 0
./find_x_bump 1000000 1 0
./find_x_bump 1000000 2 0
./find_x_bump 1000000 3 0
./find_x_bump 1000000 4 2
./find_x_bump 1000000 5 12
./find_x_bump 1000000 6 36
./find_x_bump 10000000 7 88
