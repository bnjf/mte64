#!/bin/sh

set -eu

makeheaders find_x_bump.c  ../op_tree.c ../integer_inverse.c mock/rnd.c ../mte64.c ../common.h
clang find_x_bump.c -o find_x_bump ../op_tree.c ../integer_inverse.c mock/rnd.c -O -Wall -g -Wno-unused-variable

exec 1>/dev/null
./find_x_bump 10000000 0 0
./find_x_bump 10000000 1 0
./find_x_bump 10000000 2 0
./find_x_bump 10000000 3 0
./find_x_bump 10000000 4 0
./find_x_bump 10000000 5 0
./find_x_bump 10000000 6 0
./find_x_bump 10000000 7 0
