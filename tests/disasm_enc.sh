#!/bin/sh

gdb demo \
  -ex 'break exec_enc_stage' \
  -ex run \
  -ex 'dump binary memory encrypt_stage.0.bin encrypt_stage encrypt_stage+0x200' \
  -ex c \
  -ex 'dump binary memory encrypt_stage.1.bin encrypt_stage encrypt_stage+0x200' \
  -ex c \
  -ex 'dump binary memory encrypt_stage.2.bin encrypt_stage encrypt_stage+0x200' \
  -ex c \
  -ex 'dump binary memory encrypt_stage.3.bin encrypt_stage encrypt_stage+0x200' \
  -ex q 
