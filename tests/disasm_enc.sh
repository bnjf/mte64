#!/bin/sh

gdb demo \
  -ex 'break invert_ops' \
  -ex run \
  -ex 'dump binary memory encrypt_stage.bin &encrypt_stage cpu_state.rdi+1' \
  -ex q \
  && ndisasm -b 64 encrypt_stage.bin
