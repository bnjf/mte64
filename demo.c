#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mte64.h"

int main(int argc, char *argv[]) {
  mut_input in;
  mut_output out;

  srandom(2);
  for (int i = 0; i < 1; i++) {
    in.code = (uint8_t *)"\x90\x90\x90\xc3";
    in.len = 4; // XXX failing if we're not on a boundary

    in.exec_offset = 0;
    in.entry_offset = 0;
    in.payload_offset = 0;
    in.flags = MUT_FLAGS_PRESERVE_AX | MUT_FLAGS_RUN_ON_DIFFERENT_CPU;

    in.routine_size = 15;

    mut_engine(&in, &out);

    printf("mut_engine returned\n"
           "code: %p\n"
           "len: %d\n"
           "decrypted_len: %d\n"
           "routine_end: %p\n"
           "loop_start: %p\n",
           out.code, out.len, out.decrypted_len, out.routine_end,
           out.loop_start);
  }

  return 0;
}
