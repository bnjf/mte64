
#include <stdint.h>

#include "mte64.h"

int main(int argc, char *argv[]) {
  mut_input in;
  mut_output out;

  for (int i = 0; i < 10000; i++) {
    in.code = "\x90\xc3";
    in.len = 2;
    in.exec_offset = 0;
    in.entry_offset = 0;
    in.payload_offset = 0;
    in.flags = 0;
    in.routine_size = MUT_ROUTINE_SIZE_BIG;

    mut_engine(&in, &out);
  }

  return 0;
}
