
#include <stdint.h>

#include "mte64.h"

int main(int argc, char *argv[]) {
  mut_input in;
  mut_output out;

  for (int i = 0; i < 1; i++) {
    in.code = (uint8_t *)"\x90\x90\x90\xc3";
    in.len = 4;

    in.exec_offset = 0;
    in.entry_offset = 0;
    in.payload_offset = 0;

    in.flags = 0x101;

    in.routine_size = 15;

    mut_engine(&in, &out);
  }

  return 0;
}
