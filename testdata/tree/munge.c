#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mut_work16.h"

int main(int argc, char *argv[]) {
  const long pagesize = sysconf(_SC_PAGESIZE);
  const int batch =
      (pagesize + sizeof(mut_work16_t) - 1) / sizeof(mut_work16_t);
  const int wsize = batch * sizeof(mut_work16_t);
  char buf[wsize];
  mut_work16_t *w;

  if (argc < 2) {
    exit(1);
  }

  printf("#include <stdint.h>\n"
         "#include \"mut_work16.h\"\n"
         "mut_work16_t %s[] = {\n",
         argv[1]);
  int i, rv;
  for (i = 0; (rv = read(0, &buf, wsize)) > 0;) {
    int c;
    for (c = wsize - rv; c % sizeof(mut_work16_t) != 0; c -= rv) {
      if ((rv = read(0, buf + rv, c % sizeof(mut_work16_t))) == -1) {
        exit(1);
      }
    }
    if (c < 0 || c % sizeof(mut_work16_t) != 0) {
      exit(2);
    }
    int blocks_read = (wsize - c) / sizeof(mut_work16_t);
    for (mut_work16_t *w0 = w = (mut_work16_t *)&buf; w < w0 + blocks_read;
         w++) {
      // printf("// seed: %u (at chunk %lu/%u)\n", i++, w - w0 + 1,
      // blocks_read);
      printf("// seed: %u\n", i++);
      printf("{\n");
      printf("  .op_root_idx = %u, .op_cur_idx = %u, .op_arg_idx= %u, "
             ".op_x_idx=%u,\n",
             w->op_root_idx, w->op_cur_idx, w->op_arg_idx, w->op_x_idx);
      printf("  .ops = { ");
      for (int j = 0; j < 0x21; j++) {
        printf("%u, ", w->ops[j]);
      }
      printf("  },\n");
      printf("  .ops_args = { ");
      for (int j = 0; j < 0x21; j++) {
        printf("%u, ", w->ops_args[j]);
      }
      printf("  },\n");
      printf("},\n");
    }
  }
  printf("};\n");
}
