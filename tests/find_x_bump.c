#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mut_work16.h"

#include "find_x_bump.h"

int main(int argc, char *argv[]) {
  uint32_t x = 1;
  op_node_t *t, *t_x, *tinv, *tinv_x;
  const int NUM_TESTS = 100000;

  for (int i = 0; i < NUM_TESTS; i++) {
    rnd_init(x++);

    op_node_t *const t0 = (op_node_t *)calloc(0x21, sizeof(op_node_t));
    t = t0;
    t_x = make_ops_tree(t, 0xf, 0);
    tinv_x = invert_ops_tree(t0, t_x);
    // empty
    if (tinv_x == NULL)
      continue;
    // printf("%u\t%u,%u\n", tinv_x->op, tinv_x->left->op, tinv_x->right->op);

    if (tinv_x->op == OP_ADD || tinv_x->op == OP_SUB) {
      uint32_t a = tinv_x->left->op;
      uint32_t b = tinv_x->right->op;
      // printf("%u %u %u %u\n", tinv_x->op, a, b,
      // -adjust_ptr_operand(tinv_x));
      printf("%s\n",
             adjust_ptr_operand(tinv_x) ? "adjusted" : "not_adjusted");
    } else {
      printf("not_add_or_sub\n");
    }
    // adjust_ptr_operand(tinv_x);
    // printf("[%u] %u\t%u,%u => %u\t%u,%u\r", i, tinv_x->op, a, b,
    // tinv_x->op, tinv_x->left->operand, tinv_x->right->operand);
    free(t0);
  }
  exit(0);
}
