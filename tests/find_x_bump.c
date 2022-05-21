#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mut_work16.h"

#include "find_x_bump.h"

static const char *const op_to_str[] = {
    [OPERAND_IMM] = "#", [OPERAND_TARGET] = "x", [OPERAND_PTR] = "%ptr",
    [OP_SUB] = "SUB",    [OP_ADD] = "ADD",       [OP_XOR] = "XOR",
    [OP_MUL] = "MUL",    [OP_ROL] = "ROL",       [OP_ROR] = "ROR",
    [OP_SHL] = "SHL",    [OP_SHR] = "SHR",       [OP_OR] = "OR",
    [OP_AND] = "AND",    [OP_IMUL] = "IMUL",     [OP_JNZ] = "JNZ"};

void print_ops_tree(const op_node_t *t, const int d) {
  const char *const tree_chars =
      "+-------------------------------------------------------------";

  if (is_operand(t)) {
    printf("%.*s %s %x\n", (d + 1) * 2, tree_chars, op_to_str[t->op],
           t->operand);
    return;
  }

  printf("%.*s %s\n", (d + 1) * 2, tree_chars, op_to_str[t->op]);
  print_ops_tree(t->left, d + 1);
  print_ops_tree(t->right, d + 1);
  return;
}

int main(int argc, char *argv[]) {
  uint32_t x = 1;
  op_node_t *t, *t_x, *tinv, *tinv_x;
  const int NUM_TESTS = atoi(argv[1]);
  const int JUNK_NUM = atoi(argv[2]);
  const int JUNK_FLAG = ((1 << JUNK_NUM) - 1);
  const int NODES = 2 + (JUNK_FLAG * 2) - atoi(argv[3]);

  D("%u %u %u %u %lu\n", NUM_TESTS, JUNK_NUM, JUNK_FLAG, NODES,
    NODES * sizeof(op_node_t));
  for (int i = 0; i < NUM_TESTS; i++) {
    rnd_init(x++);

    op_node_t *const t0 = (op_node_t *)calloc(NODES, sizeof(op_node_t));

    t_x = make_ops_tree(t0, JUNK_FLAG, 0);
    tinv_x = invert_ops_tree(t0, t_x);

    // empty
    if (tinv_x == NULL) {
      free(t0);
      continue;
    }
    // printf("%u\t%u,%u\n", tinv_x->op, tinv_x->left->op,
    // tinv_x->right->op);

    if (tinv_x->op == OP_ADD || tinv_x->op == OP_SUB) {
      printf("%s\n",
             adjust_ptr_operand(tinv_x) ? "adjusted" : "not_adjusted");
    } else {
      printf("not_add_or_sub\n");
    }
    free(t0);
  }
  exit(0);
}
