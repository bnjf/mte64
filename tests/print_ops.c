#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "print_ops.h"

static const char *const op_to_opcode[] = {
    [OPERAND_IMM] = "#", [OPERAND_TARGET] = "x", [OPERAND_PTR] = "%ptr",
    [OP_SUB] = "SUB",    [OP_ADD] = "ADD",       [OP_XOR] = "XOR",
    [OP_MUL] = "MUL",    [OP_ROL] = "ROL",       [OP_ROR] = "ROR",
    [OP_SHL] = "SHL",    [OP_SHR] = "SHR",       [OP_OR] = "OR",
    [OP_AND] = "AND",    [OP_IMUL] = "IMUL",     [OP_JNZ] = "JNZ"};

static const char *const op_to_str[] = {
    [OPERAND_IMM] = "#", [OPERAND_TARGET] = "x", [OPERAND_PTR] = "%ptr",
    [OP_SUB] = "-",      [OP_ADD] = "+",         [OP_XOR] = "^",
    [OP_MUL] = "*",      [OP_ROL] = "<<<",       [OP_ROR] = ">>>",
    [OP_SHL] = "<<",     [OP_SHR] = ">>",        [OP_OR] = "|",
    [OP_AND] = "&",      [OP_IMUL] = "*",        [OP_JNZ] = "JNZ"};

void print_ops_tree_as_expression(const op_node_t *t,
                                  const op_node_t *parent) {
  static int reg = 0;

  if (t == NULL) {
    return;
  }
  if (parent == NULL) {
    reg = 1 - reg;
  }

  switch (t->op) {
  case OPERAND_IMM:
    switch (parent->op) {
    case OP_ROL:
    case OP_ROR:
    case OP_SHL:
    case OP_SHR:
      if (parent->right == t) {
        printf("%u", t->operand & 0x1f);
      } else {
        printf("%u", t->operand);
      }
      return;
    default:
      printf("%u", t->operand & 0xffff);
      return;
    }
  case OPERAND_TARGET:
    // printf("x=%u", t->operand);
    printf("x");
    return;
  case OPERAND_PTR:
    printf("p");
    return;
  default:
    printf("(");
    print_ops_tree_as_expression(t->left, t);
    printf(" %s ", op_to_str[t->op]);
    print_ops_tree_as_expression(t->right, t);
    printf(")");
    return;
  }
}
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

  if (argc < 5) {
    fprintf(stderr, "Usage: %s seed junk phase adjust\n", argv[0]);
    exit(1);
  }

  uint32_t x = 1;
  op_node_t *t, *t_x, *tinv, *tinv_x;
  const int SEED = atoi(argv[1]);
  const int JUNK_NUM = atoi(argv[2]);
  const int JUNK_FLAG = ((1 << JUNK_NUM) - 1);
  const int NODES = 2 + (JUNK_FLAG * 2);
  const int PHASE = atoi(argv[3]);
  const int ADJUST = atoi(argv[4]);

  rnd_init(SEED);

  op_node_t *const t0 = (op_node_t *)calloc(NODES, sizeof(op_node_t));

  t_x = make_ops_tree(t0, JUNK_FLAG, PHASE);

  if (t_x == NULL) {
    exit(0);
  }
  printf("-- enc\n");
  for (t = get_parent(t0 + 1, t_x); get_parent(t0 + 1, t) != NULL;) {
    t = get_parent(t0 + 1, t);
  }
  if (t == NULL) {
    t = t0 + 1;
  }
  print_ops_tree_as_expression(t, NULL);
  printf("\n");

  tinv_x = invert_ops_tree(t0, t_x);
  // empty
  if (tinv_x == NULL) {
    free(t0);
    exit(0);
  }

  if (ADJUST && adjust_ptr_operand(tinv_x)) {
    printf("-- dec (adjusted)\n");
  } else {
    printf("-- dec\n");
  }
  // print_ops_tree_as_expression(t0 + 1, NULL);
  print_ops_tree_as_expression(tinv_x, NULL);
  printf("\n");

  free(t0);
  exit(0);
}
