#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "op_tree.h"

#if INTERFACE
struct op_node_t {
  op_t op;
  int pending;
  uint32_t value;
  op_node_t *left;
  op_node_t *right;
};
#endif

// phase = { -1, 0, 1, unsigned, signed }
op_node_t *make_ops_tree(mut_routine_size_t junk_mask_len, int phase)
{
  assert(((junk_mask_len + 1) & junk_mask_len) == 0);
  op_node_t *t = malloc(sizeof(struct op_node_t) * (junk_mask_len + 2));
  int op_idx;      // head
  int op_next_idx; // current
  int op_free_idx; // next
  int op_end_idx;  // tail

  t[0].op = t[1].op = OP_MOV_REG;
  t[0].pending = 0;
  t[1].pending = 1;

  op_idx = op_next_idx = op_free_idx = 1;

  struct op_node_t *left = &t[op_next_idx];
  struct op_node_t *right = &t[op_next_idx - 1];

  int even = op_next_idx & 1;
  while (op_next_idx >= op_free_idx) {
    // mul needs a reg init
    if (left->op == OP_MUL) {
      left->value = random() | 1;
      left->op = OP_IMM;
    }
    op_next_idx++;
  }
  return t;
}
