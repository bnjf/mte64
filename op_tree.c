#include <assert.h>
#include <stdint.h>
#include <stdio.h>
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
//
// returns the root of the tree
op_node_t *make_ops_tree(mut_routine_size_t junk_mask_len, int phase)
{
  assert(((junk_mask_len + 1) & junk_mask_len) == 0);
  op_node_t *t = malloc(sizeof(struct op_node_t) * (junk_mask_len + 2));

  // init
  t[0] = (op_node_t){.op = OP_TARGET, .pending = 0};
  t[1] = (op_node_t){.op = OP_TARGET, .pending = 1};
  op_node_t *root, *cur, *next,
      *end = NULL; /* right-most leaf, needed for inversion */
  root = cur = next = &t[1];

  int count = 1;
  uint32_t r = random();
  uint32_t pick = random() & junk_mask_len;
  if (count < pick) { assert(0); }
  else {
    // otherwise a value
    uint32_t val = r;
    op_t val_type = OP_VAL_IMM;
    if ((
            // odd?  (table populated)
            (count & 1) ||
            // not an imm val?
            cur->op > 0 ||
            // lower byte zero means a reg move, so skip over it
            ((val & 0xff) || ++val)) &&
        phase == 0) {
      // we can use the pointer reg as the argument when we're
      // creating the loop
      val_type = OP_VAR_PTR;
      if (cur->pending) {
        val_type = OP_TARGET;
        end = cur; // mark end
      }
    }
    cur->op = val_type;
    cur->pending = 0;
    cur->value = r;
  }

  return t;
}
