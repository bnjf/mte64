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

static op_t save_op_arg(op_node_t *cur_op, op_t val_type, uint32_t val) {
  if (cur_op->pending) {
    val_type = OP_TARGET;
  }
  cur_op->op = val_type;
  cur_op->pending = 0;
  cur_op->value = val;
  return val_type;
}

// phase == 0 or not 0
// returns the node with OP_TARGET
op_node_t *make_ops_tree(op_node_t *t, mut_routine_size_t junk_mask_len,
                         int phase) {
  assert(((junk_mask_len + 1) & junk_mask_len) == 0);

  // init
  t[0] = (op_node_t){.op = OP_TARGET, .pending = 0};
  t[1] = (op_node_t){.op = OP_TARGET, .pending = 1};
  op_node_t *root = &t[1];
  op_node_t *cur_op = &t[1];
  op_node_t *cur_arg = &t[1];
  op_node_t *target_loc = NULL; // where we've inserted `x`

  int count = 1;
  do {
    uint32_t r = random();
    uint32_t pick = random() & junk_mask_len;

    printf("cur_op:%lu cur_arg:%lu\n", cur_op - t, cur_arg - t);

    // hacks for mul {{{
    if (cur_op->op == OP_MUL) {
      printf("val:%x r:%x\n", cur_op->value, r);
      if (!cur_op->pending) {
        r |= 1;
        if (save_op_arg(cur_op, OP_VAL_IMM, r) == OP_TARGET) {
          target_loc = cur_op;
        }
        count++;
        cur_op++;
        continue;
      } else {
        ;
      }
    } // }}}
    if (count > pick) {
      // inserts a value
      uint32_t val = r;
      op_t val_type = OP_VAL_IMM;
      // we can use the pointer reg as the argument when we're
      // creating the loop
      if (((pick % 2) == 1 && (cur_op - 1)->op == 0) ||
          //((pick % 2) == 0 && (r & 0xff) == 0)) {
          ((r & 0xff) == 0)) {
        if (phase == 0) {
          printf("using op_var_ptr pick%%2=%u r=%x\n", pick % 2, r);
          val_type = OP_VAR_PTR;
        } else {
          val |= 1; // dodge 0, it's used to indicate a reg move
        }
      }
      if (save_op_arg(cur_op, val_type, val) == OP_TARGET) {
        target_loc = cur_op;
      }
    } else {
      op_t new_op = (uint8_t)r % 12; // only non-val ops
      if (cur_op->pending) {
        new_op /= 2; // [0,6] => don't create junk
      }
      new_op += 3; // op_sub .. op_jnz

      // allocate our two arguments
      cur_op->left = ++cur_arg;
      cur_op->right = ++cur_arg;

      // flip args
      if (r % 2 == 0 || new_op >= 6) {
        cur_op->left->pending = cur_op->pending;
      } else {
        cur_op->right->pending = cur_op->pending;
      }
      cur_op->pending = 0;
      cur_op->op = cur_op->left->op = cur_op->right->op = new_op;
    }
    cur_op++;
    count++; // XXX
  } while (cur_op <= cur_arg);

  return target_loc;
}

// vim:set commentstring=//\ %s
