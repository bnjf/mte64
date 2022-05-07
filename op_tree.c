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

LOCAL const char *const op_to_str[] = {
    // data loads
    [OP_VAL_IMM] = "#",
    [OP_TARGET] = "x",
    [OP_VAR_PTR] = "%ptr",
    // general ops (invertible)
    [OP_SUB] = "SUB",
    [OP_ADD] = "ADD",
    [OP_XOR] = "XOR",
    [OP_MUL] = "MUL",
    [OP_ROL] = "ROL",
    [OP_ROR] = "ROR",
    // junk ops
    [OP_SHL] = "SHL",
    [OP_SHR] = "SHR",
    [OP_OR] = "OR",
    [OP_AND] = "AND",
    [OP_IMUL] = "IMUL",
    // dummy jnz
    [OP_JNZ] = "JNZ"};
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

  // used as the terminal when we invert
  t[0] = (op_node_t){.op = OP_TARGET, .pending = 0};
  // start
  t[1] = (op_node_t){.op = OP_TARGET, .pending = 1};
  // init
  op_node_t *root = &t[1];
  op_node_t *cur_op = &t[1];
  op_node_t *cur_arg = &t[1];
  op_node_t *target_loc = NULL; // where we've inserted `x`

  int count = 1;
  do {
    uint32_t r = random();
    uint32_t pick = random() & junk_mask_len;

    // printf("cur_op:%lu cur_arg:%lu\n", cur_op - t, cur_arg - t);

    int zzz = 0;
    if (cur_op->op == OP_MUL) {
      if (!cur_op->pending) {
        if (save_op_arg(cur_op, 0, r | 1) == OP_TARGET) {
          target_loc = cur_op;
        }
        goto done;
      } else {
        zzz++;
      }
    }
    if (pick < count + zzz) {
      uint32_t val = r;
      op_t val_type = OP_VAL_IMM;
      // we can use the pointer reg as the argument when we're
      // creating the loop
      if (((count % 2) == 1 && (cur_op - 1)->op == OP_VAL_IMM) ||
          ((val & 0xff) == 0)) {
        if (phase == 0) {
          val_type = OP_VAR_PTR;
        } else {
          // val |= 1; // dodge 0, it's used to indicate a reg move
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
  done:
    cur_op++;
    count++; // XXX
  } while (cur_op <= cur_arg);

  return target_loc;
}

// vim:set commentstring=//\ %s
