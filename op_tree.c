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

    // commit an odd argument for MUL
    if (cur_op->op == OP_MUL && !cur_op->pending) {
      if (save_op_arg(cur_op, OP_VAL_IMM, r | 1) == OP_TARGET) {
        target_loc = cur_op;
      }
      goto done;
    }

    int pending_mul = (cur_op->op == OP_MUL && cur_op->pending);
    /* bump count by 1 if there's a MUL waiting for a load */
    if (pick < (count + pending_mul)) {
      uint32_t val = r;
      op_t val_type = OP_VAL_IMM;

      /**
        ```asm
          ; rewritten slightly for clarity
        @@save_arg:
          mov  al,0         ; immediate value
          shr  bl,1         ; n.b. bx++ if pending mul
          jnb  @@check_arg
            or   cl,cl      ; z => pending mul (or last op mov)
            jz @@try_ptr
          @@check_arg:
            or dl,dl        ; lower byte !0 can be used as-is
            jnz @@save_op_idx
        @@try_ptr:
          or bp,bp          ; creating loop?
          jz @@use_ptr
            or dl,1         ; ... we're not.  oddify.
            jmp @@save_op_idx
          @@use_ptr:
            mov al,2        ; in loop, can use ptr
        @@save_op_idx:
        ```
      */

      // we can use the pointer reg as the argument when we're
      // creating the loop
      int pending_mul = (cur_op->op == OP_MUL && cur_op->pending);
      int is_left = ((count + pending_mul) % 2) == 0;
      int is_arg_zero = (val & 0xff) == 0;
      op_t previous_op = (cur_op - 1)->op;
      if ((is_left && is_arg_zero) ||
          (!is_left && (previous_op == OP_VAL_IMM || pending_mul)) ||
          (!is_left && is_arg_zero)) {
        if (phase == 0) {
          val_type = OP_VAR_PTR;
        } else {
          val |= 1;
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
