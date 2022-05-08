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

#define SWAP(x, y)                                                           \
  do {                                                                       \
    typeof(x) SWAP = x;                                                      \
    x = y;                                                                   \
    y = SWAP;                                                                \
  } while (0)

// returns the node with OP_TARGET
static op_t save_op_arg(op_node_t *cur_op, op_t val_type, uint32_t v) {
  if (cur_op->pending) {
    val_type = OP_TARGET;
  }
  cur_op->op = val_type;
  cur_op->pending = 0;
  cur_op->value = v;
  return val_type;
}

// phase == 0 or not 0
op_node_t *make_ops_tree(op_node_t *t, mut_routine_size_t junk_mask_len,
                         int phase) {

  op_node_t *cur_op;
  op_node_t *cur_arg;
  op_node_t *target_loc = NULL; // where we've inserted `x`

  // mask must be 2^n-1
  if (((junk_mask_len + 1) & junk_mask_len) != 0) {
    return NULL;
  }

  // init
  t[0] = (op_node_t){.op = OP_TARGET, .pending = 0};
  t[1] = (op_node_t){.op = OP_TARGET, .pending = 1};

  int count = 1;
  for (cur_op = cur_arg = &t[1]; cur_op <= cur_arg; cur_op++, count++) {
    uint32_t r = random();
    uint32_t pick = random() & junk_mask_len;

    // commit an odd argument for MUL
    if (cur_op->op == OP_MUL && !cur_op->pending) {
      if (save_op_arg(cur_op, OP_VAL_IMM, r | 1) == OP_TARGET) {
        target_loc = cur_op;
      }
      continue;
    }

    int pending_mul = (cur_op->op == OP_MUL && cur_op->pending);
    /* bump count by 1 if there's a MUL waiting for a load */
    if (pick < (count + pending_mul)) {
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
      int is_right = ((count + pending_mul) % 2) == 1;
      int is_val_zero = (r & 0xff) == 0;
      op_t previous_op = (cur_op - 1)->op;

      if (is_val_zero ||
          (is_right && (previous_op == OP_VAL_IMM || pending_mul))) {
        if (phase == 0) {
          val_type = OP_VAR_PTR; // can use ptr
        } else {
          // this serves two purposes:
          // - avoiding the lower byte being 0 (sentinel for reg move)
          // - if it's an argument for mul, ensures it's odd for inv
          r |= 1;
        }
      }
      if (save_op_arg(cur_op, val_type, r) == OP_TARGET) {
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
  }

  return target_loc;
}

// find
op_node_t *get_parent(op_node_t *const cur, op_node_t *const n) {
  op_node_t *t;
  if (cur->op < 3) {
    return NULL;
  }
  if (cur->left == n || cur->right == n) {
    return cur;
  }
  if ((t = get_parent(cur->left, n)) != NULL) {
    return t;
  }
  if ((t = get_parent(cur->right, n)) != NULL) {
    return t;
  }
  return NULL;
}

// given a node with a OP_TARGET, invert the dependent ops, and return the
// new root
op_node_t *invert_ops_tree(op_node_t *const root, op_node_t *const n) {
  op_node_t *cur = get_parent(root, n);

  if (!cur) {
    return NULL;
  }

  while (cur != &root[0]) {
    op_node_t *parent;
    if ((parent = get_parent(root, cur)) == NULL) {
      parent = &root[0]; // use the placeholder at index 0
    }

    switch (parent->op) {
    case OP_MUL:
      cur->value = integer_inverse(cur->value);
      break;
    case OP_SUB:
      if (parent->right == cur) {
        parent->op = OP_ADD;
      }
      break;
    case OP_ADD:
      parent->op = OP_SUB;
      if (parent->left == cur) {
        SWAP(parent->left, parent->right);
      }
      break;
    case OP_ROL:
      parent->op = OP_ROR;
      break;
    case OP_ROR:
      parent->op = OP_ROL;
      break;
    default:
      break;
    }

    cur = parent;
  }

  return cur;
}

// vim:set commentstring=//\ %s
