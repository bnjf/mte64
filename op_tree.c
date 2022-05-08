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
#ifndef NDEBUG
#define D(...)                                                               \
  do {                                                                       \
    fprintf(stderr, "[%s:%s L%u] ", __FILE__, __func__, __LINE__);           \
    fprintf(stderr, __VA_ARGS__);                                            \
  } while (0)
#endif

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

// find (don't descend!)
op_node_t *get_parent(op_node_t *const cur, op_node_t *const n) {
  op_node_t *t;
  if (cur == n) {
    return NULL;
  }
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

// given a node with an `x`, invert the dependent ops, and return the new root
op_node_t *invert_ops_tree(op_node_t *const root, op_node_t *const n) {
  op_node_t *child;
  op_node_t *cur;
  op_node_t *new_root;
  op_node_t *parent;

  for (
      // new_root is our return value
      (new_root = cur = get_parent(root + 1, n)), child = n;
      // until we find no more parents
      cur != NULL && cur != &root[0];
      // ascend
      child = cur,
                                                  cur = parent) {

    // if we reach the root, put our `x` back in
    if ((parent = get_parent(root + 1, cur)) == NULL) {
      parent = &root[0]; // use the placeholder at index 0
    }

    switch (cur->op) {
    case OP_MUL:
      // mul x,y => mul x*y^{-1}
      cur->right->value = integer_inverse(cur->right->value);
      break;
    case OP_SUB:
      // sub is left associative
      if (cur->left == child) {
        cur->op = OP_ADD;
      }
      break;
    case OP_ADD:
      // add -> sub, but ensure we're on the left
      cur->op = OP_SUB;
      if (cur->right == child) {
        SWAP(cur->left, cur->right);
      }
      break;
    case OP_ROL:
      cur->op = OP_ROR;
      break;
    case OP_ROR:
      cur->op = OP_ROL;
      break;
    default:
      break;
    }

    assert(cur->left == child || cur->right == child);
    if (child == cur->left) {
      cur->left = parent;
    } else if (child == cur->right) {
      cur->right = parent;
    }
  }

  D("new_root=%lu\n", new_root - root);
  return new_root;
}

// vim:set commentstring=//\ %s:
