#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "op_tree.h"

#if INTERFACE
struct op_node_t {
  op_t op;
  int pending;
  uint32_t operand;
  op_node_t *left;
  op_node_t *right;
};
#endif

// returns the operand type
static op_t save_operand(op_node_t *cur_op, op_t operand_type, uint32_t v) {
  if (cur_op->pending) {
    operand_type = OPERAND_TARGET;
  }
  cur_op->op = operand_type;
  cur_op->pending = 0;
  cur_op->operand = v;
  return operand_type;
}

// if phase is 0, we're creating the memory load/stores
op_node_t *make_ops_tree(op_node_t *t, mut_routine_size_t junk_mask,
                         int phase) {

  op_node_t *cur_op;
  op_node_t *cur_arg;
  op_node_t *target_loc = NULL; // where we've inserted `x`

  // mask must be 2^n-1
  if (((junk_mask + 1) & junk_mask) != 0) {
    return NULL;
  }

  // init root for when we invert
  t[0] = (op_node_t){.op = OPERAND_TARGET, .pending = 0};
  // current root
  t[1] = (op_node_t){.op = OPERAND_TARGET, .pending = 1};

  int count = 1; // nodes in the tree
  for (cur_op = cur_arg = &t[1]; cur_op <= cur_arg; cur_op++, count++) {
    uint32_t r = rnd();
    uint32_t pick = rnd() & junk_mask;

    // commit an odd argument for MUL
    if (cur_op->op == OP_MUL && !cur_op->pending) {
      if (save_operand(cur_op, OPERAND_IMM, r | 1) == OPERAND_TARGET) {
        target_loc = cur_op;
      }
      continue;
    }

    int pending_mul = (cur_op->op == OP_MUL && cur_op->pending);
    /* bump count by 1 if there's a MUL waiting for a load */
    if (pick < (count + pending_mul)) {
      op_t operand_type = OPERAND_IMM;

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
      int is_right = ((count + pending_mul) % 2) == 1;
      int is_val_zero = (r & 0xff) == 0;
      op_t previous_op = (cur_op - 1)->op;

      if (is_val_zero ||
          (is_right && (previous_op == OPERAND_IMM || pending_mul))) {
        if (phase == 0) {
          operand_type = OPERAND_PTR; // can use ptr
        } else {
          // this serves two purposes:
          // - avoiding the lower byte being 0 (sentinel for reg move)
          // - if it's an argument for mul, ensures it's odd for inv
          r |= 1;
        }
      }
      if (save_operand(cur_op, operand_type, r) == OPERAND_TARGET) {
        target_loc = cur_op;
      }
    } else {
      op_t new_op;

      if (cur_op->pending) {
        new_op = (op_t[]){OP_SUB, OP_ADD, OP_XOR, OP_MUL, OP_ROL, OP_ROR}
            [((uint8_t)r % 12) >> 1];
      } else {
        new_op = (op_t[]){
            OP_SUB, OP_ADD, OP_XOR, OP_MUL, OP_ROL,  OP_ROR,
            OP_SHL, OP_SHR, OP_OR,  OP_AND, OP_IMUL, OP_JNZ}[(uint8_t)r % 12];
      }

      // allocate our two arguments
      cur_op->left = ++cur_arg;
      cur_op->right = ++cur_arg;

      switch (new_op) {
      case OP_SUB:
      case OP_ADD:
      case OP_XOR:
        // flip a coin!
        if (r % 2 == 1) {
          cur_op->right->pending = cur_op->pending;
          break;
        }
        // FALLTHROUGH
      default:
        cur_op->left->pending = cur_op->pending;
        break;
      }

      cur_op->pending = 0;
      cur_op->op = cur_op->left->op = cur_op->right->op = new_op;
    }
  }

  return target_loc;
}

int is_operand(const op_node_t *const n) {
  switch (n->op) {
  case OPERAND_IMM:
  case OPERAND_TARGET:
  case OPERAND_PTR:
    return 1;
  default:
    return 0;
  }
}

// find (don't descend!)
op_node_t *get_parent(op_node_t *const cur, op_node_t *const n) {
  op_node_t *t;

  // done: descended to ourself, or an operand
  if (cur == n || cur->op < 3) {
    return NULL;
  }

  // if n is a child of cur, return
  if (cur->left == n || cur->right == n) {
    return cur;
  }

  // otherwise ascend
  if ((t = get_parent(cur->left, n)) != NULL) {
    return t;
  }
  if ((t = get_parent(cur->right, n)) != NULL) {
    return t;
  }

  return NULL;
}

// given a node with an `x`, invert the dependent ops, and return the new
// root
op_node_t *invert_ops_tree(op_node_t *const root, op_node_t *const n) {
  op_node_t *child;
  op_node_t *cur;
  op_node_t *x_op;
  op_node_t *parent;

  // walk from the current x upward
  for ((x_op = cur = get_parent(root + 1, n)), child = n;
       cur != NULL && cur != &root[0]; child = cur, cur = parent) {

    // if we reach the root, put our `x` back in
    if ((parent = get_parent(root + 1, cur)) == NULL) {
      parent = &root[0]; // use the placeholder at index 0
    }

    switch (cur->op) {
    case OP_MUL:
      cur->right->operand = integer_inverse(cur->right->operand);
      break;
    case OP_SUB:
      if (cur->left == child)
        cur->op = OP_ADD;
      break;
    case OP_ADD:
      cur->op = OP_SUB;
      if (cur->right == child)
        SWAP(cur->left, cur->right);
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

  return x_op;
}

// given x's parent
int adjust_ptr_operand(op_node_t *parent) {
  uint32_t adj;
  int done = 0;

  if (parent->op != OP_ADD && parent->op != OP_SUB) {
    return 0;
  }

  // nb. lower byte zero is a special operand, don't adjust
  adj = (parent->op == OP_ADD) ? 4 : -4;
  if (parent->right->op == OPERAND_IMM) {
    adj += parent->right->operand;
    if ((adj & 0xff) != 0) {
      parent->right->operand = adj;
      done--;
    }
  }
  // XXX immediate operand on the left => sub?
  adj = 4;
  if (parent->left->op == OPERAND_IMM) {
    assert(parent->op == OP_SUB);
    adj += parent->left->operand;
    if ((adj & 0xff) != 0) {
      parent->left->operand = adj;
      done--;
    }
  }

  return done;
}

// vim:set commentstring=//\ %s:
