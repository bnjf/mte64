#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "op_tree.h"

#if INTERFACE
struct op_node_t {
  op_t op;
  unsigned x_path : 1;
  union {
    uint32_t operand;
    struct {
      uint8_t left;
      uint8_t right;
    };
  };
};
#endif

// returns the operand type
static op_t save_operand(op_node_t *t, int i, op_t operand_type, uint32_t v) {
  op_node_t *cur_op = t + i;
  if (cur_op->x_path) {
    operand_type = OPERAND_TARGET;
  }
  cur_op->op = operand_type;
  cur_op->x_path = 0;
  cur_op->operand = v;
  D("t[%u] = (%u,%u)\n", i, operand_type, v);
  return operand_type;
}

// if phase is 0, we're creating the memory load/stores
uint8_t make_ops_tree(op_node_t *t, mut_routine_size_t junk_mask, int phase) {
  int i; // operator
  int j; // operand
  int x; // where we've inserted `x`

  // mask must be 2^n-1
  if (((junk_mask + 1) & junk_mask) != 0) {
    abort();
  }

  // init root for when we invert
  t[0] = (op_node_t){.op = OPERAND_TARGET, .x_path = 0};
  // current root
  t[1] = (op_node_t){.op = OPERAND_TARGET, .x_path = 1};

  for (i = j = x = 1; i <= j; i++) {
    uint32_t r = rnd_get();
    uint32_t pick = rnd_get() & junk_mask;

    D("i:%u j:%u\n", i, j);

    // commit an odd argument for MUL
    if (t[i].op == OP_MUL && !t[i].x_path) {
      if (save_operand(t, i, OPERAND_IMM, r | 1) == OPERAND_TARGET) {
        x = i;
      }
      continue;
    }

    int pending_mul_x = (t[i].op == OP_MUL && t[i].x_path);
    /* bump count by 1 if there's a MUL waiting for a load */
    if (pick < (i + pending_mul_x)) {
      op_t operand_type = OPERAND_IMM;

      /**
{{{ ```asm
      ; rewritten slightly for clarity
    @@save_arg:
      mov  al,0         ; immediate value
      shr  bl,1         ; n.b. bx++ if x_path mul
+--<  jnb  @@check_arg
|       or   cl,cl      ; z => x_path mul (or last op mov)
|+-<    jz @@try_ptr
+|->   @@check_arg:
 |      or dl,dl        ; lower byte !0 can be used as-is
+|-<    jnz @@save_op_idx ; break
|+->@@try_ptr:
|     or bp,bp          ; creating loop?
|+-<  jz @@use_ptr
||      or dl,1         ; ... we're not.  oddify.
+--<    jmp @@save_op_idx ; break
|+->  @@use_ptr:
|       mov al,2        ; in loop, can use ptr
+-->@@save_op_idx:
```
}}}
      */

      // we can use the pointer reg as the argument when we're
      // creating the loop
      int is_right = ((i + pending_mul_x) % 2) == 1;
      int is_val_zero = (r & 0xff) == 0;
      op_t previous_op = t[i - 1].op;

      if (is_val_zero ||
          (is_right && (previous_op == OPERAND_IMM || pending_mul_x))) {
        if (phase != 0) {
          operand_type = OPERAND_PTR; // can use ptr
        } else {
          // this serves two purposes:
          // - avoiding the lower byte being 0 (sentinel for reg move)
          // - if it's an argument for mul, ensures it's odd for inv
          r |= 1;
        }
      }

      // commit
      if (save_operand(t, i, operand_type, r) == OPERAND_TARGET) {
        x = i;
      }
    } else {
      op_t new_op;

#ifdef DEBIAS_OP_PICK
      // 16 = next pow 2
      // while (r > -(16 % 12)) {
      // 256 - (256 % 12) equiv
      while ((r & 0xff) > 252) {
        r = rnd_get();
      }
#endif
      new_op = (op_t[]){
          // invertible
          OP_SUB, OP_ADD, OP_XOR, OP_MUL, OP_ROL, OP_ROR,
          // uninvertible (junk ops used if not on the x path)
          OP_SHL, OP_SHR, OP_OR, OP_AND, OP_IMUL, OP_JNZ //
      }[((uint8_t)r % 12) >> !!t[i].x_path];

      // allocate our two arguments
      set_left(t, i, ++j);
      set_right(t, i, ++j);

      switch (new_op) {
      case OP_SUB:
      case OP_ADD:
      case OP_XOR:
        // flip a coin!
        if (r % 2 == 1) {
          t[t[i].right].x_path = t[i].x_path;
        } else {
          t[t[i].left].x_path = t[i].x_path;
        }
        break;
      default:
        t[t[i].left].x_path = t[i].x_path;
        break;
      }

      D("op = %u\n", new_op);
      t[i].x_path = 0;
      t[i].op = t[t[i].left].op = t[t[i].right].op = new_op;
    }
  }

  return x;
}

int is_operand(const op_node_t *const t, const int i) {
  switch (t[i].op) {
  case OPERAND_IMM:
  case OPERAND_TARGET:
  case OPERAND_PTR:
    return 1;
  default:
    return 0;
  }
}

// find
int get_parent(op_node_t *const t, int const n) {
  int i;

  for (i = 1 /* skip 0, it's the placeholder */; i < n; i++) {
    if (is_operand(t, i)) {
      continue;
    }
    // got an operator
    if (t[i].left == n || t[i].right == n) {
      return i;
    }
  }
  return 0;
}

// given a node with an `x`, invert the dependent ops, and return the new
// root
uint8_t invert_ops_tree(op_node_t *const root, int const n) {
  int i;
  int xi;
  int childi;
  int parenti;

  D("get_parent(root=%p, n=%d) == %d\n", (void *)root, n,
    get_parent(root, n));
  // walk from the current x upward
  for ((xi = i = get_parent(root, n)), childi = n; //
       /*n != 1 ||*/ i != 0;                       //
       childi = i, i = parenti) {

    parenti = get_parent(root, i);
    D("get_parent(root=%p, i=%d) == %d\n", (void *)root, i, parenti);
    // if we reach the root, put our `x` back in
    // if ((parenti = get_parent(root, i)) == 1) {
    //   D("head!\n");
    //   // parenti = -1; // use the placeholder at index 0
    // }

    // assert(0);
    op_node_t *cur = root + i;
    op_t inv_op[] = {[OP_SUB] = OP_ADD,
                     [OP_ADD] = OP_SUB,
                     [OP_ROL] = OP_ROR,
                     [OP_ROR] = OP_ROL,
                     [OP_MUL] = OP_MUL};
    switch (cur->op) {
    case OP_MUL:
      set_right_operand(root, i, integer_inverse(get_right_operand(root, i)));
      break;
    case OP_SUB:
      // if it's on the right we generate SUB+NEG
      if (cur->left == childi)
        cur->op = inv_op[cur->op];
      break;
    case OP_ADD:
      cur->op = inv_op[cur->op];
      if (cur->left != childi)
        SWAP(cur->left, cur->right);
      break;
    case OP_ROL:
    case OP_ROR:
      cur->op = inv_op[cur->op];
      break;
    default:
      break;
    }

    assert(cur->left == childi || cur->right == childi);
    if (childi == cur->left) {
      D("setting cur->left:%d to %d\n", cur->left, parenti);
      cur->left = parenti;
    } else if (childi == cur->right) {
      D("setting cur->right:%d to %d\n", cur->right, parenti);
      cur->right = parenti;
    }
  }

  return xi;
}

int has_right_operand(op_node_t *t, int i) {
  switch (t[t[i].right].op) {
  case OPERAND_IMM:
  case OPERAND_TARGET:
  case OPERAND_PTR:
    return 1;
  default:
    return 0;
  }
}
uint32_t is_right_immediate(op_node_t *t, int i) {
  return t[t[i].right].op == OPERAND_IMM && t[t[i].right].operand;
}
int has_left_operand(op_node_t *t, int i) {
  switch (t[t[i].right].op) {
  case OPERAND_IMM:
  case OPERAND_TARGET:
  case OPERAND_PTR:
    return 1;
  default:
    return 0;
  }
}
int is_left_immediate(op_node_t *t, int i) {
  return t[t[i].left].op == OPERAND_IMM && t[t[i].left].operand;
}
void set_left(op_node_t *t, int i, uint8_t j) { t[i].left = j; }
void set_right(op_node_t *t, int i, uint8_t j) { t[i].right = j; }
void set_left_operand(op_node_t *t, int i, uint32_t operand) {
  t[t[i].left].operand = operand;
}
uint32_t get_left_operand(op_node_t *t, int i) {
  return t[t[i].left].operand;
}
void set_right_operand(op_node_t *t, int i, uint32_t operand) {
  t[t[i].right].operand = operand;
}
uint32_t get_right_operand(op_node_t *t, int i) {
  return t[t[i].right].operand;
}

// given x's parent
int adjust_ptr_operand(op_node_t *t, int parent_idx) {
  uint32_t adj;
  int done = 0;
  op_node_t *parent = t + parent_idx;

  if (parent->op != OP_ADD && parent->op != OP_SUB) {
    return 0;
  }

  // nb. lower byte zero is a special operand, don't adjust
  adj = (parent->op == OP_ADD) ? 4 : -4;
  uint32_t operand;
  if ((operand = is_right_immediate(t, parent_idx)) != 0) {
    adj += operand;
    if ((adj & 0xff) != 0) {
      set_right_operand(t, parent_idx, adj);
      done--;
    }
  }
  // XXX immediate operand on the left implies sub?
  adj = 4;
  if ((operand = is_left_immediate(t, parent_idx)) != 0) {
    assert(parent->op == OP_SUB);
    adj += operand;
    if ((adj & 0xff) != 0) {
      set_left_operand(t, parent_idx, adj);
      done--;
    }
  }

  return done;
}

// vim:set commentstring=//\ %s:
