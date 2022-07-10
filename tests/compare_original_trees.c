#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mut_work16.h"

#include "compare_original_trees.h"

int main(int argc, char *argv[]) {
  uint32_t x = 1;
  op_node_t *t, *tinv;
  uint8_t t_x, tinv_x;
  const int NUM_TESTS = 100000;

  mut_work16_t *t_workn, *t_workinvn;
  for (t_workn = t_work, t_workinvn = t_workinv; t_workn < t_work + NUM_TESTS;
       t_workn++, t_workinvn++) {

    printf("\rtest %lu", t_workn - t_work);

    rnd_init(x++);

    op_node_t *const t0 = (op_node_t *)calloc(0x21, sizeof(op_node_t));
    t = t0;
    t_x = make_ops_tree(t, 0xf, 1);
    for (int i = 0; i < 0x21; i++) {
      D("%u == %u?\n", t[i].op, t_workn->ops[i]);
      assert(t[i].op == t_workn->ops[i]);
      if (t_workn->ops[i] < 3) {
        // check operand
        if (!(t[i].operand % 0x10000 == t_workn->ops_args[i])) {
          printf("\nop:%u arg:%u expected_arg:%u\n", t[i].op, t[i].operand,
                 t_workn->ops_args[i]);
        }
        assert(t[i].operand % 0x10000 == t_workn->ops_args[i]);
      } else {
        // check op l/r
        // assert(t[t[i].left].op == t_workn->ops[t_workn->ops_args[i] &
        // 0xff]);
        assert(t[i].left == (t_workn->ops_args[i] & 0xff));
        // assert(t[t[i].right].op == t_workn->ops[(t_workn->ops_args[i] >> 8)
        // & 0xff]);
        assert(t[i].right == ((t_workn->ops_args[i] >> 8) & 0xff));
      }
    }
    // check tinv
    t = t0;
    D("inverting... t_x:%d\n", t_x);
    t_x = invert_ops_tree(t0, t_x);
    D("...inverted! t_x:%d\n", t_x);
    for (int i = 0; i < 0x21; i++) {
      assert(t[i].op == t_workinvn->ops[i]);
      if (t_workinvn->ops[i] < 3) {
        // check operand
        if (!(t[i].operand % 0x10000 == t_workinvn->ops_args[i])) {
          printf("\nop:%u arg:%u expected_arg:%u\n", t[i].op, t[i].operand,
                 t_workinvn->ops_args[i]);
        }
        assert(t[i].operand % 0x10000 == t_workinvn->ops_args[i]);
      } else {
        // check op l/r
        D("inv[%u]: left %u == %u?\n", i, t[i].left,
          (t_workinvn->ops_args[i] & 0xff));
        D("inv[%u]: right %u == %u?\n", i, t[i].right,
          ((t_workinvn->ops_args[i] >> 8) & 0xff));
        assert(t[i].left == (t_workinvn->ops_args[i] & 0xff));
        assert(t[i].right == ((t_workinvn->ops_args[i] >> 8) & 0xff));
      }
    }
    int pto_ret = adjust_ptr_operand(t, t_x);
    assert(pto_ret == 0 || pto_ret == -1);
    free(t0);
  }
  printf("\nok\n");
  exit(0);
}
