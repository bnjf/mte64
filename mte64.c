#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

// for dladdr()
//#include <dlfcn.h>

#include "mte64.h"

// public stuff {{{
#if INTERFACE
#define MAX_ADD 512
#define MAX_ADD_LEN 25
// static const int CODE_LEN = 2100; // NOTUSED

// size of the work segment + MAX_ADD_LEN
// 1394-(0x21+0x42+0x42+0x42+0x42+19+16+1+1+1+1+2+7+(512*2))=0
// static const int MAX_LEN = 1394;

enum mut_routine_size_t {
  MUT_ROUTINE_SIZE_TINY = 0x1,
  MUT_ROUTINE_SIZE_SMALL = 0x3,
  MUT_ROUTINE_SIZE_MEDIUM = 0x7,
  MUT_ROUTINE_SIZE_BIG = 0xf
}; // BL
enum mut_flags_t {
  MUT_FLAGS_PRESERVE_AX = 0x001,
  MUT_FLAGS_PRESERVE_CX = 0x002,
  MUT_FLAGS_PRESERVE_DX = 0x004,
  MUT_FLAGS_PRESERVE_BX = 0x008,
  MUT_FLAGS_PRESERVE_SP = 0x010,
  MUT_FLAGS_PRESERVE_BP = 0x020,
  MUT_FLAGS_PRESERVE_SI = 0x040,
  MUT_FLAGS_PRESERVE_DI = 0x080,
  MUT_FLAGS_RUN_ON_DIFFERENT_CPU = 0x100, // NOTUSED
  MUT_FLAGS_CS_IS_NOT_DS = 0x200,         // NOTUSED
  MUT_FLAGS_CS_IS_NOT_SS = 0x400,         // NOTUSED
  MUT_FLAGS_DONT_ALIGN = 0x800,           // paragraph boundary alignment
};

struct mut_input {
  uint8_t *code;            // ds:DX
  unsigned int len;         // CX
  uintptr_t exec_offset;    // BP
  uintptr_t entry_offset;   // DI
  uintptr_t payload_offset; // SI
  mut_flags_t flags;        // AX
  mut_routine_size_t routine_size;
};
struct mut_output {
  uint8_t *code;               // ds:DX
  unsigned int len;            // AX
  uint8_t *routine_end_offset; // DI
  uint8_t *loop_offset;        // SI
};
#endif
// }}}

// macros {{{
#define SWAP(x, y)                                                           \
  do {                                                                       \
    typeof(x) SWAP = x;                                                      \
    x = y;                                                                   \
    y = SWAP;                                                                \
  } while (0)

#define D(...)                                                               \
  do {                                                                       \
    printf("%s:%u %s ", __FILE__, __LINE__, __func__);                       \
    printf(__VA_ARGS__);                                                     \
  } while (0)
// }}}

// enums {{{
#if LOCAL_INTERFACE
enum op_t {
  // loads and stores
  OP_DATA,         // mov ptr_reg,data_reg || mov data_reg,ptr_reg
  OP_START_OR_END, // mov ptr,imm || mov data,ptr
  OP_POINTER,      // mov [ptr],data_reg || mov data_reg,[ptr]
  // invertible ops
  OP_SUB,
  OP_ADD,
  OP_XOR,
  OP_MUL,
  OP_ROL,
  OP_ROR,
  // junk ops
  OP_SHL,
  OP_SHR,
  OP_OR,
  OP_AND,
  OP_IMUL,
  // dummy jump
  OP_JNZ
};
enum opcode_t {
  OPCODE_ADD = 0x03,
  OPCODE_OR = 0x0B,
  OPCODE_AND = 0x23,
  OPCODE_SUB = 0x2B,
  OPCODE_XOR = 0x33,
  OPCODE_MOV_IMM8 = 0xB0,
  OPCODE_MOV_IMM16 = 0xB8,
  OPCODE_MOV_REG_MRM8 = 0x8A,
  OPCODE_MOV_REG_MRM16 = 0x8B
};
enum opcode_f7_t {
  OPCODE_F7_TEST_IMM = 0,
  OPCODE_F7_TEST_IMM_ALT,
  OPCODE_F7_NOT,
  OPCODE_F7_NEG,
  OPCODE_F7_MUL,
  OPCODE_F7_IMUL,
  OPCODE_F7_DIV,
  OPCODE_F7_IDIV
};
enum opcode_80_t {
  OPCODE_80_ADD = 0,
  OPCODE_80_OR,
  OPCODE_80_ADC,
  OPCODE_80_SBB,
  OPCODE_80_AND,
  OPCODE_80_SUB,
  OPCODE_80_XOR
};
enum reg16_t {
  REG_AX = 0,
  REG_CX,
  REG_DX,
  REG_BX,
  REG_SP,
  REG_BP,
  REG_SI,
  REG_DI
};
enum reg8_t {
  REG_AL = 0,
  REG_CL,
  REG_DL,
  REG_BL,
  REG_AH,
  REG_CH,
  REG_DH,
  REG_BH
};
union mrm_t {
  uint8_t byte;
  struct {
    // note to self: bitfields are right to left
    uint8_t reg : 3;
    uint8_t op : 3;
    uint8_t mod : 2;
  };
};
#endif
// }}}

// mappings {{{
LOCAL const uint8_t const opcodes[] = {[OP_ADD] = OPCODE_ADD,
                                       [OP_OR] = OPCODE_OR,
                                       [OP_AND] = OPCODE_AND,
                                       [OP_SUB] = OPCODE_SUB,
                                       [OP_XOR] = OPCODE_XOR};
LOCAL const char const *op_to_str[] = {
    // data loads
    [OP_DATA] = "# =",
    [OP_START_OR_END] = "D =",
    [OP_POINTER] = "P =",
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
LOCAL const char *const reg_names[] = {
    // normal assignments
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    // catch reg ref if we've masked it off
    [0x7f] = "PTR_REG",
    // normal assignments, with pending flag
    [0x80 | REG_AX] = "ax (signed)", [0x80 | REG_CX] = "cx (signed)",
    [0x80 | REG_DX] = "dx (signed)", [0x80 | REG_BX] = "bx (signed)",
    [0x80 | REG_SP] = "sp (signed)", [0x80 | REG_BP] = "bp (signed)",
    [0x80 | REG_SI] = "si (signed)", [0x80 | REG_DI] = "di (signed)",
    // reg ref
    [0xff] = "PTR_REG (signed)"};
// }}}

// scratch struct {{{

// 0x21 -> 0xf ops max
// 0x80 is set on the op if it's the head
//
// [0] load, [0..(2**5 - 1)] ops, [N+1] store
//
// TODO config knob (e.g. 0x11, 0x21, 0x41, 0x81)
LOCAL op_t ops[0x21];

// when addressing this in byte mode recast as such
//   ((uint8_t*)&ops_args)[BX] = AL;
//   to index as byte
//   ((uint8_t*)&ops_args[BX]) = AL;
//   to index as word
LOCAL uint32_t ops_args[0x21];
LOCAL uintptr_t jnz_patch_dec[0x21];
LOCAL uintptr_t jnz_patch_hits[0x21];
LOCAL uintptr_t jnz_patch_enc[0x21];
LOCAL uint8_t op_idx = 1;
LOCAL uint8_t op_free_idx = 1;
LOCAL uint8_t op_next_idx = 1;
LOCAL uint8_t op_end_idx;
LOCAL uint8_t junk_len_mask;
LOCAL uint8_t is_8086 = 0;
LOCAL uint64_t op_off_patch;
LOCAL uint64_t arg_code_entry;
LOCAL uint16_t arg_flags;
LOCAL uint64_t arg_size_neg;
LOCAL uint64_t arg_exec_off;
LOCAL uint64_t arg_start_off;
LOCAL uint8_t reg_set_dec[8]; // 0xff: free, 0: used
LOCAL uint8_t reg_set_enc[8]; // 0xff: free, 0: used
LOCAL uint8_t ptr_reg;
LOCAL uint8_t data_reg;
LOCAL uint8_t last_op; // 0,0x8a,0xf7,0xc1,-1
LOCAL uint8_t last_op_flag;
LOCAL uint32_t patch_dummy; // this is only u8 in the original, and it
                            // overlaps onto the push reserve space
LOCAL uint8_t decrypt_stage_pushes[8];
LOCAL uint8_t decrypt_stage[MAX_ADD];
LOCAL uint8_t encrypt_stage[MAX_ADD];
LOCAL uint8_t target_start[100000]; // XXX this should be caller supplied
// }}}

#define REG_IS_USED 0
#define REG_IS_FREE 0xff

// stuff to help while we keep global state
#define STACK_SIZE 512 // 256 not enough?
LOCAL uint64_t stack[STACK_SIZE], *stackp = stack + STACK_SIZE - 1;
#define STACK_INFO_INIT(x) int x##stackp0 = stackp - stack;
#define STACK_INFO(x)                                                        \
  D("stack now %i (was %i)\n", stackp - stack, x##stackp0);
#define STACK_CHECK(x) assert(x##stackp0 == stackp - stack);
#define STACK_UPDATE(x) x##stackp0 = stackp - stack;
#define PUSH(reg) (assert(stackp > stack), *(--stackp) = (reg))
#define POP(reg) (assert(stackp < stack + STACK_SIZE), (reg) = *(stackp++))

// https://stackoverflow.com/questions/8938347/c-how-do-i-simulate-8086-registers
LOCAL struct {
  // global registers {{{
  union {
    uint64_t rax;
    uint32_t eax;
    uint16_t ax;
    struct {
      uint8_t al;
      uint8_t ah;
    };
  };
  union {
    uint64_t rcx;
    uint32_t ecx;
    uint16_t cx;
    struct {
      uint8_t cl;
      uint8_t ch;
    };
  };
  union {
    uint64_t rdx;
    uint32_t edx;
    uint16_t dx;
    struct {
      uint8_t dl;
      uint8_t dh;
    };
  };
  union {
    uint64_t rbx;
    uint32_t ebx;
    uint16_t bx;
    struct {
      uint8_t bl;
      uint8_t bh;
    };
  };
  union {
    uint64_t rsp;
    uint32_t esp;
    uint16_t sp;
  };
  union {
    uint64_t rbp;
    uint32_t ebp;
    uint16_t bp;
  };
  union {
    uint64_t rsi;
    uint32_t esi;
    uint16_t si;
  };
  union {
    uint64_t rdi;
    uint32_t edi;
    uint16_t di;
  };
  union {
    uint16_t flags;
    uint8_t flags8;
    struct {
      uint8_t c : 1;
      uint8_t : 1;
      uint8_t p : 1;
      uint8_t : 1;
      uint8_t a : 1;
      uint8_t : 1;
      uint8_t z : 1;
      uint8_t s : 1;
      uint8_t t : 1;
      uint8_t i : 1;
      uint8_t d : 1;
      uint8_t o : 1;
    };
  };
  // }}}
} cpu_state;
#define AX (cpu_state.rax)
#define BX (cpu_state.rbx)
#define CX (cpu_state.rcx)
#define DX (cpu_state.rdx)
#define BP (cpu_state.rbp)
#define SP (cpu_state.rsp)
#define SI (cpu_state.rsi)
#define DI (cpu_state.rdi)
#define AL (cpu_state.al)
#define AH (cpu_state.ah)
#define CL (cpu_state.cl)
#define CH (cpu_state.ch)
#define DL (cpu_state.dl)
#define DH (cpu_state.dh)
#define BL (cpu_state.bl)
#define BH (cpu_state.bh)
// }}}

// upper/lower stuff
//#define LOWER(x) ((x)&0xff)
//#define UPPER(x) LOWER(((x) >> 8))
#define GETLO(reg) ((reg)&0xff)
#define GETHI(reg) (GETLO(((reg) >> 8)))
#define SETLO(reg, val) (reg = GETHI(reg) | ((val)&0xff), val)
#define SETHI(reg, val) (reg = (((val)&0xff) << 8) | GETLO(reg), val)
#define CBW16(x) (x##H = (x##L & 0x80) ? 0xff : 0)
#define CBW(x) (((x##X) = (((x##L) & 0x80) ? (~0xff) : 0) | (x##L)), x##H)
#define SIGNBIT(x) ((typeof(x))((x) << 1) < (x))

static void make_ops_table(enum mut_routine_size_t routine_size) {

  // doesn't use the stack
  op_idx = 1;
  op_free_idx = 1;
  op_next_idx = 1;
  DI = (uintptr_t)&op_end_idx;

  ops[0] = OP_START_OR_END;
  ops[1] = OP_START_OR_END | 0x80; // head op, reg init

  do {
    DX = random();
    AX = random();

    SI = BX = op_next_idx;

    CL = ops[SI - 1];
    CH = ops[SI];

    if (CH == OP_MUL) {
      AL = 0;  // reg init
      DL |= 1; // ensure argument is odd for mul inv
      goto save_op_idx;
    } else if (CH == (OP_MUL | 0x80)) {
      CL = 0; // OP_DATA;
      BX++;   // consume an op
    }

    AL = AL & junk_len_mask;
    if (AL < BL) {
      // commit arguments for ops {{{
      D("do register init BX=%x CX=%x\n", BX, CX);

      // check if we're on a boundary
      BL = shr8(BL);
      if (!cpu_state.c)
        goto check_arg;
      cpu_state.z = CL == 0;
      if (cpu_state.z)
        goto last_op;

    check_arg:
      cpu_state.z = DL == 0;

    last_op:
      AL = 0; // reg load/store
      if (!cpu_state.z)
        goto save_op_idx;
      cpu_state.z = BP == 0;
      if (!cpu_state.z) {
        DL |= 1;
        goto check_arg;
      }
      AL = 2; // data load/store

    save_op_idx:
      cpu_state.c = 0;

      // save_op_idx
      if (CH & 0x80) {
        op_end_idx = SI;
        AL = OP_START_OR_END;
      }
      assert(SI < 0x21);
      ops[SI] = AL;
      // }}}
    } else {
      // insert more ops {{{
      cpu_state.c = 0; // from CMP AL,BL @L480

      SWAP(AX, DX);
      // because 12 isn't congruent to the wordsize, there's a very small bias
      // towards 0..3 by 0.002%
      AL = AL % 12;

      CH = CH & 0x80;
      if (CH != 0) {
        AL = shr8(AL);
      }
      AX += 3;
      AH = AL;
      assert(SI < 0x21);
      ops[SI] = AL;
      DL = ++op_free_idx;
      DH = ++op_free_idx;
      BL = DL;
      BH = CL = 0;
      if (!cpu_state.c || AL >= 6) {
        // inserts the new op, moves the current item along
        SWAP(CL, CH);
      }
      AX ^= CX;
      ops[BX] = AL;
      ops[BX + 1] = AH;
      // }}}
    }

    ops_args[SI] = DX; // save arg
    SI <<= 1;          // matching original
    op_next_idx++;
    AL = op_free_idx;
  } while (op_next_idx <= op_free_idx);

  // dump_ops_table();
  // dump_ops_tree(op_end_idx << 1);
  // dump_ops_tree(op_end_idx, 1);
  // dump_ops_tree_as_stack(op_idx);
  printf("\n");

  return;
}

static uint8_t _get_op_arg(int i) {
  assert(i < 0x42);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = ((uint8_t *)(&ops_args))[(i & -2) << 1 | (i & 1)];
  return rv;
}
static uint8_t _set_op_arg(int i, uint8_t arg) {
  assert(i < 0x42);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = _get_op_arg(i);
  ((uint8_t *)(&ops_args))[(i & -2) << 1 | (i & 1)] = arg;
  return rv;
}
static void dump_ops_table() {
  printf("ops table (i=%hu, free=%d, next=%d, end=%d)\n", op_idx, op_free_idx,
         op_next_idx, op_end_idx);
  for (int i = 0; i <= op_free_idx; i++) {
    /*printf("%d\t%-10s (%x)\t%04x\n", i, op_to_str[ops[i] & 0x7f],
     *       ops[i] & 0x7f,
     *       ((ops[i] & 0x7f) < 3 ? ops_args[i] : ops_args[i] & 0xffff));*/
    if (ops[i] >= 3) {
      printf("%d\t%-10s (%x)\t#%u, #%u\n", i, op_to_str[ops[i] & 0x7f],
             ops[i] & 0x7f, _get_op_arg(i * 2), _get_op_arg((i * 2) + 1));
    } else {
      if (ops_args[i]) {
        printf("%d\t%-10s (%x)\t%04x\n", i, op_to_str[ops[i] & 0x7f],
               ops[i] & 0x7f, ops_args[i]);
      } else {
        // XXX shouldn't have arg=0 for op=0 or op=2
        printf("%d\t%-10s (%x)\t%s\n", i,
               (char *[]){"REG = REG XXX", "D = ", "REG = [ptr]XXX"}[ops[i]],
               ops[i], (char *[]){"XXX", "LAST_REG", "[P]"}[ops[i]]);
      }
    }
  }
}
static void dump_ops_tree(int i, int d) {
  assert(i < 0x21);
  assert(d < 8);

  // NB. we can't do the same kind of pointer arith used in the original
  // since the word size is a different width (i.e. SHL/SHR 1 doesn't get a
  // pointer).  let's do it like this...

  if (ops[i] >= 3) {
    printf("%.*s [%u] %s #%u, #%u\n", d * 2, "+-------", i,
           op_to_str[ops[i] & 0x7f], _get_op_arg(i << 1),
           _get_op_arg((i << 1) | 1));
    dump_ops_tree(_get_op_arg(i << 1), d + 1);
    dump_ops_tree(_get_op_arg((i << 1) + 1), d + 1);
    return;
  }

  // if (ops[i] < 3) {
  if (ops_args[i]) {
    printf("%.*s [%u] %s %x\n", d * 2, "+--------", i, op_to_str[ops[i]],
           ops_args[i]);
  } else {
    printf("%.*s [%u] %s\n", d * 2, "+--------", i,
           (char *[]){"REG = REG XXX", "D = LAST_REG",
                      "REG = [ptr]XXX"}[ops[i]]);
  }
  return;
}
static void dump_ops_tree_as_stack(int i) {
  assert(i < 0x21);

  if (ops[i] >= 3) {
    dump_ops_tree_as_stack(_get_op_arg(i << 1));
    dump_ops_tree_as_stack(_get_op_arg((i << 1) + 1));
    printf("%s ", op_to_str[ops[i]]);
    return;
  }

  if (ops[i] < 3) {
    printf("%x %s \n", ops_args[i], op_to_str[ops[i]]);
    return;
  }

  assert(0);
}

/*
 * a generated ops table is a binary tree represented as such
 *
 *  0  MOV_AUX   (1)  0
 *  1  XOR       (5)  2,3
 *  2  SUB       (3)  4,5
 *  3  MOV_DATA  (0)  376c6775
 *  4  MOV_AUX   (1)  1fe116b1
 *  5  MOV_DATA  (0)  104eef97
 *
 * which, as a tree:
 *
 * - MOV_AUX
 * - XOR
 *   ^-- SUB
 *   |   ^-- MOV_AUX
 *   |   `-- MOV_DATA_5
 *   `-- MOV_DATA_3
 *
 * (mov_aux/mov_data/mov_ptr are always terminal nodes)
 *
 * would generate something like:
 *   mov aux,[ptr]
 *   sub aux,data_5
 *   xor aux,data_3
 *   mov [ptr],aux
 *
 */

// returns op index in AX, or sets carry
static void get_op_loc() {
  assert(AL < 0x42); // AL is an index into ops_args
  AX = AL;           // zero extend into ax
  BX = AX;
  AL >>= 1;     // index into ops
  CX = AX << 1; // args to scan (rounded)

  for (int i = 2; i < CX; i++) {
    if (ops[i >> 1] >= 3 && _get_op_arg(i) == AL) {
      cpu_state.c = 0;
      AX = i;
      return;
    }
  }
  cpu_state.c = 1;
  return;
}

static void invert_ops() {
  D("starting at idx=%u\n", op_end_idx);
  AX = op_end_idx << 1;
  get_op_loc();
  if (cpu_state.c) {
    D("not inverting! %x\n", AL);
    return;
  }
  op_idx = AL;
  dump_ops_tree(0, 1);
  dump_ops_tree(1, 1);
  invert_ops_loop();
  dump_ops_table();
  /*dump_ops_tree(6, 1);*/
  /*dump_ops_tree(4, 1);*/
}
static void invert_ops_loop() {
  do {
    get_op_loc();
    if (cpu_state.c) {
      AL = 0;
    }
    PUSH(AX);
    AL >>= 1;
    assert(BX < 0x42);
    _set_op_arg(BX, AL);

    // emulate SHR's flag generation for the LAHF/SAHF
    BX = shr8(BL);
    AH = cpu_state.flags8; // LAHF
    AL = ops[BX] & 0x7f;

    D("inverting %s\n", op_to_str[AL]);
    // sub?
    if (AL == OP_SUB) {
      cpu_state.flags8 = AH;
      if (cpu_state.c) {
        goto done;
      }
      AX++; // OP_SUB -> OP_ADD
      goto store;
    }
    // add?
    else if (AL == OP_ADD) {
      cpu_state.flags8 = AH;
      if (cpu_state.c) {
        // doing upper arg?
        SI = BX;
        uint8_t l = _get_op_arg(BX + SI), r = _get_op_arg(BX + SI + 1);
        _set_op_arg(BX + SI, r);
        _set_op_arg(BX + SI + 1, l);
      }
      AX--; // OP_ADD -> OP_SUB
      goto store;
    } else if (AL < 6) {
      goto done;
    } else if (AL != OP_MUL) {
      D("inverting op @ %x: %s (%x) => %s (%x)\n", BX, op_to_str[AL], AL,
        op_to_str[AL ^ 0xf], AL ^ 0xf);
      assert(AL < 9);
      AL ^= 0xf; // toggle rol/ror
      goto store;
    } else {
      D("inverting op @ %x: %s (%x) arg=%x\n", BX, op_to_str[AL], AL,
        ops_args[BX]);
      assert(BX < 0x21);
      // BX = (ops_args[BX] >> 8) & 0xff;
      BX = _get_op_arg(BX * 2 + 1);
      assert(BX < 0x21);
      SI = ops_args[BX];
      CX = AX = 0;
      ops_args[BX] = DI = DX = 1;
      D("finding inverse of %x\n", SI);
      ops_args[BX] = integer_inverse(SI);
      assert((uint32_t)(ops_args[BX] * SI) == 1);
      SI = DX = 0;
      goto done;
    }
  store:
    ops[BX] = AL;
  done:
    POP(AX);
  } while (AL != 0);

  op_idx >>= 1; // back to byte/word index
  return;
}

// shr imm8, and set flags
static uint8_t shr8(uint8_t x) {
  cpu_state.flags = (cpu_state.flags & 0xf0) | 0x2; // always on
  cpu_state.c = x & 1;
  cpu_state.o = (x & 0x80) == 0x80;
  x >>= 1;
  cpu_state.s = (x & 0x80) == 0x80;
  cpu_state.z = BL == 0;
  cpu_state.p = is_parity_even(x);
  return x;
}

static void try_ptr_advance() {
  CX = 0; // flag if we succeeded
  assert(op_idx < 0x21);
  AX = op_idx;
  SWAP(AX, BX);
  DX = -2;
  AL = ops[BX];

  // looking for OP_SUB or OP_ADD
  if (AL != 3 && AL != 4) {
    return;
  }
  if (AL == 4) {
    DX = -DX;
  }

  // if we've got a
  //   OP_{ADD,SUB} #load, #ptr_store
  //   OP_{ADD,SUB} #ptr_store, #load
  // then we set the load argument to 2 (or -2 depending on the op due to
  // commutativity)
  //
  // ptr_reg_load = 2, n
  // ptr_reg_store = 2, 0
  // (this requires a ptr_reg_store argument to be 0)
  //
  // e.g.
  //
  //   (sub (reg_alloc ptr_reg_store))
  //     ptr_reg = ptr_val; ptr_reg += val; reg -= val
  //   (add (ptr_reg_store reg_alloc))
  //     reg = val;         reg -= ptr_val; ptr += reg
  //   (sub (ptr_reg_store reg_alloc)):
  //     reg = val;         reg += ptr_val; ptr -= reg
  //   (add (reg_alloc ptr_reg_store))
  //     ptr_reg = ptr_val; ptr_reg -= val; reg += val
  BL <<= 1;
  PUSH(BX);
  BX++;
  fix_arg(); // right arg, add 2 or -2 if
  POP(BX);
  DX = 2;
  fix_arg(); // left arg
  // returns CX=0 not found, or CX=-1 or -2 if found and adjusted
  return;
}
static void fix_arg() {
  // BL = ((uint8_t *)&ops_args)[BX];
  assert(BX < 0x42);
  BL = _get_op_arg(BX);

  // only looking for reg init args
  if (ops[BX] != 0) {
    return;
  }

  // found a reg init

  SI = BX;
  DX += ops_args[BX]; // tally the args if we've got a reg init

  if (DL != 0) {
    // is the argument already 2?
    return;
  }

  ops_args[BX] = DX; // seg arg to 2
  CX--;
  return;
}

// checks for any pending register allocations
static uint32_t get_op_args(uint8_t i) {
  BX = 0 + (BL & 0x7f); // clear top
  assert(BX < 0x21);

  DL = ops[BX];
  AX = BX;
  BX = ops_args[BX];
  if (DL < 3) {
    // terminal node
    D("%s %x\n", op_to_str[DL], BX);
    return BX;
  }

  STACK_INFO_INIT(__func__);

  PUSH(AX); // save op_idx

  PUSH(BX);
  get_op_args(BX); // get the left arg
  POP(BX);         // bx=ops_args[i]
  BL = BH;         // go right
  PUSH(DX);        // save left opcode
  get_op_args(BX); // get the right arg
  AX = BX;         // hold index for right arg
  POP(CX);         // cx=left opcode
  POP(BX);         // get the index
  assert(BX < 0x21);
  DH = ops[BX]; // current op = ops[op_idx]
  assert(DH == ops[i]);

  // DH = current op, DL = previous op
  // imul/mul?
  if ((DH -= 0xd) == 0 || (DH += 7) == 0) {
    last_op_flag = 0;
    reg_set_dec[REG_DX] = 0;
    D("reserved DX\n");
  }
  //
  else if (DH < 5) {
    // no junk ops (11, 12, 13, 14)
    // DH range is [6,10]: mul, rol, ror, shl, shr
    if (DL != 0 // need cx for op on reg
        || (is_8086 != 0 &&
            ((AL = ((AL - 0xe) & 0xf) >= 5 // op [3,13]?
                   || (AL >= 2 && DH >= 3) // op jnz with a pointer reg used
              )))) {
      // >>> [(x,(x+0xd-7-0xe)&0xf) for x in range(15)]
      //  [(0, 8), (1, 9), (2, 10), (3, 11), (4, 12), (5, 13), (6, 14), (7,
      //  15), (8, 0), (9, 1), (10, 2), (11, 3), (12, 4), (13, 5), (14, 6)]

      D("reserved CX\n");
      reg_set_dec[REG_CX] = BH; // mark cx used
      DL = 0x80;                // pending cx
    }
  }
  // done, mark op as reg required
  assert(BX < 0x21);
  ops[BX] = DL = ((CL | DL) & 0x80) | ops[BX];

  STACK_INFO(__func__);
  STACK_CHECK(__func__);

  return 0;
}

static int generating_enc() {
  int rv = (DI >= (uintptr_t)encrypt_stage &&
            DI < ((uintptr_t)encrypt_stage) + MAX_ADD);
  assert(rv != ((DI >= (uintptr_t)decrypt_stage_pushes &&
                 DI < ((uintptr_t)decrypt_stage_pushes) + 8) ||
                (DI >= (uintptr_t)decrypt_stage &&
                 DI < ((uintptr_t)decrypt_stage) + MAX_ADD)));
  return rv;
}
static int generating_dec() {
  int rv = (DI >= (uintptr_t)decrypt_stage_pushes &&
            DI < ((uintptr_t)decrypt_stage_pushes) + 8) ||
           (DI >= (uintptr_t)decrypt_stage &&
            DI < ((uintptr_t)decrypt_stage) + MAX_ADD);
  assert(rv != ((DI >= (uintptr_t)encrypt_stage &&
                 DI < ((uintptr_t)encrypt_stage) + MAX_ADD)));
  return rv;
}

// emits an op and a REG,REG MRM
// if the op is 0xF7, src is:
//   0,1  TEST r/m,imm8/16
//   2    NOT  r/m
//   3    NEG  r/m
//   4    MUL  r/m
//   5    IMUL r/m
//   6    DIV  r/m (not generated)
//   7    IDIV r/m (not generated)

// emits for byte/word/dword {{{
static uint8_t emitb(uint8_t x) {
  /*Dl_info info;                         */
  /*if (!dladdr((uintptr_t *)DI, &info)) {*/
  /*  abort();                            */
  /*}                                     */
  char where[32] = {"*DI"};

  if (DI >= (uintptr_t)encrypt_stage &&
      DI <= (uintptr_t)encrypt_stage + MAX_ADD) {
    sprintf(where, "enc[%u]", DI - (uintptr_t)encrypt_stage);
  } else if (DI >= (uintptr_t)decrypt_stage &&
             DI <= (uintptr_t)decrypt_stage + MAX_ADD) {
    sprintf(where, "dec[%u]", DI - (uintptr_t)decrypt_stage);
  }
  D("%s = %x\n", where, x);
  *((uint8_t *)cpu_state.rdi) = x;
  cpu_state.rdi++;
  return x;
}
static uint16_t emitw(uint16_t x) {
  D("%x\n", x);
  *((uint16_t *)cpu_state.rdi) = x;
  cpu_state.rdi += 2;
  return x;
}
static uint32_t emitd(uint32_t x) {
  D("%x\n", x);
  *((uint32_t *)cpu_state.rdi) = x;
  cpu_state.rdi += 4;
  return x;
}
// }}}

static void emit_mov_data() {
  AL = data_reg;
  // printf("emit_mov_data: AX=%x DX=%x\n", AX, DX);
  return emit_mov();
}
// lower byte of val == 0 then encode mov reg,reg instead
static void emit_mov() {
  // AX = AL;
  CBW(A);
  PUSH(AX);

  // XXX AL=DH, move from ops_args?
  assert(AH != 0xff);
  D("# ptr_reg=%s/%x data_reg=%s/%x\n", reg_names[ptr_reg], ptr_reg,
    reg_names[data_reg], data_reg);
  if (AL == DH) {
    D("XXX ptr_reg = %x (%x)\n", ops_args[_get_op_arg((DL >> 2) | (DL & 1))],
      DX);
    dump_all_regs();
    // XXX hackhackhack
    DX = ops_args[_get_op_arg((DL >> 2) | (DL & 1))];
    AL = ptr_reg;
    // abort(); // we're missing a dl<>dh somewhere
  } else if (DL != 0) {
    D("P = %x (%x)\n", DX, AL);
  } else {
    D("register %s = %s\n", reg_names[AL], reg_names[DH]);
  }

  if (generating_dec()) {
    BX = AX;
    reg_set_dec[BL] = BH;
  }

  if (DL == 0) {
    BL = 0x8b;
    cpu_state.c = 0;
    encode_mrm_dh_s();
    if (!cpu_state.c) {
      POP(AX);
      return;
    }
    assert(BP == DI + 1);
    // otherwise we get DX=BP, BP=DI+1
    // ... and AL=BX?
    // ... and BX<=>AX
  }
  assert(AL < 8);
  D("mov %s,%x\n", reg_names[AL], DX);
  AL = 0xb8 | AL;
  emitb(AL);
  SWAP(AX, DX);
  emitd(AX);
  POP(AX);
  return;
}

static void encode_mrm_dh_s() {
  if (SIGNBIT(DH)) {
    // DH = -1: load ptr_reg into DH
    // and then
    // BP = -1: do op=BL ptr_reg,reg
    // BP =  0: do op=BL [ptr_reg],reg
    // BP != 0: DX=BP, BP=DI+1, C=1
    return encode_mrm_ptr();
  }
  return emit_op_mrm();
}

// https://arxiv.org/pdf/2204.04342.pdf
uint32_t integer_inverse(uint32_t a) {
  assert(a % 2 == 1);
  uint32_t x0 = (3 * a) ^ 2; // See section 5, formula 3.
  uint32_t y = 1 - a * x0;
  uint32_t x1 = x0 * (1 + y);
  y *= y;
  uint32_t x2 = x1 * (1 + y);
  y *= y;
  uint32_t x3 = x2 * (1 + y);
  // only need 3 reps for u32:
  // https://lemire.me/blog/2017/09/18/computing-the-inverse-of-odd-integers/
  return x3;
  y *= y;
  uint32_t x4 = x3 * (1 + y);
  return x4;
}

//__attribute__((optimize("omit-frame-pointer")))
static void exec_enc_stage() {
  PUSH(DI);

  PUSH(AX);
  CX = 0;

  // TODO config trap handler

  BX = (uintptr_t)&encrypt_stage;
  int pagesize = sysconf(_SC_PAGE_SIZE);
  assert(pagesize != -1);
  assert(pagesize > (MAX_ADD * 2));
  uintptr_t page = (uintptr_t)encrypt_stage / pagesize;

  if (mprotect((uintptr_t *)(page * pagesize), (MAX_ADD * 2),
               PROT_READ | PROT_EXEC) == -1) {
    fprintf(stderr, "mprotect() failed: %s\n", strerror(errno));
    abort();
  }

  // hmm.  there's fastcall, but that's for cx,dx as an arg.
  // uint64_t (*encrypt_stage_f)(uint64_t)
  //__attribute__((no_caller_saved_registers, fastcall))
  //__attribute__((fastcall))
  //   = (uint64_t(*)(uint64_t))encrypt_stage;
  // AX = encrypt_stage_f(BP);
  //
  // ah.  "You can't make the compiler pass a function arg in EAX/RAX in
  // 64-bit mode."
  //
  // the calling convention for x86-64 is di,si,dx,cx,r8,r9

  // bp is used unless we've got omit-frame-pointer when compiling, and
  // can't be listed in clobbers.  hack around a bit and do our own saves.
  printf("%s:%u %s ax=%llx bp=%llx\n", __FILE__, __LINE__, __func__, AX, BP);
  asm("push %%rbp\n\t"
      "movq %0,%%rax\n\t"
      "movq %1,%%rbp\n\t"
      "call encrypt_stage\n\t"
      "movq %%rbp,%1\n\t"
      "movq %%rax,%0\n\t"
      "pop %%rbp"
      : "+%rax"(AX), "+r"(BP)                                // out
      : "%rax"(AX), "r"(BP)                                  // in
      : "%rax", "%rcx", "%rdx", "%rbx", "%rsi", "%rdi", "cc" // clobbers
  );
  printf("%s:%u %s ax=%llx bp=%llx\n", __FILE__, __LINE__, __func__, AX, BP);

  // reset perms
  if (mprotect((uintptr_t *)(page * pagesize), MAX_ADD * 2,
               PROT_READ | PROT_WRITE) == -1) {
    fprintf(stderr, "mprotect() failed: %s\n", strerror(errno));
    abort();
  }

  BP = AX; // returned val

  // TODO deconfig trap handler

  POP(BX);

  DI = (uintptr_t)jnz_patch_dec;
  SI = 0;
  CX = 0x21;
  do {
    AX = 0;
    // REPZ SCASW
    cpu_state.z = 1;
    while (CX--) {
      if (*((uint16_t *)(DI += (sizeof(jnz_patch_dec[0])))) != AX) {
        cpu_state.z = 0;
        break;
      }
    }
    if (cpu_state.z) {
      // emit_ops::@@done
      POP(DX);
      return;
    }
    D("found jnz @ %x (%p) si=%x\n",
      DI - (sizeof(jnz_patch_dec[0])) - (uintptr_t)&jnz_patch_dec,
      jnz_patch_dec[0x21 - CX], SI);
    assert((((uint8_t *)(jnz_patch_dec[0x21 - CX]))[-1]) == 0x75);
    // TODO junk loops
    assert(SI == 0);
    if ((AX = jnz_patch_dec[0x21 - CX]) > 0) {
      DX = 1;
      SI = AX;
      AX = jnz_patch_hits[0x21 - CX];
      assert(BX == 1);
      // if it's always taken, nuke the jnz loc
      // if it's never taken, nuke the stuff between here and the dest
      if (AX == BX || ((AL = *(uint8_t *)(SI++)), CBW(A), (DX = AX))) {
        // BX == 1 here?
        while (DX) {
          D("trashing dx=%lx bytes\n", DX);
          AX = random();
#ifdef OP_JNZ_JUNK
          *(uint8_t *)(SI++) = AL;
#else
          SI++;
#endif
          DX--;
        }
      }
    }
  } while (1);

  POP(DX);
  return;
}

static uint32_t get_arg_size() { return -arg_size_neg; }

static void make_enc_and_dec() {
  CX += MAX_ADD_LEN - 5; // MAX_ADD_LEN - JMP NEAR (was 3)
  CX = -CX;
  CL &= 0xfe;
  if (CL == 0) {
    CX -= 2;
  }
  SWAP(AX, DI);
  arg_code_entry = AX;
  AX += CX;
  AL &= 0xfe;
  if (AL == 0) {
    AX -= 2;
  }
  PUSH(AX);
  SWAP(AX, DI);
  DI = (uintptr_t)&arg_flags;
  arg_flags = AX;
  SWAP(AX, CX);
  arg_size_neg = AX;
  SWAP(AX, BP);
  arg_exec_off = AX;
  SWAP(AX, SI);
  arg_start_off = SI;

  is_8086 = 0; // 0x20 if shift masking didn't occur

  DI = (uintptr_t)&reg_set_dec;

  // XXX moved this out of restart
  srandom(1);

  return restart();
}

// LOCAL long seed = 1;
static void restart() {
  STACK_INFO_INIT(__func__);
  POP(BP);
  PUSH(BP);
  PUSH(BX);

  // srandom(time(NULL));
  // AX = random(); // dunno if upper bits are used

  AL = -1;
  CX = 8;
  DI = (uintptr_t)&reg_set_dec;
  while (CX--) {
    emitb(AL);
  }

  DI = (uintptr_t)&decrypt_stage;
  BL = 7;
  STACK_INFO(__func__);
  make();
  STACK_INFO(__func__);
  assert((*(uint8_t *)DI) == 0xc3);
  DI -= 1;
  if (DI != (uintptr_t)&decrypt_stage) {
    // printf("decrypt_stage len currently %p,%p\n", &decrypt_stage, DI);
    printf("decrypt_stage len currently %p\n",
           DI - (uintptr_t)&decrypt_stage);
    PUSH(DX);
    PUSH(DI);

    PUSH(BP); // XXX this should be the offset?!
    AX = 1;
    exec_enc_stage();
    POP(DI);
    SWAP(AX, BP);

    emitd(AX);

    POP(DI);
    POP(DX);
  }
  // make_enc_and_dec::@@nothing_emitted
  POP(BX);
  POP(AX);
  BP = 0;

  STACK_INFO(__func__);
  // STACK_CHECK(__func__);

  return make();
}

static void make() {
  STACK_INFO_INIT(__func__);

  PUSH(AX); // -1 on first call (from the L188 al=-1)
  PUSH(BX);
  PUSH(DX);
  PUSH(DI);

  AX = 0;
  for (int i = 0; i < 0x21; i++) {
    jnz_patch_dec[i] = 0;
    jnz_patch_hits[i] = 0;
    jnz_patch_enc[i] = 0;
  }
  CX = 0;
  AX = 4;
  DI = (uintptr_t)&op_idx;

  PUSH(arg_flags);
  SETHI(arg_flags, MUT_FLAGS_CS_IS_NOT_SS >> 8);

  DX = arg_size_neg;
  DI = (uintptr_t)&encrypt_stage;

  PUSH(BP);
  g_code();
  POP(BP);

  invert_ops();

  POP(AX); // old flags

  POP(DI);
  POP(DX);

  SETHI(arg_flags, AL);
  AL &= 1;
  is_8086 -= AL; // -> 0xff or 0x1f
  PUSH(AX);

  g_code_from_ops();

  POP(AX);
  is_8086 += AL; // restore

  AX = BX;
  POP(BX);
  D("ax0=%llx sign=%u ", AX, SIGNBIT(AH));
  AX = ((-SIGNBIT(AH)) & ~0xffff) | AX; // sign extend
  AX -= (uintptr_t)&patch_dummy;
  printf("ax1=%llx patch_dummy=%p\n", AX, &patch_dummy);

  STACK_INFO(__func__);

  if (AX < (uintptr_t)&patch_dummy) {
    // value on stack is make's initial AX, restart() pops it as BP
    // so the phases go something like
    // on restart entry
    // bp = previous phase, ax = current phase
    // phases: value to store -> -1 -> 0
    STACK_INFO(__func__);
    // stack should have an extra item XXX
    return restart();
  }
  if (AX == 0 && arg_start_off != 0) {
    assert(0);
    // value on stack is make's initial AX
    return restart();
  }

  POP(BX);

  STACK_INFO(__func__);
  STACK_CHECK(__func__);
  return;
}

static void g_code() {
  junk_len_mask = BL;
  return g_code_no_mask();
}
static void g_code_no_mask() {
  PUSH(DX);
  PUSH(DI);
  make_ops_table(BX);
  POP(DI);
  POP(DX);
  return g_code_from_ops();
}
static void g_code_from_ops() {
  assert(generating_enc() || generating_dec());
  STACK_INFO_INIT(__func__);
  D("bp=%x\n", BP);
  PUSH(DI);

  // init register tracking for enc {{{
  DI = (uintptr_t)reg_set_enc;
  AX = -1;
  // ax cx dx bx sp bp si di
  // ff ff 00 ff 00 ff ff ff
  emitw(AX);
  AL += 1;
  emitw(AX);
  emitw(AX);
  AL -= 1;
  emitw(AX);
  assert(*(uint64_t *)reg_set_enc == 0xffffff00ff00ffffULL);
  // }}}

  DI = (uintptr_t)ptr_reg;

  last_op_flag = -1; // AL
  BL = op_idx;

  assert(op_idx <= 0x21);

  PUSH(BX);
  PUSH(DX);
  // set DX to the initializer, AX=ops index, BX=ops_args index

  // check for any pending register allocs
  get_op_args(BL);
  SI = DI;
  // picks ptr and data reg, sets BH=FF BL=AL=data_reg
  ptr_and_r_sto();
  POP(DX);
  POP(BX);

  POP(DI);

  PUSH(BX);
  // if (!(BP == -1 || BP == 0)) {
  if (BP == -1 || BP == 0) {
    // {{{
    DX++;
    if (DX != 0) {
      // init pointer reg
      DX--;
      BP--; // BP is 1 here?
      AL = ptr_reg;
      emit_mov();
      BP++;
    }
    POP(BX);
    PUSH(DI);
    // stack ok
    emit_ops();
    if (BP == 0) {
      // @@making_junk {{{
      POP(CX);
      BP--;

      D("patch points: %p, %p\n", op_off_patch, &patch_dummy);
      AX = op_off_patch;
      op_off_patch = (uintptr_t)&patch_dummy;

      if ((DH & 0x80) == 0) {
        BP++;
        PUSH(CX);
        PUSH(AX); // offset to patch
        AL = last_op_flag;
        D("al=%x bp=%x\n", AL, BP);
        if ((AL & 0b10110111) == 0b10000111 && BP == arg_start_off) {
          // flip direction
          D("flipping %x to %x\n", *((uint8_t *)DI - 6) ^ 2,
            *((uint8_t *)DI - 6));
          *((uint8_t *)DI - 6) ^= 2; // 4 in the original, but we have off32
          assert(0);
          last_op_flag <<= 1;
          if (last_op_flag & 0x80) {
            // add -> sub/neg
            BL = 0xf7;
            AL = 3; // OPCODE_F7_NEG
            STACK_CHECK(__func__);
            return emit_eol_bl();
          }
          STACK_CHECK(__func__);
          return single_ref();
        } else {
          // @@do_end_of_loop
          // emit the store, doesn't matter if we MOV or XCHG
          AX = random();
          AL = 0x87 + (AL & 2);
          SWAP(AX, BX);
          AL = DH;
          STACK_INFO(__func__);
          return emit_eol_bl();
        }
      } else {
        // null?
        if (CX == (uintptr_t)&decrypt_stage[5]) {
          CX -= 5;
          DI -= 5;
          reg_set_dec[ptr_reg]--;
          BX = (uintptr_t)&patch_dummy;
          STACK_INFO(__func__);
          return size_ok();
        }
      }
      // }}}
    } else {
      // @@not_dec_end
      if (DH & 0x80) {
        DH = ptr_reg;
      }
      POP(AX);
      *((uint8_t *)DI) = 0xc3;
      STACK_INFO(__func__);
      return;
    }
    // }}}
  } else {
    // @@do_intro_garbage {{{
    PUSH(BP);
    emit_ops(); // gives us an initial value for the pointer
    AL = 0x90 | data_reg;
    emitb(AL);
    POP(AX);
    if (DH & 0x80) {
      DX = AX;
    }
    POP(AX);
    BH = 0xff;
    encode_retf();
    // seems ok
    STACK_INFO(__func__);
    STACK_CHECK(__func__);
    dump_ops_table();
    D("returning ax=%x bx=%x dx=%x (op_idx=%u) (op_arg=%x)\n", AX, BX, DX,
      op_idx, ops_args[ops_args[op_idx] & 0xff]);
    dump_all_regs();
    assert(AX == op_idx);
    assert(
        BH == 0xff &&
        // bl could also be the opcode
        (BL == op_idx | BL == 0xf7 | BL == 0x81 | BL == 0xc1 | BL == 0xd3));
    assert(
        // pointer init
        (SIGNBIT(DH) && DX == arg_size_neg) ||
        // imm init
        DX == ops_args[ops_args[op_idx] & 0xff] ||
        // mul
        (BL == 0xf7 && DX == 0x2ba) ||
        // 81 ops
        (BL == 0x81 && (DL & 0xc0) == 0xc0) ||
        // rotates/shifts
        ((BL == 0xc1 || BL == 0xd3) && DL == 0));
    return;
    // }}}
  }
}

static void bl_op_reg_mrm() {
  AL |= 0b00011000;
  SWAP(AX, BX);
  return encode_op_mrm();
}
static void encode_op_mrm() {
  emitb(AL);
  SWAP(AX, BX);
  CL = 3;
  AL <<= CL;
  AL |= DH;
  emitb(AL);
  cpu_state.c = 0;
  // CL=3
  // AL=0xc0 | (AL << 3) | DH
  return;
}

static void encode_mrm() {
  if ((DH & 0x80) == 0) {
    return bl_op_reg_mrm();
  }
  return encode_mrm_ptr();
}
static void encode_mrm_ptr() {
  DH = ptr_reg;
  // D("reg=%x op=%x val=%x (bp=%x)\n", DH, BL, DX, BP);
  cpu_state.c = 0;
  if (BP == -1) {
    return bl_op_reg_mrm();
  } else if (BP != 0) {
    // D("staging memory load\n");
    DX = BP;
    BP = DI + 1;
    cpu_state.c = 1;
    return;
  }

  assert(BP == 0);

  PUSH(BX);
  SWAP(AL, DH);
  assert(AL == ptr_reg);

  // xlat the mrm byte!
  // AL = ((uint8_t[]) { 0x87, 0, 0x86, 0x84, 0x85 })[BX - 3 + AL];
  // mrm byte is a little more sane in 32/64 mode
  dump_all_regs();
  assert(AL == REG_BX || AL == REG_BP || AL == REG_SI || AL == REG_DI);
  AL |= 0x80; // reg+off32
  SWAP(AL, DH);
  SWAP(AX, BX);
  CL = 0x2e; // cs:
  // XXX skip the rest

  // @@no_override
  POP(AX);

  // in: al=op, bl=reg, dh=rm
  // out: di=di+1, bx<=>ax, cl=3, al=mrm
  encode_op_mrm();

  op_off_patch = DI;
  D("saved patch point %p\n", op_off_patch);
  emitd(AX);
  return;
}
static void emit_eol_bl() {
  STACK_INFO_INIT(__func__);
  STACK_INFO(__func__);
  encode_mrm_ptr();
  STACK_INFO(__func__);
  STACK_CHECK(__func__);
  D("bx=%llx generating_enc=%d generating_dec=%d\n", BX, generating_enc(),
    generating_dec());
  D("stack[.]=%llx stack[.-1]=%llx\n", *stackp, *(stackp - 1));
  return single_ref();
}
static void single_ref() {

  AL = ptr_reg;

  if (generating_dec()) {
    // doing post crypt ops [ops][inverse ops] {{{
    //
    // if we add/sub on the ptr_reg adjust the op_args by 2
    // XXX this should be by 4
    PUSH(AX);

    BP--;
    DL = 0;
    DH = AL;

    // generate ogenerate ops, then
    junk_len_mask >>= 1;
    g_code_no_mask();
    PUSH(DX);
    PUSH(DI);
    invert_ops();
    try_ptr_advance();
    dump_ops_tree(1, 1);
    POP(DI);
    POP(DX);
    PUSH(CX);

    // vvv
    g_code_from_ops();
    // ^^^

    POP(CX);
    POP(AX);
    emit_mov();
    // }}}
    if ((CH & 0x80) == 0) {
      // we did sub/add arith on the ptr reg, and we adjusted it by 2
      goto emit_jnz;
    }
  }

  // emit inc {{{
  // 0x40->0x47 are REX prefixes now.  we can either encode:
  //   0x48 0xFF (0xC0 | reg)
  //   0x48 0xFF (0xC0 | reg)
  // or just go straight for an add +2?
  AL |= 0x40;
  for (int i = 4; i; i--) {
    emitb(0x48);
    emitb(0xff);
    emitb(0xc0 | AL);
  }
  // }}}
emit_jnz:
  // emit the jnz to the start of the loop
  AL = 0x75;
  emitb(AL);
  POP(BX);          // patch
  POP(AX);          // cx=start of loop
  CX = AX;          // cx=start of loop
  AX = AX - DI - 1; // ax=rel8 (1 ahead because we already STOSB)
  emitb(AL);
  D("bx=%x cx=%x\n", BX, AX);

  // loop start is > 126 bytes, can't encode a backward jump
  // TODO encode JNZ NEAR instead: 0F 85 rel32
  if ((AL & 0x80) == 0) {
    BX = 0;
    return;
  }
  return size_ok();
}

static void size_ok() {
  encode_retf();
  PUSH(CX);
  DX = (uintptr_t)&target_start;
  if (generating_enc()) {
    D("generating enc, patching offsets (bx=%llx)\n", BX);
    return patch_offsets();
  }
  PUSH(BX);

  BL = 7;
  DX = BP;
  g_code();

  PUSH(DI);
  DI = ((uintptr_t)&decrypt_stage) - 1; // decrypt_stage_pushes
  assert(DI == (uintptr_t)&decrypt_stage_pushes[7]);
  BX = 0;
  DX = DI;
  CL = arg_flags;
  do {
    CL = shr8(CL);
    if (cpu_state.c && reg_set_dec[BL] == BH) {
      AX = BX + 0x50; // PUSH
      *((uint8_t *)DI--) = AL;
    }
    BX++;
  } while (CL);

  /*if (DI == ((uintptr_t)&decrypt_stage) - 1) {*/
  /*  DI = (uintptr_t)&decrypt_stage;           */
  /*} else {                                    */
  /*  DI++;                                     */
  /*}                                           */
  DI++;

  if (DI < DX) {
    // @@randomize_pushes
    assert(0);
  }
  // @@pushes_done
  POP(BP);
  printf("[%s] %x\n", __func__, BP);

  CX = BP - DI;
  if (arg_code_entry != 0) {
    // 5 bytes for jump
    CX += (uintptr_t)&decrypt_stage + 5 - DI;
  }
  DX = arg_exec_off;
  AX = DX;
  DX += CX;
  AX += arg_start_off;

  POP(BX);
  if (arg_start_off == 0) {
    DX = AX;
  }
  return patch_offsets();
}

static void patch_offsets() {
  // printf("patch_offsets(): BX=%llx\n", cpu_state.rbx);
  D("patching %p and %p\n", BX, op_off_patch);
  AX = DX;
  patch();
  AX = DX;
  POP(DX);
  BX = op_off_patch;
  patch();
}

static void patch() {
  AX = AX - arg_size_neg;
  if (BX == 0) {
    // in the original this would've just zapped the first two ops
    D("got null patch point?! bx=%x ax=%x\n", BX, AX);
    assert(0);
    return;
  }
  *((uint32_t *)BX) = AX;
}

static void encode_retf() {
  // actually retn
  *((uint8_t *)DI) = 0xc3;
}

static void mark_reg_used() {
  SWAP(AX, BX);
  assert(BX < 8);
  reg_set_enc[BX]++;
  DH = AL;
  return store_data_reg();
}

static void emit_ops() {
  // take BL as the head
  last_op = 0xff;      // no last op
  last_op_flag = 0x80; // last_op_flag 0x80 end, 0x40 sub, &0b111 (reg)
  BX = BL;             // BH = 0;
  assert(BX < 0x21);
  AL = ops[BX];
  AX &= 0x7f;
  BL <<= 1; // unmask the op_idx and prepare to index ops_args

  D("got ax=%x bx=%x\n", AX, BX);
  if (AL < 3) {
    D("got init: %s (%x)\n", op_to_str[AL], ops_args[BX >> 1]);
  } else {
    D("got op: %s #%u, #%u\n", op_to_str[AL], _get_op_arg(BX),
      _get_op_arg(BX + 1));
  }

  // OP_MOV_MEM?
  // DX = -1 & ~0xff; // 0xff00; // aux reg into ax
  // DH = 0xff; DL = 0;
  DX = ~0xff;
  D("eh? dx=%x\n", DX);
  if (--AX == 0) {
    D("op %s, returning: %x\n", op_to_str[AX + 1], DX);
    return;
  }

  // OP_POINTER?
  if (--AX == 0) {
    DH = ptr_reg;
    D("op %s, returning: %x\n", op_to_str[AX + 2], DX);
    return;
  }

  // OP_REG_INIT
  DX = ops_args[BX / 2];
  if (AX == -2) {
    D("op %s, returning: %x\n", op_to_str[AX + 3], DX);
    return;
  }

  PUSH(AX);
  PUSH(DX);
  PUSH(BX);

  // walk right
  // D("at %x, heading to %x\n", BL, DH);
  BL = DH; // op_idx = upper(ops_args[i])
  emit_ops();

  POP(BX);
  POP(CX);
  POP(AX);

  if (AL == 0xc) {
    return emit_ops_jnz();
  }

  // L1204 {{{
  PUSH(AX);
  PUSH(CX); // [0] old DX, cur op args

  D("doing %s\n", op_to_str[AL + 2]);
  if (DL != 0 || DH != data_reg) {
    return store_data_reg();
  }

  AL = last_op_flag;

  // flip op direction, neg req? {{{2
  if (!SIGNBIT(AL) && // no pending move
      (
          // lower bits clear: done mov_mem + (op_mul or op_sub)
          (AL & 7) == 0 ||
          // an unused pointer reg
          (AL != ptr_reg && AL >= 3))) {
    // flip direction
    *((uint8_t *)DI - 2) ^= 2;
    if (last_op_flag & 0x40) {
      PUSH(AX);
      // 3 == mode reg reg
      AH = AL | (mrm_t){.mod = 3, .op = OPCODE_F7_NEG, .reg = 0}.byte;
      AL = 0xf7;
      emitw(AX);
      POP(AX);
    }
    return mark_reg_used();
  }
  // }}}

  // otherwise pick an available register {{{2
  // emit_ops::@@pick_reg
  AX = random();
  CX = 8; // 8 attempts
  do {
    emitb(DH | 0x50); // PUSH
    BL = 0x80;
    if (CX == 0) {
      // emit_ops::@@push_instead
      // exhausted?
      DH = BL; // DH = 0x80
      return store_data_reg();
    }

    DI--; // rewind STOS
    CX--; // decrement attempts

    AX = (AL + 1) & 7;
    BX = AX;
    assert(BX < 8);
    AH = reg_set_enc[BX];
    // try again if it's used
    if (AH == 0) {
      continue;
    }

    // is the reg cx, and the right arg op is the head?
    if (BX-- == REG_CX) {
      POP(BX); // CX from [^0] (current ops_args)
      PUSH(BX);
      BX = BL; // BH = 0;
      assert(BX < 0x21);
      AH = ops[BX];
      if (SIGNBIT(AH)) {
        dump_ops_table();
        abort();
        continue;
      }
    }

    // reg ok
    break;
  } while (1);

  // AL=reg

  // 0x80 set on the op => OP_NEEDS_CX?  so we don't trash it before
  // firing off a shift or rotate
  emit_mov();
  return mark_reg_used();
  // }}}
}

static void emit_ops_maybe_mul() {
  // L1410
  assert(!SIGNBIT(AL));
  CL = 4; // OPCODE_F7_MUL
  if (AL != 0) {
    CX++; // OPCODE_F7_IMUL
    if (AL != 7) {
      AX++;
      return emit_ops_not_mul();
    }
  }

  // al == 0 || al == 7

  // generating mul {{{
  // emit_ops::@@emit_mov_dx
  if (DL != 0) {
    AH = REG_DX;
    AL = 0xba; // mov DX,arg
    emitb(AL);
    SWAP(AX, DX);
    emitd(AX);
  }
  SWAP(AX, CX);
  return emit_f7_op();
  // }}}
}

// rotates/shifts
static void emit_ops_not_mul() {
  // AL is off by 5 at this point
  if ((cpu_state.c = (AL < 4)) == 1) {
    // rol  7   =>  2  =>  0 (0xD3 series: ROL)
    // ror  8   =>  3  =>  1 (0xD3 series: ROR)
    // shl  9   =>  4        (0xD3 series: SHL)
    // shr  10  =>  5        (0xD3 series: SHR)
    AL -= 2;
  }
  int save_carry = cpu_state.c; // flag: rotate or shift

  D("al=%x\n", AX);
  if (DL != 0) {
    // if dl == 0 it's a reg shift/rotate
    return emit_ops_maybe_rol(save_carry);
  }

  // need to init CX first {{{
  PUSH(AX);
  // if we used BX in the last op we can generate `MOV CL,BL`, otherwise do
  // a full reg16 load
  AL = REG_CL;    // need cl for rotate
  CH = BL = 0x8a; // OPCODE_MOV_REG_MRM8
  // last_op_flag 0x80 end, 0x40 sub, &0b111 (reg)
  if (DH != REG_BX) {
    // if BX wasn't used, load the whole register
    // XXX are we saying that if BX is used BL will be & 01f?
    BL = 0x8b; // OPCODE_MOV_REG_MRM16
  }
  D("emitting bl=%x al=%x dx=%x\n", BL, AL, DX);
  emit_op_mrm();
  POP(AX); // 0:rol, 1:ror, 4:shl, shr:5
  assert(AL == 0 || AL == 1 || AL == 4 || AL == 5);
  // }}}

  // if it's shift, generate an AND CL,1Fh too {{{
  PUSH(AX);
  if (!save_carry) {
    // did we emit a shift?  mask cl off.
    AH = 0x1f;
    AL = 0x80; // 80-series opcode
    if ((is_8086 & AH) != 0) {
      // emit `AND CL,1Fh` for 8086
      emitb(AL); // emit 0x1f
      AL = (mrm_t){.mod = 0b11, .op = OPCODE_80_AND, .reg = REG_CL}.byte;
      emitw(AX); // emit MRM, 0x1f
      assert(0);
    }
  }
  POP(AX);
  // }}}

  // 0xd3 series ops: ROL/ROR/RCL/RCR/SHL/SHR/SAL/SAR arg,CL
  BL = 0xd3;
  DL = REG_CL;
  return emit_ops_emit_bl();
}
static void emit_ops_maybe_rol(int is_rotate) {

  D("got AL=%x\n", AL);
  assert(AL == 0 || AL == 1 || AL == 4 || AL == 5);

  // can emit the 286+ version
  // 0xc1 series ops: ROL/ROR/RCL/RCR/SHL/SHR/SAL/SAR arg,count
  BL = 0xc1;
  if (is_rotate) {
    // generating ROL/ROR
    CH = BL; // set last_op
    // is_8086 does double duty
    // 0 286+
    // 0x20 8086
    // 0x1f 8086, generating decrypter
    // 0xff 286+, generating decrypter

    if ((DL & 8)) {
      // optimize the rotate!
      DL = -DL;
      AL ^= 1; // rol,ror -> ror,rol
      // why isn't this done in invert_ops_table()?
      // we're optimizing ops from the table (the same is done for small
      // add/subs and xor -1)
    }
  }

  // cl = 5?  IMUL?
  assert(CL == 5);

  // clamp the arg to 15.  TODO should probably be 31 now.
  DL &= 0xf;

  // don't rotate/shift by 0
  if (DL == 0) {
    DH = data_reg;
    DL = 0;
    return;
  }

  assert(DL > 0 && DL <= 0xf);
  dump_ops_table();
  dump_all_regs();
  assert(AH == 0xff || AH == 0x0 || AH == 1);
  if (DL != 1 && AH == is_8086) {
    // can encode imm8, if:
    //
    // arg > 1
    // and on 286+
    D("emit %x %x %x\n", BL, 0xc0 | (AL << 3) | DH, DL);
    return emit_ops_emit_bl(); // reg,reg
    // returns cl=3 di+=2 al=(0xc0|(al<<3)|dh), dl=data_reg
  }

  // ROL/ROR/SHL/SHR arg,1
  BL = 0xd1;
  D("dl=%x\n", DL);
  if (DL < 3) {
    // if it's rotate by 1..2, generate two ops?
    // rol/ror/shl/shr ax/cx/dx,1
    assert(AL == 0 || AL == 1 || AL == 4 || AL == 5);
    return emit_ops_emit_bl(); // reg,reg
  }

  // otherwise we need to generate `MOV CL,imm8`
  PUSH(AX);
  AL = 0xb1; // MOV CL,imm8
  AH = DL;
  emitw(AX);
dont_mask_cl:
  POP(AX);
  BL = 0xd3; // ROL/ROR/SHL/SHR data_reg,CL
  DL = REG_CL;
  assert(AL == 0 || AL == 1 || AL == 4 || AL == 5);
  //  bl=op, al=op/reg field in mrm (will be 0,1,4,5)
  return emit_ops_emit_bl(); // data_reg,cl
}

static void emit_op_mrm() {
  if (DH == AL) {
    return;
  }
  if (is_8086 != 0xff) {
    // we're on a 8086, or we're generating 8086-compat code
    return bl_op_reg_mrm();
  }

  PUSH(AX);
  if (DH == 0) {
    goto zero_dest;
  }
  if (AL != 0) {
    POP(AX);
    return bl_op_reg_mrm();
  }
  AL = DH;
zero_dest:
  if (BP == 0 && AL == ptr_reg) {
    POP(AX);
    return bl_op_reg_mrm();
  }
  POP(BX);
  AL = 0x90 | AL; // XCHG AX,reg
  emitb(AL);
  return;
}

static void emit_ops_emit_bl() {
  DH = data_reg;

  uint8_t save_bl = BL;
  // dh=reg, bl=op, al=op/reg field in mrm
  bl_op_reg_mrm();
  // returns cl=3 di+=2 al=(0xc0|(al<<3)|dh)
  SWAP(AX, DX);

  dump_all_regs();
  assert(BL == save_bl);
  // did we emit ROL/ROR/SHL/SHR reg,imm8?
  if (BL == 0xc1) {
    emitb(AL); // imm8 arg
    last_op = CH;
    DX = data_reg << 8;
    uint8_t *p = (uint8_t *)DI - 3;
    printf("emitted %x %x %x\n", p[0], p[1], p[2]);
    return;
  }

  cpu_state.c = AL & 1;
  AL >>= 1;
  if (cpu_state.c) {
    // reg,reg
    last_op = CH;
    DX = data_reg << 8;
    return;
  }

  // emitted AND CL,0x1f, now do 0xC
  // or emitted SHL reg,imm8 and do the arg
  SWAP(AX, BX);
  emitb(AL);
  SWAP(AX, DX);
  emitb(AL);
  last_op = CH;
  DX = data_reg << 8;
  return;
}
static void emit_ops_jnz() {
  if (DL != 0 || DH == ptr_reg) {
    return;
  }
  PUSH(AX);
  PUSH(CX);
  PUSH(BX);

  PUSH(DX);
  emit_mov_data();
  POP(DX);

  AL = data_reg;
  AH = last_op;
  if (DH != AL && AH != 0) {
    BL = 0x85;
    bl_op_reg_mrm();
  }
  POP(BX);
  AL = 0x75;
  emitb(AL);
  if (BP != -1) {
    if (generating_enc()) {
      assert(*((uint8_t *)DI - 1) == 0x75);
      // TODO int3 hook
      //*((uint8_t *)DI - 1) += 0x57;
    }
    AX = DI;
    assert(BX < 0x21);
    SWAP(AX, jnz_patch_dec[BX]);
    jnz_patch_enc[BX] = AX;
  }
  DX = ++DI;
  return store_data_reg();
}

// emit_ops::@store_data_reg
static void store_data_reg() {
  STACK_INFO_INIT(__func__);

  POP(BX);

  PUSH(DX);

  assert(BL < 0x21);
  emit_ops();      // walk left
  emit_mov_data(); // finalize

  POP(DX); // this is meant to have our register
  POP(AX);

  last_op_flag = 0x80;

  if (AL == 0xc) {
    BX = DX;
    DX = DI - BX;
    *((uint8_t *)cpu_state.rbx - 1) = DL;
    DX = data_reg << 8;
    return;
  }

  CH = AH;
  PUSH(AX);
  if (DL == 0) {
    // reg op?

    dump_all_regs();
    D("stack: %x %x %x\n", stack[0], stackp[1], stackp[2]);

    if (DH == 0x80) {
      // needed dx for mul or cx for shifts/rotates
      AL = (AL - 5) < 4 ? REG_DX : REG_CX;
      DH = AL;
      AL |= 0x58; // POP reg
      emitb(AL);
    } else {
      // emit_ops::@@didnt_push

      // nothing pending, we can free this register
      if (!SIGNBIT(DH) && DH != ptr_reg) {
        BX = DH;
        assert(BX < 8);
        reg_set_enc[BX]--;
      }
    }
  }
  // emit_ops::@@emit_op

  POP(AX);

  BL = OPCODE_OR; // OR
  AL -= 9;
  if (AL != 0) {
    BL = OPCODE_AND; // AND
    if (--AX == 0) {
      goto got_op;
    }
    AL += 6;
    if (!CBW(A)) {
      assert(AH == 0);
      D("ax=%x\n", AX);
      return emit_ops_maybe_mul();
    }
    assert(AH == 0xff);
    BL = OPCODE_XOR;
    if (++AX) {
      BL = OPCODE_ADD;
      if (is_parity_even(AX)) {
        assert(is_parity_even(cpu_state.ax));
        BL = OPCODE_SUB;
      }
    }
  }
  D("got op %x\n", BL);

  // emit_ops::@@got_op
got_op:
  AL = data_reg;
  if (DL == 0) {
    DH &= 0b10000111; // mask off reg and mode
    if (BL == OPCODE_SUB) {
      DH |= 0b01000000;
    }
    last_op_flag = DH;
    encode_mrm();
    if (!cpu_state.c) {
      return save_op_done();
    }
    if (AL != 0) {
      BP++; // phase change
    }
  }
  // emit_ops::@try_optimization
  BL ^= 0b110; // 0x81,0x35<<3 (sub) => 0xf7,0x33 (neg)
  PUSH(DX);
  DX += 2;
  cpu_state.c = DX < 5;
  POP(DX);

  // not in -2..2
  if (!cpu_state.c) {
    return emit_81_ops();
  }

  // in -2..2, we can optimize:
  //   x + -2 => dec, dec
  //   x + -1 => dec
  //   x + 1 => inc
  //   x + 2 => inc, inc
  //   x - -2 => inc, inc
  //   x - -1 => inc
  //   x - 1 => dec
  //   x - 2 => dec, dec
  //   x ^ -1 => not
  //
  //  none of these optimizations impact the carry flag when they're
  //  executed
  if (!SIGNBIT(AX)) {
    if (BL != 0b00110101) {
      return emit_81_ops();
    } else if (++DX != 0) {
      --DX;
      return emit_81_ops();
    }
    DH = AL;
    AL = 2; // F7,2<<3 => not
    return emit_f7_op();
  }
  if (SIGNBIT(DX)) {
    DX = -DX;
    BL ^= 0b00101000; // toggle add/sub
  }
  // emit_ops::@emit_inc
  AL = (BL == 0b101 ? 0x40 : 0x48) | AL; // add,sub=>inc,dec
  emitb(AL);                             // inc/dec
  if (--DX != 0) {
    emitb(AL); // inc/dec
  }
  return save_op_done();
}
// emit_ops::@@save_op_done
static void save_op_done() {
  last_op = CH;
  DX = data_reg;
  return;
}
static void emit_f7_op() {
  BL = 0xf7;
  CH = BL; // last_op_flag
  return encode_mrm();
}
// emit an 81 series op, unless AL=0 (emit op in BL and store word)
static void emit_81_ops() {
  // implied by the `or AL,AL` at entry (or clears c)
  cpu_state.c = 0;
  if (AL != 0) {
    BL = (mrm_t){.mod = 0b11, .op = (BL >> 3), .reg = AL}.byte;
    AL = DL;

    // if imm16 == signextend(imm8), optimize into imm8
    CBW(A);
    // AX ^= DX;
    cpu_state.ax ^= cpu_state.dx;
    AL = cpu_state.ax != 0 ? 0x81 : 0x83; // imm16 or imm8
    if (AL == 0x83) {
      cpu_state.c = 1;
    }
    emitb(AL);
  }

  dump_all_regs();
  SWAP(AX, BX);
  emitb(AL);
  SWAP(AX, DX); // XXX trashing DX here

  // if AL was 0 it's a 3-byte (or 2-byte if C was set)
  // originally written like this
  /*emitw(AX);
   *if (cpu_state.c) {
   *  cpu_state.rdi--;
   *}*/
  // emit a sign-extended imm8, or otherwise full word size
  if (cpu_state.c) {
    emitb(AL);
  } else {
    emitd(AX);
  }
  return;
}

int is_parity_even(uint64_t x) { return __builtin_parity(x) == 0; }

// register picking {{{
static void pick_ptr_register(uint8_t *p) {
  AX = random() & 3;
  if (AL == 0) {
    AL = 7;
  }
  AL ^= 4;
  // AL = 3, 5, 6, 7
  return mark_and_emit(p);
}
static void mark_and_emit(uint8_t *p) {
  AX = AL;
  BX = AX;
  SWAP(BH, reg_set_enc[BL]);
  if (BH == 0) {
    return pick_ptr_register(p);
  }
  // got reg al
  *p = AL;
  DI++;
}
static void ptr_and_r_sto() {
  pick_ptr_register(&ptr_reg);
  AX = random() & 7;
  if (AL == 0) {
    // data reg = immediate
    return mark_and_emit(&data_reg);
  }
  AL = 0;
  // if (AL == last_op_flag) {
  if (last_op_flag == 0) {
    // if we made an op with an immediate load, use that reg
    return mark_and_emit(&data_reg);
  }
  // otherwise grab a second ptr reg as the data_reg?
  return pick_ptr_register(&data_reg);
}
// }}}

static void encrypt_target() {
  // ... BP is the segment of the ds:DX

  // zero entry?
  CX += DX;
  DX = DI;
  DI = AX;
  AX = arg_code_entry;
  if (AX == 0) {
    DI = (uintptr_t)target_start;
  }
  BX = (uintptr_t)&decrypt_stage_pushes[8]; // end

  PUSH(CX);
  PUSH(AX);
  D("generated %d pushes\n", BX - DX);
  while (BX != DX) {
    BX--;
    AL = *((uint8_t *)BX) ^ 1;
    assert(AL == 0x61 || (AL >= 0x50 && AL <= 0x57));
    if (AL != 0x61) {
      AL ^= 9; // POP reg
    }
    D("copying push %x to %p as pop %x\n", *((uint8_t *)BX), DI, AL);
    assert(AL == 0x61 || (AL >= 0x58 && AL <= 0x5f));
    emitb(AL);
    CX++;
  }
  POP(DX);
  POP(AX);

  BX = (uintptr_t)&patch_dummy;
  if (DX != 0) {
    // emit jump
    SWAP(AX, CX);
    AL = 0xe9;
    emitb(AL);
    BX = DI;
    SWAP(AX, DX);
    emitd(AX);
    DI = (uintptr_t)target_start;
  }

  // emit nops for alignment
  if ((arg_flags & MUT_FLAGS_DONT_ALIGN) == 0) {
    CX = -CX & 0xf;
    AL = 0x90;
    while (CX--) {
      emitb(AL);
    }
  }

  AX = DI - (uintptr_t)target_start;
  *((uint32_t *)BX) += AX;
  AL &= 0xfe;
  arg_size_neg += AX;
  get_arg_size();

  // mov ds,bp
  AX >>= 1;
  CX = AX;
  // rep movsw
  D("moving %d words of payload from %p to %p\n", CX, SI, DI);
  while (CX--) {
    // *((uint16_t*)(SI += 2)) = *((uint16_t*)(DI += 2));
    *((uint16_t *)(DI += 2)) = *((uint16_t *)(SI += 2));
  }
  return exec_enc_stage();
}

struct mut_output *mut_engine(struct mut_input *f_in,
                              struct mut_output *f_out) {
  // in = f_in;
  // out = f_out;
  stackp = stack + STACK_SIZE - 1;

  PUSH((uintptr_t)f_in->code / 16); // let's pretend it's a segment
  PUSH((uintptr_t)f_in->code);
  PUSH((uintptr_t)f_in->exec_offset);

  DX = (uintptr_t)f_in->code;
  CX = f_in->len;
  BP = f_in->exec_offset;
  DI = f_in->entry_offset;
  SI = f_in->payload_offset;
  BX = f_in->routine_size;
  AX = f_in->flags;

  make_enc_and_dec();

  BX = DX;
  SWAP(AX, BP);
  POP(DX); // execution offset
  POP(SI); // payload
  POP(BP); // segment of ds:dx
  BX -= DI;
  PUSH(BX);
  PUSH(DI);
  PUSH(CX);

  encrypt_target(); // something wonky here

  POP(CX);
  POP(SI);
  DI = ((uintptr_t)&target_start) - CX;
  PUSH(DI);
  PUSH(DX);

  // rep movsb
  POP(CX);
  POP(DX);
  POP(SI);
  CX -= DX;
  DI -= DX;
  AX = get_arg_size();

  assert(stackp == &stack[0]);
  return f_out;
}

static void dump_all_regs() {
  printf("ax=%08llx bx=%08llx cx=%08llx dx=%08llx\n", cpu_state.rax,
         cpu_state.rbx, cpu_state.rcx, cpu_state.rdx);
  printf("sp=%08llx bp=%08llx si=%08llx di=%08llx\n", cpu_state.rsp,
         cpu_state.rbp, cpu_state.rsi, cpu_state.rdi);
}

// TODO need some unit tests for shr8(), SIGNBIT, etc
