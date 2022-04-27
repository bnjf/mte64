#include <stdint.h>

#include "mte64.h"

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
#define SWAP(x, y)                                                             \
  do {                                                                         \
    typeof(x) SWAP = x;                                                        \
    x = y;                                                                     \
    y = SWAP;                                                                  \
  } while (0)

#define D(...)                                                                 \
  do {                                                                         \
    fprintf(stderr, "%s:%u %s ", __FILE__, __LINE__, __func__);                \
    printf(__VA_ARGS__);                                                       \
  } while (0)
// }}}

// enums {{{
#if LOCAL_INTERFACE
enum reg_set_t { REG_SET_BUSY, REG_SET_AVAILABLE = 0xff };
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
enum mrm_mode_t {
  MRM_MODE_INDEX = 0,
  MRM_MODE_INDEX_DISP8,
  MRM_MODE_INDEX_DISP32,
  MRM_MODE_REGISTER
};
union mrm_t {
  uint8_t byte;
  struct {
    // note to self: bitfields are right to left
    reg16_t reg : 3;
    reg16_t reg1 : 3;
    mrm_mode_t mod : 2;
  };
  struct {
    reg16_t reg : 3;
    opcode_80_t op : 3;
    mrm_mode_t mod : 2;
  } op_80;
  struct {
    reg16_t reg : 3;
    opcode_f7_t op : 3;
    mrm_mode_t mod : 2;
  } op_f7;
  struct {
    reg8_t reg8 : 3;
    reg8_t reg1_8 : 3;
    mrm_mode_t : 2;
  } mrm_8;
};
#endif
// }}}

// mappings {{{
// LOCAL const uint8_t const opcodes[] = {[OP_ADD] = OPCODE_ADD, [OP_OR] =
// OPCODE_OR, [OP_AND] = OPCODE_AND, [OP_SUB] = OPCODE_SUB, [OP_XOR] =
// OPCODE_XOR};
LOCAL const char *op_to_str[] = {
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
LOCAL uint32_t patch_dummy; // this is only u8 in the original, and it overlaps
                            // onto the push reserve space
LOCAL uint8_t decrypt_stage_pushes[8];
LOCAL uint8_t decrypt_stage[MAX_ADD];
LOCAL uint8_t encrypt_stage[MAX_ADD];
LOCAL uint8_t target_start[100000]; // XXX this should be caller supplied
// }}}

// local prototypes for static funcs {{{
static uint8_t _get_op_arg(int);
static void dump_all_regs();
static void dump_ops_tree_as_stack(int);
static void emit_81_ops();
static void emit_eol_bl();
static void emit_f7_op();
static void emit_mov();
static void emit_op_mrm();
static void emit_ops();
static void emit_ops_emit_bl();
static void emit_ops_jnz();
static void emit_ops_maybe_rol();
static void emit_ops_not_mul();
static void encode_mrm_dh_s();
static void encode_mrm_ptr();
static void encode_op_mrm();
static void encode_retf();
static void fix_arg();
static void g_code();
static void g_code_from_ops();
static void g_code_no_mask();
static uint32_t get_arg_size();
static void invert_ops_loop();
static void make();
static void patch();
static void patch_offsets();
static void ptr_and_r_sto();
static void restart();
static void save_op_done();
static void single_ref();
static void size_ok();
static void store_data_reg();
static void test();
// }}}

// stuff to help while we keep global state
#define STACK_SIZE 512 // 256 not enough?
LOCAL uint64_t stack[STACK_SIZE], *stackp = stack + STACK_SIZE - 1;
#define STACK_INFO_INIT(x) int x##stackp0 = stackp - stack;
#define STACK_INFO(x) D("stack now %li (was %i)\n", stackp - stack, x##stackp0);
#define STACK_CHECK(x) assert(x##stackp0 == stackp - stack);
#define STACK_UPDATE(x) x##stackp0 = stackp - stack;
#define PUSH(reg) (assert(stackp > stack), *(--stackp) = (reg))
#define POP(reg) (assert(stackp < stack + STACK_SIZE), (reg) = *(stackp++))

// https://stackoverflow.com/questions/8938347/c-how-do-i-simulate-8086-registers
LOCAL struct { // global registers {{{
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
#define SETHI(reg, val) ((reg = (((val)&0xff) << 8) | GETLO(reg)), val)
//#define CBW16(x) (x##H = (x##L & 0x80) ? 0xff : 0)
//#define CBW(x) (((x##X) = (((x##L) & 0x80) ? (~0xff) : 0) | (x##L)), x##H)
#define CBW(x) (((x##X) = ((x##L) < 128 ? (x##L) : -(x##L))) >= 128U)
#define SIGNBIT(x) ((typeof(x))((x) << 1) < (x))

// some helper stuff for faking out condition flags {{{

int is_parity_even(uint64_t x) { return __builtin_parity(x) == 0; }

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

// }}}

static uint32_t get_arg_size() { return -arg_size_neg; }

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
      D("do register init BX=%lx CX=%lx\n", BX, CX);

      // check if we're on a boundary
      // i.e. doing the second arg from the op
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
      // because 12 isn't congruent to the wordsize, there's a very small
      // bias towards 0..3 by 0.002%
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
  dump_ops_tree_as_stack(op_idx);
  printf("\n");

  return;
}

static uint8_t _set_op_arg(int i, uint8_t arg) {
  assert(i < 0x42);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = _get_op_arg(i);
  ((uint8_t *)(&ops_args))[(i & -2) << 1 | (i & 1)] = arg;
  return rv;
}
static uint8_t _get_op_arg(int i) {
  assert(i < 0x42);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = ((uint8_t *)(&ops_args))[(i & -2) << 1 | (i & 1)];
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
    printf(
        "%.*s [%u] %s\n", d * 2, "+--------", i,
        (char *[]){"REG = REG XXX", "D = LAST_REG", "REG = [ptr]XXX"}[ops[i]]);
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

// finds a dependent by op reference
static void get_op_loc() {
  assert(AL < 0x42); // AL is an index into ops_args
  assert(AH == 0);
  BX = AX;
  AL >>= 1;     // index into ops
  CX = AX << 1; // args to scan (rounded)
  // DI = (uintptr_t)&ops_args[1];
  DI = 2;

  for (CX = AX << 1; CX > 0; CX--, DI++) {
    // D("looking for al=%x at di=%lx (%lx), %lx to go\n", AL, DI, DI / 2, CX);
    if (_get_op_arg(DI) != AL) {
      continue;
    }

    SI = DI / 2;
    if (ops[SI] < 3) {
      continue;
    }

    D("%lx found at %lx (di=%lx)\n", AX, SI, DI);
    cpu_state.c = 0;
    // returns SI=op# DI=addr_of_arg+1 CX=0x42-op# BX=op_arg# AX=op#
    AX = DI;
    DI = (uintptr_t)&ops_args[DI];
    return;
  }
  // couldn't find a reference
  DI += (uintptr_t)&ops_args;
  cpu_state.c = 1;
  return;
}

static void invert_ops() {
  D("starting at idx=%u\n", op_end_idx);

  AL = op_end_idx;
  assert(AL <= 127);
  (void)CBW(A);
  AL <<= 1; // clearing the top bit off

  get_op_loc();
  if (cpu_state.c) {
    dump_ops_table();
    D("couldn't find a dependent of op_end_idx=%x, returning!\n", AL);
    return;
  }
  op_idx = AL;
  invert_ops_loop();
  return;
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

static void invert_ops_loop() {
  do {
    get_op_loc();
    if (cpu_state.c) {
      // no more dependents, now do ops[0]
      AL = 0;
    }
    PUSH(AX);
    AL >>= 1;
    assert(BX < 0x42);

    _set_op_arg(BX, AL); // push down

    // emulate SHR's flag generation for the LAHF/SAHF
    BX = shr8(BL);
    AH = cpu_state.flags8; // LAHF
    AL = ops[BX] & 0x7f;

    D("inverting %s\n", op_to_str[AL]);
    // sub?
    if (AL == OP_SUB) {
      cpu_state.flags8 = AH;
      if (cpu_state.c) {
        // don't sub->add if we're on the second arg
        goto done;
      }
      AX++; // OP_SUB -> OP_ADD
      goto store;
    }
    // add?
    else if (AL == OP_ADD) {
      cpu_state.flags8 = AH;
      if (cpu_state.c) {
        // doing second/upper arg?
        SI = BX;
        // switch arguments
        uint8_t l = _get_op_arg(BX + SI), r = _get_op_arg(BX + SI + 1);
        _set_op_arg(BX + SI, r);
        _set_op_arg(BX + SI + 1, l);
      }
      // invert add #x,#y as sub #x,#y (or #y,#x if the upper arg)
      // sub
      AX--; // OP_ADD -> OP_SUB
      goto store;
    } else if (AL < 6) {
      goto done;
    } else if (AL != OP_MUL) {
      D("inverting op @ %lx: %s (%x) => %s (%x)\n", BX, op_to_str[AL], AL,
        op_to_str[AL ^ 0xf], AL ^ 0xf);
      assert(AL < 9); // flipping only makes sense for ROL/ROR<>ROR/ROL
      AL ^= 0xf;      // toggle rol/ror
      goto store;
    } else {
      D("inverting op @ %lx: %s (%x) arg=%x\n", BX, op_to_str[AL], AL,
        ops_args[BX]);
      assert(BX < 0x21);
      // BX = (ops_args[BX] >> 8) & 0xff;
      BX = _get_op_arg(BX * 2 + 1);
      assert(BX < 0x21);
      SI = ops_args[BX];
      CX = AX = 0;
      ops_args[BX] = DI = DX = 1;
      D("finding inverse of %lx\n", SI);
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
    D("%s %lx\n", op_to_str[DL], BX);
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
  char where[32] = {"*DI"};

  if (DI >= (uintptr_t)encrypt_stage &&
      DI < (uintptr_t)encrypt_stage + MAX_ADD) {
    sprintf(where, "enc[%lu]", DI - (uintptr_t)encrypt_stage);
  } else if (DI >= (uintptr_t)decrypt_stage &&
             DI < (uintptr_t)decrypt_stage + MAX_ADD) {
    sprintf(where, "dec[%lu]", DI - (uintptr_t)decrypt_stage);
  } else if (DI >= (uintptr_t)target_start &&
             DI < (uintptr_t)target_start + MAX_ADD) {
    sprintf(where, "target[%lu]", DI - (uintptr_t)target_start);
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
  dump_all_regs();
  // assert(SI == (uintptr_t)&ptr_reg);
  AL = data_reg; // XXX [SI-1]
  // printf("emit_mov_data: AX=%x DX=%x\n", AX, DX);
  emit_mov();
  return;
}
// lower byte of val == 0 then encode mov reg,reg instead
static void emit_mov() {
  // AX = AL;
  (void)CBW(A);
  PUSH(AX);

  // XXX AL=DH, move from ops_args?
  assert(AH != 0xff);
  D("# ptr_reg=%s/%x data_reg=%s/%x\n", reg_names[ptr_reg], ptr_reg,
    reg_names[data_reg], data_reg);
  if (AL == DH) {
    D("XXX ptr_reg = %x (*%lx)\n", ops_args[_get_op_arg((DL >> 2) | (DL & 1))],
      DX);
    // XXX hackhackhack
    // DX = ops_args[_get_op_arg((DL >> 2) | (DL & 1))];
    // AL = ptr_reg;
    // we _WERE_ missing a dl<>dh somewhere
    // i messed up `save_op_done` in a couple of places, fixed in 637fd27
  } else if (DL != 0) {
    D("P = %lx (%x)\n", DX, AL);
  } else {
    D("register %s = %s\n", reg_names[AL], reg_names[DH]);
  }

  if (generating_dec()) {
    BX = AX;
    reg_set_dec[BL] = BH;
  }

  dump_all_regs();
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
  dump_all_regs();
  assert(AL < 8);
  D("mov %s,%lx\n", reg_names[AL], DX);
  AL = 0xb8 | AL;
  emitb(AL);
  SWAP(AX, DX);
  emitd(AX);
  if (SIGNBIT(AX)) {
    D("ptr_reg=%x data_reg=%x dx=%lx\n", ptr_reg, data_reg, DX);
    assert(DL == (0xb8 | ptr_reg) || DL == (0xb8 | data_reg));
    // intel zero extends eax into rax, so do a full load for signed
    DI -= 5;
    emitb(0x48);
    emitb(DL);
    emitd(AX);
    // unless it's a pointer
    if (DL == (0xb8 | ptr_reg)) {
      // if it's the pointer, encode the upper part of the addr
      emitd((DI >> 32) - 1);
    } else {
      emitd(AX >> 32);
    }
  }
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
    encode_mrm_ptr();
    return;
  }
  emit_op_mrm();
  return;
}

//__attribute__((optimize("omit-frame-pointer")))
static void exec_enc_stage() {
  PUSH(DI);

  PUSH(AX);
  CX = 0;

  // TODO config trap handler

  BX = (uintptr_t)&encrypt_stage;
  int pagesize = 4096; // XXX sysconf(_SC_PAGE_SIZE);
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
  D("calling encrypt_stage\n");
  dump_all_regs();

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
  D("encrypt_stage returned\n");
  dump_all_regs();

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
    D("found jnz @ %lx (%p) si=%lx\n",
      (DI - (sizeof(jnz_patch_dec[0])) - (uintptr_t)&jnz_patch_dec),
      (void *)jnz_patch_dec[0x21 - CX], SI);
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
      if (AX == BX || ((AL = *(uint8_t *)(SI++)), (void)CBW(A), (DX = AX))) {
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

static void make_enc_and_dec() {
  CX += MAX_ADD_LEN - 5; // MAX_ADD_LEN - JMP NEAR (was 3)
  CX = -CX;
  CL &= -2;
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

  restart();
  return;
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
    D("decrypt_stage len currently %p\n",
      (void *)(DI - (uintptr_t)&decrypt_stage));
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

  make();
  return;
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
  // in the original, while execing the encrypter SS was the caller's SS,
  // so we'd emit a segment override.  not needed nowadays.
  arg_flags = MUT_FLAGS_CS_IS_NOT_SS | (arg_flags & 0xff);

  DX = arg_size_neg;
  DI = (uintptr_t)&encrypt_stage;

  PUSH(BP);
  g_code();
  POP(BP);

  invert_ops();

  POP(AX); // old flags

  POP(DI);
  POP(DX);

  arg_flags = AH | (arg_flags & 0xff); // restore arg_flags
  AL &= 1;
  is_8086 -= AL; // -> 0xff or 0x1f
  PUSH(AX);

  g_code_from_ops();

  POP(AX);
  is_8086 += AL; // restore

  AX = BX;
  POP(BX);
  D("ax0=%lx sign=%u ", AX, SIGNBIT(AH));
  // AX = ((-SIGNBIT(AH)) & ~0xffff) | AX; // sign extend
  (void)CBW(A);

  AX -= (uintptr_t)&patch_dummy;
  printf("ax1=%lx patch_dummy=%p\n", AX, (void *)&patch_dummy);

  STACK_INFO(__func__);

  if (AX < (uintptr_t)&patch_dummy) {
    // value on stack is make's initial AX, restart() pops it as BP
    // so the phases go something like
    // on restart entry
    // bp = previous phase, ax = current phase
    // phases: value to store -> -1 -> 0
    STACK_INFO(__func__);
    // stack should have an extra item XXX
    restart();
    return;
  }
  if (AX == 0 && arg_start_off != 0) {
    assert(0);
    // value on stack is make's initial AX
    restart();
    return;
  }

  POP(BX);

  STACK_INFO(__func__);
  STACK_CHECK(__func__);
  return;
}

static void g_code() {
  junk_len_mask = BL;
  g_code_no_mask();
  return;
}
static void g_code_no_mask() {
  PUSH(DX);
  PUSH(DI);
  make_ops_table(BX);
  POP(DI);
  POP(DX);
  g_code_from_ops();
  return;
}
static void g_code_from_ops() {
  assert(generating_enc() || generating_dec());
  STACK_INFO_INIT(__func__);
  D("bp=%lx\n", BP);
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

      D("patch points: %p, %p\n", (void *)op_off_patch, (void *)&patch_dummy);
      AX = op_off_patch;
      op_off_patch = (uintptr_t)&patch_dummy;

      if ((DH & 0x80) == 0) {
        BP++;
        PUSH(CX);
        PUSH(AX); // offset to patch
        AL = last_op_flag;
        D("al=%x bp=%lx\n", AL, BP);
        // if ((AL & 0b10110111) == 0b10000111 && BP == arg_start_off) {
        if ((AL & 0xb7) == 0x87 && BP == arg_start_off) {
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
            emit_eol_bl();
            return;
          }
          STACK_CHECK(__func__);
          single_ref();
          return;
        } else {
          // @@do_end_of_loop
          // emit the store, doesn't matter if we MOV or XCHG
          AX = random();
          // AL = 0x87 + (AL & 2);
          AL = 0x89;
          SWAP(AX, BX);
          AL = DH;
          STACK_INFO(__func__);
          emit_eol_bl();
          return;
        }
      } else {
        // null?
        if (CX == (uintptr_t)&decrypt_stage[5]) {
          CX -= 5;
          DI -= 5;
          reg_set_dec[ptr_reg]--;
          BX = (uintptr_t)&patch_dummy;
          STACK_INFO(__func__);
          size_ok();
          return;
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
    D("returning ax=%lx bx=%lx dx=%lx (op_idx=%u) (op_arg=%x)\n", AX, BX, DX,
      op_idx, ops_args[ops_args[op_idx] & 0xff]);
    dump_all_regs();
    assert(AX == op_idx);
    assert(
        BH == 0xff &&
        // bl could also be the opcode
        (BL == op_idx || BL == 0xf7 || BL == 0x81 || BL == 0xc1 || BL == 0xd3));
    assert(
        // pointer init
        (SIGNBIT(DH) && DX == arg_size_neg) ||
        // imm init
        DX == ops_args[ops_args[op_idx] & 0xff] ||
        // mul
        (BL == 0xf7 && DX == 0x2ba) ||
        // 81 ops
        (BL == 0x81 ||
         /* rotates/shifts */
         BL == 0xc1 || BL == 0xd3));
    return;
    // }}}
  }
}

static void bl_op_reg_mrm() {
  // shifting the mode bit over 3 times, we shift it back in encode_op_mrm()
  uint8_t al0 = AL;
  AL = (mrm_t){.mod = MRM_MODE_REGISTER, .reg1 = AL}.byte >> 3;
  assert((AL & ~(0xc0 >> 3)) == al0);
  SWAP(AX, BX);
  encode_op_mrm();
  return;
}
static void encode_op_mrm() {
  emitb(AL);
  SWAP(AX, BX);
  CL = 3;
  AL <<= CL;
  AL |= DH; // reg0
  emitb(AL);
  cpu_state.c = 0; // cleared from the OR
  return;
}

static void encode_mrm() {
  if ((DH & 0x80) == 0) {
    bl_op_reg_mrm();
    return;
  }
  encode_mrm_ptr();
  return;
}
static void encode_mrm_ptr() {

  // bl=op, dh=mrm, al=reg

  DH = ptr_reg;
  // D("reg=%x op=%x val=%x (bp=%x)\n", DH, BL, DX, BP);
  cpu_state.c = 0;
  if (BP == -1) {
    bl_op_reg_mrm();
    return;
  } else if (BP != 0) {
    D("staging memory load\n");
    DX = BP;
    BP = DI + 1;
    cpu_state.c = 1;
    return;
  }

  assert(BP == 0);

  PUSH(BX);
  SWAP(AL, DH);
  assert(AL == ptr_reg);
  assert(AL == REG_BX || AL == REG_BP || AL == REG_SI || AL == REG_DI);

  // AL = ((uint8_t[]) { 0x87, 0, 0x86, 0x84, 0x85 })[BX - 3 + AL];
  // mrm byte is a little more sane in 32/64 mode
  AL |= 0x80; // reg+off32
  SWAP(AL, DH);
  SWAP(AX, BX);
  CL = 0x36; // ss:
  // XXX skip the rest

  // @@no_override
  POP(AX);

  // in: al=op, bl=reg, dh=rm
  // out: di=di+1, bx<=>ax, cl=3, al=mrm
  encode_op_mrm();

  op_off_patch = DI;
  D("saved patch point %p\n", (void *)op_off_patch);
  emitd(AX);
  return;
}
static void emit_eol_bl() {
  STACK_INFO_INIT(__func__);
  STACK_INFO(__func__);
  encode_mrm_ptr();
  STACK_INFO(__func__);
  STACK_CHECK(__func__);
  D("bx=%lx generating_enc=%d generating_dec=%d\n", BX, generating_enc(),
    generating_dec());
  D("stack[.]=%lx stack[.+1]=%lx\n", *stackp, *(stackp + 1));
  single_ref();
  return;
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
  D("bx=%lx cx=%lx\n", BX, AX);

  // loop start is > 126 bytes, can't encode a backward jump
  // TODO encode JNZ NEAR instead: 0F 85 rel32
  if ((AL & 0x80) == 0) {
    BX = 0;
    return;
  }
  size_ok();
  return;
}

static void size_ok() {
  encode_retf();
  PUSH(CX);
  DX = (uintptr_t)&target_start;
  if (generating_enc()) {
    D("generating enc, patching offsets (bx=%lx)\n", BX);
    patch_offsets();
    return;
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
  D("bp=%lx\n", BP);

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
  patch_offsets();
  return;
}

static void patch_offsets() {
  // printf("patch_offsets(): BX=%llx\n", cpu_state.rbx);
  D("patching %p and %p\n", (void *)BX, (void *)op_off_patch);
  AX = DX;
  patch();
  AX = DX;
  POP(DX);
  BX = op_off_patch;
  patch();
}

static void patch() {
  AX = AX - arg_size_neg;
  assert(BX != 0);
  if (BX == 0) {
    // in the original this would've just zapped the first two ops
    D("got null patch point?! bx=%lx ax=%lx\n", BX, AX);
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
  store_data_reg();
  return;
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

  D("got ax=%lx bx=%lx\n", AX, BX);
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
  if (--AX == 0) {
    D("data reg op %s, returning: %lx\n", op_to_str[AX + 1], DX);
    return;
  }

  // OP_POINTER?
  if (--AX == 0) {
    DH = ptr_reg;
    D("pointer op %s, returning: %lx\n", op_to_str[AX + 2], DX);
    return;
  }

  // OP_REG_INIT
  DX = ops_args[BX / 2];
  if (AX == -2) {
    D("register init op %s, returning: %lx\n", op_to_str[AX + 2], DX);
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
    emit_ops_jnz();
    return;
  }

  // L1204 {{{
  PUSH(AX);
  PUSH(CX); // [0] old DX, cur op args

  D("doing %s\n", op_to_str[AL + 2]);
  if (DL != 0 || DH != data_reg) {
    store_data_reg();
    return;
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
      AH = (mrm_t){.op_f7.mod = MRM_MODE_REGISTER,
                   .op_f7.op = OPCODE_F7_NEG,
                   .op_f7.reg = AL}
               .byte;
      assert((AH & ~7) == (0xc0 | (OPCODE_F7_NEG << 3)));
      AL = 0xf7;
      emitw(AX);
      POP(AX);
    }
    mark_reg_used();
    return;
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
      store_data_reg();
      return;
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
  mark_reg_used();
  return;
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
      emit_ops_not_mul();
      return;
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
  emit_f7_op();
  return;
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

  D("al=%lx\n", AX);
  if (DL != 0) {
    // if dl == 0 it's a reg shift/rotate
    emit_ops_maybe_rol(save_carry);
    return;
  }

  // L1479
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
  D("emitting bl=%x al=%x dx=%lx\n", BL, AL, DX);
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
      AL = (mrm_t){.op_80.mod = MRM_MODE_REGISTER,
                   .op_80.op = OPCODE_80_AND,
                   .op_80.reg = REG_CL}
               .byte;
      emitw(AX); // emit MRM, 0x1f
      assert(0);
    }
  }
  POP(AX);
  // }}}

  // 0xd3 series ops: ROL/ROR/RCL/RCR/SHL/SHR/SAL/SAR arg,CL
  BL = 0xd3;
  DL = REG_CL;
  emit_ops_emit_bl();
  return;
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
    // 0 286+; 0x20 8086
    // 0x1f 8086, generating decrypter; 0xff 286+, generating decrypter

    /*
     * this was originally written for u16, where we could avoid rotates by >8
     * by negating the argument  e.g.
     *   ROL AX,15 -> ROR AX,1
     * for u32 we'll need to optimize for rotates by >16, but we're currently
     * clamping rotates at 0xf.
     */
    if ((DL & 0x10)) {
      // DL = -DL;
      // AL ^= 1; // rol,ror -> ror,rol
      D("skipping rotate optimization! %s %s,%u -> %s %s,%u\n",
        op_to_str[OP_ROL + AL], reg_names[AH], DL & 0x1f,
        op_to_str[OP_ROL + (AL ^ 1)], reg_names[AH], -DL & 0x1f);
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
  dump_all_regs();
  // assert(DH == 0 || DH == data_reg);          // could be any reg
  assert(AH == 0xff || AH == 0x0 || AH == 1); // old bp?
  if (DL != 1 && AH == is_8086) {
    // can encode imm8, if:
    //
    // arg > 1
    // and on 286+
    D("emit %x %x %x\n", BL, 0xc0 | (AL << 3) | DH, DL);
    emit_ops_emit_bl(); // reg,reg
    // returns cl=3 di+=2 al=(0xc0|(al<<3)|dh), dl=data_reg
    return;
  }

  // ROL/ROR/SHL/SHR arg,1
  BL = 0xd1;
  D("dl=%x\n", DL);
  if (DL < 3) {
    // if it's rotate by 1..2, generate two ops?
    // rol/ror/shl/shr ax/cx/dx,1
    assert(AL == 0 || AL == 1 || AL == 4 || AL == 5);
    emit_ops_emit_bl(); // reg,reg
    return;
  }

  // otherwise we need to generate `MOV CL,imm8`
  PUSH(AX);
  AL = 0xb1; // MOV CL,imm8
  AH = DL;
  emitw(AX);
  POP(AX);

  BL = 0xd3; // ROL/ROR/SHL/SHR data_reg,CL
  DL = 1;    // data reg
  assert(AL == 0 || AL == 1 || AL == 4 || AL == 5);
  //  bl=op, al=op/reg field in mrm (will be 0,1,4,5)
  emit_ops_emit_bl(); // data_reg,cl
  return;
}

static void emit_op_mrm() {
  if (DH == AL) {
    return;
  }
  if (is_8086 != 0xff) {
    // we're on a 8086, or we're generating 8086-compat code
    bl_op_reg_mrm();
    return;
  }

  PUSH(AX);
  if (DH == 0) {
    goto zero_dest;
  }
  if (AL != 0) {
    POP(AX);
    bl_op_reg_mrm();
    return;
  }
  AL = DH;
zero_dest:
  if (BP == 0 && AL == ptr_reg) {
    POP(AX);
    bl_op_reg_mrm();
    return;
  }
  POP(BX);
  AL = 0x90 | AL; // XCHG AX,reg
  emitb(AL);
  return;
}

// uses the data reg
static void emit_ops_emit_bl() {
  DH = data_reg;

  // dh=reg, bl=op, al=op/reg field in mrm
  bl_op_reg_mrm();
  // returns cl=3 di+=2 al=(0xc0|(al<<3)|dh)
  SWAP(AX, DX);

  // did we emit ROL/ROR/SHL/SHR reg,imm8?
  if (BL == 0xc1) {
    emitb(AL); // imm8 arg
    last_op = CH;
    DX = data_reg << 8;
    uint8_t *p = (uint8_t *)DI - 3;
    printf("emitted %x %x %x\n", p[0], p[1], p[2]);
    return;
  }

  AL = shr8(AL);
  if (cpu_state.c) {
    // reg,reg (op=1)
    last_op = CH;
    DX = data_reg << 8;
    return;
  }

  // emitted AND CL,0x1f, now do 0xC
  SWAP(AX, BX);
  emitb(AL); // get the op back
  SWAP(AX, DX);
  emitb(AL); // get the mrm
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
  store_data_reg();
  return;
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
    STACK_CHECK(__func__);
    return;
  }

  CH = AH;
  PUSH(AX);
  if (DL == 0) {
    // reg op?

    dump_all_regs();
    D("stack: %lx %lx %lx\n", stack[0], stackp[1], stackp[2]);

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
    dump_all_regs();
    if (CBW(A) == 0) {
      assert(AH == 0);
      D("ax=%lx\n", AX);
      emit_ops_maybe_mul();
      return;
    }
    dump_all_regs();
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
    DH &= 0x87; // mask off reg and mode
    if (BL == OPCODE_SUB) {
      DH |= 0x40; // indicate we're SUB-ing
    }
    last_op_flag = DH;
    encode_mrm();
    if (!cpu_state.c) {
      save_op_done();
      return;
    }
    if (AL != 0) {
      BP++; // phase change
    }
  }
  // emit_ops::@try_optimization
  BL ^= 0x06; // 0x81,0x35<<3 (sub) => 0xf7,0x33 (neg)
  PUSH(DX);
  DX += 2;
  cpu_state.c = DX < 5;
  POP(DX);

  // not in -2..2
  if (!cpu_state.c) {
    emit_81_ops();
    return;
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
    if (BL != 0x35) {
      emit_81_ops();
      return;
    } else if (++DX != 0) {
      --DX;
      emit_81_ops();
      return;
    }
    DH = AL;
    AL = 2; // F7,2<<3 => not
    emit_f7_op();
    return;
  }
  if (SIGNBIT(DX)) {
    DX = -DX;
    BL ^= 0x28; // toggle add/sub
  }
  // emit_ops::@emit_inc
  AL = (BL == 5 ? 0x40 : 0x48) | AL; // add,sub=>inc,dec
  emitb(AL);                         // inc/dec
  if (--DX != 0) {
    emitb(AL); // inc/dec
  }
  save_op_done();
  return;
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
  encode_mrm();
  return;
}
// emit an 81 series op, unless AL=0 (emit op in BL and store word)
static void emit_81_ops() {
  // implied by the `or AL,AL` at entry (or clears c)
  cpu_state.c = 0;
  if (AL != 0) {
    BL = (mrm_t){.op_80.mod = MRM_MODE_REGISTER,
                 .op_80.op = (BL >> 3),
                 .op_80.reg = AL}
             .byte;
    AL = DL;

    // if imm16 == signextend(imm8), optimize into imm8
    (void)CBW(A);
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

// register picking {{{
// TODO stop `mkhdr -local`-ing, and define the static funcs up the top of
// the file
static void pick_ptr_register(uint8_t *);
static void mark_and_emit(uint8_t *p) {
  AX = AL;
  BX = AX;
  SWAP(BH, reg_set_enc[BL]);
  if (BH == 0) {
    pick_ptr_register(p);
    return;
  }
  // got reg al
  *p = AL;
  DI++;
}
static void pick_ptr_register(uint8_t *p) {
  AX = random() & 3;
  if (AL == 0) {
    AL = 7;
  }
  AL ^= 4;
  // AL = 3, 5, 6, 7
  mark_and_emit(p);
  return;
}
static void ptr_and_r_sto() {
  pick_ptr_register(&ptr_reg);
  AX = random() & 7;
  if (AL == 0) {
    // data reg = immediate
    mark_and_emit(&data_reg);
    return;
  }
  AL = 0;
  // if (AL == last_op_flag) {
  if (last_op_flag == 0) {
    // if we made an op with an immediate load, use that reg
    mark_and_emit(&data_reg);
    return;
  }
  // otherwise grab a second ptr reg as the data_reg?
  pick_ptr_register(&data_reg);
  return;
}
// }}}

static void encrypt_target() {
  // ... BP is the segment of the ds:DX

  // AX should point to the end of our decrypt routine
  // CX should have the size (including pushes)
  assert((AX - (uintptr_t)&decrypt_stage) +
             __builtin_popcount(arg_flags & 0xf) ==
         CX);
  CX += DX;
  DX = DI;
  DI = AX;
  AX = arg_code_entry;
  if (AX == 0) {
    DI = (uintptr_t)target_start;
  }

  // TODO should have decrypt_stage_pushes+decrypt_stage in a struct.
  // instead let's point beyond the end of decrypt_stage_pushes so the BX--
  // gets the desired location. BX = (uintptr_t)&decrypt_stage;
  BX = (uintptr_t)&decrypt_stage_pushes[8]; // end

  PUSH(CX);
  PUSH(AX);

  // copy pushes to pops
  D("pushes @bx: ");
  for (int i = 0; i < 8; i++) {
    fprintf(stderr, "%.02x ", decrypt_stage_pushes[i]);
  }
  fprintf(stderr, "\n");

  assert(BX >= DX);
  D("generated %ld pushes\n", BX - DX);
  while (BX != DX) {
    BX--;
    D("bx=%p dx=%p dec=%p target=%p\n", (void *)BX, (void *)DX,
      (void *)decrypt_stage, (void *)target_start);

    AL = *((uint8_t *)BX) ^ 1;
    assert(AL == 0x61 || (AL >= 0x50 && AL <= 0x57));
    if (AL != 0x61) {
      AL ^= 9; // POP reg
    }
    D("copying push %x to %p as pop %x\n", *((uint8_t *)BX), (void *)DI, AL);
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
    BX = DI; // patch point
    SWAP(AX, DX);
    emitd(AX);
    DI = (uintptr_t)target_start;
  }
  // bx is either &patch_dummy, or the jmp offset

  // emit nops for alignment
  if ((arg_flags & MUT_FLAGS_DONT_ALIGN) == 0) {
    dump_all_regs();
    CX = -CX & 0xf;
    dump_all_regs();
    D("currently at %lx\n", DI - (uintptr_t)&target_start);
    // TODO
    // assert((CX + __builtin_popcount(arg_flags & 0xf) * 2) % 16 == 0);
    AL = 0x90;
    while (CX--) {
      emitb(AL);
    }
  }

  // patch the (optional) jump dest
  AX = DI - (uintptr_t)&target_start;
  *((uint32_t *)BX) += AX;
  AL &= -2;
  arg_size_neg += AX;
  get_arg_size();

  // mov ds,bp
  AX >>= 1;
  CX = AX;
  // rep movsw
  D("moving %ld words of padding from %p to %p\n", CX, (void *)SI, (void *)DI);
  while (CX--) {
    //*((uint16_t *)(DI += 2)) = *((uint16_t *)(SI += 2));
    emitb(*((uint8_t *)(SI++)));
    emitb(*((uint8_t *)(SI++)));
  }
  exec_enc_stage();
  return;
}

struct mut_output *mut_engine(struct mut_input *f_in,
                              struct mut_output *f_out) {
  // test
  // mrm_t m = (mrm_t){.mod = MRM_MODE_REGISTER, .reg1 = REG_CX, .reg =
  // REG_CX}; D("%hx %hx %hx %hx\n", m.mod, m.reg1, m.reg, m.byte);
  // D("%x\n", (mrm_t){.mod = MRM_MODE_REGISTER}.byte);
  // D("%x\n", (mrm_t){.op_f7.mod = MRM_MODE_INDEX_DISP32, .op_f7 =
  // OPCODE_F7_NEG}.byte); D("%x\n", (mrm_t){.mod = MRM_MODE_REGISTER, .op_f7
  // = OPCODE_F7_NEG, .reg = REG_CX} .byte);

  memcpy(ops, (op_t[]){1, 6, 7, 0, 4, 8, 1, 0, 0, 0}, 10 * sizeof(ops[0]));
  // check enum vs raw
  assert(memcmp((op_t[]){1, OP_MUL, OP_ROL, 0, OP_ADD, OP_ROR, 1, 0, 0, 0, 0},
                ops, 10 * sizeof(ops[0])) == 0);
  memcpy(ops_args,
         (uint32_t[]){0, 0x302, 0x504, 0x74b0dc51, 0x706, 0x908, 0x3d1b58ba,
                      0x2eb141f2, 0x79e2a9e3, 0x515f007d},
         10 * sizeof(ops_args[0]));
  op_idx = 1;
  op_free_idx = 9;
  op_next_idx = 10;
  op_end_idx = 6;

  test();

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
  BX = 15; // f_in->routine_size;
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

  assert(stackp == stack + STACK_SIZE - 1 - 3); // stack looks ok!
  encrypt_target();

  POP(CX);
  POP(SI);
  DI = ((uintptr_t)&target_start) - CX;
  PUSH(DI);
  PUSH(DX);

  // rep movsb
  while (CX--) {
    emitb(*((uint8_t *)(SI++)));
  }
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
  printf("ax=%08lx bx=%08lx cx=%08lx dx=%08lx\n", cpu_state.rax, cpu_state.rbx,
         cpu_state.rcx, cpu_state.rdx);
  printf("sp=%08lx bp=%08lx si=%08lx di=%08lx\n", cpu_state.rsp, cpu_state.rbp,
         cpu_state.rsi, cpu_state.rdi);
}

// TODO need some unit tests for shr8(), SIGNBIT, etc

// {{{ tests
static void test() {

  // 10 doesn't exist
  AX = 10 * 2;
  get_op_loc();
  assert(AX == 10 && cpu_state.c == 1);
  // 9 is used at 5 (-> 10), and is a data load
  AX = 9 * 2;
  get_op_loc();
  assert(AX == (5 * 2) + 1 && cpu_state.c == 0);
  // 8 is used at 5 (-> 10), and is a data load
  AX = 8 * 2;
  get_op_loc();
  assert(AX == (5 * 2) && cpu_state.c == 0);
  // 7 is used at 4 (-> 10), and is not a data load
  AX = 7 * 2;
  get_op_loc();
  assert(AX == (4 * 2) + 1 && cpu_state.c == 0);
  // 6 is used at 4 (-> 10), and is not a data load
  AX = 6 * 2;
  get_op_loc();
  assert(AX == (4 * 2) && cpu_state.c == 0);
  // 5 is used at 4 (-> 10), and is not a data load
  AX = 5 * 2;
  get_op_loc();
  dump_all_regs();
  dump_ops_table();
  assert(AX == 5 && cpu_state.c == 0);
  // 4 is used at 4 (-> 10), and is not a data load
  AX = 4 * 2;
  get_op_loc();
  assert(AX == 4 && cpu_state.c == 0);

  dump_ops_table();
  invert_ops_loop();
  dump_ops_table();
}
// }}}  zc:w
