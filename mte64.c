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

// public stuff {{{
#if INTERFACE

#if !LITTLE_ENDIAN
#error
#endif

// 512 -> 0x200.  it's the size of the buffers for the routine staging.
#define MAX_ADD 512
// this is defined as "32" in the doc, but the obj actually has 25.
#define MAX_ADD_LEN 25

// NOTUSED
// static const int CODE_LEN = 2100;

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
  uint8_t *code;              // ds:DX
  unsigned int len;           // CX
  unsigned int decrypted_len; // AX
  uint8_t *routine_end;       // DI
  uint8_t *loop_start;        // SI
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

#if !DEBUG
#define D(...)
#else
#define D(...)                                                               \
  do {                                                                       \
    fprintf(stderr, "[%s L%u] ", __func__, __LINE__);                        \
    fprintf(stderr, __VA_ARGS__);                                            \
  } while (0)
#endif
// }}}

// enums {{{
#if LOCAL_INTERFACE
enum reg_set_t { REG_SET_BUSY = 0, REG_SET_FREE = 0xff };
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
    [OP_DATA] = "MOV_REG",
    [OP_START_OR_END] = "MOV_KEY",
    [OP_POINTER] = "MOV_DATA",
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
#define STACK_INFO(x)                                                        \
  D("stack now %li (was %i)\n", stackp - stack, x##stackp0);
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
static uint8_t shr8(uint8_t x)
{
  cpu_state.flags = (cpu_state.flags & 0xf0) | 0x2; // always on
  cpu_state.c = (x & 1);
  cpu_state.o = (x & 0x80) == 0x80;
  x >>= 1;
  cpu_state.s = (x & 0x80) == 0x80;
  cpu_state.z = BL == 0;
  cpu_state.p = is_parity_even(x);
  return x;
}

// }}}

static uint32_t get_arg_size() { return -arg_size_neg; }

static void make_ops_table(enum mut_routine_size_t routine_size)
{

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
    }
    else if (CH == (OP_MUL | 0x80)) {
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
      if (!cpu_state.c) goto check_arg;
      cpu_state.z = CL == 0;
      if (cpu_state.z) goto last_op;

    check_arg:
      cpu_state.z = DL == 0;

    last_op:
      AL = 0; // reg load/store
      if (!cpu_state.z) goto save_op_idx;
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
    }
    else {
      // insert more ops {{{
      cpu_state.c = 0; // from CMP AL,BL @L480

      SWAP(AX, DX);
      // because 12 isn't congruent to the wordsize, there's a very small
      // bias towards 0..3 by 0.002%
      AL = AL % 12;

      CH = CH & 0x80;
      if (CH != 0) { AL = shr8(AL); }
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

static uint8_t _set_op_arg(int i, uint8_t arg)
{
  assert(i < 0x42);
  assert(arg <= 0x21);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = _get_op_arg(i);
  ((uint8_t *)(&ops_args))[(i & -2) << 1 | (i & 1)] = arg;
  return rv;
}
static uint8_t _get_op_arg(int i)
{
  assert(i < 0x42);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = ((uint8_t *)(&ops_args))[(i & -2) << 1 | (i & 1)];
  // D("%x\n", rv);
  assert(rv <= 0x21);
  return rv;
}

static void dump_ops_table()
{
#if !DEBUG
  return;
#endif
  printf("ops table (i=%hu, free=%d, next=%d, end=%d)\n", op_idx, op_free_idx,
         op_next_idx, op_end_idx);
  for (int i = 0; i <= op_free_idx; i++) {
    if (ops[i] >= 3) {
      printf("%d\t%-10s (%x)\t#%u, #%u\n", i, op_to_str[ops[i] & 0x7f],
             ops[i] & 0x7f, _get_op_arg(i * 2), _get_op_arg((i * 2) + 1));
    }
    else {
      if (ops_args[i]) {
        printf("%d\t%-10s (%x)\t%04x\n", i, op_to_str[ops[i] & 0x7f],
               ops[i] & 0x7f, ops_args[i]);
      }
      else {
        // XXX shouldn't have arg=0 for op=0 or op=2
        assert(ops[i] != 0);
        assert(ops[i] != 2);
        printf(
            "%d\t%-10s (%x)\t%s\n", i,
            (char *[]){"REG = REG XXX", "MOV_KEY", "REG = [ptr]XXX"}[ops[i]],
            ops[i], (char *[]){"XXX", "LAST_REG", "[P]"}[ops[i]]);
      }
    }
  }
}
static void dump_ops_tree(int i, int d)
{
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
  }
  else {
    printf("%.*s [%u] %s\n", d * 2, "+--------", i,
           (char *[]){"REG = REG XXX", "D = LAST_REG",
                      "REG = [ptr]XXX"}[ops[i]]);
  }
  return;
}
static void dump_ops_tree_as_stack(int i)
{
#if !DEBUG
  return;
#endif
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
static void get_op_loc()
{
  assert(AL < 0x42); // AL is an index into ops_args
  assert(AH == 0);
  BX = AX;
  AL >>= 1; // index into ops

  for (CX = AX << 1, DI = 2; CX > 0; CX--, DI++) {
    // swapped these so i can assert in _get_op_arg()
    if (ops[SI = DI / 2] < 3) { continue; }
    if (_get_op_arg(DI) != AL) { continue; }

    D("%lx found at %lx (di=%lx)\n", AX, SI, DI);
    cpu_state.c = 0;
    AX = DI;
    DI = (uintptr_t)&ops_args[DI];
    return;
  }
  // couldn't find a reference
  DI += (uintptr_t)&ops_args;
  cpu_state.c = 1;
  return;
}

static void invert_ops()
{
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
uint32_t integer_inverse(uint32_t a)
{
  assert(a % 2 == 1);
  uint32_t x0 = (3 * a) ^ 2; // See section 5, formula 3.
  uint32_t y = 1 - a * x0;
  uint32_t x1 = x0 * (1 + y);
  y *= y;
  uint32_t x2 = x1 * (1 + y);
  y *= y;
  uint32_t x3 = x2 * (1 + y);
  return x3;
  // only need 3 reps for u32:
  // https://lemire.me/blog/2017/09/18/computing-the-inverse-of-odd-integers/
  // y *= y;
  // uint32_t x4 = x3 * (1 + y);
  // return x4;
}

static void invert_ops_loop()
{
  do {
    get_op_loc();
    // no more dependents, now do ops[0]
    if (cpu_state.c) { AL = 0; }
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
    }
    else if (AL < 6) {
      goto done;
    }
    else if (AL != OP_MUL) {
      D("inverting op @ %lx: %s (%x) => %s (%x)\n", BX, op_to_str[AL], AL,
        op_to_str[AL ^ 0xf], AL ^ 0xf);
      assert(AL - 7 < 2); // flipping only makes sense for ROL/ROR<>ROR/ROL
      AL ^= 0xf;          // toggle rol/ror
      goto store;
    }
    else {
      assert(AL == OP_MUL);
      D("inverting op @ %lx: %s (%x) arg=%x\n", BX, op_to_str[AL], AL,
        ops_args[BX]);
      assert(BX < 0x21);
      BX = _get_op_arg(BX * 2 + 1);
      assert(BX < 0x21);
      SI = ops_args[BX];
      CX = AX = 0;
      DI = DX = 1;
      // @@gcd_loop {{{
      while ((ops_args[BX] = DI), SI != 1) {
        union {
          struct {
            uint32_t lo, hi;
          };
          uint64_t x;
        } r;
        r.lo = AX;
        r.hi = DX;
        D("%lx\n", r.x);
        AX = r.x / SI;
        DX = r.x % SI;
        PUSH(DX);
        r.x = AX * DI;
        CX -= r.lo;
        SWAP(CX, DI);
        AX = SI;
        DX = 0;
        POP(SI);
      }
      assert(ops_args[BX] * integer_inverse(ops_args[BX]) == 1);
      // }}}
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

static void try_ptr_advance()
{
  CX = 0; // flag if we succeeded
  assert(op_idx < 0x21);
  AX = op_idx;
  SWAP(AX, BX);
  DX = -2;
  AL = ops[BX];

  // looking for OP_SUB or OP_ADD
  if (AL != 3 && AL != 4) { return; }
  if (AL == 4) { DX = -DX; }

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

static void fix_arg()
{
  // BL = ((uint8_t *)&ops_args)[BX];
  assert(BX < 0x42);
  BL = _get_op_arg(BX);

  // only looking for reg init args
  if (ops[BX] != 0) { return; }

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
static uint32_t get_op_args(uint8_t i)
{
  BX = 0 + (BL & 0x7f); // clear top
  assert(BX < 0x21);
  assert(BX == i);

  DL = ops[BX];
  AX = BX;
  BX = ops_args[BX];
  if (DL < 3) {
    // terminal node
    D("returning (%x) %s %lx\n", DL, op_to_str[DL], BX);
    return BX;
  }

  STACK_INFO_INIT(__func__);

  PUSH(AX); // save [op_idx]

  PUSH(BX);
  get_op_args(BX); // get the left arg
  POP(BX);         // bx=ops_args[i]
  BL = BH;         // go right
  PUSH(DX);        // save left opcode
  get_op_args(BX); // get the right arg
  AX = BX;         // hold index for right arg
  POP(CX);         // cx=left opcode

  POP(BX); // get [^op_idx]
  assert(BX < 0x21);
  DH = ops[BX]; // current op = ops[op_idx]
  D("i=%x\n", i);
  dump_all_regs();
  dump_ops_table();
  assert(BX == i);
  assert(DH == ops[i]);
  assert(
      // mask flag, ensure it's a valid op
      (CL & 127) < 0xf ||
      // ... or if it's an immediate, check the value loaded
      (CL < 3 && AX == ops_args[_get_op_arg(i * 2 + 1)]));
  assert((DL & 127) - 3 < 0xc);

  // DH = current op, DL = previous op
  // imul/mul?
  if ((DH -= 0xd) == 0 || (DH += 7) == 0) {
    last_op_flag = 0;
    reg_set_dec[REG_DX] = 0;
    D("reserved DX\n");
  }
  // DH range is [6,10]: mul, rol, ror, shl, shr
  else if (DH < 5) {
    // no junk ops (11, 12, 13, 14)
    if (DL != 0 ||
        // need cx for op on reg
        (is_8086 != 0 &&
         // op [3,13]?
         (((AL = ((AL - 0xe) & 0xf)) >= 5 ||
           // jnz
           (AL < 2 && DH >= 3))))) {
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

static int generating_enc()
{
  int rv = (DI >= (uintptr_t)encrypt_stage &&
            DI < ((uintptr_t)encrypt_stage) + MAX_ADD);
  assert(rv != ((DI >= (uintptr_t)decrypt_stage_pushes &&
                 DI < ((uintptr_t)decrypt_stage_pushes) + 8) ||
                (DI >= (uintptr_t)decrypt_stage &&
                 DI < ((uintptr_t)decrypt_stage) + MAX_ADD)));
  return rv;
}
static int generating_dec()
{
  int rv = (DI >= (uintptr_t)decrypt_stage_pushes &&
            DI < ((uintptr_t)decrypt_stage_pushes) + 8) ||
           (DI >= (uintptr_t)decrypt_stage &&
            DI < ((uintptr_t)decrypt_stage) + MAX_ADD);
  assert(rv != ((DI >= (uintptr_t)encrypt_stage &&
                 DI < ((uintptr_t)encrypt_stage) + MAX_ADD)));
  return rv;
}

// emits for byte/word/dword {{{
static inline uint8_t emitb(uint8_t x)
{
  char where[32] = {"*DI"};

  if (DI >= (uintptr_t)encrypt_stage &&
      DI < (uintptr_t)encrypt_stage + MAX_ADD) {
    sprintf(where, "enc[%lu]", DI - (uintptr_t)encrypt_stage);
  }
  else if (DI >= (uintptr_t)decrypt_stage &&
           DI < (uintptr_t)decrypt_stage + MAX_ADD) {
    sprintf(where, "dec[%lu]", DI - (uintptr_t)decrypt_stage);
  }
  else if (DI >= (uintptr_t)target_start &&
           DI < (uintptr_t)target_start + MAX_ADD) {
    sprintf(where, "target[%lu]", DI - (uintptr_t)target_start);
  }
  D("%s = %x\n", where, x);
  *((uint8_t *)cpu_state.rdi) = x;
  cpu_state.rdi++;
  return x;
}
static uint16_t emitw(uint16_t x)
{
  D("%x\n", x);
  *((uint16_t *)cpu_state.rdi) = x;
  cpu_state.rdi += 2;
  return x;
}
static uint32_t emitd(uint32_t x)
{
  /*D("%x\n", x);                  */
  /**((uint32_t *)cpu_state.rdi) = x;*/
  /*cpu_state.rdi += 4;              */
  emitb(x);
  emitb(x >>= 8);
  emitb(x >>= 8);
  emitb(x >>= 8);
  return *(uint32_t *)(DI - 4);
}
// }}}

static void emit_mov_data()
{
  assert(SI == (uintptr_t)&ptr_reg);
  AL = data_reg; // [si+1]
  emit_mov();
  return;
}

/*
 * al=dst_reg
 * dl is zero?
 *   emit: mov dst_reg,imm_in_dx
 *   done.
 *
 * bl=OPCODE_MOV_REG_MRM16 (0x8B)
 * dh unsigned?
 *   generating dec on 286+ && dh != 0 && al == 0?
 *     al = dh (dst_reg = src_reg)
 *   bp != 0 && al != ptr_reg
 *     emit: xchg dst_reg,src_reg
 *     return bx=dst_reg
 *   emit: mov dst_reg,src_reg
 *   return bx=(0xc0>>3)|dst_reg
 * dh signed?
 *   dh = ptr_reg
 *   bp == -1?
 *     emit: mov dst_reg,ptr_reg
 *     return bx=(0xc0>>3)|dst_reg
 *   bp == 0?
 *     (bl is op)
 *     emit: mov dst_reg,[ptr_reg]
 *     return bx=(0xc0>>3)|ptr_reg
 *   return dx=bp, bp=di+1, carry=set
 */
static void emit_mov()
{
  // AX = AL;
  (void)CBW(A);
  PUSH(AX);

  D("ptr_reg=%s/%x data_reg=%s/%x\n", reg_names[ptr_reg], ptr_reg,
    reg_names[data_reg], data_reg);

  // checks {{{
  assert(!SIGNBIT(ptr_reg));
  assert(SI == (uintptr_t)&ptr_reg);
  cpu_state.c = 0;
  dump_ops_table();
  dump_all_regs();
  /*assert(AL < 8 &&
   *       (DL == 0 || (SIGNBIT(DH) && AL == ptr_reg) ||
   *        (AL == ptr_reg && ops[CL] < 3) || (!(BL & 1) && ops[BL / 2] <
   * 3)));*/
  // reg,reg or reg,key or reg,[ptr]
  // }}}

  if (generating_dec()) {
    BX = AX;
    dump_all_regs();
    assert(BH == REG_SET_BUSY);
    for (int i = 0; i < 8; i++) {
      D("reg_set_dec[%s/%x] = %x\n", reg_names[i], i, reg_set_dec[i]);
    }
    if (reg_set_dec[BL] != REG_SET_FREE) {
      D("warning: %s/%x already in use!\n", reg_names[BL], BL);
    }
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
  dump_all_regs();
  assert(AL < 8);
  D("mov %s,%lx\n", reg_names[AL], DX);
  AL = 0xb8 | AL;
  emitb(AL);
  SWAP(AX, DX);
  emitd(AX);

  // we need the pointer reg to have a 64-bit address, but also have the lower
  // 32 bits equal to -PAYLOAD_SIZE
  if (SIGNBIT(AX) && DL == (0xb8 | ptr_reg)) {
    D("ptr_reg=%x data_reg=%x dx=%lx\n", ptr_reg, data_reg, DX);
    assert(DL == (0xb8 | ptr_reg) || DL == (0xb8 | data_reg));
    // intel zero extends eax into rax, so do a full load for the ptr, and
    // drop a 2^32 off it
    DI -= 5;
    assert((*((uint8_t *)DI) & ~7) == 0xb8);
    emitb(0x48);
    emitb(DL);
    emitd(AX);
    // if it's the pointer, encode the upper part of the addr
    emitd((DI >> 32) - 1);
  }
  POP(AX);
  return;
}

static void encode_mrm_dh_s()
{
  // DH = -1: load ptr_reg into DH
  // and then
  // BP = -1: do op=BL ptr_reg,reg
  // BP =  0: do op=BL [ptr_reg],reg
  // BP != 0: DX=BP, BP=DI+1, C=1
  if (SIGNBIT(DH)) {
    encode_mrm_ptr();
    return;
  }
  emit_op_mrm();
  return;
}

//__attribute__((optimize("omit-frame-pointer")))
static void exec_enc_stage()
{
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
               PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
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
  D(">>> calling encrypt_stage\n");
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
  dump_all_regs();
  D("<<< encrypt_stage returned\n");

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
#undef OP_JNZ_JUNK
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

static void make_enc_and_dec()
{
  const int align = 4; // was 2

  // MAX_ADD_LEN:
  CX += MAX_ADD_LEN - align - 1; // MAX_ADD_LEN rounded
  CX = -CX;
  CL &= -align;
  if (CL == 0) { CX -= align; }
  SWAP(AX, DI);
  arg_code_entry = AX;
  AX += CX;
  AL &= -align;
  if (AL == 0) { AX -= align; }
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
  // srandom();

  restart();
  return;
}

// LOCAL long seed = 1;
static void restart()
{
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
  BL = MUT_ROUTINE_SIZE_MEDIUM; // 7
  make();

  assert((*(uint8_t *)DI) == 0xc3);
  DI -= 1;
  if (DI != (uintptr_t)&decrypt_stage) {
    // patch the values into the pointer and key init {{{
    D("decrypt_stage len currently %p\n",
      (void *)(DI - (uintptr_t)&decrypt_stage));
    PUSH(DX);
    PUSH(DI);

    PUSH(BP);
    AX = 1;
    exec_enc_stage();
    POP(DI);
    SWAP(AX, BP);

    D("got key: %lx ptr_reg=%s data_reg=%s\n", AX, reg_names[ptr_reg],
      reg_names[data_reg]);

    emitd(AX);

    POP(DI);
    POP(DX);
    // }}}
  }
  // make_enc_and_dec::@@nothing_emitted
  POP(BX); // restore BX
  POP(AX); // grab the BP
  BP = 0;

  make();
  return;
}

static void make()
{
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
  AX = 4; // MUT_FLAGS_CS_IS_NOT_SS >> 8;
  DI = (uintptr_t)&op_idx;

  // in the original, while execing the encrypter SS was the caller's SS,
  // so we'd emit a segment override.  not needed nowadays.
  AL = arg_flags >> 8;
  PUSH(AX);
  arg_flags = MUT_FLAGS_CS_IS_NOT_SS | (arg_flags & 0xff);

  DX = arg_size_neg;
  DI = (uintptr_t)&encrypt_stage;

  PUSH(BP);
  g_code();
  POP(BP);

  invert_ops();

  POP(AX); // get arg_flags back

  POP(DI);
  POP(DX);

  arg_flags = AL | (arg_flags & 0xff); // restore arg_flags
  AL &= 1;                             // run on diff cpu
  is_8086 -= AL;                       // -> 0xff or 0x1f
  PUSH(AX);
  g_code_from_ops();
  POP(AX);
  is_8086 += AL; // restore

  AX = BX;
  POP(BX);

  (void)CBW(A);
  D("got AX=%lx (patch_dummy = %p)\n", AX, (void *)&patch_dummy);
  STACK_INFO(__func__);
  // AX -= (uintptr_t)&patch_dummy;
  if (__builtin_usubl_overflow(cpu_state.rax, (uintptr_t)&patch_dummy,
                               &cpu_state.rax)) {
    // value on stack is make's initial AX, restart() pops it as BP
    // so the phases go something like
    // on restart entry
    // bp = previous phase, ax = current phase
    // phases: value to store -> -1 -> 0
    STACK_INFO(__func__);
    restart();
    return;
  }
  if (AX == 0 && arg_start_off != 0) {
    assert(0);
    restart();
    return;
  }

  POP(BX);

  STACK_INFO(__func__);
  STACK_CHECK(__func__);
  return;
}

static void g_code()
{
  junk_len_mask = BL;
  g_code_no_mask();
  return;
}
static void g_code_no_mask()
{
  PUSH(DX);
  PUSH(DI);
  make_ops_table(BX);
  POP(DI);
  POP(DX);
  g_code_from_ops();
  return;
}
static void g_code_from_ops()
{
  assert(generating_enc() || generating_dec());
  STACK_INFO_INIT(__func__);
  D("bp=%lx\n", BP);
  PUSH(DI);

  // init register tracking for enc {{{
  DI = (uintptr_t)&reg_set_enc;
  AX = -1;
  // ax cx dx bx sp bp si di
  // ff ff 00 ff 00 ff ff ff
  emitw(AX);
  AL += 1;
  emitw(AX);
  emitw(AX);
  AL -= 1;
  emitw(AX);
  assert(0 == memcmp(reg_set_enc,
                     (uint8_t[]){
                         [REG_AX] = REG_SET_FREE,
                         [REG_CX] = REG_SET_FREE,
                         [REG_BX] = REG_SET_FREE,
                         [REG_BP] = REG_SET_FREE,
                         [REG_SI] = REG_SET_FREE,
                         [REG_DI] = REG_SET_FREE,
                         // don't trash dx during exec_enc_stage
                         [REG_DX] = REG_SET_BUSY,
                         [REG_SP] = REG_SET_BUSY,
                     },
                     8));
  // }}}

  DI = (uintptr_t)&ptr_reg;

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

  PUSH(BX); // [op_idx]

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
        }
        else {
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
      }
      else {
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
    }
    else {
      // @@not_dec_end
      if (DH & 0x80) { DH = ptr_reg; }
      POP(AX);
      *((uint8_t *)DI) = 0xc3;
      STACK_INFO(__func__);
      return;
    }
    // }}}
  }
  else {
    // @@do_intro_garbage {{{

    // setup ptr and key {{{
    PUSH(BP);
    emit_ops();
    assert(generating_enc() || generating_dec()); // check di
    AL = 0x90 | data_reg;
    emitb(AL);
    POP(AX);
    if (SIGNBIT(DH)) { DX = AX; }
    // }}}

    POP(AX); // [^op_idx]
    BH = 0xff;
    encode_retf();

    dump_ops_table();
    dump_all_regs();
    assert(AX == op_idx);
    assert(BH == 0xff &&
           // bl could also be the opcode
           (BL == op_idx || BL == 0xf7 || BL == 0x81 || BL == 0xc1 ||
            BL == 0xd3 || BL == 0 || BL == 0x2b));
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
         BL == 0xc1 || BL == 0xd3) ||
        // key load
        (BX == ~0xff) ||
        // XXX hmm, this shouldn't be here
        (BL == 0x2b));
    return;
    // }}}
  }
}

static void bl_op_reg_mrm()
{
  // shifting the mode bit over 3 times, we shift it back in encode_op_mrm()
  uint8_t al0 = AL;
  AL = (mrm_t){.mod = MRM_MODE_REGISTER, .reg1 = AL}.byte >> 3;
  assert((AL & ~(0xc0 >> 3)) == al0);
  SWAP(AX, BX);
  encode_op_mrm();
  return;
}
static void encode_op_mrm()
{
  emitb(AL);
  SWAP(AX, BX);
  CL = 3;
  AL <<= CL;
  AL |= DH; // reg0
  emitb(AL);
  cpu_state.c = 0; // cleared from the OR
  return;
}

static void encode_mrm()
{
  if ((DH & 0x80) == 0) {
    bl_op_reg_mrm();
    return;
  }
  encode_mrm_ptr();
  return;
}
static void encode_mrm_ptr()
{

  // bl=op, dh=mrm, al=reg

  DH = ptr_reg;
  // D("reg=%x op=%x val=%x (bp=%x)\n", DH, BL, DX, BP);
  cpu_state.c = 0;
  if (BP == -1) {
    bl_op_reg_mrm();
    return;
  }
  else if (BP != 0) {
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
static void emit_eol_bl()
{
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
static void single_ref()
{

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

    // generate ops, then
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
    if (SIGNBIT(CH)) {
      // we did sub/add arith on the ptr reg, and we adjusted it by 2
      //
      // this needs to be changed to 4
      assert(0);
      goto emit_jnz;
    }
  }

  // emit inc {{{
  // 0x40->0x47 are REX prefixes now.  we can either encode:
  //   0x48 0xFF (0xC0 | reg)
  //
  // or... we're using a u64 index, so let's encode the upper bits of the addr
  // in there.  we can then explicitly test we we wrapped the u32 part with a
  // TEST.
  AL |= 0x40;

  emitb(0x48); // rex
  emitb(0x83); // 80 series op
  emitb((mrm_t){.op_80.mod = MRM_MODE_REGISTER,
                .op_80.op = OPCODE_80_ADD,
                .op_80.reg = AL}
            .byte);
  emitb(4); // XXX we actually need to be on a u32 boundary
  emitb(0x85);
  emitb((mrm_t){.mod = MRM_MODE_REGISTER, .reg1 = AL, .reg = AL}.byte);

  // }}}
emit_jnz:
  // emit the jnz to the start of the loop
  // AL = 0x75;
  AL = 0x78; // js
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

static void size_ok()
{
  encode_retf();
  PUSH(CX);

  DX = (uintptr_t)&target_start;
  if (generating_enc()) {
    // if we're generating the encryption routine, patch the first memory
    // access to the caller supplied code (originally ds:dx), and the second
    // offset to target_start+arg_size.  this means the encryption routine
    // will copy in the data from the caller, perform the crypt ops, then
    // store into `target_start`.  e.g.
    //
    //   mov bx,-size
    // l:mov ax,dword [ptr+caller_code+size]
    //   xor ax,random
    //   mov dword [ptr+target_stage+size],ax
    //   add bx,4
    //   jnz l
    patch_offsets();
    return;
  }

  PUSH(BX); // save op_off_patch

  // junk
  BL = MUT_ROUTINE_SIZE_MEDIUM;
  DX = BP;
  g_code();

  // emit pushes into decrypt_stage_pushes {{{
  PUSH(DI);
  DI = ((uintptr_t)&decrypt_stage) - 1; // decrypt_stage_pushes
  assert(DI == (uintptr_t)&decrypt_stage_pushes[7]);
  BX = 0;
  DX = DI;
  CL = arg_flags; // grab the lower byte
  do {
    CL = shr8(CL);
    if (cpu_state.c && reg_set_dec[BL] == BH) {
      AX = BX + 0x50; // PUSH
      *((uint8_t *)DI--) = AL;
    }
    BX++;
  } while (CL);

  DI++;

  if (DI < DX) {
    // @@randomize_pushes
    assert(0);
  }
  // @@pushes_done
  POP(BP);
  // }}}

  // adjust for user supplied offsets {{{
  CX = BP - DI;
  if (arg_code_entry != 0) {
    // 5 bytes for jump
    CX += (uintptr_t)&decrypt_stage + 5 - DI;
  }
  DX = arg_exec_off;
  AX = DX;
  DX += CX;
  AX += arg_start_off;
  // }}}

  POP(BX); // retrieve op_off_patch
  if (arg_start_off == 0) { DX = AX; }
  patch_offsets();
  return;
}

static void patch_offsets()
{
  D("arg_size_neg=-%lx\n", -arg_size_neg);
  D("patching\n"
    "\tencrypt_stage[%p]=-%lx and\n"
    "\tencrypt_stage[%p]=target_start+%lx\n",
    (void *)(BX - (uintptr_t)encrypt_stage), -(AX - arg_size_neg),
    (void *)(op_off_patch - (uintptr_t)encrypt_stage),
    (DX - arg_size_neg) - (uintptr_t)&target_start);
  AX = DX;
  patch();
  AX = DX;
  POP(DX);
  BX = op_off_patch;
  patch();
}

static void patch()
{
  // XXX i forgot about the optmization that's done when signed imm8 == imm16,
  // but that's not for memory ops
  AX = AX - arg_size_neg;
  assert(BX != 0);
  D("patching [%lx] with %lx\n", BX, AX);
  *((uint32_t *)BX) = AX;
}

static void encode_retf()
{
  // actually retn
  *((uint8_t *)DI) = 0xc3;
}

static void mark_reg_used()
{
  D("op:%x reg:%s reg:%s\n", BL, reg_names[AL], reg_names[DH]);
  SWAP(AX, BX);
  assert(BX < 8);
  assert(reg_set_enc[BX] == REG_SET_FREE);
  reg_set_enc[BX]++;
  DH = BL;
  store_data_reg();
  return;
}

static void emit_ops()
{
  assert(SI != 0);
  assert(SI == (uintptr_t)&ptr_reg);

  // take BL as the head
  last_op = 0xff;      // no last op
  last_op_flag = 0x80; // last_op_flag 0x80 end, 0x40 sub, &0b111 (reg)
  BX = BL;             // BH = 0;
  assert(BX < 0x21);
  AL = ops[BX];
  AX &= 0x7f;
  BL <<= 1; // unmask the op_idx and prepare to index ops_args

  // ptr reg init
  DX = ~0xff;
  if (--AX == 0) {
    D("pointer reg op %s, returning: %lx\n", op_to_str[AX + 1], DX);
    return;
  }

  // data load/store
  if (--AX == 0) {
    DH = ptr_reg;
    D("key reg init %s, returning: %lx\n", op_to_str[AX + 2], DX);
    return;
  }

  // reg, imm
  DX = ops_args[BX / 2];
  if (AX == -2) {
    D("register init op %s, returning: %lx\n", op_to_str[AX + 2], DX);
    return;
  }

  PUSH(AX);
  PUSH(DX);
  PUSH(BX);

  // walk right
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
  if (!SIGNBIT(AL) && // nothing pending
      ((AL &= 7) == 0 || (AL != ptr_reg && AL >= 3))) {
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
    assert(AH == REG_SET_FREE || AH == REG_SET_BUSY);
    if (AH == REG_SET_BUSY) { continue; }

    // is the reg cx, and the right arg op is the head?
    if (BX-- == REG_CX) {
      POP(BX); // CX from [^0] (current ops_args)
      PUSH(BX);
      BX = BL; // BH = 0;
      assert(BX < 0x21);
      AH = ops[BX];
      if (SIGNBIT(AH)) { continue; }
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

static void emit_ops_maybe_mul()
{
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
static void emit_ops_not_mul()
{
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
static void emit_ops_maybe_rol(int is_rotate)
{

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
    DX = data_reg << 8;
    return;
  }

  assert(DL > 0 && DL <= 0xf);
  assert(AH == 0xff || AH == 0x0 || AH == 1); // old bp?
  if (DL != 1 && AH == is_8086) {
    // can encode imm8, if:
    // arg > 1
    // and on 286+
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

static void emit_op_mrm()
{
  if (DH == AL) { return; }
  if (is_8086 != 0xff) {
    // we're on a 8086, or we're generating 8086-compat code
    bl_op_reg_mrm();
    return;
  }

  PUSH(AX);
  if (DH == 0) { goto zero_dest; }
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
static void emit_ops_emit_bl()
{
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
static void emit_ops_jnz()
{
  if (DL != 0 || DH == ptr_reg) { return; }
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
static void store_data_reg()
{
  POP(BX);
  assert(BL < 0x21);
  PUSH(DX);

  emit_ops(); // walk left
  dump_all_regs();
  // assert(cpu_state.dx != 0x2d);
  if (cpu_state.dx == 0x2d) { cpu_state.dx = 12; }
  if (ops[cpu_state.cl] == 0x0) {
    cpu_state.dx = ops_args[cpu_state.cl << 2];
  }
  emit_mov_data(); // finalize

  POP(DX); // this is meant to have our register
  POP(AX); // op

  STACK_INFO_INIT(__func__);

  last_op_flag = 0x80;

  if (AL == 0xc) {
    BX = DX;
    DX = DI - BX;
    *((uint8_t *)cpu_state.rbx - 1) = DL; // patch the jump
    DX = data_reg << 8;                   // @@done
    STACK_CHECK(__func__);
    return;
  }

  CH = AH;
  PUSH(AX);
  if (DL == 0) {
    if (DH == 0x80) {
      // needed dx for mul or cx for shifts/rotates
      AL = (AL - 5) < 4 ? REG_DX : REG_CX;
      DH = AL;
      AL |= 0x58; // POP reg
      emitb(AL);
    }
    else {
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

  BL = 0xb; // OR
  AL -= 9;
  if (AL != 0) {
    BL = 0x23; // AND
    if (--AX == 0) { goto got_op; }
    AL += 6;
    dump_all_regs();
    if (!CBW(A)) {
      assert(AH == 0);
      emit_ops_maybe_mul();
      return;
    }
    BL = 0x33; // OPCODE_XOR
    if (++AX) {
      BL = 0x3; // OPCODE_ADD
      if (is_parity_even(AX)) {
        assert(is_parity_even(cpu_state.ax));
        BL = 0x2b; // OPCODE_SUB
      }
    }
  }
  D("got op %x\n", BL);

  // emit_ops::@@got_op
got_op:
  AL = data_reg;
  if (DL == 0) {
    DH &= 0x87; // mask off reg and mode
    if (BL == 0x2B) {
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
    // xor?
    if (BL != 0x35) {
      emit_81_ops();
      return;
    }

    // arg -1?
    if (++DX != 0) {
      --DX;
      emit_81_ops();
      return;
    }
    DH = AL; // set dh to register
    if (generating_enc()) { assert(reg_set_enc[DH] == REG_SET_BUSY); }
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
static void save_op_done()
{
  assert(SI == (uintptr_t)&ptr_reg);
  last_op = CH;
  DX = data_reg << 8;
  return;
}
static void emit_f7_op()
{
  BL = 0xf7;
  CH = BL; // last_op_flag
  encode_mrm();
  return;
}
// emit an 81 series op, unless AL=0 (emit op in BL and store word)
static void emit_81_ops()
{
  // implied by the `or AL,AL` at entry (or clears c)
  cpu_state.c = 0;
  if (AL != 0) {
    BL = (mrm_t){.op_80.mod = MRM_MODE_REGISTER,
                 .op_80.op = (BL >> 3),
                 .op_80.reg = AL}
             .byte;

    D("%x\n", BL);

    // if imm16 == signextend(imm8), optimize into imm8
    AL = DL;
    (void)CBW(A);
    AX ^= DX;
    AL = AX != 0 ? 0x81 : 0x83; // imm16 or imm8
    if (AL == 0x83) { cpu_state.c = 1; }
    emitb(AL);
  }

  // @@not_imm
  SWAP(AX, BX);
  emitb(AL);
  SWAP(AX, DX);

  // if AL was 0 it's a 3-byte (or 2-byte if C was set)
  // emit a sign-extended imm8, or otherwise full word size
  if (cpu_state.c) { emitb(AL); }
  else {
    emitd(AX);
  }
  return;
}

// register picking {{{
// TODO stop `mkhdr -local`-ing, and define the static funcs up the top of
// the file
static void pick_ptr_register(uint8_t *);
static void mark_and_emit(uint8_t *p)
{
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
static void pick_ptr_register(uint8_t *p)
{
  AX = random() & 3;
  if (AL == 0) { AL = 7; }
  AL ^= 4;
  // AL = 3, 5, 6, 7
  mark_and_emit(p);
  return;
}
static void ptr_and_r_sto()
{
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

static void encrypt_target()
{
  // ... BP is the segment of the ds:DX

  // AX should point to the end of our decrypt routine
  // CX should have the size (including pushes)

  // getting ax -1 .. something wrong with the phase changes?
  dump_all_regs();
  assert(((AX - (uintptr_t)&decrypt_stage) +
              __builtin_popcount(arg_flags & 0xf) ==
          CX));
  CX += DX;
  DX = DI;
  DI = AX;
  AX = arg_code_entry;
  if (AX == 0) { DI = (uintptr_t)target_start; }

  // TODO should have decrypt_stage_pushes+decrypt_stage in a struct.
  // instead let's point beyond the end of decrypt_stage_pushes so the BX--
  // gets the desired location. BX = (uintptr_t)&decrypt_stage;
  BX = (uintptr_t)&decrypt_stage_pushes[8]; // end

  PUSH(CX);
  PUSH(AX);

  // copy pushes to pops
  D("pushes @bx: ");
  for (int i = 0; i < 8; i++) {
    // fprintf(stderr, "%.02x ", decrypt_stage_pushes[i]);
  }
  // fprintf(stderr, "\n");

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
  D("moving %ld words of padding from %p to %p\n", CX, (void *)SI,
    (void *)DI);
  while (CX--) {
    //*((uint16_t *)(DI += 2)) = *((uint16_t *)(SI += 2));
    emitb(*((uint8_t *)(SI++)));
    emitb(*((uint8_t *)(SI++)));
  }
  exec_enc_stage();
  return;
}

mut_output *mut_engine(mut_input *f_in, mut_output *f_out)
{
#if DEBUG
  test();
#endif
  // in = f_in;
  // out = f_out;
  stackp = stack + STACK_SIZE - 1;

  // PUSH((uintptr_t)f_in->code / 16); // let's pretend it's a segment
  PUSH(0);
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

  f_out->code = (uint8_t *)DX;
  f_out->len = CX;
  f_out->decrypted_len = AX;
  f_out->routine_end = (uint8_t *)DI;
  f_out->loop_start = (uint8_t *)SI;

  assert(stackp == stack + STACK_SIZE - 1);
  return f_out;
}

static void dump_all_regs()
{
#if DEBUG
  fprintf(stderr, "\tax=%08x bx=%08x cx=%08x dx=%08x\n", cpu_state.eax,
          cpu_state.ebx, cpu_state.ecx, cpu_state.edx);
  fprintf(stderr, "\tbp=%08x sp=         si=%08x di=%08x\n", cpu_state.ebp,
          cpu_state.esi, cpu_state.edi);
  fprintf(stderr, "\tflags=%s %s %s %s %s %s %s %s\n",
          cpu_state.o ? "OV" : "NV", cpu_state.d ? "DN" : "UP",
          cpu_state.i ? "EI" : "ED", cpu_state.s ? "NG" : "PL",
          cpu_state.z ? "ZR" : "NZ", cpu_state.a ? "AC" : "NA",
          cpu_state.p ? "PE" : "PO", cpu_state.c ? "CY" : "NC");
#endif
}

// TODO need some unit tests for shr8(), SIGNBIT, etc

// {{{ tests
static void test()
{

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

  /* something got corrupted with this one */
#if 0
    op_idx = 1;
    op_end_idx = 2;
    op_next_idx = 8;
    op_free_idx = 7;
    memcpy(ops,
        (op_t[]){OP_START_OR_END, 133, OP_START_OR_END, 138, OP_MUL, OP_DATA,
        OP_DATA, OP_DATA, OP_DATA, OP_START_OR_END, OP_DATA,
        OP_POINTER, OP_POINTER, OP_DATA, OP_DATA, OP_POINTER,
        OP_DATA},
        17);
    memcpy(ops_args,
        (uint32_t[]){0, 155321090, 8936987, 387319044,
        // ?
        841090822, 1960709859, 771151433, 1244316437,
        1633108117, 2007905771, 822890675, 791698927, 498777856,
        524872353, 1572276965, 1703964683, 0},
        17 * sizeof(uint32_t));
    dump_ops_table();
    dump_ops_tree(0, 1);
    dump_ops_tree(op_idx, 1);
    invert_ops();
    dump_ops_tree(op_end_idx, 1);
    dump_ops_tree(op_idx, 1);
#endif
}
// }}}
// ^Z
