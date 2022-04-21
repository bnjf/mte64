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

#include "mte64.h"

// {{{
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
  uint8_t* code;            // ds:DX
  unsigned int len;         // CX
  uintptr_t exec_offset;    // BP
  uintptr_t entry_offset;   // DI
  uintptr_t payload_offset; // SI
  mut_flags_t flags;        // AX
  mut_routine_size_t routine_size;
};
struct mut_output {
  uint8_t* code;               // ds:DX
  unsigned int len;            // AX
  uint8_t* routine_end_offset; // DI
  uint8_t* loop_offset;        // SI
};
#endif
// }}}

#define SWAP(x, y)      \
  do {                  \
    typeof(x) SWAP = x; \
    x = y;              \
    y = SWAP;           \
  } while (0)

#define D(...)                                         \
  do {                                                 \
    printf("%s:%u %s ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__);                               \
  } while (0)

// {{{
LOCAL struct mut_input* in;
LOCAL struct mut_output* out;
// }}}

#if LOCAL_INTERFACE
// XXX start or end prob means "misc ops"... nah, op_mem_move?
enum op_t {
  OP_DATA,         // mov ptr_reg,data_reg || mov data_reg,ptr_reg
  OP_START_OR_END, // mov ptr,imm || mov data,ptr
  OP_POINTER,      // mov [ptr],data_reg || mov data_reg,[ptr]
  OP_SUB,
  OP_ADD,
  OP_XOR,
  OP_MUL,
  OP_ROL,
  OP_ROR,
  OP_SHL,
  OP_SHR,
  OP_OR,
  OP_AND,
  OP_IMUL,
  OP_JNZ
};
enum opcode_t {
  OPCODE_ADD = 0x03,
  OPCODE_OR = 0x0B,
  OPCODE_AND = 0x23,
  OPCODE_SUB = 0x2B,
  OPCODE_XOR = 0x33,
  OPCODE_MOV_IMM = 0xB8,
  OPCODE_MOV_REG_MRM8 = 0x8a,
  OPCODE_MOV_REG_MRM16 = 0x8b
};
enum opcode_f7_t {
  OPCODE_F7_TEST_IMM,
  OPCODE_F7_TEST_IMM_ALT,
  OPCODE_F7_NOT,
  OPCODE_F7_NEG,
  OPCODE_F7_MUL,
  OPCODE_F7_IMUL,
  OPCODE_F7_DIV,
  OPCODE_F7_IDIV
};
enum opcode_80_t {
  OPCODE_80_ADD,
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

LOCAL uint8_t opcodes[]
    = { [OP_ADD] = OPCODE_ADD, [OP_OR] = OPCODE_OR, [OP_AND] = OPCODE_AND, [OP_SUB] = OPCODE_SUB, [OP_XOR] = OPCODE_XOR };
LOCAL char* const op_to_str[] = {
  // data loads
  [OP_DATA] = "IMM_VALUE",
  [OP_START_OR_END] = "INIT_PTR",
  [OP_POINTER] = "INIT_DATA",
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
  [OP_JNZ] = "JNZ"
};

// 0x21 -> 0xf ops max
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
LOCAL uint32_t patch_dummy; // this is only u8 in the original, and it overlaps onto the push reserve space
LOCAL uint8_t decrypt_stage_pushes[8];
LOCAL uint8_t decrypt_stage[MAX_ADD];
LOCAL uint8_t encrypt_stage[MAX_ADD];
LOCAL uint8_t target_start[100000]; // XXX this should be caller supplied

#define REG_IS_USED 0
#define REG_IS_FREE 0xff

// stuff to help while we keep global state
#define STACK_SIZE 128
LOCAL uint64_t stack[STACK_SIZE], *stackp = stack + STACK_SIZE - 1;
#define PUSH(reg) (assert(stackp > stack), *(--stackp) = (reg))
#define POP(reg) (assert(stackp < stack + STACK_SIZE), (reg) = *(stackp++))

// https://stackoverflow.com/questions/8938347/c-how-do-i-simulate-8086-registers
LOCAL struct {
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

// upper/lower stuff
//#define LOWER(x) ((x)&0xff)
//#define UPPER(x) LOWER(((x) >> 8))
#define GETLO(reg) ((reg)&0xff)
#define GETHI(reg) (GETLO(((reg) >> 8)))
#define SETLO(reg, val) (reg = GETHI(reg) | ((val)&0xff), val)
#define SETHI(reg, val) (reg = (((val)&0xff) << 8) | GETLO(reg), val)
#define CBW(x) (x##H = (x##L & 0x80) ? 0xff : 0)
#define SIGNBIT(x) ((typeof(x))((x) << 1) < (x))

static void make_ops_table(enum mut_routine_size_t routine_size)
{
  op_idx = 1;
  op_free_idx = 1;
  op_next_idx = 1;
  DI = (uintptr_t)&op_end_idx;

  ops[0] = OP_START_OR_END;
  ops[1] = OP_START_OR_END | 0x80;

  do {
    DX = random();
    AX = random();

    SI = BX = op_next_idx;

    CL = ops[SI - 1];
    CH = ops[SI];

    if (CH == OP_MUL) {
      AL = 0;
      DL |= 1;
      goto save_op_idx;
    } else if (CH == (OP_MUL | 0x80)) {
      CL = 0; //OP_DATA;
      BX++;   //consume an op
      dump_all_regs();
    }

    AL = AL & junk_len_mask;
    if (AL < BL) {
      D("finalizing, BX=%x CX=%x\n", BX, CX);
      // if we've made enough junk, finalize with a move
      BL = shr8(BL);
      if (!cpu_state.c)
        goto check_arg;
      cpu_state.z = CL == 0;
      if (cpu_state.z)
        goto last_op;
    check_arg:
      cpu_state.z = DL == 0;
    last_op:
      AL = 0;
      if (!cpu_state.z)
        goto save_op_idx;
      cpu_state.z = BP == 0;
      if (!cpu_state.z) {
        DL |= 1;
        goto check_arg;
      }
      AL = 2;

    save_op_idx:
      cpu_state.c = 0;

      // save_op_idx
      if (CH & 0x80) {
        op_end_idx = SI;
        AL = OP_START_OR_END;
      }
      assert(SI < 0x21);
      ops[SI] = AL;
    } else {
      // make more ops
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
    }

    ops_args[SI] = DX; // save arg
    SI <<= 1;          // matching original
    op_next_idx++;
    AL = op_free_idx;
  } while (op_next_idx <= op_free_idx);

  //dump_ops_table();
  //dump_ops_tree(op_end_idx << 1);
  //dump_ops_tree(op_end_idx, 1);
  //dump_ops_tree_as_stack(op_idx);
  printf("\n");

  return;
}

static uint8_t _get_op_arg(int i)
{
  assert(i < 0x42);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = ((uint8_t*)(&ops_args))[(i & -2) << 1 | (i & 1)];
  return rv;
}
static uint8_t _set_op_arg(int i, uint8_t arg)
{
  assert(i < 0x42);
  assert(sizeof(ops_args[0]) == 4); // otherwise need to adjust the arith
  uint8_t rv = _get_op_arg(i);
  ((uint8_t*)(&ops_args))[(i & -2) << 1 | (i & 1)] = arg;
  return rv;
}
static void dump_ops_table()
{
  printf("ops table (%d, %d, %d, %d)\n", op_idx, op_free_idx, op_next_idx, op_end_idx);
  for (int i = 0; i <= op_free_idx; i++) {
    printf("%d\t%-10s (%x)\t%04x\n", i, op_to_str[ops[i] & 0x7f], ops[i] & 0x7f, ((ops[i] & 0x7f) < 3 ? ops_args[i] : ops_args[i] & 0xffff));
  }
}
static void dump_ops_tree(int i, int d)
{
  assert(i < 0x21);
  assert(d < 6);

  // NB. we can't do the same kind of pointer arith used in the original
  // since the word size is a different width (i.e. SHL/SHR 1 doesn't get a
  // pointer).  let's do it like this...

  if (ops[i] >= 3) {
    printf("%.*s [%u] %s\n", d * 2, "+-------", i, op_to_str[ops[i] & 0x7f]);
    dump_ops_tree(_get_op_arg(i << 1), d + 1);
    dump_ops_tree(_get_op_arg((i << 1) + 1), d + 1);
  }

  if (ops[i] < 3) {
    printf("%.*s [%u] %s %x\n", d * 2, "+--------", i, op_to_str[ops[i]], ops_args[i]);
    return;
  }
}
static void dump_ops_tree_as_stack(int i)
{
  assert(i < 0x21);

  if (ops[i] >= 3) {
    dump_ops_tree_as_stack(_get_op_arg(i << 1));
    dump_ops_tree_as_stack(_get_op_arg((i << 1) + 1));
    printf("%s ", op_to_str[ops[i]]);
    return;
  }

  if (ops[i] < 3) {
    printf("%x %s ", ops_args[i], op_to_str[ops[i]]);
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

static void get_op_loc()
{
  // returns op index in AX, or sets carry
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

static void invert_ops()
{
  AX = op_end_idx << 1;
  get_op_loc();
  if (cpu_state.c) {
    D("not inverting! %x\n", AL);
    return;
  }
  op_idx = AL;
  //dump_ops_table();
  dump_ops_tree(0, 1);
  dump_ops_tree(1, 1);
  invert_ops_loop();
  dump_ops_tree(6, 1);
  dump_ops_tree(4, 1);
  assert(0);
}
static void invert_ops_loop()
{
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
      D("inverting op @ %x: %s (%x) => %s (%x)\n", BX, op_to_str[AL], AL, op_to_str[AL ^ 0xf], AL ^ 0xf);
      assert(AL < 9);
      AL ^= 0xf; // toggle rol/ror
      goto store;
    } else {
      D("inverting op @ %x: %s (%x) arg=%x\n", BX, op_to_str[AL], AL, ops_args[BX]);
      assert(BX < 0x21);
      //BX = (ops_args[BX] >> 8) & 0xff;
      BX = _get_op_arg(BX * 2 + 1);
      assert(BX < 0x21);
      SI = ops_args[BX];
      CX = AX = 0;
      ops_args[BX] = DI = DX = 1;
      D("finding inverse of %x\n", SI);
      ops_args[BX] = integer_inverse(SI);
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
static uint8_t shr8(uint8_t x)
{
  cpu_state.flags = (cpu_state.flags & 0xf0) | 0x2; // always on
  cpu_state.c = x & 1;
  cpu_state.o = (x & 0x80) == 0x80;
  x >>= 1;
  cpu_state.s = (x & 0x80) == 0x80;
  cpu_state.z = BL == 0;
  cpu_state.p = is_parity_even(x);
  return x;
}

static void try_ptr_advance()
{
  CX = 0; // flag if we succeeded
  assert(op_idx < 0x21);
  AX = op_idx;
  SWAP(AX, BX);
  DX = -2;
  AL = ops[BX];
  if (AL != 3 && AL != 4) {
    return;
  }
  if (AL == 4) {
    DX = -DX;
  }
  BL <<= 1;
  PUSH(BX);
  BX++;
  fix_arg();
  POP(BX);
  DX = 2;
  fix_arg();
  return;
}
static void fix_arg()
{
  uint64_t _bx0 = BX;
  BL = ((uint8_t*)&ops_args)[BX];
  if (ops[BX] != OP_POINTER) {
    return;
  }
  SI = BX;
  // [bx+si] to double in the original, not needed as we're storing words
  DX += ops_args[BX];
  if (DL != 0) {
    return;
  }
  if (CX) {
    printf("try_ptr_advance OK: %s %s %llx -> %llx\n",
        op_to_str[ops[_bx0]], op_to_str[ops[BX]], ops_args[BX], DX);
  }
  ops_args[BX] = DX;
  CX--;
  return;
}

// checks for any pending register allocations
static uint32_t get_op_args(uint8_t i)
{
  BX = 0 + (BL & 0x7f); // clear top
  // printf("BX=%x BH=%x BL=%x\n", BX, BH, BL);
  assert(BX < 0x21);

  DL = ops[BX];
  AX = BX;
  BX = ops_args[BX];
  if (DL < 3) {
    return BX;
  }

  PUSH(AX);
  PUSH(BX);
  D("BX=%x BH=%x BL=%x\n", BX, BH, BL);
  assert(BL < 0x21);
  get_op_args(BX);
  POP(BX);
  BL = BH;
  PUSH(DX);
  assert(BL < 0x21);
  get_op_args(BX);
  AX = BX;
  POP(CX);
  POP(BX);
  assert(BX < 0x21);
  DH = ops[BX];

  // DH = current op, DL = previous op
  // imul/mul?
  if ((DH -= 0xd) == 0 || (DH += 7) == 0) {
    last_op_flag = DH;
    reg_set_dec[REG_DX] = DH;
  }
  //
  else if (DH < 5) {
    // no junk ops (11, 12, 13, 14)
    // DH range is [6,10]: mul, rol, ror, shl, shr
    if (DL != 0 // need cx for op on reg
        || (is_8086 != 0
               && ((AL = ((AL - 0xe) & 0xf) >= 5  // op [3,13]?
                          || (AL >= 2 && DH >= 3) // op jnz with a pointer reg used
                      )))) {
      // >>> [(x,(x+0xd-7-0xe)&0xf) for x in range(15)]
      //  [(0, 8), (1, 9), (2, 10), (3, 11), (4, 12), (5, 13), (6, 14), (7,
      //  15), (8, 0), (9, 1), (10, 2), (11, 3), (12, 4), (13, 5), (14, 6)]

      reg_set_dec[REG_CX] = BH; // mark cx available
      DL = 0x80;                // pending cx
    }
  }
  assert(BX < 0x21);
  ops[BX] = DL = ((CL | DL) & 0x80) | ops[BX];
  return 0;
}

static int generating_enc()
{
  int rv = (DI >= (uintptr_t)encrypt_stage
      && DI < ((uintptr_t)encrypt_stage) + MAX_ADD);
  assert(rv != ((DI >= (uintptr_t)decrypt_stage_pushes && DI < ((uintptr_t)decrypt_stage_pushes) + 8) || (DI >= (uintptr_t)decrypt_stage && DI < ((uintptr_t)decrypt_stage) + MAX_ADD)));
  return rv;
}
static int generating_dec()
{
  int rv = (DI >= (uintptr_t)decrypt_stage_pushes && DI < ((uintptr_t)decrypt_stage_pushes) + 8) || (DI >= (uintptr_t)decrypt_stage && DI < ((uintptr_t)decrypt_stage) + MAX_ADD);
  assert(rv != ((DI >= (uintptr_t)encrypt_stage && DI < ((uintptr_t)encrypt_stage) + MAX_ADD)));
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

static uint8_t emitb(uint8_t x)
{
  *((uint8_t*)cpu_state.rdi) = x;
  cpu_state.rdi++;
  return x;
}
static uint16_t emitw(uint16_t x)
{
  *((uint16_t*)cpu_state.rdi) = x;
  cpu_state.rdi += 2;
  return x;
}
static uint32_t emitd(uint32_t x)
{
  *((uint32_t*)cpu_state.rdi) = x;
  cpu_state.rdi += 4;
  return x;
}

static void emit_mov_data()
{
  AL = data_reg;
  //printf("emit_mov_data: AX=%x DX=%x\n", AX, DX);
  return emit_mov();
}
// lower byte of val == 0 then encode mov reg,reg instead
static void emit_mov()
{
  AX = AL;
  PUSH(AX);

  if (generating_dec()) {
    BX = AX;
    reg_set_dec[BL] = BH;
  }

  const char* reg_names[] = {
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    [127] = "PTR_REG"
  };
  if (DL == 0) {
    //D("mov %s, %s %s\n", reg_names[AL], reg_names[DH & 0x7f], SIGNBIT(DH) ? "(signed!)" : "");
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
    // >>> list(map(lambda f: hex(f[0]), (filter(lambda f: f[1] == 0xb8|5,
    // [(x,x|0xb8) for x in range(256)] ))))
    //  ['0x5', '0xd', '0x15', '0x1d', '0x25', '0x2d', '0x35', '0x3d', '0x85',
    //  '0x8d', '0x95', '0x9d', '0xa5', '0xad', '0xb5', '0xbd']
    // 0x8b -> 0xbd if we're in the right state
  }
  //D("... got %x\n", AL);
  assert(AL < 8);
  //D("mov %s,%x\n", reg_names[AL], DX);
  AL = 0xb8 | AL;
  emitb(AL);
  SWAP(AX, DX);
  emitd(AX);
  POP(AX);
  return;
}

static void encode_mrm_dh_s()
{
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
  y *= y;
  uint32_t x4 = x3 * (1 + y);
  return x4;
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

  if (mprotect((uintptr_t*)(page * pagesize), (MAX_ADD * 2), PROT_READ | PROT_EXEC) == -1) {
    fprintf(stderr, "mprotect() failed: %s\n", strerror(errno));
    abort();
  }

  // hmm.  there's fastcall, but that's for cx,dx as an arg.
  //uint64_t (*encrypt_stage_f)(uint64_t)
  //__attribute__((no_caller_saved_registers, fastcall))
  //__attribute__((fastcall))
  //   = (uint64_t(*)(uint64_t))encrypt_stage;
  //AX = encrypt_stage_f(BP);
  //
  // ah.  "You can't make the compiler pass a function arg in EAX/RAX in 64-bit
  // mode."
  //
  // the calling convention for x86-64 is di,si,dx,cx,r8,r9

  // bp is used unless we've got omit-frame-pointer when compiling, and can't
  // be listed in clobbers.  hack around a bit and do our own saves.
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
  if (mprotect((uintptr_t*)(page * pagesize), MAX_ADD * 2, PROT_READ | PROT_WRITE) == -1) {
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
      if (*((uint16_t*)(DI++)) != AX) {
        cpu_state.z = 0;
        break;
      }
    }
    if (cpu_state.z) {
      // emit_ops::@@done
      POP(DX);
      return;
    }
    // TODO junk loops
    assert(0);
  } while (1);

  POP(DX);
  return;
}

static uint32_t get_arg_size()
{
  return -arg_size_neg;
}

static void make_enc_and_dec(struct mut_input* in, struct mut_output* out)
{
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
static void restart()
{
  int sp0 = stackp - stack;
  D("got sp0: %i\n", sp0);
  POP(BP);
  PUSH(BP);
  PUSH(BX);

  // srandom(time(NULL));
  //AX = random(); // dunno if upper bits are used

  AL = -1;
  CX = 8;
  DI = (uintptr_t)&reg_set_dec;
  while (CX--) {
    emitb(AL);
  }

  DI = (uintptr_t)&decrypt_stage;
  BL = 7;
  make();
  assert((*(uint8_t*)DI) == 0xc3);
  DI -= 1;
  if (DI != (uintptr_t)&decrypt_stage) {
    //printf("decrypt_stage len currently %p,%p\n", &decrypt_stage, DI);
    printf("decrypt_stage len currently %p\n", DI - (uintptr_t)&decrypt_stage);
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

  D("stack now %i (was %i)\n", stackp - stack, sp0);
  //assert((stackp - stack) == sp0);
  return make();
}

static void make()
{
  int sp0 = stackp - stack;
  D("got sp0: %i\n", sp0);
  PUSH(AX);
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
  AX -= (uintptr_t)&patch_dummy;
  //if (AX < 0) {
  if (AX > (uintptr_t)&patch_dummy) {
    //D("stack now %i (was %i)\n", stackp - stack, sp0);
    assert((stackp - stack) == sp0 - 1); // got an item on the stack
    return restart();
  }
  if (AX == 0 && arg_start_off != 0) {
    assert(0);
    return restart();
  }

  POP(BX);
  D("stack now %i (was %i)\n", stackp - stack, sp0);
  assert((stackp - stack) == sp0);
  return;
}

static void g_code()
{
  junk_len_mask = BL;
  return g_code_no_mask();
}
static void g_code_no_mask()
{
  PUSH(DX);
  PUSH(DI);
  make_ops_table(BX);
  POP(DI);
  POP(DX);
  return g_code_from_ops();
}
static void g_code_from_ops()
{
  assert(generating_enc() || generating_dec());
  PUSH(DI);

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
  assert(*(uint64_t*)reg_set_enc == 0xffffff00ff00ffffULL);

  DI = (uintptr_t)ptr_reg;

  last_op_flag = -1; // AL
  BL = op_idx;

  PUSH(BX);
  PUSH(DX);
  get_op_args(BL);
  SI = DI;
  ptr_and_r_sto();
  POP(DX);
  POP(BX);

  POP(DI);

  PUSH(BX);
  if (BP != -1 && BP != 0) {
    // @@do_intro_garbage
    PUSH(BP);
    emit_ops();
    AL = 0x90 | data_reg;
    emitb(AL);
    POP(AX);
    if (DH & 0x80) {
      DX = AX;
    }
    POP(AX);
    BH = 0xff;
    encode_retf();
    assert(*((uint8_t*)DI) == 0xc3);
    //*((uint8_t*)&cpu_state.rdi) = 0xc3;
    return;
  } else {
    // @@making_junk
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
    emit_ops();
    if (BP == 0) {
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
          D("flipping %x to %x\n", *((uint8_t*)DI - 6) ^ 2, *((uint8_t*)DI - 6));
          *((uint8_t*)DI - 6) ^= 2; // 4 in the original, but we have off32
          assert(0);
          last_op_flag <<= 1;
          if (last_op_flag & 0x80) {
            // add -> sub/neg
            BL = 0xf7;
            AL = 3;
            return emit_eol_bl();
          }
          return single_ref();
        } else {
          // @@do_end_of_loop
          AX = random();
          AL = 0x87 + (AL & 2);
          SWAP(AX, BX);
          AL = DH;
          return emit_eol_bl();
        }
      } else {
        // null?
        if (CX == (uintptr_t)&decrypt_stage[5]) {
          CX -= 5;
          DI -= 5;
          reg_set_dec[ptr_reg]--;
          BX = (uintptr_t)&patch_dummy;
          return size_ok();
        }
      }
    } else {
      // @@not_dec_end
      if (DH & 0x80) {
        DH = ptr_reg;
      }
      POP(AX);
      BH = 0xff;
      *((uint8_t*)&cpu_state.rdi) = 0xc3;
      return;
    }
  }
}

static void bl_op_reg_mrm()
{
  AL |= 0b00011000;
  SWAP(AX, BX);
  encode_op_mrm();
}
static void encode_op_mrm()
{
  emitb(AL);
  SWAP(AX, BX);
  CL = 3;
  AL <<= CL;
  AL |= DH;
  emitb(AL);
  return;
}

static void encode_mrm()
{
  if ((DH & 0x80) == 0) {
    return bl_op_reg_mrm();
  }
  return encode_mrm_ptr();
}
static void encode_mrm_ptr()
{
  DH = ptr_reg;
  //D("reg=%x op=%x val=%x (bp=%x)\n", DH, BL, DX, BP);
  cpu_state.c = 0;
  if (BP == -1) {
    return bl_op_reg_mrm();
  } else if (BP != 0) {
    //D("staging memory load\n");
    DX = BP;
    BP = DI + 1;
    cpu_state.c = 1;
    return;
  }

  assert(BP == 0);

  PUSH(BX);
  SWAP(AL, DH);

  // xlat the mrm byte!
  //AL = ((uint8_t[]) { 0x87, 0, 0x86, 0x84, 0x85 })[BX - 3 + AL];
  // mrm byte is a little more sane in 32/64 mode
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
static void emit_eol_bl()
{
  encode_mrm_ptr();
  D("bx=%llx generating_enc=%d generating_dec=%d\n", BX, generating_enc(), generating_dec());
  D("stack[.]=%llx stack[.-1]=%llx\n", *stackp, *(stackp - 1));
  return single_ref();
}
static void single_ref()
{
  AL = ptr_reg;
  if (generating_dec()) {
    PUSH(AX);
    BP--;
    DL = 0;
    DH = AL;
    junk_len_mask >>= 1;
    g_code_no_mask();
    PUSH(DX);
    PUSH(DI);
    uint64_t di0 = DI;
    invert_ops();
    try_ptr_advance();
    dump_ops_tree(1, 1);
    POP(DI);
    assert(DI == di0);
    POP(DX);
    PUSH(CX);

    // vvv
    g_code_from_ops();
    // ^^^

    POP(CX);
    POP(AX);
    emit_mov();
    if ((CH & 0x80) == 0) {
      goto emit_jnz;
    }
  }

  // 0x40->0x47 are REX prefixes now.  we can either encode:
  //   0x48 0xFF (0xC0 | reg)
  //   0x48 0xFF (0xC0 | reg)
  // or just go straight for an add +2?
  AL |= 0x40;
  emitb(0x48);
  emitb(0xff);
  emitb(0xc0 | AL);
  emitb(0x48);
  emitb(0xff);
  emitb(0xc0 | AL);
emit_jnz:
  AL = 0x75;
  emitb(AL);
  POP(BX);
  POP(AX);
  CX = AX;
  AX = AX - DI - 1;
  emitb(AL);
  if ((AL & 0x80) == 0) {
    BX = 0;
    return;
  }
  return size_ok();
}

static void size_ok()
{
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
      *((uint8_t*)DI--) = AL;
    }
    BX++;
  } while (CL);
  DI++;
  if (DI < DX) {
    // XXX generated pushes...
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

static void patch_offsets()
{
  //printf("patch_offsets(): BX=%llx\n", cpu_state.rbx);
  D("patching %p and %p\n", BX, op_off_patch);
  AX = DX;
  patch();
  AX = DX;
  POP(DX);
  BX = op_off_patch;
  patch();
}

static void patch()
{
  AX = AX - arg_size_neg;
  if (BX == 0) {
    // in the original this would've just zapped the first two ops
    D("got null patch point");
    return;
  }
  *((uint32_t*)BX) = AX;
}

static void encode_retf()
{
  // actually retn
  *((uint8_t*)DI) = 0xc3;
}

static void mark_reg_used()
{
  SWAP(AX, BX);
  reg_set_enc[BX]++;
  DH = AL;
  return store_data_reg();
}

static void emit_ops()
{
  last_op = 0xff;
  last_op_flag = 0x80;
  BX = BL; //BH = 0;
  assert(BX < 0x21);
  AL = ops[BX];
  AX &= 0x7f;

  //D("got op: %s (%x)\n", op_to_str[AL], ops_args[BX]);

  // OP_MOV_MEM?
  DX = 0xff00; // aux reg into ax
  if (--AX == 0) {
    return;
  }
  // OP_POINTER?
  if (--AX == 0) {
    DH = ptr_reg;
    return;
  }
  // OP_REG_INIT
  DX = ops_args[BX];
  if (SIGNBIT(AX)) {
    return;
  }

  PUSH(AX);
  PUSH(DX);
  PUSH(BX);

  // walk right
  //D("at %x, heading to %x\n", BL, DH);
  BL = DH;
  emit_ops();

  POP(BX);
  POP(CX);
  POP(AX);

  if (AL == 0xc) {
    return emit_ops_jnz();
  }

  // L1204 {{{
  PUSH(AX);
  PUSH(CX); // [0]

  if (DL != 0 || DH != data_reg) {
    return store_data_reg();
  }
  D("doing %s\n", op_to_str[AL + 2]);

  AL = last_op_flag;

  // flip op direction, neg req? {{{2
  if (!SIGNBIT(AL) && // no pending move
      (
          // lower bits clear: done mov_mem + (op_mul or op_sub)
          (AL & 7) == 0 ||
          // an unused pointer reg
          (AL != ptr_reg && AL >= 3))) {
    // flip direction
    *((uint8_t*)DI - 2) ^= 2;
    if (last_op_flag & 0x40) {
      PUSH(AX);
      // 3 == mode reg reg
      AH = AL | (mrm_t) { .mod = 3, .op = OPCODE_F7_NEG, .reg = 0 }.byte;
      AL = 0xf7;
      emitw(AX);
      POP(AX);
    }
    return mark_reg_used();
  }
  // }}}

  // otherwise pick a register {{{2
  AX = random();
  CX = 8;           // 8 attempts
  emitb(DH | 0x50); // PUSH
  BL = 0x80;
  while (DI--, CX--) {
    AX = (AX + 1) & 7;
    BX = AX;
    AH = reg_set_enc[BX];
    if (AH == 0) {
      // register is used, retry
      continue;
    }

    // is the reg cx, and we've got a pending init?
    if (BX-- == REG_CX) {
      POP(BX); // CX from [^0]
      PUSH(BX);
      BX = BL; // BH = 0;
      AH = ops[BX];
      if (!SIGNBIT(AH)) {
        // 0x80 set on the op => OP_NEEDS_CX?  so we don't trash it before
        // firing off a shift or rotate
        emit_mov();
        return mark_reg_used();
      }
    } else {
      emit_mov();
      return mark_reg_used();
    }
    emitb(DH | 0x50);
    BL = 0x80;
  }
  // }}}
  // emit_ops::@@push_instead
  DH = BL;
  return mark_reg_used();
}
static void emit_ops_maybe_mul()
{
  CL = 4; // OPCODE_F7_MUL
  if (AL != 0) {
    CX++; // OPCODE_F7_IMUL
    if (AL != 7) {
      AX++;
      return emit_ops_not_mul();
    }
  }
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
}
static void emit_ops_not_mul()
{
  if (cpu_state.c = (AL < 4)) {
    AL -= 2;
  }
  if (DL == 0) {
    return emit_ops_maybe_rol();
  }

  PUSH(AX);
  AL = REG_CX;
  CH = BL = OPCODE_MOV_REG_MRM8;
  if (DH == REG_BX) {
    BL = OPCODE_MOV_REG_MRM16; //BX++;
  }
  emit_op_mrm();
  POP(AX);
  PUSH(AX);
  if (!cpu_state.c) {
    AH = 0x1f;
    AL = 0x80; // 80-series opcode
    if ((is_8086 & AH) != 0) {
      // emit `AND CL,1Fh`.  not needed nowadays.
      emitb(AL);
      AL = (mrm_t) { .mod = 0b11, .op = OPCODE_80_AND, .reg = REG_CL }.byte;
      emitw(AX);
    }
  }
  POP(AX);

  BL = 0xd3; // ROL reg,CL
  DL = REG_CL;
  return emit_ops_emit_bl();
}
static void emit_ops_maybe_rol()
{
  BL = 0xc1;
  if (cpu_state.c) {
    CH = BL;
    if (DL & 8) {
      DL = -DL;
      AL ^= 1;
    }
  }

  // clamp the arg to 15.  TODO should probably be 31 now.
  DL &= 0xf;

  // don't emit rotate by 0
  if (DL == 0) {
    DH = data_reg;
    DL = 0;
    return;
  }

  if (DL != 1 && AH == is_8086) {
    // can encode imm8
    return emit_ops_emit_bl();
  }

  BL = 0xd1; // ROL arg,1
  if (DL < 3) {
    return emit_ops_emit_bl();
  }

  PUSH(AX);
  AL = 0xb1; // MOV CL,imm8
  AH = DL;
  emitw(AX);
  // dont_mask_cl
  POP(AX);
  BL = 0xd3; // ROL arg,CL
  DL = REG_CL;
  return emit_ops_emit_bl();
}
static void emit_op_mrm()
{
  if (DH == AL) {
    return;
  }
  if (is_8086 != 0xff) {
    // XXX look for the dec is_8086
    return bl_op_reg_mrm();
  }
  PUSH(AX);
  if (DH != 0 && AL != 0) {
    POP(AX);
    return bl_op_reg_mrm();
  }
  if (BP == 0 && AL == ptr_reg) {
    POP(AX);
    return bl_op_reg_mrm();
  }
  POP(BX);
  AL = 0x90 | AL; // XCHG AX,reg
  emitb(AL);
  return;
}
static void emit_ops_emit_bl()
{
  DH = data_reg;
  bl_op_reg_mrm();
  SWAP(AX, DX);
  if (BL == 0xc1) {
    // ROL reg,imm8
    emitb(AL);
    return save_op_done();
  }

  cpu_state.c = AL & 1;
  AL >>= 1;
  if (cpu_state.c) {
    // reg,reg
    //printf("emitting op=%x mrm=%x\n", BL, (AL << 1) | 1);
    return save_op_done();
  }

  SWAP(AX, BX);
  emitb(AL);
  SWAP(AX, DX);
  emitb(AL);
  return save_op_done();
}
static void emit_ops_jnz()
{
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
      *((uint8_t*)DI - 1) += 0x57;
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
static void store_data_reg()
{
  POP(BX);
  PUSH(DX);

  //D("emit ops @ %x\n", BL);
  emit_ops(); // walk left
  //D("got arg %x\n", DX);
  emit_mov_data();
  POP(DX);
  POP(AX);
  last_op_flag = 0x80;

  if (AL == 0xc) {
    BX = DX;
    // XXX prob should be on the 64-bit regs
    DX = DI - BX;
    *((uint8_t*)cpu_state.rbx - 1) = DL;
    DH = data_reg;
    DL = 0;
    return;
  }

  CH = AH;
  PUSH(AX);
  if (DL == 0) {
    if (DH == 0x80) {
      AL = (AL - 5) < 4 ? REG_CX : REG_DX;
      DH = AL | 0x58;
      emitb(AL);
    } else {
      // emit_ops::@@didnt_push
      if ((DH & 0x80) == 0 && DH != ptr_reg) {
        BL = DH;
        BH = 0;
        reg_set_enc[BX]--;
      }
    }
  }
  // emit_ops::@@emit_op
  POP(AX);
  BL = OPCODE_OR; // or
  AL -= 9;
  if (AL != 0) {
    BL = OPCODE_AND; // and
    AL += 6;
    if (!CBW(A)) {
      assert(AH == 0);
      return emit_ops_maybe_mul();
    }
    assert(AH == 0xff);
    BL = OPCODE_XOR;
    if (++AX) {
      BL = OPCODE_ADD;
      if (is_parity_even(AX)) {
        BL = OPCODE_SUB;
      }
    }
  }

  // emit_ops::@@got_op
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
    emit_81_ops();
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
      emit_81_ops();
    } else if (++DX != 0) {
      --DX;
      emit_81_ops();
    }
    DH = AL;
    AL = 2; // F7,2<<3 => not
    return emit_f7_op();
  }
  if (!SIGNBIT(DX)) {
    DX = -DX;
    BL ^= 0b00101000; // toggle add/sub
  }
  // emit_ops::@emit_inc
  AL = (BL == 0b101 ? 0x40 : 0x48) | AL; // add,sub=>inc,dec
  emitb(AL);
  if (--DX != 0) {
    emitb(AL);
  }
  return save_op_done();
}
// emit_ops::@@save_op_done
static void save_op_done()
{
  last_op = CH;
  DX = data_reg;
  return;
}
static void emit_f7_op()
{
  BL = 0xf7;
  CH = BL; // last_op_flag
  return encode_mrm();
}
// emit an 81 series op, unless AL=0 (emit op in BL and store word)
static void emit_81_ops()
{
  // implied by the `or AL,AL` at entry (or clears c)
  cpu_state.c = 0;
  if (AL != 0) {
    BL = (mrm_t) { .mod = 0b11, .op = (BL >> 3), .reg = AL }.byte;
    AL = DL;

    // if imm16 == signextend(imm8), optimize into imm8
    CBW(A);
    AX ^= DX;
    cpu_state.c = AX == 0;
    AL = AX != 0 ? 0x81 : 0x83; // imm16 or imm8
    emitb(AL);
  }

  SWAP(AX, BX);
  emitb(AL);
  SWAP(AX, DX);

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

int is_parity_even(uint64_t x)
{
  return __builtin_parity(x) == 0;
}

// register picking {{{
static void pick_ptr_register(uint8_t* p)
{
  AX = random() & 3;
  if (AL == 0) {
    AL = 7;
  }
  AL ^= 4;
  // AL = 3, 5, 6, 7
  return mark_and_emit(p);
}
static void mark_and_emit(uint8_t* p)
{
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
static void ptr_and_r_sto()
{
  pick_ptr_register(&ptr_reg);
  AX = random() & 7;
  if (AL == 0) {
    return mark_and_emit(&data_reg);
  }
  AL = 0;
  if (AL == last_op_flag) {
    return mark_and_emit(&data_reg);
  }
  return pick_ptr_register(&data_reg);
}
// }}}

static void encrypt_target()
{
  // ... BP is the segment of the ds:DX

  // zero entry?
  CX += DX;
  DX = DI;
  DI = AX;
  AX = arg_code_entry;
  if (AX == 0) {
    DI = (uintptr_t)target_start;
  }
  BX = (uintptr_t)decrypt_stage;

  PUSH(CX);
  PUSH(AX);
  D("generated %d pushes\n", BX - DX);
  while (BX != DX) {
    BX--;
    AL = *((uint8_t*)BX) ^ 1;
    if (AL != 0x61) {
      AL ^= 9; // POP reg
    }
    D("copying push %x to %p as pop %x\n", *((uint8_t*)BX), DI, AL);
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
  if ((in->flags & MUT_FLAGS_DONT_ALIGN) == 0) {
    CX = -CX & 0xf;
    AL = 0x90;
    while (CX--) {
      emitb(AL);
    }
  }

  AX = DI - (uintptr_t)target_start;
  *((uint32_t*)BX) += AX;
  AL &= 0xfe;
  arg_size_neg += AX;
  get_arg_size();

  // mov ds,bp
  AX >>= 1;
  CX = AX;
  // rep movsw
  D("moving %d words of payload from %p to %p\n", CX, SI, DI);
  while (CX--) {
    //*((uint16_t*)(SI += 2)) = *((uint16_t*)(DI += 2));
    *((uint16_t*)(DI += 2)) = *((uint16_t*)(SI += 2));
  }
  return exec_enc_stage();
}

struct mut_output* mut_engine(struct mut_input* f_in,
    struct mut_output* f_out)
{
  in = f_in;
  out = f_out;
  stackp = stack + STACK_SIZE - 1;

  PUSH((uintptr_t)in->code / 16); // let's pretend it's a segment
  PUSH((uintptr_t)in->code);
  PUSH((uintptr_t)in->exec_offset);

  DX = (uintptr_t)in->code;
  CX = in->len;
  BP = in->exec_offset;
  DI = in->entry_offset;
  SI = in->payload_offset;
  BX = in->routine_size;
  AX = in->flags;

  make_enc_and_dec(in, out);

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
  return out;
}

static void dump_all_regs()
{
  // printf("=== encrypt_stage\n");
  // for (int i = 0; i < 32 /*MAX_ADD*/; i++) {
  //   printf("%02hx ", encrypt_stage[i]);
  //   if ((i & 15) == 15) {
  //     printf("\n");
  //   }
  // }
  // printf("\n");
  // printf("=== decrypt_stage\n");
  // for (int i = 0; i < 32 /*MAX_ADD*/; i++) {
  //   printf("%02hx ", encrypt_stage[i]);
  //   if ((i & 15) == 15) {
  //     printf("\n");
  //   }
  // }
  //printf("ax=%08llx cx=%08llx dx=%08llx bx=%08llx\n", cpu_state.rax, cpu_state.rcx, cpu_state.rdx, cpu_state.rbx);
  //printf("bp=%08llx sp=%08llx si=%08llx di=%08llx\n", cpu_state.rbp, cpu_state.rsp, cpu_state.rsi, cpu_state.rdi);
  printf("ax=%08llx bx=%08llx cx=%08llx dx=%08llx\n", cpu_state.rax, cpu_state.rbx, cpu_state.rcx, cpu_state.rdx);
  printf("sp=%08llx bp=%08llx si=%08llx di=%08llx\n", cpu_state.rsp, cpu_state.rbp, cpu_state.rsi, cpu_state.rdi);
  //printf("stack=%08llx %08llx %08llx %08llx\n", *(stackp - 4), *(stackp - 3), *(stackp - 2), *(stackp - 1));
}

// TODO need some unit tests for shr8(), SIGNBIT, etc
