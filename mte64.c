
#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
}; // bl
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
  uint8_t* code;            // ds:dx
  unsigned int len;         // cx
  uintptr_t exec_offset;    // bp
  uintptr_t entry_offset;   // di
  uintptr_t payload_offset; // si
  mut_flags_t flags;        // ax
  mut_routine_size_t routine_size;
};
struct mut_output {
  uint8_t* code;               // ds:dx
  unsigned int len;            // ax
  uint8_t* routine_end_offset; // di
  uint8_t* loop_offset;        // si
};
#endif
// }}}

#define SWAP(x, y)      \
  do {                  \
    typeof(x) SWAP = x; \
    x = y;              \
    y = SWAP;           \
  } while (0)

// {{{
LOCAL struct mut_input* in;
LOCAL struct mut_output* out;
LOCAL uint8_t reg_set_dec[8];
LOCAL uint8_t reg_set_enc[8];
LOCAL uint8_t decrypt_stage[MAX_ADD];
LOCAL uint8_t encrypt_stage[MAX_ADD];
LOCAL uint8_t target_start[100000]; // XXX this should be caller supplied
LOCAL uintptr_t jnz_patch_dec[0x21];
LOCAL uintptr_t jnz_patch_hits[0x21];
LOCAL uintptr_t jnz_patch_enc[0x21];

LOCAL uint32_t arg_code_entry;
LOCAL uint32_t arg_flags;
LOCAL uint32_t arg_size_neg;
LOCAL uint32_t arg_exec_off;
LOCAL uint32_t arg_start_off;
// }}}

#if LOCAL_INTERFACE
// XXX start or end prob means "misc ops"
enum op_t {
  OP_DATA,
  OP_START_OR_END,
  OP_POINTER,
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
  [OP_DATA] = "DATA", [OP_START_OR_END] = "START_OR_END", [OP_POINTER] = "POINTER", [OP_SUB] = "SUB", [OP_ADD] = "ADD", [OP_XOR] = "XOR", [OP_MUL] = "MUL", [OP_ROL] = "ROL", [OP_ROR] = "ROR", [OP_SHL] = "SHL", [OP_SHR] = "SHR", [OP_OR] = "OR", [OP_AND] = "AND", [OP_IMUL] = "IMUL", [OP_JNZ] = "JNZ"
};
LOCAL op_t ops[0x21];
LOCAL uint32_t ops_args[0x21];

// bp = size_neg => intro junk (sign bit!)
//    loop_start => move+crypt ops
//      1        => making loop
//      0        => making decryptor loop end+outro
//     -1        => only when called recursively
LOCAL int phase = 0;
LOCAL uint8_t op_idx = 1;
LOCAL uint8_t op_free_idx = 1;
LOCAL uint8_t op_next_idx = 1;
LOCAL uint8_t op_end_idx;
LOCAL uint32_t* op_off_patch;
LOCAL uint32_t patch_dummy;
LOCAL uint8_t* loop_start;
LOCAL uint8_t junk_len_mask;
LOCAL uint8_t is_8086 = 0;

#define STACK_SIZE 128
LOCAL uint64_t stack[STACK_SIZE], *stackp = stack;
#define PUSH(reg) (assert(stackp < stack + STACK_SIZE), *(stackp++) = (reg))
#define POP(reg) (assert(stackp > stack), (reg) = *(--stackp))
#define CBW(x) (x##h = (x##l & 0x80) ? 0xff : 0)
#define SIGNBIT(x) (((x) << 1) < (x))

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
#define ax (cpu_state.ax)
#define bx (cpu_state.bx)
#define cx (cpu_state.cx)
#define dx (cpu_state.dx)
#define bp (cpu_state.bp)
#define sp (cpu_state.sp)
#define si (cpu_state.si)
#define di (cpu_state.di)
#define al (cpu_state.al)
#define ah (cpu_state.ah)
#define cl (cpu_state.cl)
#define ch (cpu_state.ch)
#define dl (cpu_state.dl)
#define dh (cpu_state.dh)
#define bl (cpu_state.bl)
#define bh (cpu_state.bh)
#define GETLO(reg) ((reg)&0xff)
#define GETHI(reg) (GETLO(((reg) >> 8)))
#define SETLO(reg, val) (reg = GETHI(reg) | ((val)&0xff), val)
#define SETHI(reg, val) (reg = (((val)&0xff) << 8) | GETLO(reg), val)

static void make_ops_table(enum mut_routine_size_t routine_size)
{
  op_idx = 1;
  op_free_idx = 1;
  op_next_idx = 1;

  ops[0] = OP_START_OR_END;
  ops[1] = OP_START_OR_END | 0x80;

  do {
    dx = random();
    ax = random();

    si = bx = op_next_idx;

    ch = ops[op_idx];
    cl = ops[op_idx - 1];

    if (ch == OP_MUL) {
      goto mul_prep;
    } else if (ch == OP_MUL | 0x80) {
      // 0: reg move
      cl = OP_DATA;
      bx++;
    }

    al = al & junk_len_mask;
    if (bl >= al) {
      int carry = bl & 1;
      bl = bl >> 1;
      if ((!carry && dl != 0) || bp != 0) {
      mul_prep:
        al = OP_DATA;
        dx |= 1;
      } else {
        al = OP_POINTER;
      }

      // save_op_idx
      if (ch & 0x80) {
        op_end_idx = GETLO(si);
        al = OP_START_OR_END;
      }
      ops[si] = al;
    } else {
      SWAP(ax, dx);

      // because 12 isn't congruent to the wordsize, there's a very small bias
      // towards 0..3 by 0.002%
      al = al % 12;

      int carry = 0;
      ch &= 0x80;
      if (ch != 0) {
        carry = ax & 1;
        al = al >> 1;
      }
      ax += 3;
      ah = al;
      ops[si] = al;
      dl = ++op_free_idx;
      dh = ++op_free_idx;
      bl = dl;
      bh = cl = 0;
      if (!carry || al >= 6) {
        // inserts the new op, moves the current item along
        SWAP(cl, ch);
      }
      ax ^= cx;
      ops[bx] = al;
      ops[bx + 1] = ah;
    }
    // si <<= 1;
    ops_args[si] = dx;
    op_next_idx++;
    al = op_free_idx;
  } while (al >= op_next_idx);
  printf("ops table (%d, %d, %d)\n", op_idx, op_free_idx, op_next_idx);
  for (int i = 1; i <= op_free_idx; i++) {
    if (ops[i] >= 3) {
      printf("%d\t%-10s (%x)\t%d,%d\n", i, op_to_str[ops[i]], ops[i],
          GETLO(ops_args[i]), GETHI(ops_args[i]));
    } else {
      printf("%d\t%-10s (%x)\t%x\n", i, op_to_str[ops[i]], ops[i], ops_args[i]);
    }
  }
  return;
}

LOCAL uint8_t ptr_reg;
LOCAL uint8_t data_reg;

#define REG_IS_USED 0
#define REG_IS_FREE 0xff

LOCAL uint8_t last_op; // 0,0x8a,0xf7,0xc1,-1
LOCAL uint8_t last_op_flag;

static uint8_t _pick_registers(uint8_t op)
{
  uint8_t pointers[] = { REG_BX, REG_BP, REG_SI, REG_DI };
  uint8_t reg;

  // ptr reg
  do {
    reg = pointers[random() % 4];
  } while (reg_set_enc[reg] == REG_IS_USED);
  reg_set_enc[reg] = REG_IS_USED; // mark used
  ptr_reg = reg;

  // and data reg (or second pointer)
  reg = REG_AX;
  if ((random() & 7) == 0 || last_op_flag == 0) {
    while (reg_set_enc[reg] == REG_IS_USED) {
      reg = pointers[random() % 4];
    };
    reg_set_enc[reg] = REG_IS_USED;
  }
  data_reg = reg;

  return reg;
}
#define LOWER(x) ((x)&0xff)
#define UPPER(x) LOWER(((x) >> 8))

// checks for any pending register allocations
static uint32_t get_op_args(uint8_t i)
{
  bx = 0 + (bl & 0x7f); // clear top
  // printf("bx=%x bh=%x bl=%x\n", bx, bh, bl);
  assert(bx <= 0x21);

  dl = ops[bx];
  ax = bx;
  bx = ops_args[bx];
  if (dl < 3) {
    return bx;
  }

  PUSH(ax);
  PUSH(bx);
  // printf("1) bx=%x bh=%x bl=%x\n", bx, bh, bl);
  assert(bl <= 0x21);
  get_op_args(bx);
  POP(bx);
  bl = bh;
  // printf("2) bx=%x bh=%x bl=%x\n", bx, bh, bl);
  PUSH(dx);
  assert(bl <= 0x21);
  get_op_args(bx);
  ax = bx;
  POP(cx);
  POP(bx);
  assert(bx <= 0x21);
  dh = ops[bx];

  // dh = current op, dl = previous op
  // imul/mul?
  if ((dh -= 0xd) == 0 || (dh += 7) == 0) {
    last_op_flag = dh;
    reg_set_dec[REG_DX] = dh;
  }
  //
  else if (dh < 5) {
    // no junk ops (11, 12, 13, 14)
    // dh range is [6,10]: mul, rol, ror, shl, shr
    if (dl != 0 || (is_8086 != 0 && (
                                        // op [3,13]
                                        ((al -= 0xe) & 0xf) >= 5 ||
                                        // op jnz with a previous mul/rol/ror
                                        (al <= 2 && dh >= 3)))) {
      reg_set_dec[REG_CX] = bh;
      dl = 0x80;
    }
  }
  assert(bx <= 0x21);
  dl = ((dl | cl) & 0x80) | ops[bl];
  ops[bl] = dl;
  return 0;
}

static int generating_enc()
{
  return cpu_state.rdi >= (uintptr_t)decrypt_stage && cpu_state.rdi < (uintptr_t)decrypt_stage + MAX_ADD_LEN;
}
static int generating_dec() { return !generating_enc(); }

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
  *(uint8_t*)&cpu_state.rdi = x;
  cpu_state.rdi++;
  return x;
}
static uint16_t emitw(uint16_t x)
{
  *(uint16_t*)&cpu_state.rdi = x;
  cpu_state.rdi += 2;
  return x;
}
static uint32_t emitd(uint32_t x)
{
  *(uint32_t*)&cpu_state.rdi = x;
  cpu_state.rdi += 4;
  return x;
}
static void emit_mov_imm(uint8_t reg, uint32_t val)
{
  emitb(0xb8 | reg);
  emitd(val);
}
// lower byte of val == 0 then encode mov reg,reg instead
static void emit_mov()
{
  ah = al & 0x80 ? 0xff : 0; // cbw
  printf("emit_mov: ax=%x dx=%x\n", ax, dx);
  if (generating_dec()) {
    bx = ax;
    reg_set_dec[bl] = bh;
  }
  if (dl == 0) {
    bl = 0x8b;
    encode_mrm_dh_s();
    if (!cpu_state.c) {
      POP(ax);
      return;
    }
  }
  al = 0xb8 | al;
  emitb(al);
  SWAP(ax, dx);
  emitd(ax);
  POP(ax);
  return;
}
static void emit_mov_data()
{
  al = data_reg;
  return emit_mov();
}
static void encode_mrm_dh_s() {}
static int try_ptr_advance()
{
  uint32_t bump = -2;
  int rv = 0;

  if (ops[op_idx] != OP_SUB && ops[op_idx] != OP_ADD)
    return rv;
  if (ops[op_idx] == OP_ADD)
    bump = 2;

  // XXX 0 is... OP_DATA?
  if (ops[(ops_args[op_idx] >> 8) & 0xff] == 0) {
    bump += ops_args[ops_args[op_idx] >> 8];
    if ((bump & 0xff) != 0) {
      ops_args[ops_args[op_idx] >> 8] = bump;
      rv--;
    }
  }
  bump = 2;
  if (ops[ops_args[op_idx] & 0xff] == 0) {
    bump += ops_args[ops_args[op_idx] & 0xff];
    if ((bump & 0xff) != 0) {
      ops_args[ops_args[op_idx] & 0xff] = bump;
      rv--;
    }
  }
  return rv;
}

// do some shenanigans with pointers to simulate the behaviour
// get the index back with ((return_value - ops_args)/4)
static uint8_t* get_op_loc(int x)
{
  uint32_t* p = ops_args + 1;
  uint8_t find = x >> 1;
  bx = x;
  for (int i = x * 2; i; i--) {
    if (ops[i] < 3) {
      continue;
    }
    if (LOWER(ops_args[i]) == find) {
      return (uint8_t*)(ops_args + i);
    } else if (UPPER(ops_args[i]) == find) {
      return (uint8_t*)(ops_args + i) + 1;
    }
  }
  return NULL;
}
static void invert_ops()
{
  uint8_t* p1 = get_op_loc(op_end_idx);
  if (p1 == NULL) {
    return;
  }
  op_idx = ((uintptr_t)p1 - (uintptr_t)ops_args) / 4;
  int cur = op_idx;
  while (1) {
    uint8_t* p2 = get_op_loc(op_idx * 2);
    if (p2 == NULL) {
      cur = 0;
    }
    *p1 = cur;
    if ((ops[cur] & 0x7f) == OP_SUB) {
      // check whether it was unaligned
      if (((uintptr_t)p1 - (uintptr_t)ops_args) % 4 == 0) {
        ops[cur] = OP_ADD;
        if (cur == 0) {
          return;
        }
      }
    } else if ((ops[cur] & 0x7f) == OP_ADD) {
      if (((uintptr_t)p1 - (uintptr_t)ops_args) % 4 == 0) {
        // flip tree
        uint8_t tmp = *p1;
        *p1 = *p2;
        *p2 = *p1;
      }
      ops[cur] = OP_SUB;
    } else if ((ops[cur] & 0x7f) == OP_MUL) {
      // mul inv
      cur = LOWER(ops_args[cur]);
      ops_args[cur] = mul_inv(ops_args[cur]);
    } else if ((ops[cur] & 0x7f) == OP_ROL) {
      ops[cur] = OP_ROR;
    } else if ((ops[cur] & 0x7f) == OP_ROR) {
      ops[cur] = OP_ROL;
    }
    // till...
    if (cur == 0) {
      return;
    }
  }
}

// from hacker's delight
uint32_t mul_inv(uint32_t d)
{ // d must be odd.
  uint32_t xn, t;
  xn = d;
loop:
  t = d * xn;
  if (t == 1)
    return xn;
  xn = xn * (2 - t);
  goto loop;
}

static uint32_t exec_enc_stage()
{
  // TODO
  return 0;
}

static uint32_t get_arg_size() { return -arg_size_neg; }

static void make_enc_and_dec(struct mut_input* in, struct mut_output* out)
{
  cx += 16;
  cx = -cx;
  SETLO(cx, cx & 0xfe);
  if (cl == 0) {
    cx -= 2;
  }
  SWAP(ax, di);
  arg_code_entry = ax;
  ax += cx;
  SETLO(ax, ax & 0xfe);
  if (al == 0) {
    ax -= 2;
  }
  PUSH(ax);
  ax = di;
  arg_flags = ax;
  SWAP(ax, cx);
  arg_size_neg = ax;
  SWAP(ax, bp);
  arg_exec_off = ax;
  SWAP(ax, si);
  arg_start_off = si;

  // XXX moved this out of restart
  srandom(time(NULL));
  return restart();
}

// LOCAL long seed = 1;
static void restart()
{
  POP(bp);
  PUSH(bp);
  PUSH(bx);

  // srandom(time(NULL));

  for (int i = 0; i < 8; i++) {
    reg_set_dec[i] = REG_IS_USED;
  }

  cpu_state.rdi = (uintptr_t)decrypt_stage;
  bx = 7;
  make();
  di -= 1;
  if (di != (uintptr_t)decrypt_stage) {
    PUSH(dx);
    PUSH(di);
    PUSH(bp);
    ax = 1;
    exec_enc_stage();
    POP(di);
    SWAP(ax, bp);
    POP(di);
    POP(dx);
  }
  POP(bx);
  POP(ax);
  bp = 0;
  return make();
}

static void make()
{
  PUSH(ax);
  PUSH(bx);
  PUSH(dx);
  PUSH(di);

  ax = 0;
  for (int i = 0; i < 0x21; i++) {
    jnz_patch_dec[i] = 0;
    jnz_patch_hits[i] = 0;
    jnz_patch_enc[i] = 0;
  }
  cx = 0;
  ax = 4;
  PUSH(arg_flags);
  SETHI(arg_flags, MUT_FLAGS_CS_IS_NOT_SS >> 8);

  dx = arg_size_neg;
  cpu_state.rdi = (uintptr_t)encrypt_stage;

  PUSH(bp);
  g_code();
  POP(bp);

  invert_ops();

  POP(ax);
  POP(di);
  POP(dx);

  SETHI(arg_flags, al);
  SETLO(ax, ax & 1);
  is_8086 -= al;
  PUSH(ax);
  g_code_from_ops();
  POP(ax);
  is_8086 += al;

  ax = bx;
  POP(bx);

  ax -= (uintptr_t)patch_dummy;
  if (ax < 0) {
    return restart();
  }
  if (ax == 0 && arg_start_off != 0) {
    return restart();
  }

  POP(bx);
  return;
}

static void g_code()
{
  junk_len_mask = bl;
  return g_code_no_mask();
}
static void g_code_no_mask()
{
  PUSH(dx);
  PUSH(di);
  make_ops_table(bx);
  POP(di);
  POP(dx);
  return g_code_from_ops();
}
static void g_code_from_ops()
{
  printf("g_code_from_ops(): bp=%x\n", bp);
  PUSH(di);
  cpu_state.rdi = (uintptr_t)reg_set_enc;
  ax = -1;
  for (int i = 0; i < 8; i++) {
    if (i == REG_DX || i == REG_SP) {
      reg_set_enc[i] = 0;
    } else {
      reg_set_enc[i] = -1;
    }
  }
  last_op_flag = -1; // al
  bl = op_idx;
  PUSH(bx);
  PUSH(dx);
  // printf("get_op_args(bl=%x)\n", bl);
  get_op_args(bl);
  si = di;
  ptr_and_r_sto();
  POP(dx);
  POP(bx);
  POP(di);

  PUSH(bx);
  if (bp != -1 && bp != 0) {
    // @@do_intro_garbage
    PUSH(bp);
    emit_ops();
    al = 0x90 | data_reg;
    emitb(al);
    POP(ax);
    if (dh & 0x80) {
      dx = ax;
    }
    POP(ax);
    bh = 0xff;
    *((uint8_t*)&cpu_state.rdi) = 0xc3;
    return;
  } else {
    // if (bp == -1 || bp == 0) {
    dx++;
    if (dx != 0) {
      dx--;
      bp--;
      al = ptr_reg;
      emit_mov();
      bp++;
    }
    POP(bx);
    PUSH(di);
    emit_ops();
    if (bp == 0) {
      POP(cx);
      bp--;
      cpu_state.rax = (uintptr_t)&op_off_patch;
      op_off_patch = &patch_dummy;
      printf("g_code_from_ops %llx %llx\n", cpu_state.rax, op_off_patch);
      if ((dh & 0x80) == 0) {
        bp++;
        PUSH(cx);
        PUSH(ax); // offset to patch
        al = last_op_flag;
        if ((al & 0b10110111) == 0b10000111 && bp == arg_start_off) {
          // flip direction
          *((uint8_t*)&cpu_state.rdi - 4) ^= 2;
          last_op_flag <<= 1;
          if (last_op_flag & 0x80) {
            // add -> sub/neg
            bl = 0xf7;
            al = 3;
            return emit_eol_bl();
          }
          return single_ref();
        } else {
          // @@do_end_of_loop
          ax = random();
          al = 0x87 + (al & 2);
          SWAP(ax, bx);
          al = dh;
          // XXX broken?
          return emit_eol_bl();
        }
      } else {
        // null?
        if (cx == (uintptr_t)decrypt_stage + 5) {
          cx -= 5;
          di -= 5;
          reg_set_dec[ptr_reg]--;
          cpu_state.rbx = (uintptr_t)&patch_dummy;
          printf("null? %llx\n", cpu_state.rbx);
          return size_ok();
        }
      }
    } else {
      // @@not_dec_end
      if (dh & 0x80) {
        dh = ptr_reg;
      }
      POP(ax);
      bh = 0xff;
      *((uint8_t*)&cpu_state.rdi) = 0xc3;
      return;
    }
  }
}

static void bl_op_reg_mrm()
{
  al |= 0b00011000;
  SWAP(ax, bx);
  encode_op_mrm();
}
static void encode_op_mrm()
{
  emitb(al);
  SWAP(ax, bx);
  cl = 3;
  al <<= cl;
  al |= dh;
  emitb(al);
  return;
}

static void encode_mrm()
{
  if ((dh & 0x80) == 0) {
    return bl_op_reg_mrm();
  }
  return encode_mrm_ptr();
}
static void encode_mrm_ptr()
{
  dh = ptr_reg;
  cpu_state.c = 0;
  if (bp == -1) {
    return bl_op_reg_mrm();
  } else if (bp != 0) {
    dx = bp;
    bp = di + 1;
    cpu_state.c = 1;
    return;
  }
  PUSH(bx);
  SWAP(al, dh);
  SWAP(ax, bx);
  POP(ax);
  encode_op_mrm();
  op_off_patch = (uint32_t*)cpu_state.rdi; // XXX
  emitd(0);
  return;
}
static void emit_eol_bl()
{
  encode_mrm_ptr();
  return single_ref();
}
static void single_ref()
{
  al = ptr_reg;
  if (generating_dec()) {
    PUSH(ax);
    bp--;
    dl = 0;
    dh = al;
    junk_len_mask >>= 1;
    g_code_no_mask();
    PUSH(dx);
    PUSH(di);
    invert_ops();
    try_ptr_advance();
    POP(di);
    POP(dx);
    PUSH(cx);
    g_code_from_ops();
    POP(cx);
    POP(ax);
    emit_mov();
    if ((ch & 0x80) == 0) {
      goto emit_jnz;
    }
  }
  al |= 0x40;
  emitb(al);
  emitb(al);
emit_jnz:
  al = 0x75;
  emitb(al);
  POP(bx);
  POP(ax);
  cx = ax;
  ax = ax - di - 1;
  emitb(al);
  if ((al & 0x80) == 0) {
    bx = 0;
    return;
  }
  return size_ok();
}

static void size_ok()
{
  encode_retf();
  PUSH(cx);
  cpu_state.rdx = (uintptr_t)&target_start;
  if (generating_enc()) {
    return patch_offsets();
  }
  printf("size_ok(): bx=%llx\n", cpu_state.rbx);
  PUSH(bx);

  bl = 7;
  dx = bp;
  g_code();
  PUSH(di);
  // XXX generate pushes
  POP(bp);
  cx = bp - di;
  if (arg_code_entry != 0) {
    // 5 bytes for jump
    cx += (uintptr_t)&decrypt_stage + 5 - di;
  }
  dx = arg_exec_off;
  ax = dx;
  dx += cx;
  ax += arg_start_off;

  POP(bx);
  if (arg_start_off == 0) {
    dx = ax;
  }
  return patch_offsets();
}

static void patch_offsets()
{
  printf("patch_offsets(): bx=%llx\n", cpu_state.rbx);
  ax = dx;
  patch();
  ax = dx;
  POP(dx);
  cpu_state.rbx = (uintptr_t)op_off_patch;
  patch();
}
static void patch()
{
  ax = ax - arg_size_neg;
  printf("patch(): loc=%p val=%x\n", cpu_state.rbx, cpu_state.eax);
  *((uint32_t*)cpu_state.rbx) = cpu_state.eax;
}

static void encode_retf()
{
  // actually retn
  *((uint8_t*)&cpu_state.rdi) = 0xc3;
}

static void emit_ops()
{
  last_op = 0xff;
  last_op_flag = 0x80;
  bh = 0;
  al = ops[bx];
  ax &= 0x7f;

  printf("emit_ops()\n");
  if (--ax == 0) {
    return;
  }
  dh = ptr_reg;
  if (--ax == 0) {
    return;
  }
  dx = ops_args[bx];
  if (ax & 0x8000) {
    return;
  }

  PUSH(ax);
  PUSH(dx);
  PUSH(bx);
  bl = dh;
  emit_ops();
  POP(bx);
  POP(cx);
  POP(ax);

  if (al == 0xc) {
    return emit_ops_jnz();
  }
}

static void emit_ops_jnz()
{
  if (dl != 0 || dh == ptr_reg) {
    return;
  }
  PUSH(ax);
  PUSH(cx);
  PUSH(bx);
  PUSH(dx);
  emit_mov_data();
  POP(dx);
  al = data_reg;
  ah = last_op;
  if (dh != al || ah != 0) {
    bl = 0x85;
    bl_op_reg_mrm();
  }
  POP(bx);
  al = 0x75;
  emitb(al);
  if (bp != -1) {
    if (generating_enc()) {
      *((uint8_t*)cpu_state.rdi - 1) += 0x57;
    }
    ax = di;
    assert(bx < 0x21);
    SWAP(ax, jnz_patch_dec[bx]);
    jnz_patch_enc[bx] = ax;
  }
  cpu_state.rdi++;
  cpu_state.rdx = cpu_state.rdi;
  return store_data_reg();
}

// emit_ops::@store_data_reg
static void store_data_reg()
{
  POP(bx);
  PUSH(dx);
  emit_ops();
  emit_mov_data();
  POP(dx);
  POP(ax);
  last_op_flag = 0x80;

  if (al == 0xc) {
    bx = dx;
    // XXX prob should be on the 64-bit regs
    dx = di - bx;
    *((uint8_t*)cpu_state.rbx - 1) = dl;
    dh = data_reg;
    dl = 0;
    return;
  }

  ch = ah;
  PUSH(ax);
  if (dl == 0) {
    if (dh == 0x80) {
      al = (al - 5) < 4 ? REG_CX : REG_DX;
      dh = al | 0x58;
      emitb(al);
    } else {
      // emit_ops::@@didnt_push
      if ((dh & 0x80) == 0 && dh != ptr_reg) {
        bl = dh;
        bh = 0;
        reg_set_enc[bx]--;
      }
    }
  }
  // emit_ops::@@emit_op
  POP(ax);
  bl = OPCODE_OR; // or
  al -= 9;
  if (al != 0) {
    bl = OPCODE_AND; // and
    al += 6;
    if (!CBW(a)) {
      assert(ah == 0);
      return emit_ops_maybe_mul();
    }
    assert(ah == 0xff);
    bl = OPCODE_XOR;
    if (++ax) {
      bl = OPCODE_ADD;
      if (is_parity_even(ax)) {
        bl = OPCODE_SUB;
      }
    }
  }

  // emit_ops::@@got_op
  al = data_reg;
  if (dl == 0) {
    dh &= 0b10000111; // mask off reg and mode
    if (bl == OPCODE_SUB) {
      dh |= 0b01000000;
    }
    last_op_flag = dh;
    encode_mrm();
    if (!cpu_state.c) {
      return save_op_done();
    }
    if (al != 0) {
      bp++; // phase change
    }
  }
  // emit_ops::@try_optimization
  bl ^= 0b110; // 0x81,0x35<<3 (sub) => 0xf7,0x33 (neg)
  PUSH(dx);
  dx += 2;
  cpu_state.c = dx < 5;
  POP(dx);

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
  if (!SIGNBIT(ax)) {
    if (bl != 0b00110101) {
      emit_81_ops();
    } else if (++dx != 0) {
      --dx;
      emit_81_ops();
    }
    dh = al;
    al = 2; // F7,2<<3 => not
    return emit_f7_op();
  }
  if (!SIGNBIT(dx)) {
    dx = -dx;
    bl ^= 0b00101000; // toggle add/sub
  }
  // emit_ops::@emit_inc
  al = (bl == 0b101 ? 0x40 : 0x48) | al; // add,sub=>inc,dec
  emitb(al);
  if (--dx != 0) {
    emitb(al);
  }
  return save_op_done();
}
// emit_ops::@@save_op_done
static void save_op_done()
{
  last_op = ch;
  dx = data_reg;
  return;
}
static void emit_f7_op()
{
  bl = 0xf7;
  ch = bl; // last_op_flag
  return encode_mrm();
}
// emit an 81 series op, unless al=0 (emit op in bl and store word)
static void emit_81_ops()
{
  union mrm_t {
    uint8_t byte;
    struct {
      // note to self: bitfields are right to left
      uint8_t reg : 3;
      uint8_t op : 3;
      uint8_t mod : 2;
    };
  } mrm;

  // implied by the `or al,al` at entry (or clears c)
  cpu_state.c = 0;
  if (al != 0) {
    /*bl &= 0b00111000; // op
     *al |= 0b11000000; // reg,imm16
     *bl |= al; */
    mrm = (union mrm_t) { .mod = 0b11,
      .op = (bl >> 3),
      .reg = al };
    bl = mrm.byte;
    al = dl;

    // if imm16 == signextend(imm8), optimize into imm8
    CBW(a);
    ax ^= dx;
    cpu_state.c = ax == 0;
    al = ax != 0 ? 0x81 : 0x83; // imm16 or imm8
    emitb(al);
  }

  SWAP(ax, bx);
  emitb(al);
  SWAP(ax, dx);

  // if al was 0 it's a 3-byte (or 2-byte if C was set)
  // originally written like this
  /*emitw(ax);
   *if (cpu_state.c) {
   *  cpu_state.rdi--;
   *}*/
  // emit a sign-extended imm8, or otherwise full word size
  if (cpu_state.c) {
    emitb(al);
  } else {
    emitd(ax);
  }
  return;
}

static void emit_ops_maybe_mul()
{
  cl = 4; // OPCODE_F7_MUL
  if (al != 0) {
    cx++; // OPCODE_F7_IMUL
    if (al != 7) {
      ax++;
      return emit_ops_not_mul();
    }
  }
  // emit_ops::@@emit_mov_dx
  if (dl != 0) {
    ah = REG_DX;
    al = 0xba; // mov dx,arg
    emitb(al);
    SWAP(ax, dx);
    emitd(ax);
  }
  SWAP(ax, cx);
  return emit_f7_op();
}
static void emit_ops_not_mul()
{
  if (cpu_state.c = al < 4) {
    al -= 2;
  }
  if (dl == 0) {
    return emit_ops_maybe_rol();
  }

  PUSH(ax);
  al = REG_CX;
  ch = bl = OPCODE_MOV_REG_MRM8;
  if (dh == REG_BX) {
    bl = OPCODE_MOV_REG_MRM16; //bx++;
  }
  emit_op_mrm();
  POP(ax);
  PUSH(ax);
  if (!cpu_state.c) {

    ah = 0x1f;
    al = 0x80; // 80-series opcode
    if ((is_8086 & ah) != 0) {
      // emit `AND CL,1Fh`.  not needed nowadays.
      emitb(al);
      al = (union mrm_t) { .mod = 0b11, .op = OPCODE_80_AND, .reg = REG_CL }.byte;
      emitw(ax);
    }
  }
  POP(ax);

  bl = 0xd3; // ROL reg,CL
  dl = REG_CL;
  return emit_ops_emit_bl();
}
static void emit_ops_maybe_rol()
{
  bl = 0xc1;
  if (cpu_state.c) {
    ch = bl;
    if (dl & 8) {
      dl = -dl;
      al ^= 1;
    }
  }

  // clamp the arg to 15.  TODO should probably be 31 now.
  dl &= 0xf;

  // don't emit rotate by 0
  if (dl == 0) {
    dh = data_reg;
    dl = 0;
    return;
  }

  if (dl != 1 && ah == is_8086) {
    // can encode imm8
    return emit_ops_emit_bl();
  }

  bl = 0xd1; // ROL arg,1
  if (dl < 3) {
    return emit_ops_emit_bl();
  }

  PUSH(ax);
  al = 0xb1; // MOV CL,imm8
  ah = dl;
  emitw(ax);
  // dont_mask_cl
  POP(ax);
  bl = 0xd3; // ROL arg,CL
  dl = REG_CL;
  return emit_ops_emit_bl();
}
static void emit_op_mrm()
{
  if (dh == al) {
    return;
  }
  if (is_8086 != 0xff) {
    // XXX look for the dec is_8086
    return bl_op_reg_mrm();
  }
  PUSH(ax);
  if (dh != 0 && al != 0) {
    POP(ax);
    return bl_op_reg_mrm();
  }
  if (bp == 0 && al == ptr_reg) {
    POP(ax);
    return bl_op_reg_mrm();
  }
  POP(bx);
  al = 0x90 | al;
  emitb(al);
  return;
}
static void emit_ops_emit_bl()
{
  dh = data_reg;
  bl_op_reg_mrm();
  SWAP(ax, dx);
  if (bl == 0xc1) {
    // ROL reg,imm8
    emitb(al);
    return save_op_done();
  }

  cpu_state.c = al & 1;
  al >>= 1;
  if (cpu_state.c) {
    // reg,reg
    printf("emitting op=%x mrm=%x\n", bl, (al << 1) | 1);
    return save_op_done();
  }

  SWAP(ax, bx);
  emitb(al);
  SWAP(ax, dx);
  emitb(al);
  return save_op_done();
}

int is_parity_even(uint64_t x)
{
  return __builtin_parity(x) == 0;
}

// register picking {{{
static void pick_ptr_register(uint8_t* p)
{
  ax = random();
  if ((al &= 3) == 0) {
    al = 7;
  }
  return mark_and_emit(p);
}
static void mark_and_emit(uint8_t* p)
{
  ax = al;
  bx = ax;
  SWAP(bh, reg_set_enc[bl]);
  if (bh == 0) {
    return pick_ptr_register(p);
  }
  *p = al;
  di++;
}
static void ptr_and_r_sto()
{
  pick_ptr_register(&ptr_reg);
  ax = random() & 7;
  if (al == 0) {
    return mark_and_emit(&data_reg);
  }
  al = 0;
  if (al == last_op_flag) {
    return mark_and_emit(&data_reg);
  }
  return pick_ptr_register(&data_reg);
}
// }}}

static void encrypt_target()
{
  // entry not zero
  // fix pops
  // emit jump
  // emit nops for alignment

  // ... bp is the segment of the ds:dx
}

struct mut_output* mut_engine(struct mut_input* f_in,
    struct mut_output* f_out)
{
  in = f_in;
  out = f_out;
  stackp = stack;

  PUSH((uintptr_t)in->code);
  PUSH((uintptr_t)in->code);
  PUSH((uintptr_t)in->exec_offset);
  dx = (uintptr_t)in->code;
  cx = in->len;
  bp = in->exec_offset;
  di = in->entry_offset;
  si = in->payload_offset;
  bx = in->routine_size;
  ax = in->flags;

  make_enc_and_dec(in, out);
  // returns dx = end of routine?
  // returns bp = result of routine?
  encrypt_target();

  return out;
}
