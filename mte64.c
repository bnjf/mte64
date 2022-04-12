
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
  uint8_t *code;            // ds:dx
  unsigned int len;         // cx
  uintptr_t exec_offset;    // bp
  uintptr_t entry_offset;   // di
  uintptr_t payload_offset; // si
  mut_flags_t flags;        // ax
  mut_routine_size_t routine_size;
};
struct mut_output {
  uint8_t *code;               // ds:dx
  unsigned int len;            // ax
  uint8_t *routine_end_offset; // di
  uint8_t *loop_offset;        // si
};
#endif
// }}}

#define SWAP(x, y)                                                             \
  do {                                                                         \
    typeof(x) SWAP = x;                                                        \
    x = y;                                                                     \
    y = SWAP;                                                                  \
  } while (0)
#define PUSH(reg) (assert(sp < stack + 128), *(sp++) = (reg))
#define POP(reg) (assert(sp > stack), (reg) = *(sp--))

// {{{
LOCAL struct mut_input *in;
LOCAL struct mut_output *out;
LOCAL uint8_t reg_set_dec[8];
LOCAL uint8_t reg_set_enc[8];
LOCAL uint8_t decrypt_stage[MAX_ADD];
LOCAL uint8_t encrypt_stage[MAX_ADD];
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
  OPCODE_MOV_IMM = 0xB8
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
#endif

LOCAL uint8_t opcodes[] = {[OP_ADD] = OPCODE_ADD,
                           [OP_OR] = OPCODE_OR,
                           [OP_AND] = OPCODE_AND,
                           [OP_SUB] = OPCODE_SUB,
                           [OP_XOR] = OPCODE_XOR};
LOCAL char *const op_to_str[] = {
    [OP_DATA] = "DATA",       [OP_START_OR_END] = "START_OR_END",
    [OP_POINTER] = "POINTER", [OP_SUB] = "SUB",
    [OP_ADD] = "ADD",         [OP_XOR] = "XOR",
    [OP_MUL] = "MUL",         [OP_ROL] = "ROL",
    [OP_ROR] = "ROR",         [OP_SHL] = "SHL",
    [OP_SHR] = "SHR",         [OP_OR] = "OR",
    [OP_AND] = "AND",         [OP_IMUL] = "IMUL",
    [OP_JNZ] = "JNZ"};
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
LOCAL uint32_t *op_off_patch;
LOCAL uint32_t patch_dummy;
LOCAL uint8_t *loop_start;
LOCAL uint8_t junk_len_mask;
LOCAL uint8_t is_8086 = 0;

LOCAL uint32_t stack[128];
LOCAL uint32_t ax, cx, dx, bx, *sp = stack, bp, si, di;
LOCAL uint8_t *ah = (uint8_t *)(&ax) + 1, *al = (uint8_t *)&ax;
LOCAL uint8_t *ch = (uint8_t *)(&cx) + 1, *cl = (uint8_t *)&cx;
LOCAL uint8_t *dh = (uint8_t *)(&dx) + 1, *dl = (uint8_t *)&dx;
LOCAL uint8_t *bh = (uint8_t *)(&bx) + 1, *bl = (uint8_t *)&bx;
#define al (*al)
#define ah (*ah)
#define cl (*cl)
#define ch (*ch)
#define dl (*dl)
#define dh (*dh)
#define bl (*bl)
#define bh (*bh)
#define GETLO(reg) ((reg)&0xff)
#define GETHI(reg) (GETLO(((reg) >> 8)))
#define SETLO(reg, val) (reg = GETHI(reg) | ((val)&0xff), val)
#define SETHI(reg, val) (reg = ((val) << 8) | GETLO(reg), val)

static void make_ops_table(enum mut_routine_size_t routine_size) {
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

#define REG_AX 0
#define REG_CX 1
#define REG_DX 2
#define REG_BX 3
#define REG_SP 4
#define REG_BP 5
#define REG_SI 6
#define REG_DI 7

LOCAL uint8_t ptr_reg;
LOCAL uint8_t data_reg;

#define REG_IS_USED 0
#define REG_IS_FREE 0xff

LOCAL uint8_t last_op; // 0,0x8a,0xf7,0xc1,-1
LOCAL uint8_t last_op_flag;

static uint8_t _pick_registers(uint8_t op) {
  uint8_t pointers[] = {REG_BX, REG_BP, REG_SI, REG_DI};
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
static uint32_t get_op_args(uint8_t i) {
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
  printf("1) bx=%x bh=%x bl=%x\n", bx, bh, bl);
  get_op_args(bl);
  POP(bx);
  printf("2) bx=%x bh=%x bl=%x\n", bx, bh, bl);
  bl = bh;
  PUSH(dx);
  get_op_args(bl);
  ax = bx;
  POP(cx);
  POP(bx);
  bx = bl;
  // printf("..bx=%x bh=%x bl=%x\n", bx, bh, bl);
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
  dl = ((dl | cl) & 0x80) | ops[bx];
  ops[bx] = dl;
  return 0;
}

static int generating_enc() {
  return out->code >= decrypt_stage && out->code < decrypt_stage + MAX_ADD_LEN;
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
static uint8_t encode_mrm_dh_s(uint8_t op, uint8_t src, uint8_t dst) {
  if (dst & 0x80) {
    return encode_mrm_ptr(op, src);
  }
  return emit_op_mrm(op, src, dst);
}
static uint8_t bl_op_reg_mrm(uint8_t op, uint8_t src, uint8_t dst) {
  return encode_op_mrm(op, 3, src, dst);
}
static uint8_t encode_op_mrm(uint8_t op, uint8_t mode, uint8_t src,
                             uint8_t dst) {
  emitb(op);
  return (emitb((mode << 6) | (src << 3) | dst));
}
static uint16_t emit_ops(uint8_t i) {

  last_op_flag = 0x80;
  last_op = 0xff;
  dx = 0xff00;

  if (ops[i] == OP_START_OR_END) {
    return dx;
  }

  dx = (ptr_reg << 8);
  if (ops[i] == OP_POINTER) {
    return dx;
  }

  dx = ops_args[i];
  if (ops[i] == OP_DATA) {
    return dx;
  }

  // loop!
  dx = emit_ops(UPPER(dx));
  // now cx has op_args[i]

  // XXX what's emit_ops return in al?
  // return 0,0xff00 if op == 1
  // return 0,0x${ptr}00 if op == 2
  // return -2,args if op == 0
  if (ops[i] == OP_JNZ) {
    // move regN,data
    // test data,data (if we haven't created an op)
    // jnz over
    // (rest of table)
    // over:

    // XXX don't jnz during ptr,reg ops?
    if (LOWER(dx) || UPPER(dx) == ptr_reg) {
      return dx;
    }

    emit_mov_data(dx);
    if (UPPER(dx) != data_reg || last_op != 0) {
      bl_op_reg_mrm(0x85, data_reg, UPPER(dx));
    }
    emitb(0x75);
    if (phase != -1) {
      if (generating_enc()) {
        // trap on jnz for the staged encrypter
        *(out->code - 1) = 0xcc;
      }
      // XXX prob just jnz_patch_enc[i] = 0
      jnz_patch_enc[i] = jnz_patch_dec[i];
      jnz_patch_dec[i] = (uintptr_t)out->code;
    }
    emitb(0); // place holder
    uint8_t *patch = out->code;
    // stack: op_args[i], (op - 2)

    // fill
    uint16_t rv = emit_ops(LOWER(ops_args[i]));
    // move next op's arg (reg) into data
    emit_mov_data(rv);
    last_op_flag = 0x80;
    *(patch - 1) = out->code - patch;
    return (data_reg << 8) | 0; // 0 -> OP_DATA?
  }

  int attempts = 8;
  uint8_t reg = LOWER(dx) == 0 ? UPPER(dx) : -1; // XXX i guess
  if (LOWER(dx) == 0 && UPPER(dx) == data_reg) {
    // pick a reg
    if ((last_op_flag & 0x80) == 0 &&
        ((last_op_flag & 7) == 0 ||
         ((last_op_flag & 7) != ptr_reg && (last_op_flag & 7) >= REG_BX))) {
      // flip the order of the last op
      *(out->code - 2) ^= 2;
      reg = last_op_flag;
      if (last_op_flag & 0x40) {
        // emit a NEG reg
        emitb(0xf7);
        emitb(0xd8 | last_op_flag);
      }
    } else {
      reg = random();
      while (attempts-- && reg_set_enc[reg = (reg + 1) & 7] == REG_IS_USED) {
        if (reg != REG_CX && (ops[i] & 0x80) != 0) {
          emit_mov(reg, data_reg);
          break;
        }
      }
      if (attempts == 0) {
        emitb(0x50 | reg);
      }
    }
    reg_set_enc[reg] = REG_IS_USED;
  }

  // @@store_data_reg
  uint16_t rv = emit_ops(LOWER(ops_args[i]));
  // move next op's arg (reg) into data
  emit_mov_data(rv);
  last_op_flag = 0x80;
  // @@op_not_jnz
  if (dl == 0) {
    uint8_t *reg_used = ((uint8_t *)&dx);
    if (dh == 0x80) {
      // if we pushed
      switch (ops[i]) {
      case OP_ROL:
      case OP_ROR:
      case OP_SHL:
      case OP_SHR:
        SETHI(dx, REG_CX);
        emitb(0x58 | REG_CX);
        break;
      case OP_MUL:
        SETHI(dx, REG_DX);
        emitb(0x58 | REG_DX);
      default:
        assert(0);
      }
    }
    // ops[i] => (1,2)
    // if (dh != 0x80 && (ops[i] != *reg_used)) {
    if (*reg_used >= 0x80) {
      // if we didn't push, and the op is
      //   start and we didn't use cx
      //   pointer and didn't use dx
      switch (*reg_used) {
      case REG_CX:
        // rotates/shifts during arith ops (we don't need the shift count
        // anymore)
        if (ops[i] == OP_START_OR_END)
          reg_set_enc[REG_CX] = REG_IS_FREE;
        break;
      case REG_DX:
        // mul inside of pointer ops (we always set dx prior, and we don't
        // use part of the result later)
        if (ops[i] == OP_POINTER)
          reg_set_enc[REG_DX] = REG_IS_FREE;
        break;
      }
    }
  }

  if (ops[i] == OP_MUL || ops[i] == OP_IMUL) {
    uint8_t f7_op = 4;
    if (ops[i] == OP_IMUL) {
      f7_op = 5; // cl
    }
    if (dl != 0) {
      emitb(OPCODE_MOV_IMM | REG_DX);
      emitd(ops_args[i]);
      dx = 0x02BA;
    }
    last_op = 0xf7;
    if (dh & 0x80) {
      // reg,reg operation
      emitb(0xf7);
      // MUL/IMUL
      emitb(0xc0 | (f7_op << 3) | data_reg);
    } else {
      // phase change!
      // size_neg (pointer) -> out_code
      // used for recording the start of the loop
      dx = phase;
      phase = (uintptr_t)out->code;

      if (phase == -1) {
      }
    }
  }
}

static uint8_t encode_mrm(uint16_t dx, opcode_t op, uint8_t reg) {
  if (dh & 0x80) {
    return bl_op_reg_mrm(op, reg, dh);
  }
  return encode_mrm_ptr(op, reg);
}

static uint8_t encode_mrm_ptr(opcode_t op, uint8_t reg1) {
  switch (phase) {
  case -1:
    return bl_op_reg_mrm(op, reg1, ptr_reg);
  case 0: {
    // segment overrides, not needed nowadays L556
    uint8_t mode = 0;
    // mrm byte is fortunately more straightforward
    encode_op_mrm(op, 0x80, reg1, ptr_reg);
    op_off_patch = (uint32_t *)out->code;
    emitd(0);
    return 0; // XXX
  }
  default:
    dx = (uintptr_t)phase;
    phase = (uintptr_t)out->code + 1;
    return 0; // XXX (stc)
  }
  assert(0);
}

// flag is 0 (or 0x20 if on 8086) during encrypter gen
// if "run on different cpu" is set,
//   flag is 0xff (or 0x1f if on 8086) during dec gen
//
// we'll assume we're not on an 8086.
static uint8_t emit_op_mrm(opcode_t op, uint8_t reg1, uint8_t reg2) {
  if (reg1 == reg2) {
    return reg1;
  }
  // dec somewhere.. L245.
  if (is_8086 != 0xff) {
    return bl_op_reg_mrm(op, reg1, reg2);
  }
  // otherwise optimize to XCHG AX,reg
  if (reg1 == REG_AX || reg2 == REG_AX) {
    uint8_t reg_used = reg1 + reg2 - REG_AX;
    if (phase == 0 || reg_used != ptr_reg) {
      emitb(0x90 | (reg1 + reg2 - REG_AX));
      return reg1;
    }
  } else {
    return bl_op_reg_mrm(op, reg1, reg2);
  }
}

static uint8_t emitb(uint8_t x) {
  // out->code = (uint8_t *)di;
  return *(out->code++) = x;
}
static uint16_t emitw(uint16_t x) {
  // out->code = di;
  *(out->code++) = x >> 8;
  *(out->code++) = x;
  return x;
}
static uint32_t emitd(uint32_t x) {
  // out->code = di;
  *(out->code++) = x >> 24;
  *(out->code++) = x >> 16;
  *(out->code++) = x >> 8;
  *(out->code++) = x;
  return x;
}
static void emit_mov_imm(uint8_t reg, uint32_t val) {
  emitb(0xb8 | reg);
  emitd(val);
}
// phase -1,0,1,size
static int emit_mov_reg(uint8_t a, uint8_t b) {
  if (a == b)
    return 0;
  if (phase == 0 && generating_dec() && (a == REG_AX || b == REG_AX)) {
    // ... optimize to XCHG AX,reg
    uint8_t reg = (a + b) - REG_AX;
    if (reg != ptr_reg) {
      emitb(0x90 | reg);
      return 0;
    }
  }
  // MOV REG,imm
  if ((b & 0xff) == 0) {
    return 0;
  }
  // MOV REG,[ptr+off16]
  // MOV [ptr+off16],REG
  // MOV REG,REG
  emitb(0x8b);
  if (b & 0x80) {
    // ptr
    b = (ptr_reg << 8) | (b & 0xff);
    if (++phase == 0) {
      phase--;
      emitb(0xc0 | (a << 3) | b);
      return 0;
    }
    if (--phase != 0) {
      int rv = phase;
      phase = (long int)(out->code) + 1;
      return rv;
    }
    emitb((a << 3) | b);
    op_off_patch = (uint32_t *)out->code;
    emitd(0); // offset to patch
    return 0;
  } else {
    // reg
    emitb(0xc0 | (a << 3) | b); // XXX order
    return 0;
  }
}
// lower byte of val == 0 then encode mov reg,reg instead
static void emit_mov() {}
#if 0
static void emit_mov(uint8_t reg, uint32_t val) {
  if (generating_dec()) {
    reg_set_dec[reg] = REG_IS_USED;
  }
  if (val & 0xff) {
    emit_mov_imm(reg, val);
  } else {
    if ((val = emit_mov_reg(reg, (val >> 8)))) {
      // XXX val is the phase returned by emit_mov_reg
      emit_mov_imm(reg, val);
    }
  }
}
#endif

static void emit_mov_data(uint32_t val) { emit_mov(data_reg, val); }
// XXX takes bl=routine_size, dx=arg_size_neg, di=buf
static int try_ptr_advance() {
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
static uint8_t *get_op_loc(int x) {
  uint32_t *p = ops_args + 1;
  uint8_t find = x >> 1;
  bx = x;
  for (int i = x * 2; i; i--) {
    if (ops[i] < 3) {
      continue;
    }
    if (LOWER(ops_args[i]) == find) {
      return (uint8_t *)(ops_args + i);
    } else if (UPPER(ops_args[i]) == find) {
      return (uint8_t *)(ops_args + i) + 1;
    }
  }
  return NULL;
}
static void invert_ops() {
  uint8_t *p1 = get_op_loc(op_end_idx);
  if (p1 == NULL) {
    return;
  }
  op_idx = ((uintptr_t)p1 - (uintptr_t)ops_args) / 4;
  int cur = op_idx;
  while (1) {
    uint8_t *p2 = get_op_loc(op_idx * 2);
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
uint32_t mul_inv(uint32_t d) { // d must be odd.
  uint32_t xn, t;
  xn = d;
loop:
  t = d * xn;
  if (t == 1)
    return xn;
  xn = xn * (2 - t);
  goto loop;
}

#if 0
static int generate_code_from_table(enum mut_routine_size_t routine_size) {
  memset(&reg_set_enc, -1, 8);
  reg_set_enc[REG_DX] = 0;
  reg_set_enc[REG_SP] = 0;

  last_op_flag = -1;
  // XXX get_op_args, but also marks cx or dx used
  uint32_t arg = get_op_args(op_idx);
  pick_registers(arg);

  // -1: post crypt ops junk (forward and reverse)
  //  0: loop end (ptr incr, jnz loop_start, <junk>)
  //  1: loop
  switch (phase) {
  case -1:
    // making post crypt ops junk {{{
    {
      uint8_t *pre_emit_loc = out->code;
      emit_ops(op_idx);
      if (phase != 0) {
        if (dx & 0x8000) {
          dx = (ptr_reg << 8) | (dx & 0xff);
        }
        bx = 0xff00;
        *out->code = 0xc3;
        return (long int)pre_emit_loc; // XXX
      }
      // XXX if we only made a move?
      if (pre_emit_loc == decrypt_stage + 5) {
        pre_emit_loc -= 5;
        out->code -= 5;
        reg_set_dec[ptr_reg] = REG_IS_FREE;
      }
      bx = (uintptr_t)&patch_dummy; // XXX bogus
      goto size_ok;
    }
    break;
    // }}}
  case 0:
    // making loop end and outro junk {{{
    {
      emit_ops(op_idx);
      phase--;
      uint8_t *hold = op_off_patch;
      op_off_patch = (uint8_t *)&patch_dummy;
      int need_increment_ptr = 1;
      if (generating_dec()) {
        phase++;
        // 1x 11x 111
        // ^  ^   `-  want 7 (bx+disp16)
        // |  `-      want 0 or 1 (XXX unsure, prob from low 3 shifted)
        // `-         imm16, 0x40 means op was sub
        if ((last_op_flag & 0xb7) == 0x87 && in->payload_offset == 0) {
          // if we generated xor/add/sub, flip direction
          *(out->code - 6) ^= 2;
          last_op_flag <<= 1;
          if (last_op_flag & 0x80) {
            // emit a neg too
            emitb(0xf7);
            emitb(3);
            op_off_patch = out->code;
            emitw(0);
          }
        }
        phase--;

        in->routine_size >>= 1;
        generate_code(in->routine_size);
        invert_ops();
        need_increment_ptr = try_ptr_advance() == 0;
        generate_code_from_table(in->routine_size);

        emit_mov(ptr_reg, data_reg); // XXX mov [ptr+off],data
      }
      if (need_increment_ptr) {
        emitb(0x40 | ptr_reg);
        emitb(0x40 | ptr_reg);
      }
      emitb(0x75);
      int8_t delta = out->code - loop_start + 2;
      if (delta >= 0) {
        return 0;
      }
      emitb(delta);
    size_ok:
      // emitb(0xc3);
      *out->code = 0xc3;

      if (generating_dec()) {
        in->routine_size = MUT_ROUTINE_SIZE_MEDIUM;
        generate_code(in->routine_size);
        // TODO pushes
        // TODO adjust offsets (L987)
      }

      printf("%x %x %x\n", hold, op_off_patch, patch_dummy);
      assert(hold);

      // patch offsets
      uintptr_t target = (uintptr_t)out->code;
      target -= in->len;
      hold[0] = (uint8_t)target;
      hold[1] = (uint8_t)target >> 8;
      hold[2] = (uint8_t)target >> 16;
      hold[3] = (uint8_t)target >> 24;
      op_off_patch[0] = (long int)target;
      op_off_patch[1] = (long int)target >> 8;
      op_off_patch[2] = (long int)target >> 16;
      op_off_patch[3] = (long int)target >> 24;
      return 0;
    }
    break;
    // }}}
  case 1:
    // making loop {{{
    {
      uint8_t *patch1, *patch2;
      phase--;
      emit_mov(ptr_reg, in->len);
      patch1 = out->code;
      phase++;
      emit_ops(op_idx);
      if (generating_enc()) {
        emitb(0xc3);
        break;
      }
      phase = -1;
      if (ptr_reg & 0x80) {
        // did we only encode a move?
        if (out->code == decrypt_stage + 5) {
          out->code -= 5;
          reg_set_dec[ptr_reg]--;
        }
      }
      *out->code = 0xc3; // retf

      // outro junk (phase is -1)
      generate_code(MUT_ROUTINE_SIZE_MEDIUM);

      // TODO pushes (L939)

      // offset patching (L986)
      patch2 = op_off_patch;
      if (in->entry_offset != 0) {
        patch1 += 5;
        patch2 += 5;
      }
      if (in->payload_offset == 0) {
        patch1 += in->exec_offset;
        patch2 += in->exec_offset;
      }
      uint8_t *hold = out->code;
      out->code = patch1;
      emitd(in->len); // XXX
      out->code = patch2;
      emitd(in->len); // XXX
      out->code = hold;

      phase = out->len;
      break;
    }
    // }}}
  default:
    // intro junk if signed, otherwise loop start
    emit_ops(op_idx);
    emitb(0x90 | data_reg); // xchg ax,reg
    emitb(0xc3);            // retf
    phase = 0;
    break;
  }

  return 0;
}
#endif

static uint32_t exec_enc_stage() {
  // TODO
  return 0;
}

static uint32_t get_arg_size() { return -arg_size_neg; }

static void make_enc_and_dec(struct mut_input *in, struct mut_output *out) {
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
  *sp++ = ax;
  ax = di;
  arg_flags = ax;
  SWAP(ax, cx);
  arg_size_neg = ax;
  SWAP(ax, bp);
  arg_exec_off = ax;
  SWAP(ax, si);
  arg_start_off = si;
  return restart();
}

static void restart() {
  POP(bp);
  PUSH(bp);
  PUSH(bx);

  srandom(time(NULL));

  for (int i = 0; i < 8; i++) {
    reg_set_dec[i] = REG_IS_USED;
  }

  di = (uintptr_t)decrypt_stage;
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

static void make() {
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
  SETHI(arg_flags, MUT_FLAGS_CS_IS_NOT_SS);

  dx = arg_size_neg;
  di = (uintptr_t)encrypt_stage;

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

static void g_code() {
  junk_len_mask = bl;
  return g_code_no_mask();
}
static void g_code_no_mask() {
  PUSH(dx);
  PUSH(di);
  make_ops_table(bx);
  POP(di);
  POP(dx);
  return g_code_from_ops();
}
static void g_code_from_ops() {
  PUSH(di);
  di = (uintptr_t)reg_set_enc;
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
  if (bp == -1 || bp == 0) {
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
    emit_ops(bl);
    if (bp == 0) {
      POP(cx);
      bp--;
      op_off_patch = &patch_dummy;
      if ((dh & 0x80) == 0) {
        bp++;
        PUSH(cx);
        PUSH(ax);
        al = last_op_flag;
        // TODO
      }
    }
  }
}

static void pick_ptr_register(uint8_t *p) {
  ax = random();
  if ((al &= 3) == 0) {
    al = 7;
  }
  return mark_and_emit(p);
}
static void mark_and_emit(uint8_t *p) {
  ax = al;
  bx = ax;
  SWAP(bh, reg_set_enc[bl]);
  if (bh == 0) {
    return pick_ptr_register(p);
  }
  // need to stosb
  // printf("mark and emit: %x, %x, %x\n", ax, bx, di);
  *p = al;
  di++;
}
static void ptr_and_r_sto() {
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
static void encrypt_target() {
  // entry not zero
  // fix pops
  // emit jump
  // emit nops for alignment

  // ... bp is the segment of the ds:dx
  exec_enc_stage(get_arg_size());
}

struct mut_output *mut_engine(struct mut_input *f_in,
                              struct mut_output *f_out) {
  in = f_in;
  out = f_out;

  *sp++ = (uintptr_t)in->code;
  *sp++ = (uintptr_t)in->code;
  *sp++ = (uintptr_t)in->exec_offset;
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
