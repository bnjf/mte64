
#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
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
  MUT_ROUTINE_SIZE_TINY = (2 << 0) - 1,
  MUT_ROUTINE_SIZE_SMALL = (2 << 1) - 1,
  MUT_ROUTINE_SIZE_MEDIUM = (2 << 2) - 1,
  MUT_ROUTINE_SIZE_BIG = (2 << 3) - 1
}; // bl
struct mut_input_flags {
  unsigned int preserve_ax : 1;
  unsigned int preserve_cx : 1;
  unsigned int preserve_dx : 1;
  unsigned int preserve_x : 1;
  unsigned int preserve_sp : 1;
  unsigned int preserve_bp : 1;
  unsigned int preserve_si : 1;
  unsigned int preserve_di : 1;
  unsigned int run_on_different_cpu : 1; // NOTUSED
  unsigned int cs_is_not_ds : 1;         // NOTUSED
  unsigned int cs_is_not_ss : 1;         // NOTUSED
  unsigned int dont_align : 1;           // paragraph boundary alignment
};

struct mut_input {
  uint8_t *code;                // ds:dx
  unsigned int len;             // cx
  uintptr_t exec_offset;        // bp
  uintptr_t entry_offset;       // di
  uintptr_t payload_offset;     // si
  struct mut_input_flags flags; // ax
  enum mut_routine_size_t routine_size;
};
struct mut_output {
  uint8_t *code;               // ds:dx
  unsigned int len;            // ax
  uint8_t *routine_end_offset; // di
  uint8_t *loop_offset;        // si
};
#endif
// }}}

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
// }}}

#if LOCAL_INTERFACE
enum op_t {
  OP_DATA,
  OP_START_OR_END, // XXX prob means "misc ops"
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
#endif
LOCAL op_t ops[0x21];
LOCAL uint32_t ops_args[0x21];

// bp = size_neg => intro junk
//      1        => making loop
//      0        => making decryptor loop end+outro
//     -1        => only when called recursively
LOCAL int phase = 0;
LOCAL uint8_t op_idx = 1;
LOCAL uint8_t op_free_idx = 1;
LOCAL uint8_t op_next_idx = 1;
LOCAL uint8_t op_end_idx;
LOCAL uint8_t *op_off_patch;
LOCAL uint8_t patch_dummy[4];
LOCAL uint8_t *loop_start;

static void make_ops_table(enum mut_routine_size_t routine_size) {

  ops[0] = 0x81;
  ops[1] = 1;

  while (1) {
    uint32_t arg = random();
    uint8_t next_op = ops[op_next_idx];
    uint8_t current_op = ops[op_next_idx - 1];

    if (current_op == 6) {
      arg |= 1;
      if (phase == 0) {
        next_op = 2; // ptr
      }
      goto save_op_idx;
    }
    if (current_op == 0x86) {
      // 0 == data move
      next_op = 0;
      op_next_idx++;
    }
    uint32_t pick = random();
    if ((pick & routine_size) >= op_next_idx) {
      if ((op_next_idx & 1) == 0 || next_op != 0) {
        next_op = 0;
        if ((arg & 255) != 0 && phase == 0) {
          next_op = 2; // ptr
        }
      }
    save_op_idx:
      if (current_op & 0x80) {
        op_end_idx = op_next_idx;
        next_op = 1; // end
      }
      ops[op_next_idx] = next_op;
    } else {
      // random ops
      pick = arg % 12;
      if (current_op & 0x80) {
        pick >>= 1;
      }
      pick += 3;
      op_free_idx += 2;
      next_op = 0;
      if ((arg & 1) == 0 || pick >= 6) {
        uint8_t tmp;
        tmp = next_op;
        next_op = current_op;
        current_op = tmp;
      }
      ops[op_free_idx - 1] = next_op ^ pick;
      ops[op_free_idx - 2] = current_op ^ pick;
    }
    ops_args[op_next_idx] = ((op_next_idx + 1) << 8) | (op_next_idx + 2);
    op_next_idx++;
    if (op_next_idx < op_free_idx) {
      return;
    }
  }
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

static uint8_t pick_registers(uint8_t op) {
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
static uint32_t get_op_args(uint8_t i) {
  uint32_t x, y;

  ops[i] &= 0x7f; // clear top bit, mark seen?

  if (ops[i] < 3) {
    return ops_args[i];
  }

  x = get_op_args(LOWER(ops_args[i]));
  y = get_op_args(UPPER(ops_args[i]));

  // bx = i
  // cx = op arg x
  // ax = op arg y
  // dx = (op @ cur y) << 8 | (final op @ y)
  switch (ops[i]) {
  case OP_ROL: // 7
  case OP_ROR: // 8
  case OP_SHL: // 9
  case OP_SHR: // 10
    if (LOWER(y) != OP_DATA) {
      reg_set_dec[REG_CX] = REG_IS_USED;
      x = 0x80;
    } else if (LOWER(x) == OP_ROL || LOWER(x) == OP_ROR) {
      // data moves only for ror/rol
      reg_set_dec[REG_CX] = REG_IS_USED;
      x = 0x80;
    }
    break;
  case OP_MUL:
  case OP_IMUL:
    last_op_flag = 0;
    reg_set_dec[REG_DX] = REG_IS_USED;
    break;
  default:
    break;
  }

  x |= LOWER(ops_args[i]);
  x &= 0x80;
  x |= LOWER(ops[i]);

  return i;
}

static int generating_enc() {
  return out->code >= decrypt_stage && out->code < decrypt_stage + MAX_ADD_LEN;
}
static int generating_dec() { return !generating_enc(); }
static void bl_op_reg_mrm(uint8_t op, uint8_t src, uint8_t dst) {
  emitb(op);
  emitb(0xc0 | (src << 3) | dst);
}
static uint16_t emit_ops(uint8_t i) {
  uint16_t dx;

  /*
   * 0=>ops_args[i]
   * 1=>0xff00
   * 2=>ptr_reg
   */
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
#define dl (GETLO(dx))
#define dh (GETHI(dx))
#define GETLO(reg) ((reg)&0xff)
#define GETHI(reg) (GETLO(((reg) >> 8)))
#define SETLO(reg, val) (reg = UPPER(reg) | (val & 0xff))
#define SETHI(reg, val) (reg = (val << 8) | LOWER(reg))
  if (dl == 0) {
    uint8_t *reg_used = ((uint8_t*)&dx);
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
    //if (dh != 0x80 && (ops[i] != *reg_used)) {
    if (*reg_used >= 0x80) {
      // if we didn't push, and the op is
      //   start and we didn't use cx
      //   pointer and didn't use dx
      switch (*reg_used) {
        case REG_CX:
          // rotates/shifts during arith ops (we don't need the shift count
          // anymore)
          if (ops[i] == OP_START_OR_END) reg_set_enc[REG_CX] = REG_IS_FREE;
          break;
        case REG_DX:
          // mul inside of pointer ops (we always set dx prior, and we don't
          // use part of the result later)
          if (ops[i] == OP_POINTER) reg_set_enc[REG_DX] = REG_IS_FREE;
          break;
      }
    }
  }

  uint8_t opcode = 0;
}

static void emitb(uint8_t x) { *(out->code++) = x; }
static void emitw(uint16_t x) {
  *(out->code++) = x >> 8;
  *(out->code++) = x;
}
static void emitd(uint32_t x) {
  *(out->code++) = x >> 24;
  *(out->code++) = x >> 16;
  *(out->code++) = x >> 8;
  *(out->code++) = x;
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
    op_off_patch = out->code;
    emitd(0); // offset to patch
    return 0;
  } else {
    // reg
    emitb(0xc0 | (a << 3) | b); // XXX order
    return 0;
  }
}
// lower byte of val == 0 then encode mov reg,reg instead
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
static void emit_mov_data(uint32_t val) { emit_mov(data_reg, val); }
// XXX takes bl=routine_size, dx=arg_size_neg, di=buf
static void generate_code(enum mut_routine_size_t routine_size) {
  make_ops_table(routine_size);
  generate_code_from_table(routine_size);
  // ^ returns bx=patch_point
}
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
static void invert_ops_table() {}
LOCAL uint16_t dx; // size
LOCAL uint16_t bx; // patch point
static int generate_code_from_table(enum mut_routine_size_t routine_size) {
  memset(&reg_set_enc, -1, 8);
  reg_set_enc[REG_DX] = 0;
  reg_set_enc[REG_SP] = 0;

  last_op_flag = -1;
  // XXX get_op_args, but also marks cx or dx used
  uint32_t arg = get_op_args(op_idx);
  pick_registers(arg);

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
      bx = (uint16_t) &patch_dummy; // XXX bogus
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
      op_off_patch = patch_dummy;
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
        invert_ops_table();
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

      // patch offsets
      uintptr_t target = (uintptr_t)out->code;
      target -= in->len;
      hold[0] = (long int)target;
      hold[1] = (long int)target >> 8;
      hold[2] = (long int)target >> 16;
      hold[3] = (long int)target >> 24;
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

      // outro junk
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
    // intro junk
    emit_ops(op_idx);
    emitb(0x90 | data_reg); // xchg ax,reg
    emitb(0xc3);            // retf
    phase = 0;
    break;
  }

  return 0;
}

static int make(uint8_t *p, enum mut_routine_size_t routine_size) {
  generate_code(routine_size);
  invert_ops_table();
  return generate_code_from_table(routine_size);
}

static uint32_t exec_enc_stage(uint32_t init_val) {
  // TODO
  return 0;
}

static void make_enc_and_dec(struct mut_input *in, struct mut_output *out) {

  // round onto a word boundary, but not a page boundary
  in->len += MAX_ADD_LEN - 5; // XXX holding 3 bytes for JMP?
  in->len = -in->len;
  in->len = (in->len & 0xfe) == 0 ? (in->len & 0xfffe) - 2 : in->len & 0xfffe;

  // in->len negated, this is a subtract
  uintptr_t total_end = in->entry_offset + in->len;
  if (total_end & ~1) {
    total_end -= 2;
  }

  phase = total_end;

  srandom(time(NULL));
  memset(&reg_set_dec, -1, sizeof(reg_set_dec));
  unsigned int junk_len = make(decrypt_stage, MUT_ROUTINE_SIZE_MEDIUM);
  if (junk_len > 0) {
    uint32_t result = exec_enc_stage(1);
    decrypt_stage[junk_len - 1] = result; // XXX uint32_t
  }
  phase = 0;
  unsigned int loop_len = make(decrypt_stage + junk_len, in->routine_size);
  phase = 1;
  unsigned int outro_junk_len =
      make(decrypt_stage + junk_len + loop_len, in->routine_size);

  out->len = junk_len + loop_len + outro_junk_len;
  return;
}

struct mut_output *mut_engine(struct mut_input *in, struct mut_output *out) {
  make_enc_and_dec(in, out);
  return out;
}
