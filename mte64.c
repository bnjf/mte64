
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_ADD 512
#define MAX_ADD_LEN 25
// static const int CODE_LEN = 2100; // NOTUSED
// static const int MAX_LEN = 1394;

enum mut_routine_size_t {
  MUT_ROUTINE_SIZE_TINY = (2 << 0) - 1,
  MUT_ROUTINE_SIZE_SMALL = (2 << 1) - 1,
  MUT_ROUTINE_SIZE_MEDIUM = (2 << 2) - 1,
  MUT_ROUTINE_SIZE_BIG = (2 << 3) - 1
}; // bl
struct mut_input {
  uint8_t *code;            // ds:dx
  unsigned int len;         // cx
  uintptr_t exec_offset;    // bp
  uintptr_t entry_offset;   // di
  uintptr_t payload_offset; // si
  enum mut_routine_size_t routine_size;
  struct {
    unsigned int preserve_ax : 1;
    unsigned int preserve_cx : 1;
    unsigned int preserve_dx : 1;
    unsigned int preserve_bx : 1;
    unsigned int preserve_sp : 1;
    unsigned int preserve_bp : 1;
    unsigned int preserve_si : 1;
    unsigned int preserve_di : 1;
    unsigned int run_on_different_cpu : 1; // NOTUSED
    unsigned int cs_is_not_ds : 1;         // NOTUSED
    unsigned int cs_is_not_ss : 1;         // NOTUSED
    unsigned int dont_align : 1;           // paragraph boundary alignment
  } flags;                                 // ax
};
struct mut_output {
  uint8_t *code;               // ds:dx
  unsigned int len;            // ax
  uint8_t *routine_end_offset; // di
  uint8_t *loop_offset;        // si
};

static struct {
  uint8_t ax;
  uint8_t cx;
  uint8_t dx;
  uint8_t bx;
  uint8_t sp;
  uint8_t bp;
  uint8_t si;
  uint8_t di;
} reg_set_dec;
static struct {
  uint8_t ax;
  uint8_t cx;
  uint8_t dx;
  uint8_t bx;
  uint8_t sp;
  uint8_t bp;
  uint8_t si;
  uint8_t di;
} reg_set_enc;
uint8_t decrypt_stage[MAX_ADD];
uint8_t encrypt_stage[MAX_ADD];
uintptr_t jnz_patch_dec[0x21];
uintptr_t jnz_patch_hits[0x21];
uintptr_t jnz_patch_enc[0x21];

uint8_t ops[0x21];
uint32_t ops_args[0x21];

// bp = size_neg => intro junk
//      1        => making loop
//      0        => making decryptor loop end+outro
//     -1        => only when called recursively
int phase = 0;

static void make_ops_table(enum mut_routine_size_t routine_size) {
  uint8_t op_idx = 1, op_free_idx = 1, op_next_idx = 1, op_end_idx;

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

uint8_t last_op_flag;
static int generate_code_from_table(enum mut_routine_size_t routine_size) {
  memset(&reg_set_enc, -1, sizeof(reg_set_enc));
  reg_set_enc.dx = 0;
  reg_set_enc.sp = 0;

  last_op_flag = -1;
  // TODO

  return 0;
}
static void generate_code(enum mut_routine_size_t routine_size) {
  make_ops_table(routine_size);
  generate_code_from_table(routine_size);
}
static void invert_ops_table() {}

static int make(uint8_t *p, enum mut_routine_size_t routine_size) {

  // code
  generate_code(routine_size);

  // mirror
  invert_ops_table();
  return generate_code_from_table(routine_size);
}

static uint32_t exec_enc_stage(uint32_t init_val) { return 0; }

static void make_enc_and_dec(struct mut_input *in, struct mut_output *out) {

  // round onto a word boundary, but not a page boundary
  in->len += MAX_ADD_LEN - 3; // XXX holding 3 bytes for JMP?
  in->len = -in->len;
  in->len = (in->len & 0xfe) == 0 ? (in->len & 0xfffe) - 2 : in->len & 0xfffe;

  // in->len negated, this is a subtract
  uintptr_t total_end = in->entry_offset + in->len;
  if (total_end & ~1) {
    total_end -= 2;
  }

restart:
  srandom(time(NULL));

  memset(&reg_set_dec, -1, sizeof(reg_set_dec));

  unsigned int junk_len = make(decrypt_stage, MUT_ROUTINE_SIZE_MEDIUM);
  if (junk_len > 0) {
    // if we've made junk, we can do an indirect move.
    // set the initial register state to 1 (as an identity) so we can get the
    // result of the junk, and use that in our decrypter init
    uint32_t result = exec_enc_stage(1);

    // patch the mov
    decrypt_stage[junk_len - 1] = result; // XXX uint32_t
  }
  unsigned int loop_len = make(decrypt_stage + junk_len, in->routine_size);
  if (loop_len > MAX_ADD_LEN) {
    goto restart;
  }

  return;
}

struct mut_output *mut_engine(struct mut_input *in, struct mut_output *out) {
  make_enc_and_dec(in, out);
  return out;
}
