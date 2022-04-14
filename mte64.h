/* This file was automatically generated.  Do not edit! */
#undef INTERFACE
typedef struct mut_output mut_output;
typedef struct mut_input mut_input;
struct mut_output *mut_engine(struct mut_input *f_in,struct mut_output *f_out);
static void encrypt_target();
static void mark_and_emit(uint8_t *p);
static void pick_ptr_register(uint8_t *p);
static void emit_f7_op();
static void emit_81_ops();
static void save_op_done();
int is_parity_even(unsigned int n);
static void emit_ops_maybe_mul();
static void store_data_reg();
static void emit_ops_jnz();
static void patch();
static void patch_offsets();
static void encode_retf();
static void encode_mrm_ptr();
static void encode_mrm();
static void encode_op_mrm();
static void bl_op_reg_mrm();
static void size_ok();
static void single_ref();
static void emit_eol_bl();
static void emit_ops();
static void ptr_and_r_sto();
static void g_code_no_mask();
static void g_code_from_ops();
static void g_code();
static void make();
static void restart();
static void make_enc_and_dec(struct mut_input *in,struct mut_output *out);
static uint32_t get_arg_size();
static uint32_t exec_enc_stage();
uint32_t mul_inv(uint32_t d);
static void invert_ops();
static uint8_t *get_op_loc(int x);
static int try_ptr_advance();
static void emit_mov_data();
static void encode_mrm_dh_s();
static void emit_mov();
static void emit_mov_imm(uint8_t reg,uint32_t val);
static uint32_t emitd(uint32_t x);
static uint16_t emitw(uint16_t x);
static uint8_t emitb(uint8_t x);
static int generating_dec();
static int generating_enc();
static uint32_t get_op_args(uint8_t i);
static uint8_t _pick_registers(uint8_t op);
enum mut_routine_size_t {
  MUT_ROUTINE_SIZE_TINY = 0x1,
  MUT_ROUTINE_SIZE_SMALL = 0x3,
  MUT_ROUTINE_SIZE_MEDIUM = 0x7,
  MUT_ROUTINE_SIZE_BIG = 0xf
};
typedef enum mut_routine_size_t mut_routine_size_t;
static void make_ops_table(enum mut_routine_size_t routine_size);
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
typedef enum opcode_f7_t opcode_f7_t;
enum opcode_t {
  OPCODE_ADD = 0x03,
  OPCODE_OR = 0x0B,
  OPCODE_AND = 0x23,
  OPCODE_SUB = 0x2B,
  OPCODE_XOR = 0x33,
  OPCODE_MOV_IMM = 0xB8
};
typedef enum opcode_t opcode_t;
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
typedef enum op_t op_t;
#define LOCAL_INTERFACE 0
#define LOCAL static
struct mut_output {
  uint8_t *code;               // ds:dx
  unsigned int len;            // ax
  uint8_t *routine_end_offset; // di
  uint8_t *loop_offset;        // si
};
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
typedef enum mut_flags_t mut_flags_t;
struct mut_input {
  uint8_t *code;            // ds:dx
  unsigned int len;         // cx
  uintptr_t exec_offset;    // bp
  uintptr_t entry_offset;   // di
  uintptr_t payload_offset; // si
  mut_flags_t flags;        // ax
  mut_routine_size_t routine_size;
};
#define MAX_ADD_LEN 25
#define MAX_ADD 512
#define INTERFACE 0
