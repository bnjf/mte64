/* This file was automatically generated.  Do not edit! */
#undef INTERFACE
typedef struct mut_output mut_output;
typedef struct mut_input mut_input;
struct mut_output *mut_engine(struct mut_input *f_in,struct mut_output *f_out);
static void encrypt_target();
static void mark_and_emit(uint8_t *p);
static void pick_ptr_register(uint8_t *p);
static void emit_81_ops();
static void save_op_done();
static void emit_ops_emit_bl();
static void emit_ops_maybe_rol(int is_rotate);
static void emit_f7_op();
static void emit_ops_not_mul();
static void emit_ops_maybe_mul();
static void emit_ops_jnz();
static void store_data_reg();
static void mark_reg_used();
static void patch();
static void patch_offsets();
static void encode_mrm();
static void encode_op_mrm();
static void bl_op_reg_mrm();
static void size_ok();
static void single_ref();
static void emit_eol_bl();
static void encode_retf();
static void emit_ops();
static void ptr_and_r_sto();
static void g_code_no_mask();
static void g_code_from_ops();
static void g_code();
static void make();
static void restart();
static void make_enc_and_dec();
static uint32_t get_arg_size();
static void exec_enc_stage();
static void emit_op_mrm();
static void encode_mrm_ptr();
static void encode_mrm_dh_s();
static void emit_mov();
static void emit_mov_data();
static uint32_t emitd(uint32_t x);
static uint16_t emitw(uint16_t x);
static uint8_t emitb(uint8_t x);
static int generating_dec();
static int generating_enc();
static uint32_t get_op_args(uint8_t i);
static void fix_arg();
static void try_ptr_advance();
int is_parity_even(uint64_t x);
uint32_t integer_inverse(uint32_t a);
static void invert_ops_loop();
static void invert_ops();
static void get_op_loc();
static void dump_ops_tree_as_stack(int i);
static void dump_ops_tree(int i,int d);
static void dump_ops_table();
static uint8_t _set_op_arg(int i,uint8_t arg);
static uint8_t _get_op_arg(int i);
static uint8_t shr8(uint8_t x);
static void dump_all_regs();
enum mut_routine_size_t {
  MUT_ROUTINE_SIZE_TINY = 0x1,
  MUT_ROUTINE_SIZE_SMALL = 0x3,
  MUT_ROUTINE_SIZE_MEDIUM = 0x7,
  MUT_ROUTINE_SIZE_BIG = 0xf
};
typedef enum mut_routine_size_t mut_routine_size_t;
static void make_ops_table(enum mut_routine_size_t routine_size);
#define LOCAL static
typedef union mrm_t mrm_t;
union mrm_t {
  uint8_t byte;
  struct {
    // note to self: bitfields are right to left
    uint8_t reg : 3;
    uint8_t op : 3;
    uint8_t mod : 2;
  };
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
typedef enum reg8_t reg8_t;
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
typedef enum reg16_t reg16_t;
enum opcode_80_t {
  OPCODE_80_ADD = 0,
  OPCODE_80_OR,
  OPCODE_80_ADC,
  OPCODE_80_SBB,
  OPCODE_80_AND,
  OPCODE_80_SUB,
  OPCODE_80_XOR
};
typedef enum opcode_80_t opcode_80_t;
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
typedef enum opcode_f7_t opcode_f7_t;
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
typedef enum opcode_t opcode_t;
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
typedef enum op_t op_t;
#define LOCAL_INTERFACE 0
struct mut_output {
  uint8_t *code;               // ds:DX
  unsigned int len;            // AX
  uint8_t *routine_end_offset; // DI
  uint8_t *loop_offset;        // SI
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
  uint8_t *code;            // ds:DX
  unsigned int len;         // CX
  uintptr_t exec_offset;    // BP
  uintptr_t entry_offset;   // DI
  uintptr_t payload_offset; // SI
  mut_flags_t flags;        // AX
  mut_routine_size_t routine_size;
};
#define MAX_ADD_LEN 25
#define MAX_ADD 512
#define INTERFACE 0
