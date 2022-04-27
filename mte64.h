/* This file was automatically generated.  Do not edit! */
#undef INTERFACE
typedef struct mut_output mut_output;
typedef struct mut_input mut_input;
struct mut_output *mut_engine(struct mut_input *f_in,struct mut_output *f_out);
uint32_t integer_inverse(uint32_t a);
int is_parity_even(uint64_t x);
#define LOCAL static
typedef union mrm_t mrm_t;
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
enum mrm_mode_t {
  MRM_MODE_INDEX = 0,
  MRM_MODE_INDEX_DISP8,
  MRM_MODE_INDEX_DISP32,
  MRM_MODE_REGISTER
};
typedef enum mrm_mode_t mrm_mode_t;
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
enum reg_set_t { REG_SET_BUSY, REG_SET_AVAILABLE = 0xff };
typedef enum reg_set_t reg_set_t;
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
enum mut_routine_size_t {
  MUT_ROUTINE_SIZE_TINY = 0x1,
  MUT_ROUTINE_SIZE_SMALL = 0x3,
  MUT_ROUTINE_SIZE_MEDIUM = 0x7,
  MUT_ROUTINE_SIZE_BIG = 0xf
};
typedef enum mut_routine_size_t mut_routine_size_t;
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
