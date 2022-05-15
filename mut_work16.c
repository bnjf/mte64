
#if INTERFACE
struct mut_work16_t {
  uint8_t ops[0x21];
  uint16_t ops_args[0x21];
  uint16_t jnz_patch_dec[0x21];
  uint16_t jnz_patch_hits[0x21];
  uint16_t jnz_patch_enc[0x21];
  uint8_t op_root_idx;
  uint8_t op_cur_idx;
  uint8_t op_arg_idx;
  uint8_t op_x_idx;
  uint8_t ___pad;
  uint8_t junk_len_mask;
  uint8_t is_8086;
  uint16_t op_off_patch;
  uint16_t arg_code_entry;
  uint16_t arg_flags;
  uint16_t arg_size_neg;
  uint16_t arg_exec_off;
  uint16_t arg_start_off;
  uint8_t reg_set_dec[8];
  uint8_t reg_set_enc[8];
  uint8_t ptr_reg;
  uint8_t data_reg;
  uint8_t last_op;
  uint8_t last_op_flag;
  uint16_t patch_dummy;
  uint8_t dec_stage_p[7];
  uint8_t dec_stage[0x200];
  uint8_t enc_stage[0x200];
};
#endif
