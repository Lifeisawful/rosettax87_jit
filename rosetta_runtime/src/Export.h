#pragma once

#include <cstdint>

#include "X87.h"

struct Export {
    void* address;
    const char* name;
};

struct Exports {
    uint64_t version;  // 0x16A0000000000
    const Export* x87Exports;
    uint64_t x87ExportCount;
    const Export* runtimeExports;
    uint64_t runtimeExportCount;
};

static_assert(sizeof(Exports) == 0x28, "Invalid size for Exports");

extern init_library_t orig_init_library;
extern register_runtime_routine_offsets_t orig_register_runtime_routine_offsets;
extern translator_use_t8027_codegen_t orig_translator_use_t8027_codegen;
extern translator_reset_t orig_translator_reset;
extern ir_create_bad_access_t orig_ir_create_bad_access;
extern ir_create_t orig_ir_create;
extern module_free_t orig_module_free;
extern module_get_size_t orig_module_get_size;
extern module_is_bad_access_t orig_module_is_bad_access;
extern module_print_t orig_module_print;
extern translator_translate_t orig_translator_translate;
extern translator_free_t orig_translator_free;
extern translator_get_data_t orig_translator_get_data;
extern translator_get_size_t orig_translator_get_size;
extern translator_get_branch_slots_offset_t orig_translator_get_branch_slots_offset;
extern translator_get_branch_slots_count_t orig_translator_get_branch_slots_count;
extern translator_get_branch_entries_t orig_translator_get_branch_entries;
extern translator_get_instruction_offsets_t orig_translator_get_instruction_offsets;
extern translator_apply_fixups_t orig_translator_apply_fixups;
extern x87_init_t orig_x87_init;
extern x87_state_from_x86_float_state_t orig_x87_state_from_x86_float_state;
extern x87_state_to_x86_float_state_t orig_x87_state_to_x86_float_state;
extern x87_pop_register_stack_t orig_x87_pop_register_stack;
extern x87_f2xm1_t orig_x87_f2xm1;
extern x87_fabs_t orig_x87_fabs;
extern x87_fadd_ST_t orig_x87_fadd_ST;
extern x87_fadd_f32_t orig_x87_fadd_f32;
extern x87_fadd_f64_t orig_x87_fadd_f64;
extern x87_fbld_t orig_x87_fbld;
extern x87_fbstp_t orig_x87_fbstp;
extern x87_fchs_t orig_x87_fchs;
extern x87_fcmov_t orig_x87_fcmov;
extern x87_fcom_ST_t orig_x87_fcom_ST;
extern x87_fcom_f32_t orig_x87_fcom_f32;
extern x87_fcom_f64_t orig_x87_fcom_f64;
extern x87_fcomi_t orig_x87_fcomi;
extern x87_fcos_t orig_x87_fcos;
extern x87_fdecstp_t orig_x87_fdecstp;
extern x87_fdiv_ST_t orig_x87_fdiv_ST;
extern x87_fdiv_f32_t orig_x87_fdiv_f32;
extern x87_fdiv_f64_t orig_x87_fdiv_f64;
extern x87_fdivr_ST_t orig_x87_fdivr_ST;
extern x87_fdivr_f32_t orig_x87_fdivr_f32;
extern x87_fdivr_f64_t orig_x87_fdivr_f64;
extern x87_ffree_t orig_x87_ffree;
extern x87_fiadd_t orig_x87_fiadd;
extern x87_ficom_t orig_x87_ficom;
extern x87_fidiv_t orig_x87_fidiv;
extern x87_fidivr_t orig_x87_fidivr;
extern x87_fild_t orig_x87_fild;
extern x87_fimul_t orig_x87_fimul;
extern x87_fincstp_t orig_x87_fincstp;
extern x87_fist_i16_t orig_x87_fist_i16;
extern x87_fist_i32_t orig_x87_fist_i32;
extern x87_fist_i64_t orig_x87_fist_i64;
extern x87_fistt_i16_t orig_x87_fistt_i16;
extern x87_fistt_i32_t orig_x87_fistt_i32;
extern x87_fistt_i64_t orig_x87_fistt_i64;
extern x87_fisub_t orig_x87_fisub;
extern x87_fisubr_t orig_x87_fisubr;
extern x87_fld_STi_t orig_x87_fld_STi;
extern x87_fld_constant_t orig_x87_fld_constant;
extern x87_fld_fp32_t orig_x87_fld_fp32;
extern x87_fld_fp64_t orig_x87_fld_fp64;
extern x87_fld_fp80_t orig_x87_fld_fp80;
extern x87_fmul_ST_t orig_x87_fmul_ST;
extern x87_fmul_f32_t orig_x87_fmul_f32;
extern x87_fmul_f64_t orig_x87_fmul_f64;
extern x87_fpatan_t orig_x87_fpatan;
extern x87_fprem_t orig_x87_fprem;
extern x87_fprem1_t orig_x87_fprem1;
extern x87_fptan_t orig_x87_fptan;
extern x87_frndint_t orig_x87_frndint;
extern x87_fscale_t orig_x87_fscale;
extern x87_fsin_t orig_x87_fsin;
extern x87_fsincos_t orig_x87_fsincos;
extern x87_fsqrt_t orig_x87_fsqrt;
extern x87_fst_STi_t orig_x87_fst_STi;
extern x87_fst_fp32_t orig_x87_fst_fp32;
extern x87_fst_fp64_t orig_x87_fst_fp64;
extern x87_fst_fp80_t orig_x87_fst_fp80;
extern x87_fsub_ST_t orig_x87_fsub_ST;
extern x87_fsub_f32_t orig_x87_fsub_f32;
extern x87_fsub_f64_t orig_x87_fsub_f64;
extern x87_fsubr_ST_t orig_x87_fsubr_ST;
extern x87_fsubr_f32_t orig_x87_fsubr_f32;
extern x87_fsubr_f64_t orig_x87_fsubr_f64;
extern x87_fucom_t orig_x87_fucom;
extern x87_fucomi_t orig_x87_fucomi;
extern x87_fxam_t orig_x87_fxam;
extern x87_fxch_t orig_x87_fxch;
extern x87_fxtract_t orig_x87_fxtract;
extern x87_fyl2x_t orig_x87_fyl2x;
extern x87_fyl2xp1_t orig_x87_fyl2xp1;
extern sse_pcmpestri_t orig_sse_pcmpestri;
extern sse_pcmpestrm_t orig_sse_pcmpestrm;
extern sse_pcmpistri_t orig_sse_pcmpistri;
extern sse_pcmpistrm_t orig_sse_pcmpistrm;
extern is_ldt_initialized_t orig_is_ldt_initialized;
extern get_ldt_t orig_get_ldt;
extern set_ldt_t orig_set_ldt;
extern execution_mode_for_code_segment_selector_t orig_execution_mode_for_code_segment_selector;
extern mov_segment_t orig_mov_segment;
extern abi_for_address_t orig_abi_for_address;
extern determine_state_recovery_action_t orig_determine_state_recovery_action;
extern get_segment_limit_t orig_get_segment_limit;
extern translator_set_variant_t orig_translator_set_variant;
extern x87_set_init_state_t orig_x87_set_init_state;

extern runtime_cpuid_t orig_runtime_cpuid;
extern runtime_wide_udiv_64_t orig_runtime_wide_udiv_64;
extern runtime_wide_sdiv_64_t orig_runtime_wide_sdiv_64;

extern Exports kImports;

extern auto exportsInit() -> void;
