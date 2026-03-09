#pragma once

#include <cstdint>

#include "X87Float80.h"

struct SymbolList;
struct ThreadContextOffsets;
struct X86FloatState64 {};
enum X87Constant {
    kOne = 0,
    kZero = 1,
    kPi = 2,
    kLog2e = 3,
    kLoge2 = 4,
    kLog2t = 5,
    kLog102 = 6,
};

struct SegmentRegisters {};
enum SegmentRegister {};
struct X87State;

struct X87Float80StatusWordResult {
    uint64_t mantissa;
    uint16_t exponent;
    uint16_t statusWord;
};

struct X87ResultStatusWord {
    union {
        uint64_t result;
        int64_t signedResult;
    };
    uint16_t statusWord;
};
static_assert(sizeof(X87ResultStatusWord) == 0x10);

void* init_library(SymbolList const*, uint64_t, ThreadContextOffsets const*);
using init_library_t = decltype(&init_library);

void register_runtime_routine_offsets();
using register_runtime_routine_offsets_t = decltype(&register_runtime_routine_offsets);

void translator_use_t8027_codegen();
using translator_use_t8027_codegen_t = decltype(&translator_use_t8027_codegen);

void translator_reset();
using translator_reset_t = decltype(&translator_reset);

void ir_create_bad_access();
using ir_create_bad_access_t = decltype(&ir_create_bad_access);

void ir_create();
using ir_create_t = decltype(&ir_create);

void module_free();
using module_free_t = decltype(&module_free);

void module_get_size();
using module_get_size_t = decltype(&module_get_size);

void module_is_bad_access();
using module_is_bad_access_t = decltype(&module_is_bad_access);

void module_print();
using module_print_t = decltype(&module_print);

void translator_translate();
using translator_translate_t = decltype(&translator_translate);

void translator_free();
using translator_free_t = decltype(&translator_free);

void translator_get_data();
using translator_get_data_t = decltype(&translator_get_data);

void translator_get_size();
using translator_get_size_t = decltype(&translator_get_size);

void translator_get_branch_slots_offset();
using translator_get_branch_slots_offset_t = decltype(&translator_get_branch_slots_offset);

void translator_get_branch_slots_count();
using translator_get_branch_slots_count_t = decltype(&translator_get_branch_slots_count);

void translator_get_branch_entries();
using translator_get_branch_entries_t = decltype(&translator_get_branch_entries);

void translator_get_instruction_offsets();
using translator_get_instruction_offsets_t = decltype(&translator_get_instruction_offsets);

void translator_apply_fixups();
using translator_apply_fixups_t = decltype(&translator_apply_fixups);

void x87_init(X87State*);
using x87_init_t = decltype(&x87_init);

void x87_state_from_x86_float_state();
using x87_state_from_x86_float_state_t = decltype(&x87_state_from_x86_float_state);

void x87_state_to_x86_float_state();
using x87_state_to_x86_float_state_t = decltype(&x87_state_to_x86_float_state);

void x87_pop_register_stack(X87State* state);
using x87_pop_register_stack_t = decltype(&x87_pop_register_stack);

void x87_f2xm1(X87State*);
using x87_f2xm1_t = decltype(&x87_f2xm1);

void x87_fabs(X87State*);
using x87_fabs_t = decltype(&x87_fabs);

void x87_fadd_ST(X87State*, uint32_t, uint32_t, bool);
using x87_fadd_ST_t = decltype(&x87_fadd_ST);

void x87_fadd_f32(X87State*, uint32_t);
using x87_fadd_f32_t = decltype(&x87_fadd_f32);

void x87_fadd_f64(X87State*, uint64_t);
using x87_fadd_f64_t = decltype(&x87_fadd_f64);

void x87_fbld(X87State*, uint64_t, uint64_t);
using x87_fbld_t = decltype(&x87_fbld);

struct uint128_t {
    uint64_t low;
    uint64_t high;
};

uint128_t x87_fbstp(X87State*);
using x87_fbstp_t = decltype(&x87_fbstp);

void x87_fchs(X87State*);
using x87_fchs_t = decltype(&x87_fchs);

void x87_fcmov(X87State*, uint32_t, uint32_t);
using x87_fcmov_t = decltype(&x87_fcmov);

void x87_fcom_ST(X87State*, uint32_t, uint32_t);
using x87_fcom_ST_t = decltype(&x87_fcom_ST);

void x87_fcom_f32(X87State*, uint32_t, bool);
using x87_fcom_f32_t = decltype(&x87_fcom_f32);

void x87_fcom_f64(X87State*, uint64_t, bool);
using x87_fcom_f64_t = decltype(&x87_fcom_f64);

uint32_t x87_fcomi(X87State*, uint32_t, bool);
using x87_fcomi_t = decltype(&x87_fcomi);

void x87_fcos(X87State*);
using x87_fcos_t = decltype(&x87_fcos);

void x87_fdecstp(X87State*);
using x87_fdecstp_t = decltype(&x87_fdecstp);

void x87_fdiv_ST(X87State*, uint32_t, uint32_t, bool);
using x87_fdiv_ST_t = decltype(&x87_fdiv_ST);

void x87_fdiv_f32(X87State*, uint32_t);
using x87_fdiv_f32_t = decltype(&x87_fdiv_f32);

void x87_fdiv_f64(X87State*, uint64_t);
using x87_fdiv_f64_t = decltype(&x87_fdiv_f64);

void x87_fdivr_ST(X87State*, uint32_t, uint32_t, bool);
using x87_fdivr_ST_t = decltype(&x87_fdivr_ST);

void x87_fdivr_f32(X87State*, uint32_t);
using x87_fdivr_f32_t = decltype(&x87_fdivr_f32);

void x87_fdivr_f64(X87State*, uint64_t);
using x87_fdivr_f64_t = decltype(&x87_fdivr_f64);

void x87_ffree(X87State*, uint32_t);
using x87_ffree_t = decltype(&x87_ffree);

void x87_fiadd(X87State*, int32_t);
using x87_fiadd_t = decltype(&x87_fiadd);

void x87_ficom(X87State*, int32_t, bool);
using x87_ficom_t = decltype(&x87_ficom);

void x87_fidiv(X87State*, int32_t);
using x87_fidiv_t = decltype(&x87_fidiv);

void x87_fidivr(X87State*, int32_t);
using x87_fidivr_t = decltype(&x87_fidivr);

void x87_fild(X87State*, int64_t);
using x87_fild_t = decltype(&x87_fild);

void x87_fimul(X87State*, int32_t);
using x87_fimul_t = decltype(&x87_fimul);

void x87_fincstp(X87State*);
using x87_fincstp_t = decltype(&x87_fincstp);

X87ResultStatusWord x87_fist_i16(X87State const*);
using x87_fist_i16_t = decltype(&x87_fist_i16);

X87ResultStatusWord x87_fist_i32(X87State const*);
using x87_fist_i32_t = decltype(&x87_fist_i32);

X87ResultStatusWord x87_fist_i64(X87State const*);
using x87_fist_i64_t = decltype(&x87_fist_i64);

X87ResultStatusWord x87_fistt_i16(X87State const*);
using x87_fistt_i16_t = decltype(&x87_fistt_i16);

X87ResultStatusWord x87_fistt_i32(X87State const*);
using x87_fistt_i32_t = decltype(&x87_fistt_i32);

X87ResultStatusWord x87_fistt_i64(X87State const*);
using x87_fistt_i64_t = decltype(&x87_fistt_i64);

void x87_fisub(X87State*, int32_t);
using x87_fisub_t = decltype(&x87_fisub);

void x87_fisubr(X87State*, int32_t);
using x87_fisubr_t = decltype(&x87_fisubr);

void x87_fld_STi(X87State*, uint32_t);
using x87_fld_STi_t = decltype(&x87_fld_STi);

void x87_fld_constant(X87State*, X87Constant);
using x87_fld_constant_t = decltype(&x87_fld_constant);

void x87_fld_fp32(X87State*, uint32_t);
using x87_fld_fp32_t = decltype(&x87_fld_fp32);

void x87_fld_fp64(X87State*, uint64_t);
using x87_fld_fp64_t = decltype(&x87_fld_fp64);

void x87_fld_fp80(X87State*, X87Float80);
using x87_fld_fp80_t = decltype(&x87_fld_fp80);

void x87_fmul_ST(X87State*, uint32_t, uint32_t, bool);
using x87_fmul_ST_t = decltype(&x87_fmul_ST);

void x87_fmul_f32(X87State*, uint32_t);
using x87_fmul_f32_t = decltype(&x87_fmul_f32);

void x87_fmul_f64(X87State*, uint64_t);
using x87_fmul_f64_t = decltype(&x87_fmul_f64);

void x87_fpatan(X87State*);
using x87_fpatan_t = decltype(&x87_fpatan);

void x87_fprem(X87State*);
using x87_fprem_t = decltype(&x87_fprem);

void x87_fprem1(X87State*);
using x87_fprem1_t = decltype(&x87_fprem1);

void x87_fptan(X87State*);
using x87_fptan_t = decltype(&x87_fptan);

void x87_frndint(X87State*);
using x87_frndint_t = decltype(&x87_frndint);

void x87_fscale(X87State*);
using x87_fscale_t = decltype(&x87_fscale);

void x87_fsin(X87State*);
using x87_fsin_t = decltype(&x87_fsin);

void x87_fsincos(X87State*);
using x87_fsincos_t = decltype(&x87_fsincos);

void x87_fsqrt(X87State*);
using x87_fsqrt_t = decltype(&x87_fsqrt);

void x87_fst_STi(X87State*, uint32_t, bool);
using x87_fst_STi_t = decltype(&x87_fst_STi);

X87ResultStatusWord x87_fst_fp32(X87State const*);
using x87_fst_fp32_t = decltype(&x87_fst_fp32);

X87ResultStatusWord x87_fst_fp64(X87State const*);
using x87_fst_fp64_t = decltype(&x87_fst_fp64);

X87Float80StatusWordResult x87_fst_fp80(X87State const*);
using x87_fst_fp80_t = decltype(&x87_fst_fp80);

void x87_fsub_ST(X87State*, uint32_t, uint32_t, bool);
using x87_fsub_ST_t = decltype(&x87_fsub_ST);

void x87_fsub_f32(X87State*, uint32_t);
using x87_fsub_f32_t = decltype(&x87_fsub_f32);

void x87_fsub_f64(X87State*, uint64_t);
using x87_fsub_f64_t = decltype(&x87_fsub_f64);

void x87_fsubr_ST(X87State*, uint32_t, uint32_t, bool);
using x87_fsubr_ST_t = decltype(&x87_fsubr_ST);

void x87_fsubr_f32(X87State*, uint32_t);
using x87_fsubr_f32_t = decltype(&x87_fsubr_f32);

void x87_fsubr_f64(X87State*, uint64_t);
using x87_fsubr_f64_t = decltype(&x87_fsubr_f64);

void x87_fucom(X87State*, uint32_t, uint32_t);
using x87_fucom_t = decltype(&x87_fucom);

uint32_t x87_fucomi(X87State*, uint32_t, bool);
using x87_fucomi_t = decltype(&x87_fucomi);

void x87_fxam(X87State*);
using x87_fxam_t = decltype(&x87_fxam);

void x87_fxch(X87State*, uint32_t);
using x87_fxch_t = decltype(&x87_fxch);

void x87_fxtract(X87State*);
using x87_fxtract_t = decltype(&x87_fxtract);

void x87_fyl2x(X87State*);
using x87_fyl2x_t = decltype(&x87_fyl2x);

void x87_fyl2xp1(X87State*);
using x87_fyl2xp1_t = decltype(&x87_fyl2xp1);

void sse_pcmpestri();
using sse_pcmpestri_t = decltype(&sse_pcmpestri);

void sse_pcmpestrm();
using sse_pcmpestrm_t = decltype(&sse_pcmpestrm);

void sse_pcmpistri();
using sse_pcmpistri_t = decltype(&sse_pcmpistri);

void sse_pcmpistrm();
using sse_pcmpistrm_t = decltype(&sse_pcmpistrm);

void is_ldt_initialized(void);
using is_ldt_initialized_t = decltype(&is_ldt_initialized);

void get_ldt();
using get_ldt_t = decltype(&get_ldt);

void set_ldt();
using set_ldt_t = decltype(&set_ldt);

void execution_mode_for_code_segment_selector();
using execution_mode_for_code_segment_selector_t =
    decltype(&execution_mode_for_code_segment_selector);

void mov_segment();
using mov_segment_t = decltype(&mov_segment);

void abi_for_address();
using abi_for_address_t = decltype(&abi_for_address);

void determine_state_recovery_action();
using determine_state_recovery_action_t = decltype(&determine_state_recovery_action);

void get_segment_limit();
using get_segment_limit_t = decltype(&get_segment_limit);

void translator_set_variant();
using translator_set_variant_t = decltype(&translator_set_variant);

void x87_set_init_state(X87State*);
using x87_set_init_state_t = decltype(&x87_set_init_state);

void runtime_cpuid();
using runtime_cpuid_t = decltype(&runtime_cpuid);

void runtime_wide_udiv_64();
using runtime_wide_udiv_64_t = decltype(&runtime_wide_udiv_64);

void runtime_wide_sdiv_64();
using runtime_wide_sdiv_64_t = decltype(&runtime_wide_sdiv_64);
