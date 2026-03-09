#include "Export.h"

#include <array>

#include "X87.h"

__attribute__((used)) init_library_t orig_init_library;
__attribute__((used)) register_runtime_routine_offsets_t orig_register_runtime_routine_offsets;
__attribute__((used)) translator_use_t8027_codegen_t orig_translator_use_t8027_codegen;
__attribute__((used)) translator_reset_t orig_translator_reset;
__attribute__((used)) ir_create_bad_access_t orig_ir_create_bad_access;
__attribute__((used)) ir_create_t orig_ir_create;
__attribute__((used)) module_free_t orig_module_free;
__attribute__((used)) module_get_size_t orig_module_get_size;
__attribute__((used)) module_is_bad_access_t orig_module_is_bad_access;
__attribute__((used)) module_print_t orig_module_print;
__attribute__((used)) translator_translate_t orig_translator_translate;
__attribute__((used)) translator_free_t orig_translator_free;
__attribute__((used)) translator_get_data_t orig_translator_get_data;
__attribute__((used)) translator_get_size_t orig_translator_get_size;
__attribute__((used)) translator_get_branch_slots_offset_t orig_translator_get_branch_slots_offset;
__attribute__((used)) translator_get_branch_slots_count_t orig_translator_get_branch_slots_count;
__attribute__((used)) translator_get_branch_entries_t orig_translator_get_branch_entries;
__attribute__((used)) translator_get_instruction_offsets_t orig_translator_get_instruction_offsets;
__attribute__((used)) translator_apply_fixups_t orig_translator_apply_fixups;
__attribute__((used)) x87_init_t orig_x87_init;
__attribute__((used)) x87_state_from_x86_float_state_t orig_x87_state_from_x86_float_state;
__attribute__((used)) x87_state_to_x86_float_state_t orig_x87_state_to_x86_float_state;
__attribute__((used)) x87_pop_register_stack_t orig_x87_pop_register_stack;
__attribute__((used)) x87_f2xm1_t orig_x87_f2xm1;
__attribute__((used)) x87_fabs_t orig_x87_fabs;
__attribute__((used)) x87_fadd_ST_t orig_x87_fadd_ST;
__attribute__((used)) x87_fadd_f32_t orig_x87_fadd_f32;
__attribute__((used)) x87_fadd_f64_t orig_x87_fadd_f64;
__attribute__((used)) x87_fbld_t orig_x87_fbld;
__attribute__((used)) x87_fbstp_t orig_x87_fbstp;
__attribute__((used)) x87_fchs_t orig_x87_fchs;
__attribute__((used)) x87_fcmov_t orig_x87_fcmov;
__attribute__((used)) x87_fcom_ST_t orig_x87_fcom_ST;
__attribute__((used)) x87_fcom_f32_t orig_x87_fcom_f32;
__attribute__((used)) x87_fcom_f64_t orig_x87_fcom_f64;
__attribute__((used)) x87_fcomi_t orig_x87_fcomi;
__attribute__((used)) x87_fcos_t orig_x87_fcos;
__attribute__((used)) x87_fdecstp_t orig_x87_fdecstp;
__attribute__((used)) x87_fdiv_ST_t orig_x87_fdiv_ST;
__attribute__((used)) x87_fdiv_f32_t orig_x87_fdiv_f32;
__attribute__((used)) x87_fdiv_f64_t orig_x87_fdiv_f64;
__attribute__((used)) x87_fdivr_ST_t orig_x87_fdivr_ST;
__attribute__((used)) x87_fdivr_f32_t orig_x87_fdivr_f32;
__attribute__((used)) x87_fdivr_f64_t orig_x87_fdivr_f64;
__attribute__((used)) x87_ffree_t orig_x87_ffree;
__attribute__((used)) x87_fiadd_t orig_x87_fiadd;
__attribute__((used)) x87_ficom_t orig_x87_ficom;
__attribute__((used)) x87_fidiv_t orig_x87_fidiv;
__attribute__((used)) x87_fidivr_t orig_x87_fidivr;
__attribute__((used)) x87_fild_t orig_x87_fild;
__attribute__((used)) x87_fimul_t orig_x87_fimul;
__attribute__((used)) x87_fincstp_t orig_x87_fincstp;
__attribute__((used)) x87_fist_i16_t orig_x87_fist_i16;
__attribute__((used)) x87_fist_i32_t orig_x87_fist_i32;
__attribute__((used)) x87_fist_i64_t orig_x87_fist_i64;
__attribute__((used)) x87_fistt_i16_t orig_x87_fistt_i16;
__attribute__((used)) x87_fistt_i32_t orig_x87_fistt_i32;
__attribute__((used)) x87_fistt_i64_t orig_x87_fistt_i64;
__attribute__((used)) x87_fisub_t orig_x87_fisub;
__attribute__((used)) x87_fisubr_t orig_x87_fisubr;
__attribute__((used)) x87_fld_STi_t orig_x87_fld_STi;
__attribute__((used)) x87_fld_constant_t orig_x87_fld_constant;
__attribute__((used)) x87_fld_fp32_t orig_x87_fld_fp32;
__attribute__((used)) x87_fld_fp64_t orig_x87_fld_fp64;
__attribute__((used)) x87_fld_fp80_t orig_x87_fld_fp80;
__attribute__((used)) x87_fmul_ST_t orig_x87_fmul_ST;
__attribute__((used)) x87_fmul_f32_t orig_x87_fmul_f32;
__attribute__((used)) x87_fmul_f64_t orig_x87_fmul_f64;
__attribute__((used)) x87_fpatan_t orig_x87_fpatan;
__attribute__((used)) x87_fprem_t orig_x87_fprem;
__attribute__((used)) x87_fprem1_t orig_x87_fprem1;
__attribute__((used)) x87_fptan_t orig_x87_fptan;
__attribute__((used)) x87_frndint_t orig_x87_frndint;
__attribute__((used)) x87_fscale_t orig_x87_fscale;
__attribute__((used)) x87_fsin_t orig_x87_fsin;
__attribute__((used)) x87_fsincos_t orig_x87_fsincos;
__attribute__((used)) x87_fsqrt_t orig_x87_fsqrt;
__attribute__((used)) x87_fst_STi_t orig_x87_fst_STi;
__attribute__((used)) x87_fst_fp32_t orig_x87_fst_fp32;
__attribute__((used)) x87_fst_fp64_t orig_x87_fst_fp64;
__attribute__((used)) x87_fst_fp80_t orig_x87_fst_fp80;
__attribute__((used)) x87_fsub_ST_t orig_x87_fsub_ST;
__attribute__((used)) x87_fsub_f32_t orig_x87_fsub_f32;
__attribute__((used)) x87_fsub_f64_t orig_x87_fsub_f64;
__attribute__((used)) x87_fsubr_ST_t orig_x87_fsubr_ST;
__attribute__((used)) x87_fsubr_f32_t orig_x87_fsubr_f32;
__attribute__((used)) x87_fsubr_f64_t orig_x87_fsubr_f64;
__attribute__((used)) x87_fucom_t orig_x87_fucom;
__attribute__((used)) x87_fucomi_t orig_x87_fucomi;
__attribute__((used)) x87_fxam_t orig_x87_fxam;
__attribute__((used)) x87_fxch_t orig_x87_fxch;
__attribute__((used)) x87_fxtract_t orig_x87_fxtract;
__attribute__((used)) x87_fyl2x_t orig_x87_fyl2x;
__attribute__((used)) x87_fyl2xp1_t orig_x87_fyl2xp1;
__attribute__((used)) sse_pcmpestri_t orig_sse_pcmpestri;
__attribute__((used)) sse_pcmpestrm_t orig_sse_pcmpestrm;
__attribute__((used)) sse_pcmpistri_t orig_sse_pcmpistri;
__attribute__((used)) sse_pcmpistrm_t orig_sse_pcmpistrm;
__attribute__((used)) is_ldt_initialized_t orig_is_ldt_initialized;
__attribute__((used)) get_ldt_t orig_get_ldt;
__attribute__((used)) set_ldt_t orig_set_ldt;
__attribute__((
    used)) execution_mode_for_code_segment_selector_t orig_execution_mode_for_code_segment_selector;
__attribute__((used)) mov_segment_t orig_mov_segment;
__attribute__((used)) abi_for_address_t orig_abi_for_address;
__attribute__((used)) determine_state_recovery_action_t orig_determine_state_recovery_action;
__attribute__((used)) get_segment_limit_t orig_get_segment_limit;
__attribute__((used)) translator_set_variant_t orig_translator_set_variant;
// __attribute__((used)) x87_set_init_state_t orig_x87_set_init_state;

__attribute__((used)) runtime_cpuid_t orig_runtime_cpuid;
__attribute__((used)) runtime_wide_udiv_64_t orig_runtime_wide_udiv_64;
__attribute__((used)) runtime_wide_sdiv_64_t orig_runtime_wide_sdiv_64;

constexpr std::array kExportList{
    Export{(void*)&init_library,
           "__ZN7rosetta7runtime7library12init_libraryEPKNS1_10SymbolListEyPKNS_"
           "20ThreadContextOffsetsE"},
    Export{(void*)&register_runtime_routine_offsets,
           "__ZN7rosetta7runtime7library32register_runtime_routine_offsetsEPKyPPKcm"},
    Export{(void*)&translator_use_t8027_codegen,
           "__ZN7rosetta7runtime7library28translator_use_t8027_codegenEb"},
    Export{(void*)&translator_reset, "__ZN7rosetta7runtime7library16translator_resetEv"},
    Export{(void*)&ir_create_bad_access,
           "__ZN7rosetta7runtime7library20ir_create_bad_accessEy13BadAccessKind"},
    Export{(void*)&ir_create,
           "__ZN7rosetta7runtime7library9ir_createEyjj15TranslationMode13ExecutionMode"},
    Export{(void*)&module_free, "__ZN7rosetta7runtime7library11module_freeEPKNS1_12ModuleResultE"},
    Export{(void*)&module_get_size,
           "__ZN7rosetta7runtime7library15module_get_sizeEPKNS1_12ModuleResultE"},
    Export{(void*)&module_is_bad_access,
           "__ZN7rosetta7runtime7library20module_is_bad_accessEPKNS1_12ModuleResultE"},
    Export{(void*)&module_print,
           "__ZN7rosetta7runtime7library12module_printEPKNS1_12ModuleResultEi"},
    Export{(void*)&translator_translate,
           "__ZN7rosetta7runtime7library20translator_translateEPKNS1_"
           "12ModuleResultE15TranslationMode"},
    Export{(void*)&translator_free,
           "__ZN7rosetta7runtime7library15translator_freeEPKNS1_17TranslationResultE"},
    Export{(void*)&translator_get_data,
           "__ZN7rosetta7runtime7library19translator_get_dataEPKNS1_17TranslationResultE"},
    Export{(void*)&translator_get_size,
           "__ZN7rosetta7runtime7library19translator_get_sizeEPKNS1_17TranslationResultE"},
    Export{(void*)&translator_get_branch_slots_offset,
           "__ZN7rosetta7runtime7library34translator_get_branch_slots_offsetEPKNS1_"
           "17TranslationResultE"},
    Export{(void*)&translator_get_branch_slots_count,
           "__ZN7rosetta7runtime7library33translator_get_branch_slots_countEPKNS1_"
           "17TranslationResultE"},
    Export{
        (void*)&translator_get_branch_entries,
        "__ZN7rosetta7runtime7library29translator_get_branch_entriesEPKNS1_17TranslationResultE"},
    Export{(void*)&translator_get_instruction_offsets,
           "__ZN7rosetta7runtime7library34translator_get_instruction_offsetsEPKNS1_"
           "17TranslationResultE"},
    Export{(void*)&translator_apply_fixups,
           "__ZN7rosetta7runtime7library23translator_apply_fixupsEPNS1_17TranslationResultEPhy"},
    Export{(void*)&x87_init, "__ZN7rosetta7runtime7library8x87_initEPNS1_8X87StateE"},
    Export{(void*)&x87_state_from_x86_float_state,
           "__ZN7rosetta7runtime7library30x87_state_from_x86_float_stateEPNS1_8X87StateEPKNS0_"
           "15X86FloatState64E"},
    Export{(void*)&x87_state_to_x86_float_state,
           "__ZN7rosetta7runtime7library28x87_state_to_x86_float_stateEPKNS1_8X87StateEPNS0_"
           "15X86FloatState64E"},
    Export{(void*)&x87_pop_register_stack,
           "__ZN7rosetta7runtime7library22x87_pop_register_stackEPNS1_8X87StateE"},
    Export{(void*)&x87_f2xm1, "__ZN7rosetta7runtime7library9x87_f2xm1EPNS1_8X87StateE"},
    Export{(void*)&x87_fabs, "__ZN7rosetta7runtime7library8x87_fabsEPNS1_8X87StateE"},
    Export{(void*)&x87_fadd_ST, "__ZN7rosetta7runtime7library11x87_fadd_STEPNS1_8X87StateEjjb"},
    Export{(void*)&x87_fadd_f32, "__ZN7rosetta7runtime7library12x87_fadd_f32EPNS1_8X87StateEj"},
    Export{(void*)&x87_fadd_f64, "__ZN7rosetta7runtime7library12x87_fadd_f64EPNS1_8X87StateEy"},
    Export{(void*)&x87_fbld, "__ZN7rosetta7runtime7library8x87_fbldEPNS1_8X87StateEyy"},
    Export{(void*)&x87_fbstp, "__ZN7rosetta7runtime7library9x87_fbstpEPKNS1_8X87StateE"},
    Export{(void*)&x87_fchs, "__ZN7rosetta7runtime7library8x87_fchsEPNS1_8X87StateE"},
    Export{(void*)&x87_fcmov, "__ZN7rosetta7runtime7library9x87_fcmovEPNS1_8X87StateEjj"},
    Export{(void*)&x87_fcom_ST, "__ZN7rosetta7runtime7library11x87_fcom_STEPNS1_8X87StateEjj"},
    Export{(void*)&x87_fcom_f32, "__ZN7rosetta7runtime7library12x87_fcom_f32EPNS1_8X87StateEjb"},
    Export{(void*)&x87_fcom_f64, "__ZN7rosetta7runtime7library12x87_fcom_f64EPNS1_8X87StateEyb"},
    Export{(void*)&x87_fcomi, "__ZN7rosetta7runtime7library9x87_fcomiEPNS1_8X87StateEjb"},
    Export{(void*)&x87_fcos, "__ZN7rosetta7runtime7library8x87_fcosEPNS1_8X87StateE"},
    Export{(void*)&x87_fdecstp, "__ZN7rosetta7runtime7library11x87_fdecstpEPNS1_8X87StateE"},
    Export{(void*)&x87_fdiv_ST, "__ZN7rosetta7runtime7library11x87_fdiv_STEPNS1_8X87StateEjjb"},
    Export{(void*)&x87_fdiv_f32, "__ZN7rosetta7runtime7library12x87_fdiv_f32EPNS1_8X87StateEj"},
    Export{(void*)&x87_fdiv_f64, "__ZN7rosetta7runtime7library12x87_fdiv_f64EPNS1_8X87StateEy"},
    Export{(void*)&x87_fdivr_ST, "__ZN7rosetta7runtime7library12x87_fdivr_STEPNS1_8X87StateEjjb"},
    Export{(void*)&x87_fdivr_f32, "__ZN7rosetta7runtime7library13x87_fdivr_f32EPNS1_8X87StateEj"},
    Export{(void*)&x87_fdivr_f64, "__ZN7rosetta7runtime7library13x87_fdivr_f64EPNS1_8X87StateEy"},
    Export{(void*)&x87_ffree, "__ZN7rosetta7runtime7library9x87_ffreeEPNS1_8X87StateEj"},
    Export{(void*)&x87_fiadd, "__ZN7rosetta7runtime7library9x87_fiaddEPNS1_8X87StateEi"},
    Export{(void*)&x87_ficom, "__ZN7rosetta7runtime7library9x87_ficomEPNS1_8X87StateEib"},
    Export{(void*)&x87_fidiv, "__ZN7rosetta7runtime7library9x87_fidivEPNS1_8X87StateEi"},
    Export{(void*)&x87_fidivr, "__ZN7rosetta7runtime7library10x87_fidivrEPNS1_8X87StateEi"},
    Export{(void*)&x87_fild, "__ZN7rosetta7runtime7library8x87_fildEPNS1_8X87StateEx"},
    Export{(void*)&x87_fimul, "__ZN7rosetta7runtime7library9x87_fimulEPNS1_8X87StateEi"},
    Export{(void*)&x87_fincstp, "__ZN7rosetta7runtime7library11x87_fincstpEPNS1_8X87StateE"},
    Export{(void*)&x87_fist_i16, "__ZN7rosetta7runtime7library12x87_fist_i16EPKNS1_8X87StateE"},
    Export{(void*)&x87_fist_i32, "__ZN7rosetta7runtime7library12x87_fist_i32EPKNS1_8X87StateE"},
    Export{(void*)&x87_fist_i64, "__ZN7rosetta7runtime7library12x87_fist_i64EPKNS1_8X87StateE"},
    Export{(void*)&x87_fistt_i16, "__ZN7rosetta7runtime7library13x87_fistt_i16EPKNS1_8X87StateE"},
    Export{(void*)&x87_fistt_i32, "__ZN7rosetta7runtime7library13x87_fistt_i32EPKNS1_8X87StateE"},
    Export{(void*)&x87_fistt_i64, "__ZN7rosetta7runtime7library13x87_fistt_i64EPKNS1_8X87StateE"},
    Export{(void*)&x87_fisub, "__ZN7rosetta7runtime7library9x87_fisubEPNS1_8X87StateEi"},
    Export{(void*)&x87_fisubr, "__ZN7rosetta7runtime7library10x87_fisubrEPNS1_8X87StateEi"},
    Export{(void*)&x87_fld_STi, "__ZN7rosetta7runtime7library11x87_fld_STiEPNS1_8X87StateEj"},
    Export{(void*)&x87_fld_constant,
           "__ZN7rosetta7runtime7library16x87_fld_constantEPNS1_8X87StateENS_"
           "10translator3x8711X87ConstantE"},
    Export{(void*)&x87_fld_fp32, "__ZN7rosetta7runtime7library12x87_fld_fp32EPNS1_8X87StateEj"},
    Export{(void*)&x87_fld_fp64, "__ZN7rosetta7runtime7library12x87_fld_fp64EPNS1_8X87StateEy"},
    Export{(void*)&x87_fld_fp80,
           "__ZN7rosetta7runtime7library12x87_fld_fp80EPNS1_8X87StateENS1_10X87Float80E"},
    Export{(void*)&x87_fmul_ST, "__ZN7rosetta7runtime7library11x87_fmul_STEPNS1_8X87StateEjjb"},
    Export{(void*)&x87_fmul_f32, "__ZN7rosetta7runtime7library12x87_fmul_f32EPNS1_8X87StateEj"},
    Export{(void*)&x87_fmul_f64, "__ZN7rosetta7runtime7library12x87_fmul_f64EPNS1_8X87StateEy"},
    Export{(void*)&x87_fpatan, "__ZN7rosetta7runtime7library10x87_fpatanEPNS1_8X87StateE"},
    Export{(void*)&x87_fprem, "__ZN7rosetta7runtime7library9x87_fpremEPNS1_8X87StateE"},
    Export{(void*)&x87_fprem1, "__ZN7rosetta7runtime7library10x87_fprem1EPNS1_8X87StateE"},
    Export{(void*)&x87_fptan, "__ZN7rosetta7runtime7library9x87_fptanEPNS1_8X87StateE"},
    Export{(void*)&x87_frndint, "__ZN7rosetta7runtime7library11x87_frndintEPNS1_8X87StateE"},
    Export{(void*)&x87_fscale, "__ZN7rosetta7runtime7library10x87_fscaleEPNS1_8X87StateE"},
    Export{(void*)&x87_fsin, "__ZN7rosetta7runtime7library8x87_fsinEPNS1_8X87StateE"},
    Export{(void*)&x87_fsincos, "__ZN7rosetta7runtime7library11x87_fsincosEPNS1_8X87StateE"},
    Export{(void*)&x87_fsqrt, "__ZN7rosetta7runtime7library9x87_fsqrtEPNS1_8X87StateE"},
    Export{(void*)&x87_fst_STi, "__ZN7rosetta7runtime7library11x87_fst_STiEPNS1_8X87StateEjb"},
    Export{(void*)&x87_fst_fp32, "__ZN7rosetta7runtime7library12x87_fst_fp32EPKNS1_8X87StateE"},
    Export{(void*)&x87_fst_fp64, "__ZN7rosetta7runtime7library12x87_fst_fp64EPKNS1_8X87StateE"},
    Export{(void*)&x87_fst_fp80, "__ZN7rosetta7runtime7library12x87_fst_fp80EPKNS1_8X87StateE"},
    Export{(void*)&x87_fsub_ST, "__ZN7rosetta7runtime7library11x87_fsub_STEPNS1_8X87StateEjjb"},
    Export{(void*)&x87_fsub_f32, "__ZN7rosetta7runtime7library12x87_fsub_f32EPNS1_8X87StateEj"},
    Export{(void*)&x87_fsub_f64, "__ZN7rosetta7runtime7library12x87_fsub_f64EPNS1_8X87StateEy"},
    Export{(void*)&x87_fsubr_ST, "__ZN7rosetta7runtime7library12x87_fsubr_STEPNS1_8X87StateEjjb"},
    Export{(void*)&x87_fsubr_f32, "__ZN7rosetta7runtime7library13x87_fsubr_f32EPNS1_8X87StateEj"},
    Export{(void*)&x87_fsubr_f64, "__ZN7rosetta7runtime7library13x87_fsubr_f64EPNS1_8X87StateEy"},
    Export{(void*)&x87_fucom, "__ZN7rosetta7runtime7library9x87_fucomEPNS1_8X87StateEjj"},
    Export{(void*)&x87_fucomi, "__ZN7rosetta7runtime7library10x87_fucomiEPNS1_8X87StateEjb"},
    Export{(void*)&x87_fxam, "__ZN7rosetta7runtime7library8x87_fxamEPNS1_8X87StateE"},
    Export{(void*)&x87_fxch, "__ZN7rosetta7runtime7library8x87_fxchEPNS1_8X87StateEj"},
    Export{(void*)&x87_fxtract, "__ZN7rosetta7runtime7library11x87_fxtractEPNS1_8X87StateE"},
    Export{(void*)&x87_fyl2x, "__ZN7rosetta7runtime7library9x87_fyl2xEPNS1_8X87StateE"},
    Export{(void*)&x87_fyl2xp1, "__ZN7rosetta7runtime7library11x87_fyl2xp1EPNS1_8X87StateE"},
    Export{(void*)&sse_pcmpestri, "__ZN7rosetta7runtime7library13sse_pcmpestriEyyyyhxx"},
    Export{(void*)&sse_pcmpestrm, "__ZN7rosetta7runtime7library13sse_pcmpestrmEyyyyhxx"},
    Export{(void*)&sse_pcmpistri, "__ZN7rosetta7runtime7library13sse_pcmpistriEyyyyh"},
    Export{(void*)&sse_pcmpistrm, "__ZN7rosetta7runtime7library13sse_pcmpistrmEyyyyh"},
    Export{(void*)&is_ldt_initialized, "__ZN7rosetta7runtime7library18is_ldt_initializedEv"},
    Export{(void*)&get_ldt, "__ZN7rosetta7runtime7library7get_ldtEjjPvj"},
    Export{(void*)&set_ldt, "__ZN7rosetta7runtime7library7set_ldtEjjPKvj"},
    Export{(void*)&execution_mode_for_code_segment_selector,
           "__ZN7rosetta7runtime7library40execution_mode_for_code_segment_selectorEjt"},
    Export{(void*)&mov_segment,
           "__ZN7rosetta7runtime7library11mov_segmentEjPNS1_16SegmentRegistersENS1_"
           "15SegmentRegisterEt"},
    Export{(void*)&abi_for_address, "__ZN7rosetta7runtime7library15abi_for_addressEy"},
    Export{(void*)&determine_state_recovery_action,
           "__ZN7rosetta7runtime7library31determine_state_recovery_actionEPKjjj"},
    Export{(void*)&get_segment_limit, "__ZN7rosetta7runtime7library17get_segment_limitEjt"},
    Export{(void*)&translator_set_variant,
           "__ZN7rosetta7runtime7library22translator_set_variantEb"},
    Export{(void*)&x87_set_init_state,
           "__ZN7rosetta7runtime7library18x87_set_init_stateEPNS1_8X87StateE"},
};

constexpr std::array kRuntimeExportList = {
    Export{(void*)&runtime_cpuid, "runtime_cpuid"},
    Export{(void*)&runtime_wide_udiv_64, "runtime_wide_udiv_64"},
    Export{(void*)&runtime_wide_sdiv_64, "runtime_wide_sdiv_64"},
};

__attribute__((section("__DATA,exports"), used)) Exports kExports = {
    0x16A0000000000,           kExportList.data(),        kExportList.size(),
    kRuntimeExportList.data(), kRuntimeExportList.size(),
};

// this is filled in by loader with the exports of libRosettaRuntime
__attribute__((section("__DATA,imports"), used)) Exports kImports = {
    0x0, 0x0, 0x0, 0x0, 0x0,
};

auto exportsInit() -> void {
    // copy the exports from libRosettaRuntime to orig_* function pointers
    void** p = (void**)&orig_init_library;
    for (auto i = 0; i < kImports.x87ExportCount; i++) {
        *p = kImports.x87Exports[i].address;
        p++;
    }

    p = (void**)&orig_runtime_cpuid;
    for (auto i = 0; i < kImports.runtimeExportCount; i++) {
        *p = kImports.runtimeExports[i].address;
        p++;
    }
}
