#pragma once

#include <cstdint>

// Bit positions for disabled translated opcodes.
// One bit per individual opcode — no aliasing, no grouping.
enum class OpcodeId : int {
    fldz = 0,
    fld1,
    fldl2e,
    fldl2t,
    fldlg2,
    fldln2,
    fldpi,
    fld,
    fild,
    fadd,
    faddp,
    fiadd,
    fsub,
    fsubr,
    fsubp,
    fsubrp,
    fdiv,
    fdivr,
    fdivp,
    fdivrp,
    fmul,
    fmulp,
    fst,
    fst_stack,
    fstp,
    fstp_stack,
    fstsw,
    fcom,
    fcomp,
    fcompp,
    fucom,
    fucomp,
    fucompp,
    fxch,
    fchs,
    fabs,
    fsqrt,
    fistp,
    fidiv,
    fimul,
    fisub,
    fidivr,
    frndint,
    fcomi,
    fcomip,
    fucomi,
    fucomip,
    ftst,
    fist,
    fisubr,
    fcmovb,
    fcmovbe,
    fcmove,
    fcmovnb,
    fcmovnbe,
    fcmovne,
    fcmovu,
    fcmovnu,
    fisttp,
    ficom,
    ficomp,
    kCount  // = 61, fits in uint64_t
};

// Bit positions for peephole fusion patterns in TranslatorX87Fusion.cpp.
enum class FusionId : int {
    fld_arithp = 0,     // FLD + FADDP / FSUBP / FDIVP / FMULP
    fld_fstp,           // FLD + FSTP
    fld_arith_fstp,     // FLD + ARITH + FSTP  (3-instruction)
    fld_fcomp_fstsw,    // FLD + FCOMP + FSTSW (3-instruction)
    fxch_arithp,        // FXCH + FADDP / FSUBP / etc.
    fxch_fstp,          // FXCH + FSTP
    fcom_fstsw,         // FCOM/FCOMP/FUCOM/FUCOMP/FCOMPP/FUCOMPP + FSTSW
    fld_fcompp_fstsw,   // FLD + FCOMPP/FUCOMPP + FSTSW (3-instruction, net pop)
    fld_fld_fucompp,    // FLD + FLD + FCOMPP/FUCOMPP [+ FSTSW] (3- or 4-instruction)
    fld_fcomp,          // FLD + FCOMP/FUCOMP (2-instruction, no FSTSW)
    fld_arith_arithp,   // FLD + ARITH + ARITHp (3-instruction, push+pop cancel)
    arithp_fstp,        // ARITHp ST(1) + FSTP mem (2-instruction, skip stack writeback)
    fstp_fld,           // FSTP + FLD/FILD/FLDZ/FLD1/FLDconst (2-instruction, pop+push cancel)
    arith_fstp,         // non-popping ARITH + FSTP mem (2-instruction, skip intermediate stack store)
    arith_faddp,        // FMUL + FADDP/FSUBP/FSUBRP → FMADD/FMSUB/FNMSUB (2-instruction, FMA fusion)
    kCount
};

struct RosettaConfig {
    uint8_t  disable_x87_cache;      // ROSETTA_X87_DISABLE_CACHE=1
    uint8_t  fast_round;             // ROSETTA_X87_FAST_ROUND=1 — skip RC dispatch, always round-to-nearest
    uint8_t  disable_deferred_fxch;  // ROSETTA_X87_DISABLE_DEFERRED_FXCH=1 — disable OPT-G
    uint8_t  disable_x87_ir;         // ROSETTA_X87_DISABLE_IR=1 — disable IR optimization pipeline
    uint8_t  extended_fpr_scratch;   // ROSETTA_X87_EXTENDED_FPR_SCRATCH=1 — expand FPR scratch pool from 8 (V24–V31) to 16 (V16–V31)
    uint8_t  disable_const_promote;  // ROSETTA_X87_DISABLE_CONST_PROMOTE=1 — don't promote loads from read-only absolute addresses to constants
    uint8_t  fuse_fcom_test;         // ROSETTA_X87_FUSE_FCOM_TEST=1 — fuse fcom+fnstsw+test into FCMP+CSET+TST (leaves AX/status-word CC stale; opt-in)
    uint8_t  force_cpu_mode32;       // ROSETTA_FORCE_CPU_MODE32=1 — force the decoder into 32-bit mode (test-only; lets aotinvoke reach legacy opcodes like ARPL)
    uint8_t  disable_f32_narrow;     // ROSETTA_X87_DISABLE_F32_NARROW=1 — don't rewrite narrow(op_f64(widen,widen)) to S-form arithmetic
    uint8_t  f32_arith;              // ROSETTA_X87_F32_ARITH=1 — keep f32-sourced arithmetic CHAINS in f32 (not bit-exact vs f64 intermediates; opt-in)
    uint8_t  fast_recip_div;         // ROSETTA_X87_FAST_RECIP_DIV=1 — FDiv by ANY normal constant → FMul by reciprocal (up to 1 ulp off; opt-in)
    uint8_t  log_ir_declines;        // ROSETTA_X87_LOG_IR_DECLINES=1 — print address + CompileError for every run the IR pipeline declines
    uint8_t  disable_addr_fold;      // ROSETTA_X87_DISABLE_ADDR_FOLD=1 — don't fold base+disp into LDR/STR addressing modes (singular + fusion paths)
    uint8_t  decline_all;            // ROSETTA_X87_DECLINE_ALL=1 — translate_instruction declines EVERY instruction before any cache/state access (bisection: hook installed, zero engagement)
    uint8_t  disable_size_patch;     // ROSETTA_X87_DISABLE_SIZE_PATCH=1 — skip the TranslationResult alloc-size patch (0x268→0x400) (bisection)
    uint8_t  disable_decode_hook;    // ROSETTA_X87_DISABLE_DECODE_HOOK=1 — don't install hook_decode_opcode (no ARPL/DC-D8 substitution) (bisection)
    uint8_t  disable_classify_hook;  // ROSETTA_X87_DISABLE_CLASSIFY_HOOK=1 — don't install classify_arm_pc hook (bisection)
    uint8_t  disable_translate_hook; // ROSETTA_X87_DISABLE_TRANSLATE_HOOK=1 — don't install hook_translate_insn at all (bisection; implies no size patch side effects from that init)
    uint64_t disabled_ops_mask;      // ROSETTA_X87_DISABLE_OPS=fadd,fsub,...
    uint64_t disabled_fusions_mask;  // ROSETTA_X87_DISABLE_FUSIONS=fld_arithp,...
};
static_assert(sizeof(RosettaConfig) == 0x28);

inline bool op_is_disabled(const RosettaConfig& cfg, OpcodeId id) {
    return (cfg.disabled_ops_mask >> static_cast<int>(id)) & 1u;
}

inline bool fusion_is_disabled(const RosettaConfig& cfg, FusionId id) {
    return (cfg.disabled_fusions_mask >> static_cast<int>(id)) & 1u;
}

// Parse configuration from environment variables.
// Only call from normal executables (aotinvoke, runtime_loader).
// Environment variables:
//   ROSETTA_X87_DISABLE_CACHE=1          disable X87Cache
//   ROSETTA_X87_DISABLE_OPS=fadd,fmul    disable specific translated opcodes
//   ROSETTA_X87_DISABLE_ALL_OPS=1        disable all translated opcodes
//   ROSETTA_X87_DISABLE_FUSIONS=fld_arithp,fcom_fstsw  disable specific fusions
//   ROSETTA_X87_DISABLE_ALL_FUSIONS=1    disable all fusion patterns
//   ROSETTA_X87_FAST_ROUND=1             skip RC dispatch; always emit FCVTNS/FRINTN (nearest only)
//   ROSETTA_X87_DISABLE_IR=1             disable IR-based optimization pipeline
//   ROSETTA_X87_EXTENDED_FPR_SCRATCH=1   expand FPR scratch pool from 8 (V24–V31) to 16 (V16–V31)
//   ROSETTA_X87_LOG_IR_DECLINES=1        log address + CompileError for runs the IR pipeline declines
RosettaConfig parse_config_from_env();
