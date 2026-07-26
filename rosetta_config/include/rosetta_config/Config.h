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
    uint8_t  const_promote;          // ROSETTA_X87_CONST_PROMOTE=1 — promote loads from read-only absolute addresses to constants (opt-in)
    uint8_t  force_cpu_mode32;       // ROSETTA_FORCE_CPU_MODE32=1 — force the decoder into 32-bit mode (test-only; lets aotinvoke reach legacy opcodes like ARPL)
    uint8_t  f32_narrow;             // ROSETTA_X87_F32_NARROW=1 — rewrite narrow(op_f64(widen,widen)) to S-form arithmetic (opt-in)
    uint8_t  f32_arith;              // ROSETTA_X87_F32_ARITH=1 — keep f32-sourced arithmetic CHAINS in f32 (not bit-exact vs f64 intermediates; opt-in)
    uint8_t  fast_recip_div;         // ROSETTA_X87_FAST_RECIP_DIV=1 — FDiv by ANY normal constant → FMul by reciprocal (up to 1 ulp off; opt-in)
    uint8_t  log_ir_declines;        // ROSETTA_X87_LOG_IR_DECLINES=1 — print address + CompileError for every run the IR pipeline declines
    uint8_t  disable_addr_fold;      // ROSETTA_X87_DISABLE_ADDR_FOLD=1 — don't fold base+disp into LDR/STR addressing modes (singular + fusion paths)
    uint8_t  log_run_breaks;         // ROSETTA_X87_LOG_RUN_BREAKS=1 — log length + breaking opcode + gap-to-next-x87 for every x87 run
    uint8_t  run_bridge;             // ROSETTA_X87_RUN_BRIDGE=1 — keep an active run's pinned cache GPRs across run-transparent integer instrs (mov/lea/…; opt-in)
    uint8_t  transparent_int;        // ROSETTA_X87_TRANSPARENT_INT=1 — inline simple reg-form mov/lea/movzx/movsx into IR runs (requires RUN_BRIDGE; opt-in)
    uint8_t  bridge_carry;           // ROSETTA_X87_BRIDGE_CARRY=1 — carry base-address-cache + RC GPRs across bridged gaps (implies RUN_BRIDGE; opt-in)
    uint8_t  runtime_keepalive;      // ROSETTA_X87_RUNTIME_KEEPALIVE=1 — keep the pinned cache alive across runtime-routine transcendentals (fsin/fcos/…; opt-in)
    uint8_t  disable_fcos_fast;      // ROSETTA_X87_DISABLE_FCOS_FAST=1 — route FCOS through the classic prologue/vtable stub instead of the in-blob fast path
    uint8_t  disable_fsin_fast;      // ROSETTA_X87_DISABLE_FSIN_FAST=1 — same for FSIN
    uint8_t  disable_fsincos_fast;   // ROSETTA_X87_DISABLE_FSINCOS_FAST=1 — same for FSINCOS
    uint8_t  disable_fptan_fast;     // ROSETTA_X87_DISABLE_FPTAN_FAST=1 — same for FPTAN
    uint64_t disabled_ops_mask;      // ROSETTA_X87_DISABLE_OPS=fadd,fsub,...
    uint64_t disabled_fusions_mask;  // ROSETTA_X87_DISABLE_FUSIONS=fld_arithp,...
};
// Grown 0x20 → 0x28 when the 17th byte-flag (bridge_carry) crossed the old
// size. The loader writes this struct into the runtime's __DATA,config by
// sizeof — both sides compile from this header, so they stay in sync as long
// as loader and runtime dylib come from the same build.
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
