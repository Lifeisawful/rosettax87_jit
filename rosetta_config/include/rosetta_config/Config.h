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
    kCount  // = 58, fits in uint64_t
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
    kCount
};

struct RosettaConfig {
    uint8_t  disable_x87_cache;      // ROSETTA_X87_DISABLE_CACHE=1
    uint8_t  fast_round;             // ROSETTA_X87_FAST_ROUND=1 — skip RC dispatch, always round-to-nearest
    uint8_t  _pad[6];
    uint64_t disabled_ops_mask;      // ROSETTA_X87_DISABLE_OPS=fadd,fsub,...
    uint64_t disabled_fusions_mask;  // ROSETTA_X87_DISABLE_FUSIONS=fld_arithp,...
};
static_assert(sizeof(RosettaConfig) == 0x18);

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
RosettaConfig parse_config_from_env();
