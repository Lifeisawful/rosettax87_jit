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
    fcos,    // these three gate the OPT-TI translated trig (value call / IR
    fsin,    // node), not classic inline translations — see the
    fptan,   // trig_ir_*_enabled predicates
    kCount  // = 64, fits in uint64_t
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
    uint8_t  transparent_int;        // ROSETTA_X87_TRANSPARENT_INT=1 — inline simple reg-form mov/lea/movzx/movsx/not into IR runs (requires RUN_BRIDGE; opt-in)
    uint8_t  transparent_flags;      // ROSETTA_X87_TRANSPARENT_FLAGS=1 — also inline flag-writing ALU forms (xor r,r; add/sub/and/or/xor/shl/shr/sar r,imm; inc/dec/neg r; {add,sub,and,or,xor} [m],r) when Rosetta's flag-liveness analysis proves the flags each form defines dead (implies TRANSPARENT_INT; opt-in)
    uint8_t  bridge_carry;           // ROSETTA_X87_BRIDGE_CARRY=1 — carry base-address-cache + RC GPRs across bridged gaps (implies RUN_BRIDGE; opt-in)
    uint8_t  runtime_keepalive;      // ROSETTA_X87_RUNTIME_KEEPALIVE=1 — keep the pinned cache alive across runtime-routine transcendentals (fsin/fcos/…; opt-in)
    uint8_t  disable_fcos_fast;      // ROSETTA_X87_DISABLE_FCOS_FAST=1 — route FCOS through the classic prologue/vtable stub instead of the in-blob fast path
    uint8_t  disable_fsin_fast;      // ROSETTA_X87_DISABLE_FSIN_FAST=1 — same for FSIN
    uint8_t  disable_fsincos_fast;   // ROSETTA_X87_DISABLE_FSINCOS_FAST=1 — same for FSINCOS
    uint8_t  disable_fptan_fast;     // ROSETTA_X87_DISABLE_FPTAN_FAST=1 — same for FPTAN
    uint8_t  trig_ir;                // ROSETTA_X87_TRIG_IR=1 — translate FCOS as a value call (_stub_fcos_val): IR node inside runs, ldr/BL/str singular form outside (opt-in)
    uint8_t  disable_f2xm1_val;      // ROSETTA_X87_DISABLE_F2XM1_VAL=1 — keep F2XM1 on the classic prologue/vtable stub even under TRIG_IR
    uint8_t  disable_fscale_val;     // ROSETTA_X87_DISABLE_FSCALE_VAL=1 — same for FSCALE
    uint8_t  disable_fyl2x_val;      // ROSETTA_X87_DISABLE_FYL2X_VAL=1 — same for FYL2X
    uint8_t  disable_fyl2xp1_val;    // ROSETTA_X87_DISABLE_FYL2XP1_VAL=1 — same for FYL2XP1
    uint8_t  disable_fpatan_val;     // ROSETTA_X87_DISABLE_FPATAN_VAL=1 — same for FPATAN
    uint8_t  disable_fxam_fast;      // ROSETTA_X87_DISABLE_FXAM_FAST=1 — route FXAM to the classic stub instead of the in-blob fast path
    uint8_t  disable_fxtract_fast;   // ROSETTA_X87_DISABLE_FXTRACT_FAST=1 — same for FXTRACT
    uint8_t  disable_fprem_fast;     // ROSETTA_X87_DISABLE_FPREM_FAST=1 — route FPREM to the classic stub instead of the in-blob fast path
    uint8_t  disable_fprem1_fast;    // ROSETTA_X87_DISABLE_FPREM1_FAST=1 — same for FPREM1
    uint8_t  transparent_pushpop;    // ROSETTA_X87_TRANSPARENT_PUSHPOP=1 — inline push/pop r32/r64 and push imm into IR runs (flag-neutral, no liveness gate; implies TRANSPARENT_INT; opt-in)
    uint8_t  disable_stack_ops;      // ROSETTA_X87_DISABLE_STACKOPS=1 — family gate for fdecstp/fincstp/ffree inline translation (no OpcodeId bits left; also forced by DISABLE_ALL_OPS)
    uint8_t  disable_nzcv_liveness;  // ROSETTA_X87_DISABLE_NZCV_LIVENESS=1 — don't use Rosetta's flag-liveness dataflow to prove NZCV dead at run exit (fall back to the forward whitelist walk alone; bisection lever)
    uint8_t  disable_trig_sw_sink;   // ROSETTA_X87_DISABLE_TRIG_SW_SINK=1 — keep every trig/pow value call's C1|C2 status_word RMW, even when a later full-halfword writer in the same run makes it dead (bisection lever)
    uint8_t  disable_fcmov_raw;      // ROSETTA_X87_DISABLE_FCMOV_RAW=1 — FCSel reads the packed guest-EFLAGS NZCV installed by FComI's full pack instead of remapped raw FCMP conditions (bisection lever)
    uint8_t  disable_guest_cmp;      // ROSETTA_X87_DISABLE_GUEST_CMP=1 — don't consume cmp/test r32/r64 as in-run guest flag definers (GuestCmpF); the run ends there instead (bisection lever)
    uint8_t  disable_test_shortcut;  // ROSETTA_X87_DISABLE_TEST_SHORTCUT=1 — lower the fnstsw/test CC-mask idiom through the packed-AX TST instead of a raw-FCMP condition (bisection lever)
    uint8_t  disable_stp_suppress;   // ROSETTA_X87_DISABLE_STP_SUPPRESS=1 — keep forming STPs even when the stored bytes are provably reloaded in the same run/block tail (STP-sourced forwarding costs 11 cyc vs 5 on M1; bisection lever)
    uint8_t  disable_x18_state;      // ROSETTA_X87_DISABLE_X18_STATE=1 — always materialize Xbase (ADD x, x18, #off) at run entry instead of addressing fixed SW/CW halfword fields directly off x18 when the run needs nothing else (bisection lever)
    uint8_t  disable_lower_dc;       // ROSETTA_X87_DISABLE_LOWER_DC=1 — disable the Lower dead-code batch: combined pop-pair tag mask (B3), fused-window dead C2 pair elision (B6), and generic-body-deferred Xst_base ADD (bisection lever)
    uint8_t  disable_seam;           // ROSETTA_X87_DISABLE_SEAM=1 — flush TOP/tag state at every run break instead of deferring it across an intra-block seam to the next x87 run (OPT-SEAM; bisection lever)
    uint8_t  transparent_sse;        // ROSETTA_X87_TRANSPARENT_SSE=1 — consume scalar movsd/movss (xmm<->mem) into IR runs, incl. trailing absorption after the last x87 member (OPT-A3; the fstp/movsd seam collapses to a register move; opt-in)
    uint8_t  disable_window_defer;   // ROSETTA_X87_DISABLE_WINDOW_DEFER=1 — mid-window IR runs emit their TOP/tag writeback instead of deferring it into the register-window fields (top_dirty/deferred_*) that the window-ending member flushes (OPT-WD; bisection lever)
    uint8_t  log_backedge;           // ROSETTA_X87_LOG_BACKEDGE=1 — log every module seen by the post-translate hook (OPT-BE stage 0: interception + branch-scan evidence)
    uint8_t  backedge_noop_probe;    // ROSETTA_X87_BACKEDGE_NOOP_PROBE=1 — rewrite every backward conditional-branch word in the post-translate hook with its own value (OPT-BE stage 0 G0.2: buffer writability, must be a byte-identical no-op)
    uint8_t  disable_backedge;       // ROSETTA_X87_DISABLE_BACKEDGE=1 — don't retarget self-loop back edges past the priming st[] load in decode-verified accumulator blocks (OPT-BE; bisection lever)
    uint8_t  disable_test_ccmn;      // ROSETTA_X87_DISABLE_TEST_CCMN=1 — lower the OPT-PS raw-FCMP test shortcut through the two-insn CSET+ANDS pair instead of one integer CCMN (bisection lever)
    uint8_t  disable_guest_setcc;    // ROSETTA_X87_DISABLE_GUEST_SETCC=1 — don't consume setcc r8 after an in-run cmp/test (GuestSetcc), and don't absorb the trailing `test; setcc [; movzx]` compare tail (bisection lever)
    uint8_t  disable_pinned_demand;  // ROSETTA_X87_DISABLE_PINNED_DEMAND=1 — charge the historical flat 4 pinned preamble GPRs in peak_live_gprs instead of the demand-derived count (bisection lever)
    uint8_t  disable_sse_lead;       // ROSETTA_X87_DISABLE_SSE_LEAD=1 — don't form x87 windows at LEADING movsd/movss ahead of a run (R3-2 store-forward seam; bisection lever)
    uint8_t  disable_guest_sahf;     // ROSETTA_X87_DISABLE_GUEST_SAHF=1 — don't consume sahf as an in-run guest flag definer (GuestSahf AH→NZCV install; bisection lever)
    uint64_t disabled_ops_mask;      // ROSETTA_X87_DISABLE_OPS=fadd,fsub,...
    uint64_t disabled_fusions_mask;  // ROSETTA_X87_DISABLE_FUSIONS=fld_arithp,...
};
// Grown 0x20 → 0x28 when the 17th byte-flag (bridge_carry) crossed the old
// size, 0x28 → 0x30 when the 25th (disable_fyl2x_val) crossed again,
// 0x30 → 0x38 when the 33rd (transparent_flags) crossed again,
// 0x38 → 0x40 when the 41st (disable_x18_state) crossed again, and
// 0x40 → 0x48 when the 49th (disable_test_ccmn) crossed again
// (the 50th, disable_guest_setcc, fits the same size).
// The loader writes this struct into the runtime's __DATA,config by
// sizeof — both sides compile from this header, so they stay in sync as long
// as loader and runtime dylib come from the same build.
static_assert(sizeof(RosettaConfig) == 0x48);

inline bool op_is_disabled(const RosettaConfig& cfg, OpcodeId id) {
    return (cfg.disabled_ops_mask >> static_cast<int>(id)) & 1u;
}

inline bool fusion_is_disabled(const RosettaConfig& cfg, FusionId id) {
    return (cfg.disabled_fusions_mask >> static_cast<int>(id)) & 1u;
}

// OPT-TI: FCOS is translated as a value call (and the runtime routes
// kRuntimeRoutine_fcos at _stub_fcos_val) only when this agrees on ALL
// sides — Translator dispatch, X87Cache lookahead membership, X87IRBuild,
// and rewrite_runtime_routine_offsets MUST use this one predicate: a plain
// argument-less BL landing on the value stub computes cos of garbage, and a
// value call landing on a memory stub loses its result.  Boot-constant.
inline bool trig_ir_fcos_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_fcos_fast == 0 &&
           !op_is_disabled(cfg, OpcodeId::fcos);
}
inline bool trig_ir_fsin_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_fsin_fast == 0 &&
           !op_is_disabled(cfg, OpcodeId::fsin);
}
inline bool trig_ir_fptan_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_fptan_fast == 0 &&
           !op_is_disabled(cfg, OpcodeId::fptan);
}
// FSINCOS (OPT-TI Phase C): one value call returning both results
// (_stub_fsincos_val: d16 = sin, d17 = cos) — the kRuntimeRoutine_fsincos
// table entry is rerouted under exactly this predicate, same
// single-predicate discipline as fcos above.  Requires the fsin/fcos gates
// because the IR may still emit their value calls in the same runs.  It has
// no OpcodeId (never a translated op; the enum is at 64 = uint64_t
// capacity), so the per-op lever is ROSETTA_X87_DISABLE_FSINCOS_FAST.
inline bool trig_ir_fsincos_enabled(const RosettaConfig& cfg) {
    return trig_ir_fsin_enabled(cfg) && trig_ir_fcos_enabled(cfg) &&
           cfg.disable_fsincos_fast == 0;
}
// F2XM1 / FSCALE (OPT-TI pow-trio phase): value calls whose ENTIRE math runs
// in the val stub's assembly (runtime_entry.S) — no classic-C fallback path,
// so unlike the trig ops there is no *_fast stub and no huge/mega-save leg.
// Same single-predicate discipline (translator dispatch, lookahead
// membership, build(), and the offset-table routing must all agree).  Like
// fsincos they have no OpcodeId (the enum is full at 64), so the per-op
// levers are the ROSETTA_X87_DISABLE_{F2XM1,FSCALE}_VAL env flags.
inline bool trig_ir_f2xm1_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_f2xm1_val == 0;
}
inline bool trig_ir_fscale_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_fscale_val == 0;
}
inline bool trig_ir_fyl2x_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_fyl2x_val == 0;
}
inline bool trig_ir_fyl2xp1_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_fyl2xp1_val == 0;
}
inline bool trig_ir_fpatan_enabled(const RosettaConfig& cfg) {
    return cfg.trig_ir != 0 && cfg.disable_fpatan_val == 0;
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
