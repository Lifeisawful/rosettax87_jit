// =============================================================================
// runtime_entry.S — Rosetta runtime_entry segment stubs
//
// Reconstructed AArch64 assembly for the runtime_entry segment of the Rosetta
// runtime binary. Each stub saves guest GPR state into the thread-local context
// block (pointed to by x18) via a shared prologue, then branches to an external
// dispatch tail. Special stubs (indirect_jmp/call, MXCSR helpers, timer, cpuid,
// TLS, cpu number) are inlined without the standard prologue.
//
// Stubs are packed contiguously with NO padding between them. Order matters —
// the runtime locates stubs by fixed offsets from the segment base.
// =============================================================================

.section runtime_entry,runtime_entry,regular,pure_instructions
.p2align 14

// -----------------------------------------------------------------------------
// STUB_PROLOGUE — shared 12-instruction (48-byte) prologue
//
// Saves x0-x15 pairs, NZCV flags, x17 (scratch), and x30 (return address)
// into the context block at x18. Sets the high bit of x18 to signal "in stub".
// -----------------------------------------------------------------------------
.macro STUB_PROLOGUE
    stp  x0,  x1,  [x18, #0x10]
    stp  x2,  x3,  [x18, #0x20]
    stp  x4,  x5,  [x18, #0x30]
    stp  x6,  x7,  [x18, #0x40]
    stp  x8,  x9,  [x18, #0x50]
    stp  x10, x11, [x18, #0x60]
    stp  x12, x13, [x18, #0x70]
    stp  x14, x15, [x18, #0x80]
    mrs  x29, nzcv
    stp  x29, x17, [x18, #0x90]
    str  x30, [x18, #0x8]
    orr  x18, x18, #0x8000000000000000
.endm

// =============================================================================
// Standard prologue stubs — batch 1
// =============================================================================

// Start of the mapped blob.  Deliberately co-located with _stub_far_jmp rather
// than placed at the top of the file: every offset in the codebase is computed
// from _stub_far_jmp (TranslationCacheAbi::off(), map_runtime_routines' copy
// source), so the two MUST resolve to the same address.  Nothing may be emitted
// between this label and _stub_far_jmp.
//
// Paired with _runtime_blob_end at the end of this file; ExecutableHeap.cpp
// subtracts the two to size the region it maps, so the stub page grows
// automatically as stubs are added.
.globl _runtime_blob_start
_runtime_blob_start:

.globl _stub_far_jmp
_stub_far_jmp:
    STUB_PROLOGUE
    b    tail_far_jmp

.globl _stub_far_ret
_stub_far_ret:
    STUB_PROLOGUE
    b    tail_far_ret

.globl _stub_far_call
_stub_far_call:
    STUB_PROLOGUE
    b    tail_far_call

.globl _stub_far_ret_single_step
_stub_far_ret_single_step:
    STUB_PROLOGUE
    b    tail_far_ret_single_step

.globl _stub_mov_segment
_stub_mov_segment:
    STUB_PROLOGUE
    b    tail_mov_segment

.globl _stub_mov_segment_and_reg
_stub_mov_segment_and_reg:
    STUB_PROLOGUE
    b    tail_mov_segment_and_reg

// =============================================================================
// Special stub: stub_indirect_jmp (100 bytes)
//
// Fast-path hash-table lookup for indirect jumps. Falls back to the slow path
// (full prologue + tail) on a cache miss or empty slot.
// =============================================================================

.globl _stub_indirect_jmp
_stub_indirect_jmp:
    crc32cx w23, wzr, x22
    and     w23, w23, w20
Lindirect_jmp_loop:
    add     x24, x19, x23, lsl #4
    ldp     x25, x26, [x24]
    sub     x27, x25, x22
    cbnz    x27, Lindirect_jmp_miss
    mov     x22, x26
    ret
Lindirect_jmp_miss:
    cbz     x25, Lindirect_jmp_slow
    add     w23, w23, #1
    and     w23, w23, w20
    b       Lindirect_jmp_loop
Lindirect_jmp_slow:
    STUB_PROLOGUE
    b       tail_indirect_jmp

// =============================================================================
// Special stub: stub_indirect_call (100 bytes)
//
// Same hash-lookup pattern as indirect_jmp, different dispatch tail.
// =============================================================================

.globl _stub_indirect_call
_stub_indirect_call:
    crc32cx w23, wzr, x22
    and     w23, w23, w20
Lindirect_call_loop:
    add     x24, x19, x23, lsl #4
    ldp     x25, x26, [x24]
    sub     x27, x25, x22
    cbnz    x27, Lindirect_call_miss
    mov     x22, x26
    ret
Lindirect_call_miss:
    cbz     x25, Lindirect_call_slow
    add     w23, w23, #1
    and     w23, w23, w20
    b       Lindirect_call_loop
Lindirect_call_slow:
    STUB_PROLOGUE
    b       tail_indirect_call

// =============================================================================
// Standard prologue stubs — batch 2
// =============================================================================

.globl _stub_syscall_handler
_stub_syscall_handler:
    STUB_PROLOGUE
    b    tail_syscall_handler

.globl _stub_toggle_single_step
_stub_toggle_single_step:
    STUB_PROLOGUE
    b    tail_toggle_single_step

.globl _stub_load_segment_limit
_stub_load_segment_limit:
    STUB_PROLOGUE
    b    tail_load_segment_limit

.globl _stub_rdrand
_stub_rdrand:
    STUB_PROLOGUE
    b    tail_rdrand

.globl _stub_xrstor
_stub_xrstor:
    STUB_PROLOGUE
    b    tail_xrstor

.globl _stub_xsave
_stub_xsave:
    STUB_PROLOGUE
    b    tail_xsave

// =============================================================================
// Special stub: stub_mxcsr_to_fpcr_fpsr (100 bytes, 25 instructions)
//
// Converts x86 MXCSR (in w26) to AArch64 FPCR/FPSR fields (w23-w25).
// Three code paths selected by the mode byte at [x18 + 0x170].
// =============================================================================

.globl _stub_mxcsr_to_fpcr_fpsr
_stub_mxcsr_to_fpcr_fpsr:
    lsl     w28, w26, #0x11
    rbit    w28, w28
    ubfiz   w23, w28, #0x16, #2
    ubfx    w25, w26, #0, #1
    lsr     w28, w26, #2
    bfi     w25, w28, #1, #4
    lsr     w28, w26, #1
    bfi     w25, w28, #7, #1
    ldrb    w27, [x18, #0x170]
    tbnz    w27, #1, Lmxcsr_fpcr_alt2
    cbz     w27, Lmxcsr_fpcr_alt1
    lsr     w28, w26, #0xf
    bfi     w23, w28, #0x18, #1
    ret
Lmxcsr_fpcr_alt1:
    ubfx    w24, w26, #6, #1
    ubfx    w28, w26, #0xf, #1
    bfi     w24, w28, #1, #1
    ret
Lmxcsr_fpcr_alt2:
    orr     w23, w23, #2
    orr     w23, w23, #4
    ubfx    w28, w26, #6, #1
    bfxil   w23, w28, #0, #1
    ubfx    w28, w26, #0xf, #1
    bfi     w23, w28, #0x18, #1
    ret

// =============================================================================
// Special stub: stub_read_mxcsr (104 bytes, 26 instructions)
//
// Reads AArch64 FPCR/FPSR and converts back to x86 MXCSR format (in w23).
// Three code paths selected by the mode byte at [x18 + 0x170].
// Uses AFPCR_EL0 (Apple-private) in alt1 path.
// =============================================================================

.globl _stub_read_mxcsr
_stub_read_mxcsr:
    mrs     x24, fpcr
    mrs     x26, fpsr
    mov     w23, #0x1f80
    lsl     w28, w24, #8
    rbit    w28, w28
    bfi     w23, w28, #0xd, #2
    bfxil   w23, w26, #0, #1
    lsr     w28, w26, #1
    bfi     w23, w28, #2, #4
    lsr     w28, w26, #7
    bfi     w23, w28, #1, #1
    ldrb    w27, [x18, #0x170]
    tbnz    w27, #1, Lread_mxcsr_alt2
    cbz     w27, Lread_mxcsr_alt1
    lsr     w28, w24, #0x18
    bfi     w23, w28, #0xf, #1
    ret
Lread_mxcsr_alt1:
    .long   0xd53ef2b9              // mrs x25, AFPCR_EL0 (Apple-private)
    bfi     w23, w25, #6, #1
    lsr     w28, w25, #1
    bfi     w23, w28, #0xf, #1
    ret
Lread_mxcsr_alt2:
    bfi     w23, w24, #6, #1
    ubfx    w28, w24, #0x18, #1
    bfi     w23, w28, #0xf, #1
    ret

// =============================================================================
// Standard prologue stubs — batch 3 (PCMPxSTRx + x87 operations)
// =============================================================================

.globl _stub_pcmpestri
_stub_pcmpestri:
    STUB_PROLOGUE
    b    tail_pcmpestri

.globl _stub_pcmpestrm
_stub_pcmpestrm:
    STUB_PROLOGUE
    b    tail_pcmpestrm

.globl _stub_pcmpistri
_stub_pcmpistri:
    STUB_PROLOGUE
    b    tail_pcmpistri

.globl _stub_pcmpistrm
_stub_pcmpistrm:
    STUB_PROLOGUE
    b    tail_pcmpistrm

.globl _stub_f2xm1
_stub_f2xm1:
    STUB_PROLOGUE
    b    tail_f2xm1

.globl _stub_fabs
_stub_fabs:
    STUB_PROLOGUE
    b    tail_fabs

.globl _stub_fchs
_stub_fchs:
    STUB_PROLOGUE
    b    tail_fchs

// FCOS is normally dispatched to the in-blob fast path (_stub_fcos_fast at
// the end of this section) via the runtime-routine offset table — see
// rewrite_runtime_routine_offsets (RuntimeRoutineOffsets.cpp).  This classic
// slot stays exactly as the reference had it: it is the bail-out target of
// the fast path and the routing target when ROSETTA_X87_DISABLE_FCOS_FAST=1.
.globl _stub_fcos
_stub_fcos:
    STUB_PROLOGUE
    b    tail_fcos

.globl _stub_fdecstp
_stub_fdecstp:
    STUB_PROLOGUE
    b    tail_fdecstp

.globl _stub_fincstp
_stub_fincstp:
    STUB_PROLOGUE
    b    tail_fincstp

.globl _stub_fpatan
_stub_fpatan:
    STUB_PROLOGUE
    b    tail_fpatan

.globl _stub_fprem
_stub_fprem:
    STUB_PROLOGUE
    b    tail_fprem

.globl _stub_fprem1
_stub_fprem1:
    STUB_PROLOGUE
    b    tail_fprem1

.globl _stub_fptan
_stub_fptan:
    STUB_PROLOGUE
    b    tail_fptan

.globl _stub_frndint
_stub_frndint:
    STUB_PROLOGUE
    b    tail_frndint

.globl _stub_fscale
_stub_fscale:
    STUB_PROLOGUE
    b    tail_fscale

.globl _stub_fsin
_stub_fsin:
    STUB_PROLOGUE
    b    tail_fsin

.globl _stub_fsincos
_stub_fsincos:
    STUB_PROLOGUE
    b    tail_fsincos

.globl _stub_fsqrt
_stub_fsqrt:
    STUB_PROLOGUE
    b    tail_fsqrt

.globl _stub_fxam
_stub_fxam:
    STUB_PROLOGUE
    b    tail_fxam

.globl _stub_fxtract
_stub_fxtract:
    STUB_PROLOGUE
    b    tail_fxtract

.globl _stub_fyl2x
_stub_fyl2x:
    STUB_PROLOGUE
    b    tail_fyl2x

.globl _stub_fyl2xp1
_stub_fyl2xp1:
    STUB_PROLOGUE
    b    tail_fyl2xp1

.globl _stub_fbstp
_stub_fbstp:
    STUB_PROLOGUE
    b    tail_fbstp

.globl _stub_ffree
_stub_ffree:
    STUB_PROLOGUE
    b    tail_ffree

.globl _stub_fild
_stub_fild:
    STUB_PROLOGUE
    b    tail_fild

.globl _stub_fld_STi
_stub_fld_STi:
    STUB_PROLOGUE
    b    tail_fld_STi

.globl _stub_fld_constant
_stub_fld_constant:
    STUB_PROLOGUE
    b    tail_fld_constant

.globl _stub_fld_fp32
_stub_fld_fp32:
    STUB_PROLOGUE
    b    tail_fld_fp32

.globl _stub_fld_fp64
_stub_fld_fp64:
    STUB_PROLOGUE
    b    tail_fld_fp64

.globl _stub_fxch
_stub_fxch:
    STUB_PROLOGUE
    b    tail_fxch

.globl _stub_fadd_f32
_stub_fadd_f32:
    STUB_PROLOGUE
    b    tail_fadd_f32

.globl _stub_fadd_f64
_stub_fadd_f64:
    STUB_PROLOGUE
    b    tail_fadd_f64

.globl _stub_fdiv_f32
_stub_fdiv_f32:
    STUB_PROLOGUE
    b    tail_fdiv_f32

.globl _stub_fdiv_f64
_stub_fdiv_f64:
    STUB_PROLOGUE
    b    tail_fdiv_f64

.globl _stub_fdivr_f32
_stub_fdivr_f32:
    STUB_PROLOGUE
    b    tail_fdivr_f32

.globl _stub_fdivr_f64
_stub_fdivr_f64:
    STUB_PROLOGUE
    b    tail_fdivr_f64

.globl _stub_fiadd
_stub_fiadd:
    STUB_PROLOGUE
    b    tail_fiadd

.globl _stub_fidiv
_stub_fidiv:
    STUB_PROLOGUE
    b    tail_fidiv

.globl _stub_fidivr
_stub_fidivr:
    STUB_PROLOGUE
    b    tail_fidivr

.globl _stub_fimul
_stub_fimul:
    STUB_PROLOGUE
    b    tail_fimul

.globl _stub_fisub
_stub_fisub:
    STUB_PROLOGUE
    b    tail_fisub

.globl _stub_fisubr
_stub_fisubr:
    STUB_PROLOGUE
    b    tail_fisubr

.globl _stub_fmul_f32
_stub_fmul_f32:
    STUB_PROLOGUE
    b    tail_fmul_f32

.globl _stub_fmul_f64
_stub_fmul_f64:
    STUB_PROLOGUE
    b    tail_fmul_f64

.globl _stub_fsub_f32
_stub_fsub_f32:
    STUB_PROLOGUE
    b    tail_fsub_f32

.globl _stub_fsub_f64
_stub_fsub_f64:
    STUB_PROLOGUE
    b    tail_fsub_f64

.globl _stub_fsubr_f32
_stub_fsubr_f32:
    STUB_PROLOGUE
    b    tail_fsubr_f32

.globl _stub_fsubr_f64
_stub_fsubr_f64:
    STUB_PROLOGUE
    b    tail_fsubr_f64

.globl _stub_fist_i16
_stub_fist_i16:
    STUB_PROLOGUE
    b    tail_fist_i16

.globl _stub_fist_i32
_stub_fist_i32:
    STUB_PROLOGUE
    b    tail_fist_i32

.globl _stub_fist_i64
_stub_fist_i64:
    STUB_PROLOGUE
    b    tail_fist_i64

.globl _stub_fistt_i16
_stub_fistt_i16:
    STUB_PROLOGUE
    b    tail_fistt_i16

.globl _stub_fistt_i32
_stub_fistt_i32:
    STUB_PROLOGUE
    b    tail_fistt_i32

.globl _stub_fistt_i64
_stub_fistt_i64:
    STUB_PROLOGUE
    b    tail_fistt_i64

.globl _stub_fst_fp32
_stub_fst_fp32:
    STUB_PROLOGUE
    b    tail_fst_fp32

.globl _stub_fst_fp64
_stub_fst_fp64:
    STUB_PROLOGUE
    b    tail_fst_fp64

.globl _stub_fst_fp80
_stub_fst_fp80:
    STUB_PROLOGUE
    b    tail_fst_fp80

.globl _stub_fbld
_stub_fbld:
    STUB_PROLOGUE
    b    tail_fbld

.globl _stub_fld_fp80
_stub_fld_fp80:
    STUB_PROLOGUE
    b    tail_fld_fp80

.globl _stub_fcmov
_stub_fcmov:
    STUB_PROLOGUE
    b    tail_fcmov

.globl _stub_fcom_f32
_stub_fcom_f32:
    STUB_PROLOGUE
    b    tail_fcom_f32

.globl _stub_fcom_f64
_stub_fcom_f64:
    STUB_PROLOGUE
    b    tail_fcom_f64

.globl _stub_fcom_ST
_stub_fcom_ST:
    STUB_PROLOGUE
    b    tail_fcom_ST

.globl _stub_fcomi
_stub_fcomi:
    STUB_PROLOGUE
    b    tail_fcomi

.globl _stub_ficom
_stub_ficom:
    STUB_PROLOGUE
    b    tail_ficom

.globl _stub_fst_STi
_stub_fst_STi:
    STUB_PROLOGUE
    b    tail_fst_STi

.globl _stub_fucom
_stub_fucom:
    STUB_PROLOGUE
    b    tail_fucom

.globl _stub_fucomi
_stub_fucomi:
    STUB_PROLOGUE
    b    tail_fucomi

.globl _stub_fadd_ST
_stub_fadd_ST:
    STUB_PROLOGUE
    b    tail_fadd_ST

.globl _stub_fdiv_ST
_stub_fdiv_ST:
    STUB_PROLOGUE
    b    tail_fdiv_ST

.globl _stub_fdivr_ST
_stub_fdivr_ST:
    STUB_PROLOGUE
    b    tail_fdivr_ST

.globl _stub_fmul_ST
_stub_fmul_ST:
    STUB_PROLOGUE
    b    tail_fmul_ST

.globl _stub_fsub_ST
_stub_fsub_ST:
    STUB_PROLOGUE
    b    tail_fsub_ST

.globl _stub_fsubr_ST
_stub_fsubr_ST:
    STUB_PROLOGUE
    b    tail_fsubr_ST

// =============================================================================
// Special stub: stub_read_timer_nanoseconds (64 bytes, 16 instructions)
//
// Reads the hardware timer counter and converts ticks to nanoseconds.
// Three paths: ACNTVCT_EL0 (Apple-private), CNTVCTSS_EL0, or ISB+CNTVCT_EL0.
// Conversion: ns = ticks * 125 / 3  (via multiply-by-reciprocal).
// =============================================================================

.globl _stub_read_timer_nanoseconds
_stub_read_timer_nanoseconds:
    ldrb    w22, [x18, #0x171]
    tbnz    w22, #3, Ltimer_acntvct
    tbnz    w22, #2, Ltimer_cntvctss
    isb
    mrs     x22, cntvct_el0
    b       Ltimer_compute
Ltimer_acntvct:
    .long   0xd53cfad6              // mrs x22, ACNTVCT_EL0 (Apple-private)
    b       Ltimer_compute
Ltimer_cntvctss:
    .long   0xd53be0d6              // mrs x22, CNTVCTSS_EL0 (ARMv8.6)
Ltimer_compute:
    mov     x23, #0x7d
    mul     x22, x22, x23
    mov     x23, #0xAAAAAAAAAAAAAAAA
    movk    x23, #0xAAAB
    umulh   x22, x22, x23
    lsr     x22, x22, #1
    ret

// =============================================================================
// Standard prologue stub — final
// =============================================================================

.globl _stub_indirect_jmp_dyld_stub
_stub_indirect_jmp_dyld_stub:
    STUB_PROLOGUE
    b    tail_indirect_jmp_dyld_stub

// =============================================================================
// Special stub: stub_get_cpu_number (12 bytes, 3 instructions)
//
// Returns the current CPU number from TPIDR_EL0 (low 12 bits).
// =============================================================================

.globl _stub_get_cpu_number
_stub_get_cpu_number:
    mrs     x22, tpidr_el0
    and     x22, x22, #0xFFF
    ret

// =============================================================================
// Special stub: stub_get_tls_base (12 bytes, 3 instructions)
//
// Returns the TLS base pointer from TPIDRRO_EL0, masked to strip low bits.
// =============================================================================

.globl _stub_get_tls_base
_stub_get_tls_base:
    mrs     x29, tpidrro_el0
    and     x29, x29, #0xFFFFFFFFFFF8
    ret

// =============================================================================
// Special stub: stub_cpuid (12 bytes, 3 instructions)
//
// Dispatches to a CPUID handler via function pointer at [x18 + 0x158].
// The leaf selector is read from [x18 + 0x222].
// =============================================================================

.globl _stub_cpuid
_stub_cpuid:
    ldr     x29, [x18, #0x158]
    ldrb    w22, [x18, #0x222]
    br      x29

// =============================================================================
// Trig fast paths — FCOS / FSIN / FSINCOS / FPTAN
//
// Each op computes its result entirely in the blob for |x| < 2^20*(pi/2),
// skipping STUB_PROLOGUE, the vtable dispatch, the C++ handler (X87.cpp with
// its SIMDGuard + openlibm call) and runtime_exitinst.  Ported from the
// openlibm sources this runtime already ships (k_cos.h, k_sin.h, k_tan.h and
// the medium branch of e_rem_pio2.h) — same constants, same operation order
// for the exactness-critical cancellation steps.
//
// Fallback = the op's own classic slot (_stub_fcos / _stub_fsin / ...),
// bit-identical to the pre-fast-path behaviour.  It handles:
//   - |x| >= 2^20*(pi/2), Inf, NaN  (Payne-Hanek reduction stays in C++)
//   - debug/single-step sessions    (flag byte at [x18, #0x1C8])
//   - FPTAN on an empty ST(0)       (x87_fptan uses tag-checked getSt)
// Routing between fast and classic happens in the runtime-routine offset
// table (rewrite_runtime_routine_offsets), never by patching code.
//
// Register contract (must match what translated code can rely on across a
// kRuntimeRoutine BL — see OPT-KA / test_keepalive):
//   clobbered:  x27, x29            (already clobbered by the classic path)
//   preserved:  x0-x15, x17, x19-x26, x28, x30, sp, NZCV, FPCR, v0-v15
//   q16-q24 are used as scratch but saved/restored on the native stack —
//   stricter than the classic path, which clobbers v16-v31 outright.
//   ALL vector saves here are SINGLE str/ldr q, never STP/LDP Q-pairs: the
//   guest-mode (TSO) Q-pair penalty (see the TRIG_VAL_HUGE comment below)
//   applies to these fast-path frames too — converting the q16-q24
//   save/restore from pairs to singles measured ~2x on every small/medium
//   trig bench (2026-07-28, bench_trig/bench_fcos interleaved A/B).  Do not
//   "clean this up" back into pairs.
// NZCV is never written: all control flow is cbz/tbz/tbnz on integer values.
//
// X87State layout at x18+0xA0 (x87_state_offset, verified against the JIT's
// own inline lowering and guarded at init_library — see RuntimeLibrary.cpp):
//   +0xA0 controlWord  +0xA2 statusWord  +0xA4 tagWord  +0xA8 st[8]
//
// Semantics reproduced = the current C++ handlers, NOT the Intel C2 rule:
// statusWord &= ~(C1|C2), always compute, tags of written slots -> kValid.
//
// Frame layout (0xA0 bytes, shared by all four ops):
//   [sp+0x00..0x7F] q16-q23   [sp+0x80] q24 (fsincos/fptan only)
//   [sp+0x90] x25, x26
// =============================================================================

// Shared entry: debug-flag check, frame, ST(0) slot address (x25 = X87State
// base + TOP*8, x26 = TOP), eligibility classification (w27 = hi31 on exit).
// Bails to the op's classic slot before any FP register or flag is touched.
.macro TRIG_ENTRY name
.globl _stub_\name\()_fast
_stub_\name\()_fast:
    ldrb w29, [x18, #0x1C8]
    cbnz w29, _stub_\name
    sub  sp, sp, #0xA0
    stp  x25, x26, [sp, #0x90]
    ldrh w29, [x18, #0xA2]           // statusWord
    ubfx w26, w29, #11, #3           // x26 = TOP
    add  x25, x18, #0xA0             // X87State base
    add  x25, x25, x26, lsl #3       // x25 = base + TOP*8 (ST(0) at [x25, #8])
    ldr  x29, [x25, #8]              // ST(0) bits (integer side)
    ubfx x27, x29, #32, #31          // hi31 = high word & 0x7fffffff
    // Eligible iff |x| < 2^20*(pi/2)  <=>  hi31 < 0x413921fb (excludes Inf/NaN)
    mov  w29, #0x21fb
    movk w29, #0x4139, lsl #16
    sub  w29, w27, w29
    tbz  w29, #31, L\name\()_bail
    str  q16, [sp]
    str  q17, [sp, #0x10]
    str  q18, [sp, #0x20]
    str  q19, [sp, #0x30]
    str  q20, [sp, #0x40]
    str  q21, [sp, #0x50]
    str  q22, [sp, #0x60]
    str  q23, [sp, #0x70]
    ldr  d16, [x25, #8]              // x = ST(0)
.endm

// Bail: q16-q23 may have been SAVED but are never modified before any bail,
// so only the GPR spill and the frame need undoing.
.macro TRIG_BAIL name
L\name\()_bail:
    ldp  x25, x26, [sp, #0x90]
    add  sp, sp, #0xA0
    b    _stub_\name
.endm

// Medium argument reduction (e_rem_pio2 medium branch, 33-bit pi chunks):
//   fn = rnint(x * 2/pi);  r = x - fn*pio2_1;  w = fn*pio2_1t
// with up to two more Cody-Waite iterations when leading bits cancel.
// fn*pio2_1 is exact (|fn| <= 2^20, pio2_1 has 33 mantissa bits), so the
// FMSUB matches the C code bit for bit.
// In:  d16 = x, w27 = hi31.  Out: d22 = y0, d23 = y1, w27 = n.
// Clobbers d17-d21, x29.
.macro TRIG_REDUCE name
    lsr  w27, w27, #20               // j = biased exponent of x
    ldr  d17, Ltrig_invpio2
    fmul d17, d16, d17
    frintn d17, d17                  // fn (round-to-nearest-even, FPCR-independent)
    ldr  d20, Ltrig_pio2_1
    fmsub d18, d17, d20, d16         // r = x - fn*pio2_1
    ldr  d20, Ltrig_pio2_1t
    fmul d19, d17, d20               // w = fn*pio2_1t
    fsub d22, d18, d19               // y0 = r - w
    fmov x29, d22
    ubfx x29, x29, #52, #11          // biased exponent of y0
    sub  w29, w27, w29               // i = j - exp(y0)
    sub  w29, w29, #17
    tbnz w29, #31, L\name\()_red_done  // i <= 16: 1st round good to 85 bits
    // 2nd iteration (good to 118 bits)
    fmov d20, d18                    // t = r
    ldr  d21, Ltrig_pio2_2
    fmul d19, d17, d21               // w = fn*pio2_2
    fsub d18, d20, d19               // r = t - w
    fsub d20, d20, d18               // t - r
    fsub d20, d20, d19               // (t - r) - w
    ldr  d21, Ltrig_pio2_2t
    fmul d21, d17, d21
    fsub d19, d21, d20               // w = fn*pio2_2t - ((t-r)-w)
    fsub d22, d18, d19               // y0 = r - w
    fmov x29, d22
    ubfx x29, x29, #52, #11
    sub  w29, w27, w29
    sub  w29, w29, #50
    tbnz w29, #31, L\name\()_red_done  // i <= 49
    // 3rd iteration (151 bits, covers all medium cases)
    fmov d20, d18
    ldr  d21, Ltrig_pio2_3
    fmul d19, d17, d21
    fsub d18, d20, d19
    fsub d20, d20, d18
    fsub d20, d20, d19
    ldr  d21, Ltrig_pio2_3t
    fmul d21, d17, d21
    fsub d19, d21, d20
    fsub d22, d18, d19
L\name\()_red_done:
    fsub d23, d18, d22
    fsub d23, d23, d19               // y1 = (r - y0) - w
    fcvtzs w27, d17                  // n (fn is integral -> exact)
.endm

// __kernel_cos(d22 = y0, d23 = y1) -> \dst.  Clobbers d17-d21.
//   z = x*x; w = z*z; r = z*(C1+z*(C2+z*C3)) + w*w*(C4+z*(C5+z*C6))
//   hz = 0.5*z; w' = 1-hz;  cos = w' + (((1-w') - hz) + (z*r - x*y))
// The 1-hz / (1-w')-hz cancellation steps stay unfused to match the C.
// iy=0 (small paths, y = +0): the x*y multiply and the z*r - x*y subtract
// are elided — bit-exact, because x*(+0) = ±0 and z*r ∈ {+0} ∪ (0, inf)
// (z >= 0 and r > 0 for all nonzero kernel inputs), so z*r - (±0) == z*r
// under RN in every case; d23 is never read.
.macro TRIG_KCOS dst, iy=1
    fmul d17, d22, d22               // z
    fmul d18, d17, d17               // w = z*z
    ldr  d20, Ltrig_C3
    ldr  d21, Ltrig_C2
    fmadd d20, d17, d20, d21         // C2 + z*C3
    ldr  d21, Ltrig_C1
    fmadd d20, d17, d20, d21         // C1 + z*(...)
    fmul d19, d17, d20               // z*(C1+...)
    ldr  d20, Ltrig_C6
    ldr  d21, Ltrig_C5
    fmadd d20, d17, d20, d21         // C5 + z*C6
    ldr  d21, Ltrig_C4
    fmadd d20, d17, d20, d21         // C4 + z*(...)
    fmul d21, d18, d18               // (z*z)*(z*z)
    fmadd d19, d21, d20, d19         // r
    fmov d20, #0.5
    fmul d20, d20, d17               // hz
    fmov d21, #1.0
    fsub d18, d21, d20               // w' = 1 - hz
    fsub d21, d21, d18               // 1 - w'
    fsub d21, d21, d20               // (1-w') - hz
    fmul d19, d17, d19               // z*r
.if \iy == 1
    fmul d17, d22, d23               // x*y
    fsub d19, d19, d17               // z*r - x*y
.endif
    fadd d21, d21, d19
    fadd \dst, d18, d21              // result
.endm

// __kernel_sin(d22 = y0, d23 = y1, iy) -> \dst.  Clobbers d17-d21.
//   z = x*x; w = z*z; r = S2+z*(S3+z*S4) + z*w*(S5+z*S6); v = z*x
//   iy=0 (y known zero):  sin = x + v*(S1 + z*r)
//   iy=1:                 sin = x - ((z*(half*y - v*r) - y) - v*S1)
.macro TRIG_KSIN dst, iy=1
    fmul d17, d22, d22               // z
    fmul d18, d17, d17               // w = z*z
    ldr  d20, Ltrig_S4
    ldr  d21, Ltrig_S3
    fmadd d20, d17, d20, d21         // S3 + z*S4
    ldr  d21, Ltrig_S2
    fmadd d20, d17, d20, d21         // S2 + z*(S3+z*S4)
    ldr  d19, Ltrig_S6
    ldr  d21, Ltrig_S5
    fmadd d19, d17, d19, d21         // S5 + z*S6
    fmul d21, d17, d18               // z*w
    fmadd d20, d21, d19, d20         // r
    fmul d19, d17, d22               // v = z*x
.if \iy == 0
    ldr  d21, Ltrig_S1
    fmadd d20, d17, d20, d21         // S1 + z*r
    fmadd \dst, d19, d20, d22        // x + v*(S1 + z*r)
.else
    fmov d21, #0.5
    fmul d21, d21, d23               // half*y
    fmsub d21, d19, d20, d21         // half*y - v*r
    fnmsub d21, d17, d21, d23        // z*(half*y - v*r) - y
    ldr  d18, Ltrig_S1
    fmsub d21, d19, d18, d21         // ... - v*S1
    fsub \dst, d22, d21              // x - (...)
.endif
.endm

// __kernel_tan (k_tan.h) -> d16.  In: d22 = y0, d23 = y1, w27 = n (only
// bit 0 is consumed), w26 = flag storage — bits 3..5 are packed with
// (n&1, sign(x), big); bits 0..2 are preserved (the memory-entry fptan keeps
// TOP there).  Clobbers d16-d21, d24, x27, x29.
// Three shapes: |x| >= 0.6744 (pi/4 substitution + rational fixup), plain
// polynomial (n even), accurate -1/(x+r) via split high parts (n odd).
// yzero=1 (small paths, y = +0): every read of d23 is elided — the two
// "+ y" adds and the pio4lo - y subtract are identities (+0 added to /
// subtracted from provably nonzero values), so the result is bit-exact
// with the y=0.0 kernel the C small path runs; d23 is never read.
.macro TRIG_KTAN name, yzero=0
    and  w27, w27, #1
    orr  w26, w26, w27, lsl #3
    fmov x27, d22
    lsr  x29, x27, #63
    orr  w26, w26, w29, lsl #4
    ubfx x27, x27, #32, #31          // hi31 of reduced x
    mov  w29, #0x9428
    movk w29, #0x3fe5, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, L\name\()_ktan_notbig
    // |x| >= 0.6744: substitute x = pio4 - x (tail pio4lo - y), y = 0
    orr  w26, w26, #0x20
    tbz  w26, #4, L\name\()_ktan_bigpos
    fneg d22, d22
.if \yzero == 0
    fneg d23, d23
.endif
L\name\()_ktan_bigpos:
    ldr  d20, Ltrig_pio4
    fsub d17, d20, d22               // z = pio4 - x
.if \yzero == 0
    ldr  d20, Ltrig_pio4lo
    fsub d18, d20, d23               // w = pio4lo - y
.else
    ldr  d18, Ltrig_pio4lo           // w = pio4lo - (+0) = pio4lo
.endif
    fadd d22, d17, d18               // x = z + w
.if \yzero == 0
    fmov d23, xzr                    // y = 0
.endif
L\name\()_ktan_notbig:
    // polynomial: r = T1+w(T3+w(T5+w(T7+w(T9+wT11)))),
    //             v = z*(T2+w(T4+w(T6+w(T8+w(T10+wT12)))))
    fmul d17, d22, d22               // z
    fmul d18, d17, d17               // w = z*z
    ldr  d19, Ltrig_T11
    ldr  d24, Ltrig_T9
    fmadd d19, d18, d19, d24
    ldr  d24, Ltrig_T7
    fmadd d19, d18, d19, d24
    ldr  d24, Ltrig_T5
    fmadd d19, d18, d19, d24
    ldr  d24, Ltrig_T3
    fmadd d19, d18, d19, d24
    ldr  d24, Ltrig_T1
    fmadd d19, d18, d19, d24         // r
    ldr  d20, Ltrig_T12
    ldr  d24, Ltrig_T10
    fmadd d20, d18, d20, d24
    ldr  d24, Ltrig_T8
    fmadd d20, d18, d20, d24
    ldr  d24, Ltrig_T6
    fmadd d20, d18, d20, d24
    ldr  d24, Ltrig_T4
    fmadd d20, d18, d20, d24
    ldr  d24, Ltrig_T2
    fmadd d20, d18, d20, d24
    fmul d20, d17, d20               // v
    fmul d21, d17, d22               // s = z*x
    fadd d19, d19, d20               // r + v
    fmul d19, d21, d19               // s*(r+v)
.if \yzero == 0
    fadd d19, d19, d23               // s*(r+v) + y
.endif
    fmul d19, d17, d19               // z*(...)
.if \yzero == 0
    fadd d19, d19, d23               // r' = y + z*(s*(r+v)+y)
.endif
    ldr  d24, Ltrig_T0
    fmadd d19, d24, d21, d19         // r += T0*s
    fadd d18, d22, d19               // w = x + r
    tbz  w26, #5, L\name\()_ktan_plain
    // big-branch final: f * (v - 2*(x - (w*w/(w+v) - r))), v = iy = +-1,
    // f = -1 iff original x was negative
    fmov d20, #1.0
    tbz  w26, #3, L\name\()_ktan_bigiy
    fneg d20, d20                    // v = -1 (odd n)
L\name\()_ktan_bigiy:
    fmul d21, d18, d18               // w*w
    fadd d24, d18, d20               // w + v
    fdiv d21, d21, d24               // w*w/(w+v)
    fsub d21, d21, d19               // ... - r
    fsub d21, d22, d21               // x - (...)
    fmov d24, #2.0
    fmsub d16, d24, d21, d20         // v - 2*(...)
    tbz  w26, #4, L\name\()_ktan_done
    fneg d16, d16
    b    L\name\()_ktan_done
L\name\()_ktan_plain:
    tbnz w26, #3, L\name\()_ktan_recip
    fmov d16, d18                    // n even: tan = w
    b    L\name\()_ktan_done
L\name\()_ktan_recip:
    // n odd: accurate -1/(x+r) via split high parts (low words zeroed are
    // exact 21-bit factors, so t*z and the corrections round once each)
    fmov x29, d18
    and  x29, x29, #0xFFFFFFFF00000000
    fmov d17, x29                    // z = hi(w)
    fsub d20, d17, d22               // z - x
    fsub d20, d19, d20               // v' = r - (z - x)
    fmov d21, #-1.0
    fdiv d21, d21, d18               // a = -1/w
    fmov x29, d21
    and  x29, x29, #0xFFFFFFFF00000000
    fmov d24, x29                    // t = hi(a)
    fmov d19, #1.0
    fmadd d19, d24, d17, d19         // s' = 1 + t*z (t*z exact)
    fmadd d20, d24, d20, d19         // s' + t*v'
    fmadd d16, d21, d20, d24         // t + a*(s' + t*v')
L\name\()_ktan_done:
.endm

// By-value huge/Inf/NaN fallback for the _stub_*_val entries (OPT-TI): save
// what the C fallback actually clobbers and the JIT may have live — guest
// GPRs x0-x15, x16/x17, x30, NZCV, guest xmm0-7 in q0-q7, and the live IR
// pool q17-q23 (q18-q23 for fsincos; the excluded arg/result regs are dead).
// x18 is the reserved platform register on Apple targets — no compiled C
// touches it.  Result returns via x29 so the vector restores cannot clobber
// it; ends at the entry's L\name\()_ret.
//
// Two measured constraints (2026-07-27, bench_fcos huge/out_of_range — the
// original "save q0-q31 + GPRs with STP pairs" version was 2x SLOWER than the
// classic memory-state stub, ~90ns/op of pure save/restore):
//
// 1. SINGLE str/ldr Q only, never STP/LDP Q-pairs.  In guest (TSO) context a
//    Q-pair save+restore costs ~17 cycles (~5ns) VS ~0.5ns as two singles —
//    a ~10x per-pair penalty that scales linearly with pair count (native
//    arm64 runs the identical pair sequence at full speed).  GPR X-pairs are
//    fine.  Do not "clean this up" back into pairs.
//
// 2. The vector save set is the C fallbacks' ACTUAL clobber set, not the
//    AAPCS worst case.  x87_trig_{cos,sin,tan,sincos}_value are self-contained
//    (openlibm fully inlined, no outgoing calls) and touch only v0-v7 and
//    v16-v23.  v8-v15 (guest xmm8-15 — AAPCS only preserves the LOW halves)
//    and v24-v31 (live IR pool) are never saved here, so the build-time audit
//    scripts/audit_trig_value_clobbers.sh FAILS the build if a compiler
//    change makes the fallbacks touch them.  If that ever fires, either
//    restore the missing str/ldr q slots or fix the codegen.
.macro TRIG_VAL_HUGE name, fnptr
L\name\()_huge:
    sub  sp, sp, #0x190
    stp  x0,  x1,  [sp]
    stp  x2,  x3,  [sp, #0x10]
    stp  x4,  x5,  [sp, #0x20]
    stp  x6,  x7,  [sp, #0x30]
    stp  x8,  x9,  [sp, #0x40]
    stp  x10, x11, [sp, #0x50]
    stp  x12, x13, [sp, #0x60]
    stp  x14, x15, [sp, #0x70]
    stp  x16, x17, [sp, #0x80]
    mrs  x29, nzcv
    stp  x29, x30, [sp, #0x90]
    str  q0,  [sp, #0xA0]
    str  q1,  [sp, #0xB0]
    str  q2,  [sp, #0xC0]
    str  q3,  [sp, #0xD0]
    str  q4,  [sp, #0xE0]
    str  q5,  [sp, #0xF0]
    str  q6,  [sp, #0x100]
    str  q7,  [sp, #0x110]
    str  q17, [sp, #0x120]
    str  q18, [sp, #0x130]
    str  q19, [sp, #0x140]
    str  q20, [sp, #0x150]
    str  q21, [sp, #0x160]
    str  q22, [sp, #0x170]
    str  q23, [sp, #0x180]
    ldr  x29, \fnptr
    fmov d0, d16
    blr  x29
    fmov x29, d0                     // result survives the vector restores
    ldr  q23, [sp, #0x180]
    ldr  q22, [sp, #0x170]
    ldr  q21, [sp, #0x160]
    ldr  q20, [sp, #0x150]
    ldr  q19, [sp, #0x140]
    ldr  q18, [sp, #0x130]
    ldr  q17, [sp, #0x120]
    ldr  q7,  [sp, #0x110]
    ldr  q6,  [sp, #0x100]
    ldr  q5,  [sp, #0xF0]
    ldr  q4,  [sp, #0xE0]
    ldr  q3,  [sp, #0xD0]
    ldr  q2,  [sp, #0xC0]
    ldr  q1,  [sp, #0xB0]
    ldr  q0,  [sp, #0xA0]
    ldp  x27, x30, [sp, #0x90]       // x27 = saved NZCV (outer frame restores x27)
    msr  nzcv, x27
    ldp  x16, x17, [sp, #0x80]
    ldp  x14, x15, [sp, #0x70]
    ldp  x12, x13, [sp, #0x60]
    ldp  x10, x11, [sp, #0x50]
    ldp  x8,  x9,  [sp, #0x40]
    ldp  x6,  x7,  [sp, #0x30]
    ldp  x4,  x5,  [sp, #0x20]
    ldp  x2,  x3,  [sp, #0x10]
    ldp  x0,  x1,  [sp]
    add  sp, sp, #0x190
    fmov d16, x29
    b    L\name\()_ret
.endm

// Two-result variant of TRIG_VAL_HUGE for _stub_fsincos_val: the C fallback
// returns {sin, cos} in d0/d1 (HFA), stashed in two scratch slots across the
// vector restores and delivered as d16/d17 at the end (the d-writes zero the
// upper halves — runs containing the call exclude v16 AND v17 from the pool,
// so those are dead).  Same single-str/ldr + actual-clobber-set rules as
// TRIG_VAL_HUGE above, EXCEPT for the save set: x87_trig_sincos_value's
// inlined dual kernel uses callee-saved d8-d15 (AAPCS covers only the LOW
// halves) and is SLP-vectorized into v24+, so everything except the dead
// v16/v17 is saved here at full q width (still as singles).
.macro TRIG_VAL_HUGE2 name, fnptr
L\name\()_huge:
    sub  sp, sp, #0x290
    stp  x0,  x1,  [sp]
    stp  x2,  x3,  [sp, #0x10]
    stp  x4,  x5,  [sp, #0x20]
    stp  x6,  x7,  [sp, #0x30]
    stp  x8,  x9,  [sp, #0x40]
    stp  x10, x11, [sp, #0x50]
    stp  x12, x13, [sp, #0x60]
    stp  x14, x15, [sp, #0x70]
    stp  x16, x17, [sp, #0x80]
    mrs  x29, nzcv
    stp  x29, x30, [sp, #0x90]
    str  q0,  [sp, #0xA0]
    str  q1,  [sp, #0xB0]
    str  q2,  [sp, #0xC0]
    str  q3,  [sp, #0xD0]
    str  q4,  [sp, #0xE0]
    str  q5,  [sp, #0xF0]
    str  q6,  [sp, #0x100]
    str  q7,  [sp, #0x110]
    str  q8,  [sp, #0x120]
    str  q9,  [sp, #0x130]
    str  q10, [sp, #0x140]
    str  q11, [sp, #0x150]
    str  q12, [sp, #0x160]
    str  q13, [sp, #0x170]
    str  q14, [sp, #0x180]
    str  q15, [sp, #0x190]
    str  q18, [sp, #0x1A0]
    str  q19, [sp, #0x1B0]
    str  q20, [sp, #0x1C0]
    str  q21, [sp, #0x1D0]
    str  q22, [sp, #0x1E0]
    str  q23, [sp, #0x1F0]
    str  q24, [sp, #0x200]
    str  q25, [sp, #0x210]
    str  q26, [sp, #0x220]
    str  q27, [sp, #0x230]
    str  q28, [sp, #0x240]
    str  q29, [sp, #0x250]
    str  q30, [sp, #0x260]
    str  q31, [sp, #0x270]
    ldr  x29, \fnptr
    fmov d0, d16
    blr  x29
    str  d0, [sp, #0x280]            // sin
    str  d1, [sp, #0x288]            // cos
    ldr  q31, [sp, #0x270]
    ldr  q30, [sp, #0x260]
    ldr  q29, [sp, #0x250]
    ldr  q28, [sp, #0x240]
    ldr  q27, [sp, #0x230]
    ldr  q26, [sp, #0x220]
    ldr  q25, [sp, #0x210]
    ldr  q24, [sp, #0x200]
    ldr  q23, [sp, #0x1F0]
    ldr  q22, [sp, #0x1E0]
    ldr  q21, [sp, #0x1D0]
    ldr  q20, [sp, #0x1C0]
    ldr  q19, [sp, #0x1B0]
    ldr  q18, [sp, #0x1A0]
    ldr  q15, [sp, #0x190]
    ldr  q14, [sp, #0x180]
    ldr  q13, [sp, #0x170]
    ldr  q12, [sp, #0x160]
    ldr  q11, [sp, #0x150]
    ldr  q10, [sp, #0x140]
    ldr  q9,  [sp, #0x130]
    ldr  q8,  [sp, #0x120]
    ldr  q7,  [sp, #0x110]
    ldr  q6,  [sp, #0x100]
    ldr  q5,  [sp, #0xF0]
    ldr  q4,  [sp, #0xE0]
    ldr  q3,  [sp, #0xD0]
    ldr  q2,  [sp, #0xC0]
    ldr  q1,  [sp, #0xB0]
    ldr  q0,  [sp, #0xA0]
    ldp  x27, x30, [sp, #0x90]       // x27 = saved NZCV (outer frame restores x27)
    msr  nzcv, x27
    ldp  x16, x17, [sp, #0x80]
    ldp  x14, x15, [sp, #0x70]
    ldp  x12, x13, [sp, #0x60]
    ldp  x10, x11, [sp, #0x50]
    ldp  x8,  x9,  [sp, #0x40]
    ldp  x6,  x7,  [sp, #0x30]
    ldp  x4,  x5,  [sp, #0x20]
    ldp  x2,  x3,  [sp, #0x10]
    ldp  x0,  x1,  [sp]
    ldr  d16, [sp, #0x280]           // sin
    ldr  d17, [sp, #0x288]           // cos
    add  sp, sp, #0x290
    b    L\name\()_ret
.endm

// Store an in-place result (FCOS/FSIN): ST(TOP) = d16, tag -> kValid,
// statusWord &= ~(C1|C2), TOP unchanged.  Then restore and return.
.macro TRIG_STORE_INPLACE
    str  d16, [x25, #8]
    sub  x25, x25, x26, lsl #3       // back to X87State base
    lsl  w26, w26, #1
    mov  w29, #3
    lsl  w29, w29, w26               // 3 << (TOP*2)
    ldrh w27, [x25, #4]              // tagWord: slot -> kValid (00)
    bic  w27, w27, w29
    strh w27, [x25, #4]
    ldrh w27, [x25, #2]              // statusWord &= ~(C1|C2)
    and  w27, w27, #0xfffff9ff
    strh w27, [x25, #2]
.endm

// Store-and-push (FSINCOS/FPTAN): ST(TOP) = d16, push, ST(newTOP) = \val_new,
// statusWord: TOP = newTOP and C1|C2 cleared, both slots' tags -> kValid.
// In: x25 = base + TOP*8, w26 = TOP (pure).  Clobbers w26, w27, x29.
.macro TRIG_STORE_PUSH val_new
    str  d16, [x25, #8]              // ST(old TOP) = first result
    sub  x25, x25, x26, lsl #3       // X87State base
    sub  w27, w26, #1
    and  w27, w27, #7                // newTOP = (TOP-1) & 7
    add  x29, x25, x27, lsl #3
    str  \val_new, [x29, #8]         // ST(new TOP) = pushed value
    ldrh w29, [x25, #2]
    and  w29, w29, #0xffffc1ff       // clear TOP | C2 | C1
    orr  w29, w29, w27, lsl #11      // TOP = newTOP
    strh w29, [x25, #2]
    lsl  w26, w26, #1
    mov  w29, #3
    lsl  w29, w29, w26               // 3 << (oldTOP*2)
    lsl  w26, w27, #1
    mov  w27, #3
    lsl  w27, w27, w26               // 3 << (newTOP*2)
    orr  w29, w29, w27
    ldrh w27, [x25, #4]
    bic  w27, w27, w29               // both tags -> kValid (00)
    strh w27, [x25, #4]
.endm

// Restore scratch and return to translated code.
.macro TRIG_EPILOGUE q24=0
.if \q24
    ldr  q24, [sp, #0x80]
.endif
    ldr  q16, [sp]
    ldr  q17, [sp, #0x10]
    ldr  q18, [sp, #0x20]
    ldr  q19, [sp, #0x30]
    ldr  q20, [sp, #0x40]
    ldr  q21, [sp, #0x50]
    ldr  q22, [sp, #0x60]
    ldr  q23, [sp, #0x70]
    ldp  x25, x26, [sp, #0x90]
    add  sp, sp, #0xA0
    ret
.endm

// -----------------------------------------------------------------------------
// FCOS: ST(0) = cos(ST(0)).  n & 3 selects 0:+cos 1:-sin 2:-cos 3:+sin.
// -----------------------------------------------------------------------------
TRIG_ENTRY fcos
    // |x| ~< pi/4  <=>  hi31 <= 0x3fe921fb
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfcos_small
    TRIG_REDUCE fcos
    tbz  w27, #0, Lfcos_kcos
    TRIG_KSIN d16
    b    Lfcos_negmaybe
Lfcos_kcos:
    TRIG_KCOS d16
Lfcos_negmaybe:
    // negate iff (n&1) != ((n>>1)&1), i.e. quadrants 1 and 2
    eor  w29, w27, w27, lsr #1
    tbz  w29, #0, Lfcos_store
    fneg d16, d16
Lfcos_store:
    TRIG_STORE_INPLACE
    TRIG_EPILOGUE
Lfcos_small:
    // |x| < 2^-27 * sqrt(2): cos(x) = 1.0 exactly (openlibm short-circuit)
    mov  w29, #0xa09e
    movk w29, #0x3e46, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfcos_one
    fmov d22, d16                    // y0 = x
    TRIG_KCOS d16, 0                 // y known zero — skips the x*y leg
    b    Lfcos_store
Lfcos_one:
    fmov d16, #1.0
    b    Lfcos_store
TRIG_BAIL fcos

// -----------------------------------------------------------------------------
// FCOS value call (OPT-TI, research/optimizations/16-ir-trig-value-call.md):
//   d16 = x on entry, d16 = cos(x) on return.  Preserves EVERYTHING else —
//   d17-d23 and x27/x29 are saved here, NZCV is never written, and X87State
//   is never touched (the translated call site owns all state semantics).
//   Targeted only by translator-emitted calls (ROSETTA_X87_TRIG_IR); never by
//   plain argument-less BLs, so there is no classic-stub bail path.
//
// Huge/Inf/NaN arguments cannot fall back to the classic stub (inside an IR
// run the X87State memory is stale — values live in FPRs), so they are
// computed BY VALUE: save everything an AAPCS call can clobber and call the
// C fallback x87_trig_cos_value (openlibm_cos incl. Payne-Hanek) through a
// dyld-rebased absolute literal.  Rare path; only correctness matters.
// -----------------------------------------------------------------------------
.globl _stub_fcos_val
_stub_fcos_val:
    sub  sp, sp, #0x80
    stp  x27, x29, [sp, #0x70]
    fmov x29, d16
    ubfx x27, x29, #32, #31          // hi31
    mov  w29, #0x21fb
    movk w29, #0x4139, lsl #16
    sub  w29, w27, w29
    tbz  w29, #31, Lfcosv_huge       // >= 2^20*(pi/2), Inf, NaN
    str  q17, [sp]
    str  q18, [sp, #0x10]
    str  q19, [sp, #0x20]
    str  q20, [sp, #0x30]
    str  q21, [sp, #0x40]
    str  q22, [sp, #0x50]
    str  q23, [sp, #0x60]
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfcosv_small
    TRIG_REDUCE fcosv
    tbz  w27, #0, Lfcosv_kcos
    TRIG_KSIN d16
    b    Lfcosv_negmaybe
Lfcosv_kcos:
    TRIG_KCOS d16
Lfcosv_negmaybe:
    eor  w29, w27, w27, lsr #1
    tbz  w29, #0, Lfcosv_done
    fneg d16, d16
Lfcosv_done:
    ldr  q17, [sp]
    ldr  q18, [sp, #0x10]
    ldr  q19, [sp, #0x20]
    ldr  q20, [sp, #0x30]
    ldr  q21, [sp, #0x40]
    ldr  q22, [sp, #0x50]
    ldr  q23, [sp, #0x60]
Lfcosv_ret:
    ldp  x27, x29, [sp, #0x70]
    add  sp, sp, #0x80
    ret
Lfcosv_small:
    mov  w29, #0xa09e
    movk w29, #0x3e46, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfcosv_one
    fmov d22, d16
    TRIG_KCOS d16, 0                 // y known zero — skips the x*y leg
    b    Lfcosv_done
Lfcosv_one:
    fmov d16, #1.0
    b    Lfcosv_done
TRIG_VAL_HUGE fcosv, Lfcosv_fnptr

.p2align 3
Lfcosv_fnptr:
    .quad _x87_trig_cos_value        // dyld-rebased in the image; every blob
                                     // copy/remap inherits the fixed pointer

// -----------------------------------------------------------------------------
// FSIN value call (OPT-TI Phase B): d16 = sin(d16), same contract as
// _stub_fcos_val.  Tiny |x| < 2^-26 returns x unchanged (preserves -0);
// quadrant map n&3: 0:+sin 1:+cos 2:-sin 3:-cos.
// -----------------------------------------------------------------------------
.globl _stub_fsin_val
_stub_fsin_val:
    sub  sp, sp, #0x80
    stp  x27, x29, [sp, #0x70]
    fmov x29, d16
    ubfx x27, x29, #32, #31          // hi31
    mov  w29, #0x21fb
    movk w29, #0x4139, lsl #16
    sub  w29, w27, w29
    tbz  w29, #31, Lfsinv_huge
    str  q17, [sp]
    str  q18, [sp, #0x10]
    str  q19, [sp, #0x20]
    str  q20, [sp, #0x30]
    str  q21, [sp, #0x40]
    str  q22, [sp, #0x50]
    str  q23, [sp, #0x60]
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfsinv_small
    TRIG_REDUCE fsinv
    tbz  w27, #0, Lfsinv_ksin
    TRIG_KCOS d16
    b    Lfsinv_negmaybe
Lfsinv_ksin:
    TRIG_KSIN d16
Lfsinv_negmaybe:
    tbz  w27, #1, Lfsinv_done        // negate for quadrants 2 and 3
    fneg d16, d16
Lfsinv_done:
    ldr  q17, [sp]
    ldr  q18, [sp, #0x10]
    ldr  q19, [sp, #0x20]
    ldr  q20, [sp, #0x30]
    ldr  q21, [sp, #0x40]
    ldr  q22, [sp, #0x50]
    ldr  q23, [sp, #0x60]
Lfsinv_ret:
    ldp  x27, x29, [sp, #0x70]
    add  sp, sp, #0x80
    ret
Lfsinv_small:
    // |x| < 2^-26: sin(x) = x — d16 already holds it
    mov  w29, #0x3e500000
    sub  w29, w27, w29
    tbnz w29, #31, Lfsinv_done
    fmov d22, d16
    fmov d23, xzr
    TRIG_KSIN d16, 0                 // y known zero: openlibm's iy=0 form
    b    Lfsinv_done
TRIG_VAL_HUGE fsinv, Lfsinv_fnptr

.p2align 3
Lfsinv_fnptr:
    .quad _x87_trig_sin_value

// -----------------------------------------------------------------------------
// FPTAN value call (OPT-TI Phase B): d16 = tan(d16) — ONLY the tangent; the
// translated call site owns the push of 1.0 (in the IR it is a ConstOne node
// pushed after the call, in the singular form an explicit x87_push).  Same
// preserve-everything contract; additionally saves x26 (TRIG_KTAN's flag
// register) and q24 (its constant scratch).  Tiny |x| < 2^-27 returns x
// unchanged (preserves -0, which the odd polynomial would not).
// -----------------------------------------------------------------------------
.globl _stub_fptan_val
_stub_fptan_val:
    sub  sp, sp, #0xA0
    str  x26, [sp, #0x88]
    stp  x27, x29, [sp, #0x90]
    fmov x29, d16
    ubfx x27, x29, #32, #31          // hi31
    mov  w29, #0x21fb
    movk w29, #0x4139, lsl #16
    sub  w29, w27, w29
    tbz  w29, #31, Lfptanv_huge
    str  q17, [sp]
    str  q18, [sp, #0x10]
    str  q19, [sp, #0x20]
    str  q20, [sp, #0x30]
    str  q21, [sp, #0x40]
    str  q22, [sp, #0x50]
    str  q23, [sp, #0x60]
    str  q24, [sp, #0x70]
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfptanv_small
    TRIG_REDUCE fptanv
    mov  w26, wzr                    // flag storage for TRIG_KTAN (x26 saved)
    TRIG_KTAN fptanv
    b    Lfptanv_done
Lfptanv_small:
    mov  w29, #0x3e400000
    sub  w29, w27, w29
    tbnz w29, #31, Lfptanv_done      // tiny: tan(x) = x, d16 unchanged
    fmov d22, d16
    mov  w27, wzr                    // n = 0
    mov  w26, wzr                    // flag storage for TRIG_KTAN (x26 saved)
    TRIG_KTAN fptanvs, 1             // y known zero — d23 never read
Lfptanv_done:
    ldr  q17, [sp]
    ldr  q18, [sp, #0x10]
    ldr  q19, [sp, #0x20]
    ldr  q20, [sp, #0x30]
    ldr  q21, [sp, #0x40]
    ldr  q22, [sp, #0x50]
    ldr  q23, [sp, #0x60]
    ldr  q24, [sp, #0x70]
Lfptanv_ret:
    ldr  x26, [sp, #0x88]
    ldp  x27, x29, [sp, #0x90]
    add  sp, sp, #0xA0
    ret
TRIG_VAL_HUGE fptanv, Lfptanv_fnptr

.p2align 3
Lfptanv_fnptr:
    .quad _x87_trig_tan_value

// -----------------------------------------------------------------------------
// FSINCOS value call (OPT-TI Phase C): d16 = sin(d16), d17 = cos(d16).  ONE
// reduction feeds both kernels — the two-BL decomposition (fsin_val +
// fcos_val) measured fully serialized at ~2x a single call, so the pair
// shares one BL.  Preserves everything except d16/d17 (x27/x29 saved,
// d18-d24 saved — the kernels' scratch; d17 is an output, macros may scribble
// it freely before the final write).  Quadrant map as _stub_fsincos_fast:
//   n&3 = 0: sin=+s cos=+c    1: sin=+c cos=-s
//         2: sin=-s cos=-c    3: sin=-c cos=+s
// Huge/Inf/NaN: TRIG_VAL_HUGE2 mega-save fallback -> x87_trig_sincos_value
// ({sin, cos} in d0/d1), results re-enter through the saved q16/q17 slots.
// -----------------------------------------------------------------------------
.globl _stub_fsincos_val
_stub_fsincos_val:
    sub  sp, sp, #0x80
    stp  x27, x29, [sp, #0x70]
    fmov x29, d16
    ubfx x27, x29, #32, #31          // hi31
    mov  w29, #0x21fb
    movk w29, #0x4139, lsl #16
    sub  w29, w27, w29
    tbz  w29, #31, Lfsincosv_huge    // >= 2^20*(pi/2), Inf, NaN
    str  q18, [sp]
    str  q19, [sp, #0x10]
    str  q20, [sp, #0x20]
    str  q21, [sp, #0x30]
    str  q22, [sp, #0x40]
    str  q23, [sp, #0x50]
    str  q24, [sp, #0x60]
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfsincosv_small
    TRIG_REDUCE fsincosv
    TRIG_KCOS d24                    // c (d22/d23 stay live)
    TRIG_KSIN d16                    // s
    // Quadrant select, depth-1 from the kernel outputs (no serial swap):
    //   n&3 = 0: sin=+s cos=+c    1: sin=+c cos=-s
    //         2: sin=-s cos=-c    3: sin=-c cos=+s
    tbz  w27, #0, Lfsincosv_even
    tbnz w27, #1, Lfsincosv_n3
    fneg d17, d16                    // n=1: cos = -s (reads s before...)
    fmov d16, d24                    //      sin = +c (...d16 is overwritten)
    b    Lfsincosv_done
Lfsincosv_n3:
    fmov d17, d16                    // n=3: cos = +s
    fneg d16, d24                    //      sin = -c
    b    Lfsincosv_done
Lfsincosv_even:
    tbnz w27, #1, Lfsincosv_n2
    fmov d17, d24                    // n=0: cos = +c
    b    Lfsincosv_done
Lfsincosv_n2:
    fneg d16, d16                    // n=2: sin = -s
    fneg d17, d24                    //      cos = -c
    b    Lfsincosv_done
Lfsincosv_small:
    // |x| < pi/4: openlibm composition — sin has a 2^-26 short-circuit
    // (returns x, preserving -0), cos a 2^-27*sqrt(2) one (returns 1.0);
    // both kernels take y = 0 (iy=0 forms), matching the C handler's
    // openlibm_sin/openlibm_cos small paths bit for bit.
    fmov d22, d16
    mov  w29, #0x3e500000            // 2^-26
    sub  w29, w27, w29
    tbnz w29, #31, Lfsincosv_tiny
    TRIG_KSIN d16, 0                 // s (d22 stays live)
    TRIG_KCOS d17, 0                 // c
    b    Lfsincosv_done
Lfsincosv_tiny:                      // sin = x (d16 unchanged)
    mov  w29, #0xa09e
    movk w29, #0x3e46, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfsincosv_cos1
    TRIG_KCOS d17, 0
    b    Lfsincosv_done
Lfsincosv_cos1:
    fmov d17, #1.0                   // cos = 1.0
Lfsincosv_done:
    ldr  q18, [sp]
    ldr  q19, [sp, #0x10]
    ldr  q20, [sp, #0x20]
    ldr  q21, [sp, #0x30]
    ldr  q22, [sp, #0x40]
    ldr  q23, [sp, #0x50]
    ldr  q24, [sp, #0x60]
Lfsincosv_ret:
    ldp  x27, x29, [sp, #0x70]
    add  sp, sp, #0x80
    ret
TRIG_VAL_HUGE2 fsincosv, Lfsincosv_fnptr

.p2align 3
Lfsincosv_fnptr:
    .quad _x87_trig_sincos_value

// -----------------------------------------------------------------------------
// F2XM1 value call (OPT-TI pow-trio): d16 = 2^d16 - 1.  Preserves everything
// else — q17-q20 and x26/x27/x29 are saved here, NZCV is never written
// (sub + tbz/tbnz/cbz only).  Unlike the trig val stubs there is NO C
// fallback leg: the entire domain is handled in this assembly, replicating
// the classic x87_f2xm1 helper exactly:
//   |x| > 1.0  -> +0.0            (the helper's out-of-range result)
//   NaN        -> quieted x       (falls through the helper's range check)
//   |x| < 2^-54-> (1.0 + x) - 1.0 (openlibm_exp2's tiny path, minus 1)
//   else       -> openlibm_exp2's accurate-tables method (Gal-Bachelis),
//                 8-bit table indexed via the x + 0x1.8p44 low-word trick,
//                 degree-5 minimax poly, scale by 2^k (k in {-1,0,+1}),
//                 then subtract 1.0.
// The 256x2-double table is NOT duplicated: _x87_exp2_tbl (X87.cpp) is a
// dyld-rebased pointer to the same static table the classic C path uses, so
// both paths read identical table bits.  Loaded through the in-blob literal
// (works through both remap and memmove blob copies).
// -----------------------------------------------------------------------------
.globl _stub_f2xm1_val
_stub_f2xm1_val:
    sub  sp, sp, #0x60
    str  q17, [sp]
    str  q18, [sp, #0x10]
    str  q19, [sp, #0x20]
    str  q20, [sp, #0x30]
    stp  x26, x27, [sp, #0x40]
    str  x29, [sp, #0x50]
    fmov x29, d16
    and  x27, x29, #0x7FFFFFFFFFFFFFFF
    mov  x29, #0x3FF0000000000000
    sub  x29, x29, x27               // < 0 iff |x| > 1.0 or NaN
    tbnz x29, #63, Lf2xm1v_oor
    mov  x29, #0x3C90000000000000
    sub  x29, x27, x29               // < 0 iff |x| < 2^-54
    tbnz x29, #63, Lf2xm1v_tiny
    // reduce: t = x + redux; i = low word of t; k = (i+128)>>8 (wrapped)
    ldr  d17, Lf2xm1v_redux
    fadd d18, d16, d17               // t
    fmov w27, s18                    // GET_LOW_WORD(t)
    add  w27, w27, #128              // i0
    lsr  w26, w27, #8
    lsl  w26, w26, #20               // k (uint32 wrap semantics = C)
    mov  w29, #0x3FF00000
    add  w26, w26, w29               // high word of 2^k
    lsl  x26, x26, #32               // full 2^k bit pattern
    and  w27, w27, #0xFF             // table index
    fsub d18, d18, d17               // t -= redux
    fsub d19, d16, d18               // z = x - t
    ldr  x29, Lf2xm1v_tblptr
    ldr  x29, [x29]                  // &tbl[0]
    add  x29, x29, w27, uxtw #4      // &tbl[2*i0]: 16-byte interleaved pairs
    ldr  d18, [x29]                  // exp2t[i0]
    ldr  d17, [x29, #8]              // eps[i0]
    fsub d19, d19, d17               // z -= eps
    ldr  d17, Lf2xm1v_P5
    ldr  d20, Lf2xm1v_P4
    fmadd d17, d19, d17, d20
    ldr  d20, Lf2xm1v_P3
    fmadd d17, d19, d17, d20
    ldr  d20, Lf2xm1v_P2
    fmadd d17, d19, d17, d20
    ldr  d20, Lf2xm1v_P1
    fmadd d17, d19, d17, d20         // p(z)
    fmul d19, d18, d19               // t*z
    fmadd d16, d19, d17, d18         // r = t + t*z*p(z) = 2^x / 2^k
    fmov d17, x26
    fmul d16, d16, d17               // 2^x
    fmov d17, #1.0
    fsub d16, d16, d17               // 2^x - 1
    b    Lf2xm1v_ret
Lf2xm1v_tiny:
    fmov d17, #1.0
    fadd d18, d16, d17               // 1 + x (tiny rounds away — classic parity)
    fsub d16, d18, d17
    b    Lf2xm1v_ret
Lf2xm1v_oor:
    mov  x29, #0x7FF0000000000000
    sub  x29, x29, x27               // < 0 iff NaN
    tbnz x29, #63, Lf2xm1v_nan
    fmov d16, xzr                    // |x| > 1: classic helper stores +0.0
    b    Lf2xm1v_ret
Lf2xm1v_nan:
    fadd d16, d16, d16               // quiet it, keep NaN-ness
Lf2xm1v_ret:
    ldr  x29, [sp, #0x50]
    ldp  x26, x27, [sp, #0x40]
    ldr  q20, [sp, #0x30]
    ldr  q19, [sp, #0x20]
    ldr  q18, [sp, #0x10]
    ldr  q17, [sp]
    add  sp, sp, #0x60
    ret

.p2align 3
Lf2xm1v_tblptr:
    .quad _x87_exp2_tbl              // dyld-rebased; -> the C path's table
Lf2xm1v_redux:
    .quad 0x42B8000000000000         // 0x1.8p52/256
Lf2xm1v_P1:
    .quad 0x3FE62E42FEFA39EF
Lf2xm1v_P2:
    .quad 0x3FCEBFBDFF82C575
Lf2xm1v_P3:
    .quad 0x3FAC6B08D704A0A6
Lf2xm1v_P4:
    .quad 0x3F83B2AB88F70400
Lf2xm1v_P5:
    .quad 0x3F55D88003875C74

// -----------------------------------------------------------------------------
// FSCALE value call (OPT-TI pow-trio): d16 = ST(0), d17 = ST(1);
// d16 = scalbn(ST(0), clamp(trunc(ST(1)), ±100000)) — the classic
// x87_fscale + openlibm_scalbn logic, ported bit-for-bit (pure exponent
// manipulation; the only FP arithmetic is the same two54/twom54/huge/tiny
// multiplies the C performs, so over/underflow FPSR effects match).
// NaN ST(1) -> default qNaN (classic helper).  d17 is consumed (runs
// containing the node exclude v16 AND v17 from the pool); everything else is
// preserved and NZCV is never written.  No C fallback leg.
// -----------------------------------------------------------------------------
.globl _stub_fscale_val
_stub_fscale_val:
    sub  sp, sp, #0x20
    stp  x27, x29, [sp]
    stp  x25, x26, [sp, #0x10]
    fmov x29, d17
    and  x29, x29, #0x7FFFFFFFFFFFFFFF
    mov  x27, #0x7FF0000000000000
    sub  x27, x27, x29               // < 0 iff ST(1) is NaN
    tbnz x27, #63, Lfscalev_nan1
    // n = clamp(trunc(st1), ±100000); fcvtzs saturates, sxtw keeps it exact
    fcvtzs w29, d17
    sxtw x29, w29
    mov  w27, #0x86A0
    movk w27, #1, lsl #16            // x27 = 100000
    sub  x26, x27, x29               // < 0 iff n > 100000
    tbnz x26, #63, Lfscalev_clampp
    add  x26, x29, x27               // < 0 iff n < -100000
    tbnz x26, #63, Lfscalev_clampn
Lfscalev_n:                          // x29 = n
    fmov x27, d16                    // x27 = bits(x) from here on
    ubfx x26, x27, #52, #11          // k = biased exponent
    cbz  x26, Lfscalev_zsub
Lfscalev_kchk:
    sub  x25, x26, #0x7FF
    cbz  x25, Lfscalev_xinfnan       // x NaN/Inf: x + x
Lfscalev_addn:
    add  x26, x26, x29               // k += n (|k|,|n| small — no wrap)
    mov  x25, #0x7FE
    sub  x25, x25, x26               // < 0 iff k > 0x7FE
    tbnz x25, #63, Lfscalev_over
    sub  x25, xzr, x26               // < 0 iff k > 0
    tbnz x25, #63, Lfscalev_norm
    add  x25, x26, #53               // < 0 iff k <= -54
    tbnz x25, #63, Lfscalev_undover
    add  x26, x26, #54               // subnormal result
    and  x27, x27, #0x800FFFFFFFFFFFFF
    orr  x27, x27, x26, lsl #52
    fmov d16, x27
    ldr  d17, Lfscalev_twom54
    fmul d16, d16, d17
    b    Lfscalev_ret
Lfscalev_norm:
    and  x27, x27, #0x800FFFFFFFFFFFFF
    orr  x27, x27, x26, lsl #52
    fmov d16, x27
    b    Lfscalev_ret
Lfscalev_zsub:                       // exponent 0: ±0 or subnormal x
    lsl  x25, x27, #1
    cbz  x25, Lfscalev_ret           // ±0 unchanged
    ldr  d17, Lfscalev_two54
    fmul d16, d16, d17               // normalize
    fmov x27, d16
    ubfx x26, x27, #52, #11
    sub  x26, x26, #54               // k
    mov  w25, #0xC350                // 50000
    add  x25, x29, x25               // < 0 iff n < -50000
    tbnz x25, #63, Lfscalev_tinyx
    b    Lfscalev_addn
Lfscalev_tinyx:
    ldr  d17, Lfscalev_tiny
    fmul d16, d17, d16               // tiny * x: ±0 + underflow, sign via x
    b    Lfscalev_ret
Lfscalev_clampp:
    mov  x29, x27                    // n = +100000
    b    Lfscalev_n
Lfscalev_clampn:
    sub  x29, xzr, x27               // n = -100000
    b    Lfscalev_n
Lfscalev_xinfnan:
    fadd d16, d16, d16
    b    Lfscalev_ret
Lfscalev_undover:                    // k <= -54: n > 50000 ? over : underflow
    mov  w25, #0xC350                // 50000
    sub  x25, x25, x29               // < 0 iff n > 50000
    tbnz x25, #63, Lfscalev_over
    and  x27, x27, #0x8000000000000000
    ldr  d17, Lfscalev_tiny
    fmov x26, d17
    orr  x26, x26, x27
    fmov d16, x26                    // copysign(tiny, x)
    ldr  d17, Lfscalev_tiny
    fmul d16, d16, d17               // -> ±0 + underflow flag
    b    Lfscalev_ret
Lfscalev_over:
    and  x27, x27, #0x8000000000000000
    ldr  d17, Lfscalev_huge
    fmov x26, d17
    orr  x26, x26, x27
    fmov d16, x26                    // copysign(huge, x)
    ldr  d17, Lfscalev_huge
    fmul d16, d16, d17               // -> ±Inf + overflow flag
    b    Lfscalev_ret
Lfscalev_nan1:
    ldr  d16, Lfscalev_qnan
Lfscalev_ret:
    ldp  x25, x26, [sp, #0x10]
    ldp  x27, x29, [sp]
    add  sp, sp, #0x20
    ret

.p2align 3
Lfscalev_two54:
    .quad 0x4350000000000000         // 2^54
Lfscalev_twom54:
    .quad 0x3C90000000000000         // 2^-54
Lfscalev_huge:
    .quad 0x7E37E43C8800759C         // 1e300
Lfscalev_tiny:
    .quad 0x01A56E1FC2F8F359         // 1e-300
Lfscalev_qnan:
    .quad 0x7FF8000000000000

// -----------------------------------------------------------------------------
// FYL2X / FYL2XP1 value calls (OPT-TI pow-trio completion): the last leg of
// the guest pow() idiom (__powhlp = fyl2x -> f2xm1 -> fscale).  Like
// f2xm1/fscale the ENTIRE math runs here — no C fallback leg, no SIMDGuard.
//
//   _stub_fyl2x_val:   d16 = ST(0) = x, d17 = ST(1) = y (consumed);
//                      d16 = y * log2(x)
//   _stub_fyl2xp1_val: same registers; d16 = y * log2(1 + x), with the
//                      classic helper's tiny-|x| cubic series for |x| < 2^-20
//
// The kernel is openlibm e_log2 + k_log1p ported from the COMPILED classic
// helper (x87_fyl2x after LTO), operation for operation, so both paths give
// bit-identical results.  That includes clang's contractions: the val_lo
// combine is one FMADD ((lo+hi)*ivln2lo fused with + lo*ivln2hi), and the
// fyl2xp1 tiny series is FMADD(x, -1/3, 0.5) then FMSUB(1 - x*t).  It also
// includes LTO's constant-folding of log2(±0)'s -two54/0.0 into a literal
// -Inf (no DIVBYZERO in FPSR — classic parity), while log2(-x)'s
// (x-x)/0.0 stays a real division (INVALID raised — classic parity).
//
// The push/pop asymmetry vs fscale: both ops write ST(1) and POP.  The
// stack effect lives entirely in the JIT (IR: slot_val[1]=node + pop();
// singular: store to ST(1) then emit_x87_pop), the stub is a pure value
// function.  Runs containing these nodes exclude v16 AND v17 from the pool
// (FScaleCall's rule); everything else is preserved: q18-q24 + x25-x27/x29
// saved here as singles, NZCV never written (sub + tbz/tbnz/cbz only).
// -----------------------------------------------------------------------------

// log2 kernel: d16 = log2(d16).  Clobbers d18-d24, x25-x27, x29.
// Branch labels are per-instantiation (\name); the Llog2v_* literal pool is
// shared by both instantiations (PC-relative LDR reaches file-wide).
.macro LOG2_VAL_KERNEL name
    fmov x27, d16                    // bits(x)
    mov  x25, xzr                    // k = 0
    sbfx x26, x27, #32, #32          // hx = signed high word
    mov  w29, #0x100000
    sub  x29, x26, x29               // 64-bit: no wrap for any hx
    tbz  x29, #63, L\name\()_bignorm // hx >= 0x00100000
    // hx < 0x00100000: ±0 / negative / positive subnormal
    lsl  x29, x27, #1
    cbz  x29, L\name\()_zero
    tbnz x27, #63, L\name\()_neg
    ldr  d18, Llog2v_two54
    fmul d16, d16, d18               // scale subnormal up by 2^54
    fmov x27, d16
    sbfx x26, x27, #32, #32
    mov  x25, #-54                   // k = -54
    b    L\name\()_main
L\name\()_bignorm:
    mov  w29, #0x7ff00000
    sub  x29, x26, x29
    tbz  x29, #63, L\name\()_infnan  // hx >= 0x7ff00000 -> x + x
L\name\()_main:
    // x == 1.0 -> +0 exactly
    mov  x29, #0x3FF0000000000000
    sub  x29, x27, x29
    cbz  x29, L\name\()_one
    // k += hx>>20; i = ((hx&0xfffff)+0x95f64)&0x100000; normalize x or x/2
    add  x25, x25, x26, asr #20
    and  x26, x26, #0xfffff
    mov  w29, #0x5f64
    movk w29, #0x9, lsl #16          // 0x95f64
    add  x29, x26, x29
    add  x25, x25, x29, lsr #20      // k += i>>20
    and  x29, x29, #0x100000         // i
    orr  x26, x26, x29
    eor  x26, x26, #0x3ff00000       // (hx&fffff) | (i ^ 0x3ff00000)
    and  x27, x27, #0xffffffff
    orr  x27, x27, x26, lsl #32
    fmov d16, x27                    // x normalized to [sqrt(2)/2, sqrt(2))
    sub  x25, x25, #0x3ff            // unbias k
    // f = x - 1.0; hfsq = (f*0.5)*f
    fmov d19, #-1.0
    fadd d16, d16, d19               // f
    fmov d19, #0.5
    fmul d19, d16, d19
    fmul d19, d16, d19               // hfsq
    // s = f/(2+f); z = s*s; w = z*z
    fmov d20, #2.0
    fadd d20, d16, d20
    fdiv d20, d16, d20               // s
    fmul d21, d20, d20               // z
    fmul d22, d21, d21               // w
    // t1 = w*(Lg2 + w*(Lg4 + w*Lg6))
    ldr  d18, Llog2v_Lg4
    ldr  d24, Llog2v_Lg6
    fmadd d18, d22, d24, d18
    ldr  d24, Llog2v_Lg2
    fmadd d18, d22, d18, d24
    fmul d23, d22, d18               // t1
    // t2 = z*(Lg1 + w*(Lg3 + w*(Lg5 + w*Lg7)))
    ldr  d18, Llog2v_Lg5
    ldr  d24, Llog2v_Lg7
    fmadd d18, d22, d24, d18
    ldr  d24, Llog2v_Lg3
    fmadd d18, d22, d18, d24
    ldr  d24, Llog2v_Lg1
    fmadd d22, d22, d18, d24         // Lg1 + w*(...)  (w dead)
    fmul d21, d21, d22               // t2             (z dead)
    fadd d21, d23, d21               // R = t1 + t2
    fadd d21, d19, d21               // hfsq + R
    fmul d20, d20, d21               // r = s*(hfsq+R)  (s dead)
    // Dekker split: hi = clearlow32(f - hfsq); lo = (f - hi) - hfsq + r
    fsub d21, d16, d19
    fmov x29, d21
    and  x29, x29, #0xFFFFFFFF00000000
    fmov d21, x29                    // hi
    fsub d16, d16, d21
    fsub d16, d16, d19               // (f - hi) - hfsq
    fadd d16, d16, d20               // lo             (f dead)
    ldr  d22, Llog2v_ivln2hi
    fmul d20, d21, d22               // val_hi = hi*ivln2hi
    fadd d21, d16, d21               // lo + hi
    fmul d16, d16, d22               // lo*ivln2hi
    ldr  d22, Llog2v_ivln2lo
    fmadd d16, d21, d22, d16         // val_lo (single FMADD — clang parity)
    // spadd(val_hi, val_lo, y_k)
    scvtf d18, w25                   // y_k = (double)k
    fadd d19, d20, d18               // w' = val_hi + y_k
    fsub d18, d18, d19               // y_k - w'
    fadd d18, d20, d18               // val_hi + (y_k - w')
    fadd d16, d18, d16               // val_lo'
    fadd d16, d19, d16               // log2(x) = w' + val_lo'
    b    L\name\()_done
L\name\()_zero:
    ldr  d16, Llog2v_ninf            // log2(±0) = -Inf (LTO-folded constant)
    b    L\name\()_done
L\name\()_neg:
    fsub d16, d16, d16               // x - x
    fmov d18, xzr
    fdiv d16, d16, d18               // (x-x)/0 -> NaN, INVALID (classic parity)
    b    L\name\()_done
L\name\()_infnan:
    fadd d16, d16, d16               // +Inf/NaN -> x + x
    b    L\name\()_done
L\name\()_one:
    fmov d16, xzr                    // log2(1) = +0
L\name\()_done:
.endm

.macro LOG2_VAL_FRAME_PUSH
    sub  sp, sp, #0x90
    str  q18, [sp]
    str  q19, [sp, #0x10]
    str  q20, [sp, #0x20]
    str  q21, [sp, #0x30]
    str  q22, [sp, #0x40]
    str  q23, [sp, #0x50]
    str  q24, [sp, #0x60]
    stp  x25, x26, [sp, #0x70]
    stp  x27, x29, [sp, #0x80]
.endm

.macro LOG2_VAL_FRAME_POP
    ldp  x27, x29, [sp, #0x80]
    ldp  x25, x26, [sp, #0x70]
    ldr  q24, [sp, #0x60]
    ldr  q23, [sp, #0x50]
    ldr  q22, [sp, #0x40]
    ldr  q21, [sp, #0x30]
    ldr  q20, [sp, #0x20]
    ldr  q19, [sp, #0x10]
    ldr  q18, [sp]
    add  sp, sp, #0x90
.endm

.globl _stub_fyl2x_val
_stub_fyl2x_val:
    LOG2_VAL_FRAME_PUSH
    LOG2_VAL_KERNEL fyl2xv
    fmul d16, d17, d16               // y * log2(x)
    LOG2_VAL_FRAME_POP
    ret

.globl _stub_fyl2xp1_val
_stub_fyl2xp1_val:
    LOG2_VAL_FRAME_PUSH
    fmov x27, d16
    and  x29, x27, #0x7FFFFFFFFFFFFFFF
    mov  x26, #0x3EB0000000000000    // 0x1p-20
    sub  x29, x29, x26               // < 0 iff |x| < 2^-20 (NaN: >= 0)
    tbnz x29, #63, Lfyl2xp1v_tiny
    fmov d18, #1.0
    fadd d16, d16, d18               // 1 + x
    LOG2_VAL_KERNEL fyl2xp1v
    fmul d16, d17, d16               // y * log2(1+x)
    LOG2_VAL_FRAME_POP
    ret
Lfyl2xp1v_tiny:
    // y * (x * (1 - x*(0.5 - x/3)) * log2e) — compiled-helper contractions:
    // FMADD(x, -1/3, 0.5) then FMSUB(1 - x*t), then two ordered multiplies.
    ldr  d18, Llog2v_mthird
    fmov d19, #0.5
    fmadd d18, d16, d18, d19         // 0.5 - x/3
    fmov d19, #1.0
    fmsub d18, d16, d18, d19         // 1 - x*(...)
    fmul d16, d16, d18               // x * (...)
    ldr  d18, Llog2v_log2e
    fmul d16, d16, d18               // ... * log2(e)
    fmul d16, d17, d16               // y * (...)
    LOG2_VAL_FRAME_POP
    ret

.p2align 3
Llog2v_two54:
    .quad 0x4350000000000000         // 2^54
Llog2v_Lg1:
    .quad 0x3FE5555555555593
Llog2v_Lg2:
    .quad 0x3FD999999997FA04
Llog2v_Lg3:
    .quad 0x3FD2492494229359
Llog2v_Lg4:
    .quad 0x3FCC71C51D8E78AF
Llog2v_Lg5:
    .quad 0x3FC7466496CB03DE
Llog2v_Lg6:
    .quad 0x3FC39A09D078C69F
Llog2v_Lg7:
    .quad 0x3FC2F112DF3E5244
Llog2v_ivln2hi:
    .quad 0x3FF7154765200000         // 1/ln2 high (33 bits)
Llog2v_ivln2lo:
    .quad 0x3DE705FC2EEFA200         // 1/ln2 low
Llog2v_ninf:
    .quad 0xFFF0000000000000         // -Inf
Llog2v_mthird:
    .quad 0xBFD5555555555555         // -1/3
Llog2v_log2e:
    .quad 0x3FF71547652B82FE         // log2(e)

// -----------------------------------------------------------------------------
// FPATAN value call: d16 = ST(0) = x, d17 = ST(1) = y (consumed);
// d16 = atan2(y, x).  Popping value call like fyl2x — the ST(1) store, pop
// and C1 clear live in the JIT; no C fallback leg, no SIMDGuard.
//
// openlibm e_atan2 + s_atan ported from the COMPILED classic helper
// (post-LTO x87_fpatan) so both paths give bit-identical results:
//   - the reduction quotients keep clang's contractions (2x-1 and 1+1.5x as
//     FMADD), the polynomial is the same fmadd chain, and the tails are the
//     contracted forms FMSUB(x - x*(s1+s2)) / FNMSUB(x*(s1+s2) - atanlo[id]),
//   - special-path arithmetic keeps the compiled operand order:
//     (pi_lo - z) + pi, (z - pi_lo) + (-pi), atanlo[3] + atanhi[3],
//     (-pi/2) - atanlo[3], tiny + pi, (-pi) - tiny, etc.,
//   - the small-|x| leg performs the (dead-valued) huge+x add so INEXACT
//     reaches FPSR exactly like the classic path, and NaN operands return
//     x + y in that operand order,
//   - LTO's dead branches are NOT reproduced: the second atan kernel's
//     >= 2^66 / sign legs are unreachable (the quotient is |y/x| with
//     exponent gap <= 60) and the huge+x <= 1.0 fcmp can never be taken.
// Control flow is re-expressed flag-free (sub + tbz/tbnz/cbz on integer
// bits — the compiled code's fcmp/ccmp/fcsel would clobber NZCV, which
// translated code may hold live).  Saves q18-q21 + x24-x27/x29 as singles.
// -----------------------------------------------------------------------------

// atan kernel: d16 = atan(d16), x27 = bits of the argument (sign source).
// Clobbers d18-d21, x26, x29.  Mirrors the compiled s_atan inlining; the
// >= 2^66 leg is live only for instantiation 1 (x == 1.0 -> atan(y)).
.macro ATAN_VAL_KERNEL name
    ubfx x26, x27, #32, #31          // i31 = high word of |arg|
    mov  w29, #0x44100000
    sub  x29, x26, x29
    tbz  x29, #63, L\name\()_big     // |arg| >= 2^66
    mov  w29, #0x3fdc0000
    sub  x29, x26, x29
    tbz  x29, #63, L\name\()_reduce  // |arg| >= 0.4375
    // |arg| < 0.4375: id = -1, arg unchanged.  huge+arg raises INEXACT
    // (classic parity — the compiled code performs it on this whole leg).
    ldr  d18, Latanv_huge
    fadd d18, d16, d18
    mov  w29, #0x3e400000
    sub  x29, x26, x29
    tbnz x29, #63, L\name\()_done    // |arg| < 2^-27: atan(arg) = arg
    mov  x26, #-1                    // id = -1
    b    L\name\()_poly
L\name\()_reduce:
    fabs d16, d16
    mov  w29, #0x3ff30000
    sub  x29, x26, x29
    tbnz x29, #63, L\name\()_lo      // |arg| < 1.1875
    mov  w29, #0x8000
    movk w29, #0x4003, lsl #16       // 0x40038000
    sub  x29, x26, x29
    tbz  x29, #63, L\name\()_id3     // |arg| >= 2.4375
    fmov d18, #-1.5                  // id = 2: (x-1.5)/(1+1.5x)
    fadd d18, d16, d18
    fmov d19, #1.0
    fmov d20, #1.5
    fmadd d16, d16, d20, d19
    fdiv d16, d18, d16
    mov  x26, #2
    b    L\name\()_poly
L\name\()_id3:
    fmov d18, #-1.0                  // id = 3: -1/x
    fdiv d16, d18, d16
    mov  x26, #3
    b    L\name\()_poly
L\name\()_lo:
    mov  w29, #0x3fe60000
    sub  x29, x26, x29
    tbnz x29, #63, L\name\()_id0     // |arg| < 0.6875
    fmov d18, #-1.0                  // id = 1: (x-1)/(x+1)
    fadd d18, d16, d18
    fmov d19, #1.0
    fadd d16, d16, d19
    fdiv d16, d18, d16
    mov  x26, #1
    b    L\name\()_poly
L\name\()_id0:
    fmov d18, #-1.0                  // id = 0: (2x-1)/(2+x)
    fmov d19, #2.0
    fmadd d18, d16, d19, d18
    fadd d16, d16, d19
    fdiv d16, d18, d16
    mov  x26, #0
L\name\()_poly:
    fmul d18, d16, d16               // z
    fmul d19, d18, d18               // w = z*z
    // s1 = z*(aT0+w*(aT2+w*(aT4+w*(aT6+w*(aT8+w*aT10)))))
    ldr  d20, Latanv_aT8
    ldr  d21, Latanv_aT10
    fmadd d20, d19, d21, d20
    ldr  d21, Latanv_aT6
    fmadd d20, d19, d20, d21
    ldr  d21, Latanv_aT4
    fmadd d20, d19, d20, d21
    ldr  d21, Latanv_aT2
    fmadd d20, d19, d20, d21
    ldr  d21, Latanv_aT0
    fmadd d20, d19, d20, d21
    fmul d18, d18, d20               // s1
    // s2 = w*(aT1+w*(aT3+w*(aT5+w*(aT7+w*aT9))))
    ldr  d20, Latanv_aT7
    ldr  d21, Latanv_aT9
    fmadd d20, d19, d21, d20
    ldr  d21, Latanv_aT5
    fmadd d20, d19, d20, d21
    ldr  d21, Latanv_aT3
    fmadd d20, d19, d20, d21
    ldr  d21, Latanv_aT1
    fmadd d20, d19, d20, d21
    fmul d19, d19, d20               // s2
    tbnz x26, #63, L\name\()_noid
    // id >= 0: atanhi[id] - ((x*(s1+s2) - atanlo[id]) - x), negated for
    // a negative original argument
    fadd d18, d19, d18               // s2 + s1
    adr  x29, Latanv_atanhi
    ldr  d20, [x29, x26, lsl #3]
    adr  x29, Latanv_atanlo
    ldr  d21, [x29, x26, lsl #3]
    fnmsub d18, d16, d18, d21        // x*(s1+s2) - atanlo[id]
    fsub d18, d18, d16               // ... - x
    fsub d16, d20, d18               // atanhi[id] - ...
    tbz  x27, #63, L\name\()_done
    fneg d16, d16
    b    L\name\()_done
L\name\()_noid:
    fadd d18, d19, d18               // s2 + s1
    fmsub d16, d16, d18, d16         // x - x*(s1+s2)
    b    L\name\()_done
L\name\()_big:
    // |arg| >= 2^66 (never NaN here): +-(atanhi[3] + atanlo[3]), with the
    // compiled operand orders per sign
    ldr  d16, Latanv_atanlo3
    tbnz x27, #63, L\name\()_bigneg
    ldr  d18, Latanv_pio2
    fadd d16, d16, d18               // atanlo[3] + atanhi[3]
    b    L\name\()_done
L\name\()_bigneg:
    ldr  d18, Latanv_mpio2
    fsub d16, d18, d16               // (-pi/2) - atanlo[3]
L\name\()_done:
.endm

.globl _stub_fpatan_val
_stub_fpatan_val:
    sub  sp, sp, #0x70
    str  q18, [sp]
    str  q19, [sp, #0x10]
    str  q20, [sp, #0x20]
    str  q21, [sp, #0x30]
    stp  x24, x25, [sp, #0x40]
    stp  x26, x27, [sp, #0x50]
    str  x29, [sp, #0x60]
    fmov x27, d16                    // bits(x)
    fmov x25, d17                    // bits(y)
    // NaN operands -> x + y (same operand order as the classic helper)
    and  x29, x27, #0x7FFFFFFFFFFFFFFF
    mov  x26, #0x7FF0000000000000
    sub  x29, x26, x29               // < 0 iff x is NaN
    tbnz x29, #63, Lfpatanv_nan
    and  x29, x25, #0x7FFFFFFFFFFFFFFF
    sub  x29, x26, x29               // < 0 iff y is NaN
    tbnz x29, #63, Lfpatanv_nan
    // x == 1.0: atan2(y, 1) = atan(y)
    mov  x29, #0x3FF0000000000000
    sub  x29, x27, x29
    cbnz x29, Lfpatanv_gen
    fmov d16, d17
    mov  x27, x25
    ATAN_VAL_KERNEL fpatanv1
    b    Lfpatanv_ret
Lfpatanv_gen:
    // m = 2*sign(x) + sign(y)
    lsr  x24, x27, #63
    lsl  x24, x24, #1
    orr  x24, x24, x25, lsr #63
    // y == +-0
    lsl  x29, x25, #1
    cbz  x29, Lfpatanv_y0
    // x == +-0 (y != 0): +-(pi/2 + tiny) by sign of y
    lsl  x29, x27, #1
    cbz  x29, Lfpatanv_pmhalfpi
    // x == +-Inf
    and  x29, x27, #0x7FFFFFFFFFFFFFFF
    mov  x26, #0x7FF0000000000000
    sub  x29, x29, x26
    cbz  x29, Lfpatanv_xinf
    // y == +-Inf (x finite): +-(pi/2 + tiny)
    and  x29, x25, #0x7FFFFFFFFFFFFFFF
    sub  x29, x29, x26
    cbz  x29, Lfpatanv_pmhalfpi
    // exponent-gap classification on the 31-bit high words
    ubfx x29, x25, #32, #31          // iy31
    ubfx x26, x27, #32, #31          // ix31
    sub  x29, x29, x26               // iy31 - ix31 (exact in 64-bit)
    mov  w26, #0x3d00000
    sub  x26, x29, x26
    tbz  x26, #63, Lfpatanv_k60      // k > 60: z = pi/2 + 0.5*pi_lo, m &= 1
    tbz  x27, #63, Lfpatanv_quot     // x > 0: straight to the quotient
    mov  w26, #0x3c00000
    add  x26, x29, x26
    tbnz x26, #63, Lfpatanv_z0       // x < 0, k < -60: z = 0
Lfpatanv_quot:
    fdiv d16, d17, d16               // y/x
    fabs d16, d16
    fmov x27, d16                    // |y/x| bits (kernel sign leg dead)
    ATAN_VAL_KERNEL fpatanv2
    b    Lfpatanv_mswitch
Lfpatanv_k60:
    ldr  d18, Latanv_pilo
    fmov d19, #0.5
    ldr  d16, Latanv_pio2
    fmadd d16, d18, d19, d16         // z = 0.5*pi_lo + pi/2
    and  x24, x24, #1
    b    Lfpatanv_mswitch
Lfpatanv_z0:
    fmov d16, xzr
Lfpatanv_mswitch:
    // m: 0 -> z; 1 -> -z; 2 -> (pi_lo - z) + pi; 3 -> (z - pi_lo) + (-pi)
    tbnz x24, #1, Lfpatanv_m23
    tbz  x24, #0, Lfpatanv_ret
    fneg d16, d16
    b    Lfpatanv_ret
Lfpatanv_m23:
    ldr  d18, Latanv_pilo
    tbnz x24, #0, Lfpatanv_m3
    fsub d16, d18, d16               // pi_lo - z
    ldr  d18, Latanv_pi
    fadd d16, d16, d18               // + pi
    b    Lfpatanv_ret
Lfpatanv_m3:
    fsub d16, d16, d18               // z - pi_lo
    ldr  d18, Latanv_mpi
    fadd d16, d16, d18               // + (-pi)
    b    Lfpatanv_ret
Lfpatanv_y0:
    // y == +-0: m 0/1 -> y itself; 2 -> tiny + pi; 3 -> (-pi) - tiny
    tbnz x24, #1, Lfpatanv_y0_x
    fmov d16, d17
    b    Lfpatanv_ret
Lfpatanv_y0_x:
    ldr  d16, Latanv_tiny
    tbnz x24, #0, Lfpatanv_y0_m3
    ldr  d18, Latanv_pi
    fadd d16, d16, d18               // tiny + pi
    b    Lfpatanv_ret
Lfpatanv_y0_m3:
    ldr  d18, Latanv_mpi
    fsub d16, d18, d16               // (-pi) - tiny
    b    Lfpatanv_ret
Lfpatanv_pmhalfpi:
    // +-(pi/2 + tiny) by sign of y, compiled operand orders
    ldr  d16, Latanv_tiny
    tbnz x25, #63, Lfpatanv_mhalfpi
    ldr  d18, Latanv_pio2
    fadd d16, d16, d18               // tiny + pi/2
    b    Lfpatanv_ret
Lfpatanv_mhalfpi:
    ldr  d18, Latanv_mpio2
    fsub d16, d18, d16               // (-pi/2) - tiny
    b    Lfpatanv_ret
Lfpatanv_xinf:
    and  x29, x25, #0x7FFFFFFFFFFFFFFF
    sub  x29, x29, x26               // y also Inf?
    cbz  x29, Lfpatanv_bothinf
    // x = +-Inf, y finite: m 0 -> +0; 1 -> -0; 2 -> tiny + pi; 3 -> -pi - tiny
    tbnz x24, #1, Lfpatanv_y0_x      // m 2/3: same arithmetic as the y==0 leg
    fmov d16, xzr
    tbz  x24, #0, Lfpatanv_ret
    mov  x29, #0x8000000000000000
    fmov d16, x29                    // -0.0
    b    Lfpatanv_ret
Lfpatanv_bothinf:
    // m 0 -> tiny + pi/4; 1 -> (-pi/4) - tiny; 2 -> tiny + 3pi/4;
    //   3 -> (-3pi/4) - tiny
    ldr  d16, Latanv_tiny
    tbnz x24, #1, Lfpatanv_binf23
    tbnz x24, #0, Lfpatanv_binf1
    ldr  d18, Latanv_pio4
    fadd d16, d16, d18
    b    Lfpatanv_ret
Lfpatanv_binf1:
    ldr  d18, Latanv_mpio4
    fsub d16, d18, d16
    b    Lfpatanv_ret
Lfpatanv_binf23:
    tbnz x24, #0, Lfpatanv_binf3
    ldr  d18, Latanv_3pio4
    fadd d16, d16, d18
    b    Lfpatanv_ret
Lfpatanv_binf3:
    ldr  d18, Latanv_m3pio4
    fsub d16, d18, d16
    b    Lfpatanv_ret
Lfpatanv_nan:
    fadd d16, d16, d17               // x + y (classic operand order)
Lfpatanv_ret:
    ldr  x29, [sp, #0x60]
    ldp  x26, x27, [sp, #0x50]
    ldp  x24, x25, [sp, #0x40]
    ldr  q21, [sp, #0x30]
    ldr  q20, [sp, #0x20]
    ldr  q19, [sp, #0x10]
    ldr  q18, [sp]
    add  sp, sp, #0x70
    ret

.p2align 3
Latanv_atanhi:
    .quad 0x3FDDAC670561BB4F         // atan(0.5) hi
    .quad 0x3FE921FB54442D18         // atan(1.0) hi
    .quad 0x3FEF730BD281F69B         // atan(1.5) hi
Latanv_pio2:
    .quad 0x3FF921FB54442D18         // atan(inf) hi = pi/2
Latanv_atanlo:
    .quad 0x3C7A2B7F222F65E2         // atan(0.5) lo
    .quad 0x3C81A62633145C07         // atan(1.0) lo
    .quad 0x3C7007887AF0CBBD         // atan(1.5) lo
Latanv_atanlo3:
    .quad 0x3C91A62633145C07         // atan(inf) lo
Latanv_aT0:
    .quad 0x3FD555555555550D
Latanv_aT1:
    .quad 0xBFC999999998EBC4
Latanv_aT2:
    .quad 0x3FC24924920083FF
Latanv_aT3:
    .quad 0xBFBC71C6FE231671
Latanv_aT4:
    .quad 0x3FB745CDC54C206E
Latanv_aT5:
    .quad 0xBFB3B0F2AF749A6D
Latanv_aT6:
    .quad 0x3FB10D66A0D03D51
Latanv_aT7:
    .quad 0xBFADDE2D52DEFD9A
Latanv_aT8:
    .quad 0x3FA97B4B24760DEB
Latanv_aT9:
    .quad 0xBFA2B4442C6A6C2F
Latanv_aT10:
    .quad 0x3F90AD3AE322DA11
Latanv_huge:
    .quad 0x7E37E43C8800759C         // 1e300
Latanv_tiny:
    .quad 0x01A56E1FC2F8F359         // 1e-300
Latanv_pi:
    .quad 0x400921FB54442D18
Latanv_mpi:
    .quad 0xC00921FB54442D18
Latanv_mpio2:
    .quad 0xBFF921FB54442D18
Latanv_pio4:
    .quad 0x3FE921FB54442D18
Latanv_mpio4:
    .quad 0xBFE921FB54442D18
Latanv_3pio4:
    .quad 0x4002D97C7F3321D2
Latanv_m3pio4:
    .quad 0xC002D97C7F3321D2
Latanv_pilo:
    .quad 0x3CA1A62633145C07

// -----------------------------------------------------------------------------
// FXAM / FXTRACT in-blob fast paths (offset-table routed like the trig fast
// stubs, default-on, ROSETTA_X87_DISABLE_{FXAM,FXTRACT}_FAST=1 reverts to the
// classic slots).  Both are memory-state stubs: state at x18+0xA0
// (+0xA0 controlWord, +0xA2 statusWord, +0xA4 tagWord, +0xA8 st[8]).
// Register discipline (kRuntimeRoutine BL-site contract): x16/x27/x29 free,
// x25/x26 saved on the native stack (OPT-KA keepalive relies on them),
// NZCV never written (sub + tbz/tbnz/cbz only), FXTRACT saves q16 around
// its one SCVTF.  Debug/single-step sessions bail to the classic slot
// before any state is modified.
//
// FXAM: classify ST(0) into C3/C2/C0 with C1 = sign, from the tag word
// first (kEmpty/kZero) then the value bits — the exact x87_fxam logic:
//   empty 0x4100, zero 0x4000 (+C1 sign), NaN 0x0100, Inf 0x0500,
//   subnormal 0x4400, normal 0x0400; C-bits cleared with the same ~0x4700.
// -----------------------------------------------------------------------------
.globl _stub_fxam_fast
_stub_fxam_fast:
    ldrb w29, [x18, #0x1C8]
    cbnz w29, _stub_fxam
    sub  sp, sp, #0x10
    stp  x25, x26, [sp]
    ldrh w25, [x18, #0xA2]           // statusWord
    ldrh w26, [x18, #0xA4]           // tagWord
    ubfx w27, w25, #11, #3           // TOP
    lsl  w29, w27, #1
    lsr  w26, w26, w29
    and  w26, w26, #3                // tag of ST(0)
    mov  w16, #0xB8FF
    and  w25, w25, w16               // clear C3|C2|C1|C0
    sub  w29, w26, #3
    cbz  w29, Lfxam_empty
    sub  w29, w26, #1
    cbz  w29, Lfxam_zerotag
    // kValid/kSpecial: classify the value bits
    add  x29, x18, #0xA8
    ldr  x16, [x29, w27, uxtw #3]    // ST(0) bits
    tbz  x16, #63, Lfxam_signdone
    orr  w25, w25, #0x200            // C1 = sign
Lfxam_signdone:
    lsl  x29, x16, #1
    cbnz x29, Lfxam_classify
    orr  w25, w25, #0x4000           // value == ±0 despite kValid tag: C3
    b    Lfxam_store
Lfxam_classify:
    and  x29, x16, #0x7FFFFFFFFFFFFFFF
    mov  x26, #0x7FF0000000000000
    sub  x29, x29, x26
    cbz  x29, Lfxam_inf
    tbz  x29, #63, Lfxam_nan         // abs > 0x7FF0... → NaN
    and  x29, x16, #0x7FF0000000000000
    cbz  x29, Lfxam_subn             // zero exponent field (value != 0)
    orr  w25, w25, #0x400            // normal: C2
    b    Lfxam_store
Lfxam_subn:
    mov  w29, #0x4400                // subnormal: C3|C2
    orr  w25, w25, w29
    b    Lfxam_store
Lfxam_inf:
    mov  w29, #0x500                 // infinity: C2|C0
    orr  w25, w25, w29
    b    Lfxam_store
Lfxam_nan:
    orr  w25, w25, #0x100            // NaN: C0
    b    Lfxam_store
Lfxam_zerotag:
    orr  w25, w25, #0x4000           // kZero: C3, C1 = sign of the -0/+0
    add  x29, x18, #0xA8
    ldr  x16, [x29, w27, uxtw #3]
    tbz  x16, #63, Lfxam_store
    orr  w25, w25, #0x200
    b    Lfxam_store
Lfxam_empty:
    mov  w29, #0x4100                // kEmpty: C3|C0
    orr  w25, w25, w29
Lfxam_store:
    strh w25, [x18, #0xA2]
    ldp  x25, x26, [sp]
    add  sp, sp, #0x10
    ret

// -----------------------------------------------------------------------------
// FXTRACT: ST(0) ← exponent, push, ST(0) ← significand — mirrors the
// rewritten x87_fxtract bit for bit (exact bit extraction; the old
// floor(log2)+pow C path is gone from both sides).  Empty ST(0) mirrors
// getSt: statusWord |= IE|SF (0x41) and the default qNaN flows through the
// NaN leg.  Tag effects match setSt/push: slot TOP ← class(exponent),
// slot newTOP ← class(significand).
// Packing: x27 = TOP | newTop<<8 | eclass<<16 | mclass<<24.
// -----------------------------------------------------------------------------
.globl _stub_fxtract_fast
_stub_fxtract_fast:
    ldrb w29, [x18, #0x1C8]
    cbnz w29, _stub_fxtract
    sub  sp, sp, #0x20
    stp  x25, x26, [sp]
    str  q16, [sp, #0x10]
    ldrh w25, [x18, #0xA2]           // statusWord
    ldrh w26, [x18, #0xA4]           // tagWord
    ubfx w27, w25, #11, #3           // TOP
    sub  w29, w27, #1
    and  w29, w29, #7
    orr  x27, x27, x29, lsl #8       // pack newTop
    // getSt(0) with tag check
    ubfx w29, w27, #0, #3
    lsl  w29, w29, #1
    lsr  w26, w26, w29
    and  w26, w26, #3
    sub  w26, w26, #3
    cbnz w26, Lfxtr_load
    mov  w29, #0x41                  // empty: IE | SF, value = default qNaN
    orr  w25, w25, w29
    mov  x16, #0x7FF8000000000000
    b    Lfxtr_have
Lfxtr_load:
    add  x29, x18, #0xA8
    ubfx w26, w27, #0, #3
    ldr  x16, [x29, w26, uxtw #3]    // ST(0) bits
Lfxtr_have:
    lsl  x29, x16, #1
    cbz  x29, Lfxtr_zero
    and  x29, x16, #0x7FFFFFFFFFFFFFFF
    mov  x26, #0x7FF0000000000000
    sub  x29, x29, x26
    cbz  x29, Lfxtr_inf
    tbz  x29, #63, Lfxtr_nan
    // finite nonzero
    ubfx x26, x16, #52, #11
    cbnz x26, Lfxtr_normal
    // subnormal: normalize via CLZ
    and  x26, x16, #0xFFFFFFFFFFFFF
    clz  x29, x26
    sub  x29, x29, #11               // sh
    lsl  x26, x26, x29
    and  x26, x26, #0xFFFFFFFFFFFFF  // fraction of the normalized value
    and  x16, x16, #0x8000000000000000
    orr  x16, x16, x26
    orr  x16, x16, #0x3FF0000000000000
    mov  x26, #-1022
    sub  x26, x26, x29               // e = -1022 - sh
    b    Lfxtr_fin
Lfxtr_normal:
    sub  x26, x26, #0x3FF            // e = expField - 1023
    and  x16, x16, #0x800FFFFFFFFFFFFF
    orr  x16, x16, #0x3FF0000000000000
Lfxtr_fin:
    scvtf d16, w26                   // (double)e — exact, |e| <= 1074
    cbz  w26, Lfxtr_ez
    b    Lfxtr_common                // eclass 0 (valid), mclass 0 (valid)
Lfxtr_ez:
    orr  x27, x27, #0x10000          // e == 0 → eclass kZero
    b    Lfxtr_common
Lfxtr_zero:
    // exponent = -Inf; significand: #Z masked → ±0 (bits already in x16),
    // unmasked → default qNaN (the old 0/0 outcome)
    mov  x29, #0xFFF0000000000000
    fmov d16, x29
    orr  x27, x27, #0x20000          // eclass kSpecial
    ldrh w29, [x18, #0xA0]           // controlWord
    tbz  w29, #2, Lfxtr_zero_unmasked
    orr  x27, x27, #0x1000000        // mclass kZero
    b    Lfxtr_common
Lfxtr_zero_unmasked:
    mov  x16, #0x7FF8000000000000
    orr  x27, x27, #0x2000000        // mclass kSpecial
    b    Lfxtr_common
Lfxtr_inf:
    mov  x29, #0x7FF0000000000000    // exponent = +Inf; significand = ±Inf
    fmov d16, x29
    orr  x27, x27, #0x20000
    orr  x27, x27, #0x2000000
    b    Lfxtr_common
Lfxtr_nan:
    and  x29, x16, #0x7FFFFFFFFFFFFFFF
    orr  x29, x29, #0x8000000000000   // quiet(|st0|)
    fmov d16, x29
    orr  x16, x16, #0x8000000000000   // quiet(st0)
    orr  x27, x27, #0x20000
    orr  x27, x27, #0x2000000
Lfxtr_common:
    // stores: st[TOP] = e (d16), st[newTop] = m (x16)
    add  x29, x18, #0xA8
    ubfx w26, w27, #0, #3
    str  d16, [x29, w26, uxtw #3]
    ubfx w26, w27, #8, #3
    str  x16, [x29, w26, uxtw #3]
    // tag updates for both slots
    ldrh w16, [x18, #0xA4]
    ubfx w29, w27, #0, #3
    lsl  w29, w29, #1
    mov  w26, #3
    lslv w26, w26, w29
    bic  w16, w16, w26
    ubfx w26, w27, #16, #2           // eclass
    lslv w26, w26, w29
    orr  w16, w16, w26
    ubfx w29, w27, #8, #3
    lsl  w29, w29, #1
    mov  w26, #3
    lslv w26, w26, w29
    bic  w16, w16, w26
    ubfx w26, w27, #24, #2           // mclass
    lslv w26, w26, w29
    orr  w16, w16, w26
    strh w16, [x18, #0xA4]
    // statusWord: TOP ← newTop (plus any IE|SF from the empty read)
    and  w25, w25, #0xFFFFC7FF
    ubfx w29, w27, #8, #3
    orr  w25, w25, w29, lsl #11
    strh w25, [x18, #0xA2]
    ldr  q16, [sp, #0x10]
    ldp  x25, x26, [sp]
    add  sp, sp, #0x20
    ret

// -----------------------------------------------------------------------------
// FPREM / FPREM1 in-blob fast paths (offset-table routed, default-on,
// ROSETTA_X87_DISABLE_{FPREM,FPREM1}_FAST=1 reverts to the classic slots).
// Memory-state stubs like FXAM/FXTRACT above; same register discipline:
// x16/x27/x29 free, x25/x26 saved, q16-q19 saved as SINGLE str/ldr q (TSO
// Q-pair penalty), NZCV never written (tbz/tbnz/cbz/cbnz only, no FCMP).
//
// Semantics reproduced = the current C++ handlers (x87_fprem / x87_fprem1),
// bit for bit on the accepted input class.  Everything else bails to the
// classic slot BEFORE any state is modified:
//   - debug/single-step sessions            (flag byte at [x18, #0x1C8])
//   - empty ST(0)/ST(1) tags                (getSt sets IE|SF + NaN leg)
//   - x zero/subnormal/Inf/NaN              (special-case legs)
//   - e1 < 53, i.e. |y| < 2^-970: keeps every representable remainder
//     normal-or-zero, so no subnormal tag leg and no FZ-mode divergence
//     (openlibm fmod is integer-exact; an FZ-flushed FNMSUB would not be)
//   - y Inf/NaN                             (pass-through / #IA legs)
//   - D = e0-e1 >= 52                       (C2 incomplete leg needs the
//     bit-by-bit loop; also keeps the quotient < 2^53 so FDIV+FRINTZ+FMSUB
//     is exact — see below)
//
// Exactness argument for the kernel (any rounding mode, a=|x|, b=|y|):
//   q^ = FRINTZ(FDIV(a,b)) equals the true truncated quotient q or q+1,
//   never q-1 (a correctly-rounded a/b can only cross an integer upward).
//   With D <= 51, q+1 <= 2^52 is exactly representable, so
//   FMSUB(q^, b, a) = a - q^*b rounds an exactly-representable value
//   (the true remainder, or remainder-b) → exact.  The r<0 fixup adds b
//   back (Sterbenz-exact) and decrements q.  A -0 FMSUB result (directed
//   rounding modes) is normalized to +0.  fmod(a,b) is then exact and the
//   quotient's low 3 bits drive C0/C1/C3 exactly as the C++ path's
//   fmod(a,8b) reconstruction does.
//
// FPREM1 additionally mirrors s_remquo.h's fixup on the magnitude result:
//   if (r > b/2 || (r == b/2 && (q & 1))) { q++; r -= b; }   [Sterbenz-exact]
// b/2 is computed by integer exponent decrement (exact: e1 >= 53 > 1), and
// the CC bits use remquo's *quo convention: sign(x^y) applied to q first,
// then the low two's-complement bits — matching the C++ handler's (q & 4/1/2)
// on the signed int, including the negative-quotient encoding.
//
// statusWord: C3|C2|C1|C0 cleared, C0←Q2 C1←Q0 C3←Q1, C2 stays 0 (complete
// reduction is guaranteed by the D gate).  Result slot tag ← kZero/kValid
// (setSt's classes; kSpecial impossible on this input class).
//
// Frame: [sp+0x00..0x3F] q16-q19 singles, [sp+0x40] x25,x26.
// x27 packs TOP | sign(x)<<8 | sign(x^y)<<9 (fprem1 only).
// -----------------------------------------------------------------------------

// Shared entry: debug bail, frame, tag checks, exponent gate, |x|/|y| into
// d16/d17, sign packing, and the truncating fmod kernel:
//   d18 = q^ (float), x25 = q (integer, fixed up), d19 = r in [0, b).
.macro PREM_ENTRY name
.globl _stub_\name\()_fast
_stub_\name\()_fast:
    ldrb w29, [x18, #0x1C8]
    cbnz w29, _stub_\name
    sub  sp, sp, #0x50
    stp  x25, x26, [sp, #0x40]
    ldrh w25, [x18, #0xA2]           // statusWord
    ubfx w27, w25, #11, #3           // TOP
    ldrh w26, [x18, #0xA4]           // tagWord
    lsl  w29, w27, #1
    lsr  w29, w26, w29
    and  w29, w29, #3
    sub  w29, w29, #3
    cbz  w29, L\name\()_bail         // ST(0) empty
    add  w16, w27, #1
    and  w16, w16, #7                // phys idx of ST(1)
    lsl  w29, w16, #1
    lsr  w29, w26, w29
    and  w29, w29, #3
    sub  w29, w29, #3
    cbz  w29, L\name\()_bail         // ST(1) empty
    add  x25, x18, #0xA8
    ldr  x26, [x25, w16, uxtw #3]    // y bits
    ldr  x16, [x25, w27, uxtw #3]    // x bits
    // Exponent gate (biased fields; all-integer, no FP touched before bail)
    ubfx x29, x16, #52, #11          // e0
    sub  w29, w29, #1
    tbnz w29, #31, L\name\()_bail    // e0 == 0: x zero/subnormal
    ubfx x25, x26, #52, #11          // e1
    sub  w25, w25, #53
    tbnz w25, #31, L\name\()_bail    // e1 < 53: y zero/subnormal/tiny
    sub  w29, w29, w25               // (e0-1) - (e1-53) = D + 52
    sub  w29, w29, #104
    tbz  w29, #31, L\name\()_bail    // D >= 52 (also catches Inf/NaN x vs small y)
    mov  w29, #0x7CA
    sub  w25, w25, w29
    cbz  w25, L\name\()_bail         // e1 == 0x7FF: y Inf/NaN
    ubfx x29, x16, #52, #11
    mov  w25, #0x7FF
    sub  w25, w29, w25
    cbz  w25, L\name\()_bail         // e0 == 0x7FF: x Inf/NaN
    // Eligible — FP setup (q16-q19 saved as singles, TSO rule)
    str  q16, [sp]
    str  q17, [sp, #0x10]
    str  q18, [sp, #0x20]
    str  q19, [sp, #0x30]
    and  x29, x16, #0x7FFFFFFFFFFFFFFF
    fmov d16, x29                    // a = |x|
    and  x29, x26, #0x7FFFFFFFFFFFFFFF
    fmov d17, x29                    // b = |y|
    eor  x25, x16, x26
    lsr  x25, x25, #63
    orr  x27, x27, x25, lsl #9       // pack sign(x^y) at bit 9 (fprem1 CC)
    lsr  x29, x16, #63
    orr  x27, x27, x29, lsl #8       // pack sign(x) at bit 8
    // Truncating fmod kernel
    fdiv d18, d16, d17
    frintz d18, d18                  // q^ = trunc(a/b), true q or q+1
    fmsub d19, d18, d17, d16         // r = a - q^*b (exact)
    fcvtzu x25, d18                  // q^ as integer (< 2^53)
    fmov x29, d19
    tbz  x29, #63, L\name\()_rok
    lsl  x26, x29, #1
    cbz  x26, L\name\()_negz         // r == -0 (directed rounding) → +0
    fadd d19, d19, d17               // overshoot: r += b (Sterbenz-exact)
    sub  x25, x25, #1                //            q -= 1
    b    L\name\()_rok
L\name\()_negz:
    fmov d19, xzr
L\name\()_rok:
.endm

// Shared tail: CC bits from x25's low 3 bits (C0←Q2, C1←Q0, C3←Q1, C2=0),
// sign(x) applied to the magnitude result, store, kZero/kValid tag, return.
.macro PREM_TAIL name
    ldrh w26, [x18, #0xA2]
    mov  w29, #0xB8FF
    and  w26, w26, w29               // clear C3|C2|C1|C0
    ubfx x29, x25, #2, #1
    orr  w26, w26, w29, lsl #8       // C0 ← Q2
    ubfx x29, x25, #0, #1
    orr  w26, w26, w29, lsl #9       // C1 ← Q0
    ubfx x29, x25, #1, #1
    orr  w26, w26, w29, lsl #14      // C3 ← Q1
    strh w26, [x18, #0xA2]
    fmov x29, d19
    ubfx x16, x27, #8, #1
    eor  x29, x29, x16, lsl #63      // apply sign(x) (remquo: hx ^ sx)
    add  x26, x18, #0xA8
    and  w16, w27, #7
    str  x29, [x26, w16, uxtw #3]    // st[TOP] = result
    // tag ← result == ±0 ? kZero : kValid (subnormal impossible: e1 >= 53)
    lsl  x25, x29, #1
    ldrh w26, [x18, #0xA4]
    lsl  w16, w16, #1
    mov  w29, #3
    lslv w29, w29, w16
    bic  w26, w26, w29
    cbnz x25, L\name\()_tagdone
    mov  w29, #1
    lslv w29, w29, w16
    orr  w26, w26, w29
L\name\()_tagdone:
    strh w26, [x18, #0xA4]
    ldr  q16, [sp]
    ldr  q17, [sp, #0x10]
    ldr  q18, [sp, #0x20]
    ldr  q19, [sp, #0x30]
    ldp  x25, x26, [sp, #0x40]
    add  sp, sp, #0x50
    ret
// Bail: q16-q19 are saved only after the last bail site and never modified
// before one, so only the GPR spill and the frame need undoing.
L\name\()_bail:
    ldp  x25, x26, [sp, #0x40]
    add  sp, sp, #0x50
    b    _stub_\name
.endm

PREM_ENTRY fprem
    PREM_TAIL fprem

PREM_ENTRY fprem1
    // remquo fixup: round the quotient to nearest (ties to even q)
    fmov x29, d19                    // r bits (non-negative)
    fmov x16, d17
    mov  x26, #0x0010000000000000
    sub  x16, x16, x26               // b/2 bits (exact: e1 >= 53)
    sub  x16, x29, x16               // r - b/2, IEEE order == integer order
    tbnz x16, #63, Lfprem1_fixdone   // r < b/2
    cbnz x16, Lfprem1_bump           // r > b/2
    tbz  x25, #0, Lfprem1_fixdone    // r == b/2 tie, q even → keep
Lfprem1_bump:
    fsub d19, d19, d17               // r -= b (Sterbenz-exact)
    add  x25, x25, #1
Lfprem1_fixdone:
    // *quo convention: signed quotient's two's-complement low bits
    tbz  x27, #9, Lfprem1_qpos
    neg  x25, x25
Lfprem1_qpos:
    PREM_TAIL fprem1

// -----------------------------------------------------------------------------
// FSIN: ST(0) = sin(ST(0)).  n & 3 selects 0:+sin 1:+cos 2:-sin 3:-cos.
// -----------------------------------------------------------------------------
TRIG_ENTRY fsin
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfsin_small
    TRIG_REDUCE fsin
    tbz  w27, #0, Lfsin_ksin
    TRIG_KCOS d16
    b    Lfsin_negmaybe
Lfsin_ksin:
    TRIG_KSIN d16
Lfsin_negmaybe:
    tbz  w27, #1, Lfsin_store        // negate for quadrants 2 and 3
    fneg d16, d16
Lfsin_store:
    TRIG_STORE_INPLACE
    TRIG_EPILOGUE
Lfsin_small:
    // |x| < 2^-26: sin(x) = x — d16 already holds it; store unchanged.
    mov  w29, #0x3e500000
    sub  w29, w27, w29
    tbnz w29, #31, Lfsin_store
    fmov d22, d16
    fmov d23, xzr
    TRIG_KSIN d16, 0                 // y known zero: openlibm's iy=0 form
    b    Lfsin_store
TRIG_BAIL fsin

// -----------------------------------------------------------------------------
// FSINCOS: ST(0) = sin, push, new ST(0) = cos.  One reduction feeds BOTH
// kernels (the C++ handler runs openlibm_sin and openlibm_cos, reducing
// twice).  With s = kernel_sin, c = kernel_cos of the reduced argument:
//   n&3 = 0: sin=+s cos=+c    1: sin=+c cos=-s
//         2: sin=-s cos=-c    3: sin=-c cos=+s
// -----------------------------------------------------------------------------
TRIG_ENTRY fsincos
    str  q24, [sp, #0x80]
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfsincos_small
    TRIG_REDUCE fsincos
    TRIG_KCOS d24                    // c (d22/d23 stay live)
    TRIG_KSIN d16                    // s
    // Quadrant select, depth-1 from the kernel outputs (no serial swap):
    //   n&3 = 0: sin=+s cos=+c    1: sin=+c cos=-s
    //         2: sin=-s cos=-c    3: sin=-c cos=+s
    tbz  w27, #0, Lfsincos_even
    tbnz w27, #1, Lfsincos_n3
    fneg d17, d16                    // n=1: cos = -s (reads s before...)
    fmov d16, d24                    //      sin = +c (...d16 is overwritten)
    b    Lfsincos_store
Lfsincos_n3:
    fmov d17, d16                    // n=3: cos = +s
    fneg d16, d24                    //      sin = -c
    b    Lfsincos_store
Lfsincos_even:
    tbnz w27, #1, Lfsincos_n2
    fmov d17, d24                    // n=0: cos = +c
    b    Lfsincos_store
Lfsincos_n2:
    fneg d16, d16                    // n=2: sin = -s
    fneg d17, d24                    //      cos = -c
    b    Lfsincos_store
Lfsincos_small:
    // |x| < pi/4: openlibm composition — sin has a 2^-26 short-circuit
    // (returns x, preserving -0), cos a 2^-27*sqrt(2) one (returns 1.0);
    // both kernels take y = 0 (iy=0 forms), matching the C handler's
    // openlibm_sin/openlibm_cos small paths bit for bit.
    fmov d22, d16
    mov  w29, #0x3e500000            // 2^-26
    sub  w29, w27, w29
    tbnz w29, #31, Lfsincos_tiny
    TRIG_KSIN d16, 0                 // s (d22 stays live)
    TRIG_KCOS d17, 0                 // c
    b    Lfsincos_store
Lfsincos_tiny:                       // sin = x (d16 unchanged)
    mov  w29, #0xa09e
    movk w29, #0x3e46, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfsincos_cos1
    TRIG_KCOS d17, 0
    b    Lfsincos_store
Lfsincos_cos1:
    fmov d17, #1.0                   // cos = 1.0
Lfsincos_store:
    TRIG_STORE_PUSH d17
    TRIG_EPILOGUE 1
TRIG_BAIL fsincos

// -----------------------------------------------------------------------------
// FPTAN: ST(0) = tan(ST(0)), push 1.0.  __kernel_tan ported from k_tan.h:
// three shapes — |x| >= 0.6744 (pi/4 substitution + final rational fixup),
// plain polynomial (n even), accurate -1/(x+r) (n odd).
// Packs (n&1, sign(x), bigflag) into w26 bits 3..5 above TOP to survive the
// kernel with only x27/x29 as scratch; the store unpacks with `and #7`.
// -----------------------------------------------------------------------------
TRIG_ENTRY fptan
    // x87_fptan reads ST(0) via tag-checked getSt: an empty slot has
    // stack-fault semantics, so route that (rare, buggy-guest) case to the
    // classic stub for exact parity.
    lsl  w29, w26, #1
    ldrh w27, [x18, #0xA4]
    lsr  w27, w27, w29
    and  w27, w27, #3
    sub  w27, w27, #3
    cbz  w27, Lfptan_bail            // tag == kEmpty
    str  q24, [sp, #0x80]
    fmov x27, d16
    ubfx x27, x27, #32, #31          // hi31 (recompute; w27 was scratched)
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfptan_small
    TRIG_REDUCE fptan
    // TRIG_KTAN packs (n&1, sign, big) into w26 bits 3..5, above the TOP the
    // memory entry keeps in bits 0..2; the store unpacks with `and #7`.
    TRIG_KTAN fptan
    b    Lfptan_store
Lfptan_small:
    // |x| < 2^-27: tan(x) = x — d16 already holds it (also preserves -0,
    // which the odd polynomial would not).
    mov  w29, #0x3e400000
    sub  w29, w27, w29
    tbnz w29, #31, Lfptan_store
    fmov d22, d16
    mov  w27, wzr                    // n = 0
    TRIG_KTAN fptans, 1              // y known zero — d23 never read
Lfptan_store:
    and  w26, w26, #7                // unpack TOP
    fmov d17, #1.0
    TRIG_STORE_PUSH d17
    TRIG_EPILOGUE 1
TRIG_BAIL fptan

// Literal pool — IEEE-754 doubles from openlibm e_rem_pio2.h / k_cos.h /
// k_sin.h / k_tan.h.  PC-relative LDR (literal), so per-chunk blob copies
// need no relocation.
.p2align 3
Ltrig_invpio2:  .quad 0x3FE45F306DC9C883   // 2/pi, 53 bits
Ltrig_pio2_1:   .quad 0x3FF921FB54400000   // first 33 bits of pi/2
Ltrig_pio2_1t:  .quad 0x3DD0B4611A626331   // pi/2 - pio2_1
Ltrig_pio2_2:   .quad 0x3DD0B4611A600000   // second 33 bits of pi/2
Ltrig_pio2_2t:  .quad 0x3BA3198A2E037073   // pi/2 - (pio2_1+pio2_2)
Ltrig_pio2_3:   .quad 0x3BA3198A2E000000   // third 33 bits of pi/2
Ltrig_pio2_3t:  .quad 0x397B839A252049C1   // pi/2 - (pio2_1+pio2_2+pio2_3)
Ltrig_C1:       .quad 0x3FA555555555554C
Ltrig_C2:       .quad 0xBF56C16C16C15177
Ltrig_C3:       .quad 0x3EFA01A019CB1590
Ltrig_C4:       .quad 0xBE927E4F809C52AD
Ltrig_C5:       .quad 0x3E21EE9EBDB4B1C4
Ltrig_C6:       .quad 0xBDA8FAE9BE8838D4
Ltrig_S1:       .quad 0xBFC5555555555549
Ltrig_S2:       .quad 0x3F8111111110F8A6
Ltrig_S3:       .quad 0xBF2A01A019C161D5
Ltrig_S4:       .quad 0x3EC71DE357B1FE7D
Ltrig_S5:       .quad 0xBE5AE5E68A2B9CEB
Ltrig_S6:       .quad 0x3DE5D93A5ACFD57C
Ltrig_T0:       .quad 0x3FD5555555555563
Ltrig_T1:       .quad 0x3FC111111110FE7A
Ltrig_T2:       .quad 0x3FABA1BA1BB341FE
Ltrig_T3:       .quad 0x3F9664F48406D637
Ltrig_T4:       .quad 0x3F8226E3E96E8493
Ltrig_T5:       .quad 0x3F6D6D22C9560328
Ltrig_T6:       .quad 0x3F57DBC8FEE08315
Ltrig_T7:       .quad 0x3F4344D8F2F26501
Ltrig_T8:       .quad 0x3F3026F71A8D1068
Ltrig_T9:       .quad 0x3F147E88A03792A6
Ltrig_T10:      .quad 0x3F12B80F32F0A7E9
Ltrig_T11:      .quad 0xBEF375CBDB605373
Ltrig_T12:      .quad 0x3EFB2A7074BF7AD4
Ltrig_pio4:     .quad 0x3FE921FB54442D18   // pi/4
Ltrig_pio4lo:   .quad 0x3C81A62633145C07   // pi/4 low part


// =============================================================================
// Dispatch tails and runtime exit segments
//
// Reconstructed from Rosetta runtime binary via IDA.
// =============================================================================


// =============================================================================
// runtime_savedreg segment
// =============================================================================
.section runtime_savedreg,runtime_savedreg,regular,pure_instructions
.p2align 2

// Boundary between the entry stubs and the dispatch tails.  TranslationCacheAbi
// splits AbiKind_Library / AbiKind_RuntimeRoutine here (reference: runtime_savedreg
// at 0x21370).
.globl _runtime_savedreg_start
_runtime_savedreg_start:

// Tail pattern macros
// TAIL_F:  no args, no result, vtable call
// TAIL_E:  1 arg (x22), result in x22
// TAIL_EN: 1 arg (x22), no result
// TAIL_G:  1 arg (x22), 2 results (x22, x23)
// TAIL_H:  2 args (x22, x23), no result
// TAIL_I:  2 args (x22, x23), result in x22
// TAIL_J:  3 args (x22, x23, x24), result in x22

// --- Dispatch shape A: far_jmp (vtable[0x20], 2 args, setup cache, -> exitljmp)
tail_far_jmp:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x20]
    add  x0, x18, #0x10
    blr  x29
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    mov  x22, x0
    mov  x23, x1
    mov  x24, x2
    mov  x25, x3
    mov  x26, x4
    mov  x28, x1
    b    runtime_exitljmp

// --- Dispatch shape B: far_ret (vtable[0x28], 5 args, setup cache, -> exit_br)
tail_far_ret:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    mov  x4, x25
    mov  x5, x26
    ldr  x29, [x18]
    ldr  x29, [x29, #0x28]
    add  x0, x18, #0x10
    blr  x29
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    mov  x22, x0
    mov  x23, x1
    mov  x28, x1
    b    runtime_exit_br

// --- far_call: same as far_jmp but -> exitcall
tail_far_call:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x20]
    add  x0, x18, #0x10
    blr  x29
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    mov  x22, x0
    mov  x23, x1
    mov  x24, x2
    mov  x25, x3
    mov  x26, x4
    mov  x28, x1
    b    runtime_exitcall

// --- far_ret_single_step: shape B variant -> exit_ret
tail_far_ret_single_step:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    mov  x4, x25
    mov  x5, x26
    ldr  x29, [x18]
    ldr  x29, [x29, #0x28]
    add  x0, x18, #0x10
    blr  x29
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    mov  x22, x1
    mov  x28, x1
    b    runtime_exit_ret

// --- mov_segment: vtable[0x160], 2 args, no result
tail_mov_segment:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x160]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

// --- mov_segment_and_reg: vtable[0x168], 4 args, no result
tail_mov_segment_and_reg:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    mov  x4, x25
    ldr  x29, [x18]
    ldr  x29, [x29, #0x168]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

// --- indirect_jmp resolve: vtable[0x18], -> exit_ret
tail_indirect_jmp:
    mov  x28, x22
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x18]
    mov  x0, x18
    blr  x29
    mov  x22, x0
    b    runtime_exit_ret

// --- indirect_call resolve: vtable[0x18], -> exitcall
tail_indirect_call:
    mov  x28, x22
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x18]
    mov  x0, x18
    blr  x29
    mov  x22, x0
    b    runtime_exitcall

// --- branch slot miss: vtable[0x30], -> exit_br
tail_branch_miss:
    mov  x28, x22
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x30]
    mov  x0, x18
    blr  x29
    mov  x22, x0
    b    runtime_exit_br

// --- return stack miss: vtable[0x18], -> exit_br
tail_return_miss:
    mov  x28, x22
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x18]
    mov  x0, x18
    blr  x29
    mov  x22, x0
    b    runtime_exit_br

tail_toggle_single_step:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x108]
    mov  x0, x18
    blr  x29
    b    runtime_exit_ret

tail_load_segment_limit:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x158]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    eor  x23, x1, #1
    b    runtime_exitinst

tail_rdrand:
    sub  sp, sp, #0x10
    mov  x0, sp
    mov  x1, #8
    mov  x16, #500
    svc  #0x80
    ldur x23, [sp]
    cset x22, cs
    csel x23, xzr, x23, cs
    add  sp, sp, #0x10
    b    runtime_exitinst

// --- xrstor/xsave tails: Shape H (2 args, X0=raw ThreadContext, not X87State)
tail_xrstor:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x3C8]
    mov  x0, x18
    blr  x29
    b    runtime_exitinst

tail_xsave:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x3D0]
    mov  x0, x18
    blr  x29
    b    runtime_exitinst

tail_pcmpestri:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    mov  x4, x25
    mov  x5, x26
    mov  x6, x27
    mov  x7, x28
    ldr  x29, [x18]
    ldr  x29, [x29, #0x170]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_pcmpestrm:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    mov  x4, x25
    mov  x5, x26
    mov  x6, x27
    mov  x7, x28
    ldr  x29, [x18]
    ldr  x29, [x29, #0x178]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_pcmpistri:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    mov  x4, x25
    mov  x5, x26
    ldr  x29, [x18]
    ldr  x29, [x29, #0x180]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_pcmpistrm:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    mov  x4, x25
    mov  x5, x26
    ldr  x29, [x18]
    ldr  x29, [x29, #0x188]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

// --- x87 operation tails: pattern F (no args, no result)

tail_f2xm1:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x190]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fabs:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x198]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fchs:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1C8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fcos:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x200]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fdecstp:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x208]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fincstp:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x270]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fpatan:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2F8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fprem:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x300]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fprem1:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x308]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fptan:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x310]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_frndint:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x318]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fscale:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x320]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fsin:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x328]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fsincos:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x330]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fsqrt:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x338]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fxam:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x3A0]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fxtract:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x3B0]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fyl2x:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x3B8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fyl2xp1:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x3C0]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

// --- fbstp: no args, 2 results (x22, x23)
tail_fbstp:
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1C0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

// --- x87 tails: pattern EN (1 arg, no result)

tail_ffree:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x240]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fild:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x260]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fld_STi:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2D8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fld_constant:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2B8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fld_fp32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2C0]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fld_fp64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2C8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fxch:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x3A8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

// --- x87 tails: pattern E (1 arg, result in x22)

tail_fadd_f32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1A0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fadd_f64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1A8]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fdiv_f32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x228]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fdiv_f64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x230]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fdivr_f32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x210]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fdivr_f64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x218]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fiadd:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x248]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fidiv:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x250]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fidivr:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x258]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fimul:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x268]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fisub:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2A8]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fisubr:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2B0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fmul_f32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2E0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fmul_f64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2E8]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fsub_f32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x378]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fsub_f64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x380]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fsubr_f32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x360]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fsubr_f64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x368]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

// --- x87 tails: pattern G (1 arg, 2 results)

tail_fist_i16:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x290]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fist_i32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x298]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fist_i64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2A0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fistt_i16:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x278]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fistt_i32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x280]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fistt_i64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x288]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fst_fp32:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x340]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fst_fp64:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x348]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

tail_fst_fp80:
    mov  x1, x22
    ldr  x29, [x18]
    ldr  x29, [x29, #0x350]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    mov  x23, x1
    b    runtime_exitinst

// --- x87 tails: pattern H (2 args, no result)

tail_fbld:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1B8]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fld_fp80:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2D0]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

// --- x87 tails: pattern I (2 args, result in x22)

tail_fcmov:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1D0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fcom_f32:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1D8]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fcom_f64:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1E0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fcom_ST:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1E8]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fcomi:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1F0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_ficom:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1F8]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fst_STi:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x358]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exitinst

tail_fucom:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x390]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fucomi:
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x398]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

// --- x87 tails: pattern J (3 args, result in x22)

tail_fadd_ST:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    ldr  x29, [x18]
    ldr  x29, [x29, #0x1B0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fdiv_ST:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    ldr  x29, [x18]
    ldr  x29, [x29, #0x238]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fdivr_ST:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    ldr  x29, [x18]
    ldr  x29, [x29, #0x220]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fmul_ST:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    ldr  x29, [x18]
    ldr  x29, [x29, #0x2F0]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fsub_ST:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    ldr  x29, [x18]
    ldr  x29, [x29, #0x388]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_fsubr_ST:
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    ldr  x29, [x18]
    ldr  x29, [x29, #0x370]
    add  x0, x18, #0x10
    blr  x29
    mov  x22, x0
    b    runtime_exitinst

tail_indirect_jmp_dyld_stub:
    mov  x28, x22
    mov  x1, x22
    mov  x2, x23
    ldr  x29, [x18]
    ldr  x29, [x29, #0x38]
    mov  x0, x18
    blr  x29
    mov  x22, x0
    b    runtime_exit_ret

// --- Syscall dispatch targets from jump tables

// sysent case 12: vtable[0x70]
sysent_case12:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x70]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys_nzcv

// sysent case 14: vtable[0x78] with extra arg from [x22+8]
sysent_case14:
    mov  x22, x4
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x7, [x22, #8]
    ldr  x29, [x18]
    ldr  x29, [x29, #0x78]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys_nzcv

// bsd/mach class 7 dispatch targets (jpt_22D38)

bsd7_case1:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    mov  x1, x30
    ldr  x29, [x18]
    ldr  x29, [x29, #0xD8]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case2:
    mov  x22, x4
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x7, [x22, #8]
    mov  x1, x30
    ldr  x29, [x18]
    ldr  x29, [x29, #0xE0]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case3:
    mov  x1, x6
    mov  x2, x2
    mov  x3, x10
    mov  x4, x8
    ldr  x29, [x18]
    ldr  x29, [x29, #0xE8]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case4:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    mov  x1, x30
    ldr  x29, [x18]
    ldr  x29, [x29, #0xF0]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case5:
    mov  x1, x6
    mov  x2, x2
    mov  x3, x10
    mov  x4, x8
    ldr  x29, [x18]
    ldr  x29, [x29, #0xF8]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case6:
    mov  x1, x6
    mov  x2, x2
    mov  x3, x10
    ldr  x29, [x18]
    ldr  x29, [x29, #0x128]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case7:
    mov  x1, x6
    mov  x2, x2
    mov  x3, x10
    mov  x4, x8
    ldr  x29, [x18]
    ldr  x29, [x29, #0x130]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case8:
    mov  x1, x6
    ldr  x29, [x18]
    ldr  x29, [x29, #0x138]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case9:
    mov  x1, x6
    mov  x2, x2
    ldr  x29, [x18]
    ldr  x29, [x29, #0x140]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

bsd7_case0:
    mov  x1, x6
    mov  x2, x2
    ldr  x29, [x18]
    ldr  x29, [x29, #0x100]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

// Mach trap dispatch targets (jpt_22CE0 non-default cases)

mach_case46:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0xA0]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case53:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0xA8]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case59:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    mov  w5, w16
    ldr  x29, [x18]
    ldr  x29, [x29, #0xB0]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case66:
    mov  w16, #2
mach_case2:
    mov  x23, x0
    ldr  x29, [x18]
    ldr  x29, [x29, #0x40]
    mov  x0, x18
    blr  x29
    lsr  x2, x0, #32
    mov  w0, w0
    b    runtime_exit_sys

mach_case73:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x68]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case74:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x60]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case75:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x48]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case197:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x50]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case244:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x58]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case294:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x110]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case360:
    mov  x22, x4
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x7, [x22, #8]
    ldr  x29, [x18]
    ldr  x29, [x29, #0x80]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case366:
    mov  x22, x4
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x7, [x22, #8]
    ldr  x29, [x18]
    ldr  x29, [x29, #0x88]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case438:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x118]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

mach_case536:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x120]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys

// mdep dispatch targets (jpt_22DF0 cases 5,6)
mdep_case5:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x148]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exit_sys

mdep_case6:
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x150]
    add  x0, x18, #0x10
    blr  x29
    b    runtime_exit_sys

// =============================================================================
// runtime_br_miss segment
// =============================================================================
.section runtime_br_miss,runtime_br_miss,regular,pure_instructions
.p2align 2

.globl _stub_branch_slot
_stub_branch_slot:
    STUB_PROLOGUE
    b    tail_branch_miss

.globl _stub_return_stack_miss
_stub_return_stack_miss:
    ldr  x21, [x18, #0x1A8]
    crc32cx w23, wzr, x22
    and  w23, w23, w20
Lreturn_miss_loop:
    add  x24, x19, x23, lsl #4
    ldp  x25, x26, [x24]
    sub  x27, x25, x22
    cbnz x27, Lreturn_miss_check
    br   x26
Lreturn_miss_check:
    cbz  x25, Lreturn_miss_slow
    add  w23, w23, #1
    and  w23, w23, w20
    b    Lreturn_miss_loop
Lreturn_miss_slow:
    STUB_PROLOGUE
    b    tail_return_miss

// =============================================================================
// runtime_exit_ret segment
// =============================================================================
.section runtime_exit_ret,runtime_exit_ret,regular,pure_instructions
.p2align 2

.globl _runtime_exit_ret
_runtime_exit_ret:
runtime_exit_ret:
    ldr  w27, [x18, #0x1C8]
.globl _exit_ret_debug_check
_exit_ret_debug_check:
Lexit_ret_check:
    cbz  w27, Lexit_ret_restore
    tbz  w27, #9, Lexit_ret_run
    ldr  x21, [x18, #0x1A8]
Lexit_ret_run:
    adr  x29, Lexit_ret_run
    str  x29, [x18, #0x1D0]
    mov  w29, #1
    strb w29, [x18, #0x208]
    mov  x1, x30
    mov  x2, x28
    ldr  x29, [x18]
    ldr  x29, [x29]
    mov  x0, x18
    blr  x29
.globl _exit_ret_post_callback
_exit_ret_post_callback:
Lexit_ret_post:
    strb wzr, [x18, #0x208]
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  w27, [x18, #0x1C8]
    orr  w27, w27, w1
    tbz  w27, #1, Lexit_ret_restore
    mov  x0, #3
    and  x1, x18, #0x7FFFFFFFFFFFFFFF
    add  x1, x1, #0x1CC
    mov  x2, xzr
    mov  x16, #0x149
    svc  #0x80
    b.cc Lexit_ret_restore
    brk  #6
.globl _exit_ret_gpr_restore
_exit_ret_gpr_restore:
Lexit_ret_restore:
    ldp  x29, x17, [x18, #0x90]
    msr  nzcv, x29
    ldp  x14, x15, [x18, #0x80]
    ldp  x12, x13, [x18, #0x70]
    ldp  x10, x11, [x18, #0x60]
    ldp  x8,  x9,  [x18, #0x50]
    ldp  x6,  x7,  [x18, #0x40]
    ldp  x4,  x5,  [x18, #0x30]
    ldp  x2,  x3,  [x18, #0x20]
    ldp  x0,  x1,  [x18, #0x10]
    ldr  x30, [x18, #0x8]
    and  x18, x18, #0x7FFFFFFFFFFFFFFF
    ret

// =============================================================================
// runtime_exitcall segment
// =============================================================================
.section runtime_exitcall,runtime_exitcall,regular,pure_instructions
.p2align 2

.globl _runtime_exitcall
_runtime_exitcall:
runtime_exitcall:
    ldr  w27, [x18, #0x1C8]
.globl _exitcall_debug_check
_exitcall_debug_check:
Lexitcall_check:
    cbz  w27, Lexitcall_restore
    tbz  w27, #9, Lexitcall_run
    ldr  x21, [x18, #0x1A8]
Lexitcall_run:
    adr  x29, Lexitcall_run
    str  x29, [x18, #0x1D0]
    mov  w29, #1
    strb w29, [x18, #0x208]
    mov  x1, x30
    mov  x2, x28
    ldr  x29, [x18]
    ldr  x29, [x29, #0x8]
    mov  x0, x18
    blr  x29
.globl _exitcall_post_callback
_exitcall_post_callback:
Lexitcall_post:
    strb wzr, [x18, #0x208]
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  w27, [x18, #0x1C8]
    orr  w27, w27, w1
    tbz  w27, #1, Lexitcall_restore
    mov  x0, #3
    and  x1, x18, #0x7FFFFFFFFFFFFFFF
    add  x1, x1, #0x1CC
    mov  x2, xzr
    mov  x16, #0x149
    svc  #0x80
    b.cc Lexitcall_restore
    brk  #6
.globl _exitcall_gpr_restore
_exitcall_gpr_restore:
Lexitcall_restore:
    ldp  x29, x17, [x18, #0x90]
    msr  nzcv, x29
    ldp  x14, x15, [x18, #0x80]
    ldp  x12, x13, [x18, #0x70]
    ldp  x10, x11, [x18, #0x60]
    ldp  x8,  x9,  [x18, #0x50]
    ldp  x6,  x7,  [x18, #0x40]
    ldp  x4,  x5,  [x18, #0x30]
    ldp  x2,  x3,  [x18, #0x20]
    ldp  x0,  x1,  [x18, #0x10]
    ldr  x30, [x18, #0x8]
    and  x18, x18, #0x7FFFFFFFFFFFFFFF
    ret

// =============================================================================
// runtime_exitljmp segment
// =============================================================================
.section runtime_exitljmp,runtime_exitljmp,regular,pure_instructions
.p2align 2

.globl _runtime_exitljmp
_runtime_exitljmp:
runtime_exitljmp:
    ldr  w27, [x18, #0x1C8]
.globl _exitljmp_debug_check
_exitljmp_debug_check:
Lexitljmp_check:
    cbz  w27, Lexitljmp_restore
    tbz  w27, #9, Lexitljmp_run
    ldr  x21, [x18, #0x1A8]
Lexitljmp_run:
    adr  x29, Lexitljmp_run
    str  x29, [x18, #0x1D0]
    mov  w29, #1
    strb w29, [x18, #0x208]
    mov  x1, x30
    mov  x2, x28
    ldr  x29, [x18]
    ldr  x29, [x29]
    mov  x0, x18
    blr  x29
.globl _exitljmp_post_callback
_exitljmp_post_callback:
Lexitljmp_post:
    strb wzr, [x18, #0x208]
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  w27, [x18, #0x1C8]
    orr  w27, w27, w1
    tbz  w27, #1, Lexitljmp_restore
    mov  x0, #3
    and  x1, x18, #0x7FFFFFFFFFFFFFFF
    add  x1, x1, #0x1CC
    mov  x2, xzr
    mov  x16, #0x149
    svc  #0x80
    b.cc Lexitljmp_restore
    brk  #6
.globl _exitljmp_gpr_restore
_exitljmp_gpr_restore:
Lexitljmp_restore:
    ldp  x29, x17, [x18, #0x90]
    msr  nzcv, x29
    ldp  x14, x15, [x18, #0x80]
    ldp  x12, x13, [x18, #0x70]
    ldp  x10, x11, [x18, #0x60]
    ldp  x8,  x9,  [x18, #0x50]
    ldp  x6,  x7,  [x18, #0x40]
    ldp  x4,  x5,  [x18, #0x30]
    ldp  x2,  x3,  [x18, #0x20]
    ldp  x0,  x1,  [x18, #0x10]
    ldr  x30, [x18, #0x8]
    and  x18, x18, #0x7FFFFFFFFFFFFFFF
    ret

// =============================================================================
// runtime_exit_br segment
// =============================================================================
.section runtime_exit_br,runtime_exit_br,regular,pure_instructions
.p2align 2

.globl _runtime_exit_br
_runtime_exit_br:
runtime_exit_br:
    ldr  w27, [x18, #0x1C8]
.globl _exit_br_debug_check
_exit_br_debug_check:
Lexit_br_check:
    cbz  w27, Lexit_br_restore
    tbz  w27, #9, Lexit_br_run
    ldr  x21, [x18, #0x1A8]
Lexit_br_run:
    adr  x29, Lexit_br_run
    str  x29, [x18, #0x1D0]
    mov  w29, #1
    strb w29, [x18, #0x208]
    mov  x1, x22
    mov  x2, x28
    ldr  x29, [x18]
    ldr  x29, [x29]
    mov  x0, x18
    blr  x29
.globl _exit_br_post_callback
_exit_br_post_callback:
Lexit_br_post:
    strb wzr, [x18, #0x208]
    mov  x22, x0
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  w27, [x18, #0x1C8]
    orr  w27, w27, w1
    tbz  w27, #1, Lexit_br_restore
    mov  x0, #3
    and  x1, x18, #0x7FFFFFFFFFFFFFFF
    add  x1, x1, #0x1CC
    mov  x2, xzr
    mov  x16, #0x149
    svc  #0x80
    b.cc Lexit_br_restore
    brk  #6
.globl _exit_br_gpr_restore
_exit_br_gpr_restore:
Lexit_br_restore:
    ldp  x29, x17, [x18, #0x90]
    msr  nzcv, x29
    ldp  x14, x15, [x18, #0x80]
    ldp  x12, x13, [x18, #0x70]
    ldp  x10, x11, [x18, #0x60]
    ldp  x8,  x9,  [x18, #0x50]
    ldp  x6,  x7,  [x18, #0x40]
    ldp  x4,  x5,  [x18, #0x30]
    ldp  x2,  x3,  [x18, #0x20]
    ldp  x0,  x1,  [x18, #0x10]
    ldr  x30, [x18, #0x8]
    and  x18, x18, #0x7FFFFFFFFFFFFFFF
    br   x22

// =============================================================================
// runtime_exit_sys segment
// =============================================================================
.section runtime_exit_sys,runtime_exit_sys,regular,pure_instructions
.p2align 2

.globl _runtime_exit_sys
_runtime_exit_sys:
runtime_exit_sys:
    ubfiz w22, w1, #29, #1
    msr  nzcv, x22
runtime_exit_sys_nzcv:
    ccmn wzr, #0, #2, cs
    ldr  x27, [x18, #0x1C0]
    ldr  x27, [x27]
    str  x27, [x18, #0x1B8]
    ldr  w27, [x18, #0x1C8]
.globl _exit_sys_debug_check
_exit_sys_debug_check:
Lexit_sys_check:
    cbz  w27, Lexit_sys_restore
    tbz  w27, #9, Lexit_sys_save
    ldr  x21, [x18, #0x1A8]
Lexit_sys_save:
    str  x0, [x18, #0x10]
    str  x2, [x18, #0x20]
    mrs  x29, nzcv
    str  x29, [x18, #0x90]
Lexit_sys_run:
    adr  x29, Lexit_sys_run
    str  x29, [x18, #0x1D0]
    mov  w29, #1
    strb w29, [x18, #0x208]
    mov  x1, x30
    mov  x2, x28
    ldr  x29, [x18]
    ldr  x29, [x29]
    mov  x0, x18
    blr  x29
.globl _exit_sys_post_callback
_exit_sys_post_callback:
Lexit_sys_post:
    strb wzr, [x18, #0x208]
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  w27, [x18, #0x1C8]
    orr  w27, w27, w1
    tbz  w27, #1, Lexit_sys_nzcv_restore
    mov  x0, #3
    and  x1, x18, #0x7FFFFFFFFFFFFFFF
    add  x1, x1, #0x1CC
    mov  x2, xzr
    mov  x16, #0x149
    svc  #0x80
    b.cc Lexit_sys_nzcv_restore
    brk  #6
Lexit_sys_nzcv_restore:
    ldr  x29, [x18, #0x90]
    msr  nzcv, x29
    ldr  x2, [x18, #0x20]
    ldr  x0, [x18, #0x10]
.globl _exit_sys_gpr_restore
_exit_sys_gpr_restore:
Lexit_sys_restore:
    ldp  xzr, x17, [x18, #0x90]
    ldp  x14, x15, [x18, #0x80]
    ldp  x12, x13, [x18, #0x70]
    ldp  x10, x11, [x18, #0x60]
    ldp  x8,  x9,  [x18, #0x50]
    ldp  x6,  x7,  [x18, #0x40]
    ldp  x4,  x5,  [x18, #0x30]
    ldr  x3, [x18, #0x28]
    ldr  x1, [x18, #0x18]
    ldr  x30, [x18, #0x8]
    and  x18, x18, #0x7FFFFFFFFFFFFFFF
    ret

// =============================================================================
// runtime_exitinst segment
// =============================================================================
.section runtime_exitinst,runtime_exitinst,regular,pure_instructions
.p2align 2

.globl _runtime_exitinst
_runtime_exitinst:
runtime_exitinst:
    ldrb w27, [x18, #0x1C8]
.globl _exitinst_debug_check
_exitinst_debug_check:
Lexitinst_check:
    cbz  w27, Lexitinst_restore
Lexitinst_run:
    adr  x29, Lexitinst_run
    str  x29, [x18, #0x1D0]
    mov  w29, #1
    strb w29, [x18, #0x208]
    ldr  x29, [x18]
    ldr  x29, [x29, #0x10]
    mov  x0, x18
    blr  x29
.globl _exitinst_post_callback
_exitinst_post_callback:
Lexitinst_post:
    strb wzr, [x18, #0x208]
    ldrb w27, [x18, #0x1C8]
    orr  w27, w27, w0
    tbz  w27, #1, Lexitinst_restore
    mov  x0, #3
    and  x1, x18, #0x7FFFFFFFFFFFFFFF
    add  x1, x1, #0x1CC
    mov  x2, xzr
    mov  x16, #0x149
    svc  #0x80
    b.cc Lexitinst_restore
    brk  #6
.globl _exitinst_gpr_restore
_exitinst_gpr_restore:
Lexitinst_restore:
    ldp  x29, x17, [x18, #0x90]
    msr  nzcv, x29
    ldp  x14, x15, [x18, #0x80]
    ldp  x12, x13, [x18, #0x70]
    ldp  x10, x11, [x18, #0x60]
    ldp  x8,  x9,  [x18, #0x50]
    ldp  x6,  x7,  [x18, #0x40]
    ldp  x4,  x5,  [x18, #0x30]
    ldp  x2,  x3,  [x18, #0x20]
    ldp  x0,  x1,  [x18, #0x10]
    ldr  x30, [x18, #0x8]
    and  x18, x18, #0x7FFFFFFFFFFFFFFF
    ret

// =============================================================================
// runtime_exitsigr segment
// =============================================================================
.section runtime_exitsigr,runtime_exitsigr,regular,pure_instructions
.p2align 2

.globl _runtime_exitsigr
_runtime_exitsigr:
runtime_exitsigr:
    ldrb w27, [x18, #0x1C8]
.globl _exitsigr_debug_check
_exitsigr_debug_check:
Lexitsigr_check:
    cbz  w27, Lexitsigr_do_sigreturn
Lexitsigr_run:
    adr  x29, Lexitsigr_run
    str  x29, [x18, #0x1D0]
    mov  w29, #1
    strb w29, [x18, #0x208]
    ldr  x29, [x18]
    ldr  x29, [x29, #0x10]
    mov  x0, x18
    blr  x29
.globl _exitsigr_post_callback
_exitsigr_post_callback:
Lexitsigr_post:
    strb wzr, [x18, #0x208]
.globl _exitsigr_sigreturn
_exitsigr_sigreturn:
Lexitsigr_do_sigreturn:
    mov  x0, x22
    mov  x1, x23
    mov  x2, x24
    mov  x16, #0xB8
    svc  #0x80
    brk  #6

// =============================================================================
// runtime_savdnzcv segment
// =============================================================================
.section runtime_savdnzcv,runtime_savdnzcv,regular,pure_instructions
.p2align 2

.globl _stub_wide_udiv_64
_stub_wide_udiv_64:
    ldr  x29, [x18, #0x160]
    br   x29

.globl _stub_wide_sdiv_64
_stub_wide_sdiv_64:
    ldr  x29, [x18, #0x168]
    br   x29

// =============================================================================
// runtime_sigtramp segment
// =============================================================================
.section runtime_sigtramp,runtime_sigtramp,regular,pure_instructions
.p2align 2

.globl _sa_tramp_handler
_sa_tramp_handler:
    sub  sp, sp, #0x10
    mov  x6, sp
    bl   _sa_tramp
// Everything from here on has returned from sa_tramp; TranslationCacheAbi uses
// this boundary for AbiKind_Sigtramp's subkind (reference: sigtramp_post_sa_tramp
// at 0x227F4).
.globl _sigtramp_post_sa_tramp
_sigtramp_post_sa_tramp:
    ldr  x21, [sp]
    mov  x22, x0
    mov  x28, x1
    and  sp, x18, #0x7FFFFFFFFFFFFFFF
    b    runtime_exit_br

// =============================================================================
// runtime_thread segment
// =============================================================================
.section runtime_thread,runtime_thread,regular,pure_instructions
.p2align 2

.globl _runtime_thread
_runtime_thread:
runtime_thread:
    mov  x22, x17
    sub  sp, sp, #0x80
    stp  x0,  x1,  [sp]
    stp  x2,  x3,  [sp, #0x10]
    stp  x4,  x5,  [sp, #0x20]
    stp  x6,  x7,  [sp, #0x30]
    stp  x8,  x9,  [sp, #0x40]
    stp  x10, x11, [sp, #0x50]
    stp  x12, x13, [sp, #0x60]
    stp  x14, x15, [sp, #0x70]
    mvn  x0, xzr
    str  x0, [sp, #-0x10]!
    mov  x0, #3
    mov  x1, sp
    mov  x2, sp
    mov  x16, #0x149
    svc  #0x80
    b.cc Lthread_ok
    brk  #6
Lthread_ok:
    mov  x18, #3
    mov  x0, x22
    ldr  x1, [sp]
    bl   _runtime_thread_init
    add  x30, x0, #4
    add  sp, sp, #0x10
    ldp  x14, x15, [sp, #0x70]
    ldp  x12, x13, [sp, #0x60]
    ldp  x10, x11, [sp, #0x50]
    ldp  x8,  x9,  [sp, #0x40]
    ldp  x6,  x7,  [sp, #0x30]
    ldp  x4,  x5,  [sp, #0x20]
    ldp  x2,  x3,  [sp, #0x10]
    ldp  x0,  x1,  [sp]
    mov  sp, x18
    msr  fpcr, xzr
    ldrb w17, [x18, #0x170]
    tbz  w17, #1, Lthread_fpcr_done
    mov  w17, #6
    msr  fpcr, x17
Lthread_fpcr_done:
    mov  x17, #0
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  x21, [x18, #0x1A8]
    stp  x0,  x1,  [x18, #0x10]
    stp  x2,  x3,  [x18, #0x20]
    stp  x4,  x5,  [x18, #0x30]
    stp  x6,  x7,  [x18, #0x40]
    stp  x8,  x9,  [x18, #0x50]
    stp  x10, x11, [x18, #0x60]
    stp  x12, x13, [x18, #0x70]
    stp  x14, x15, [x18, #0x80]
    str  x30, [x18, #0x8]
    orr  x18, x18, #0x8000000000000000
    sub  x22, x30, #4
    b    runtime_exit_br

// =============================================================================
// runtime_pthread segment
// =============================================================================
.section runtime_pthread,runtime_pthread,regular,pure_instructions
.p2align 2

.globl _runtime_pthread
_runtime_pthread:
runtime_pthread:
    mov  x22, x0
    mov  x23, x1
    mov  x24, x2
    mov  x25, x3
    mov  x26, x4
    mov  x27, x5
    mvn  x0, xzr
    str  x0, [sp, #-0x10]!
    mov  x0, #3
    mov  x1, sp
    mov  x2, sp
    mov  x16, #0x149
    svc  #0x80
    b.cc Lpthread_ok
    brk  #6
Lpthread_ok:
    adrp x28, _pthread_entry_fptr@PAGE
    ldr  x28, [x28, _pthread_entry_fptr@PAGEOFF]
    mov  x18, #3
    mov  x0, x23
    mov  x1, x28
    ldr  x2, [sp]
    mov  x3, #1
    bl   _runtime_pthread_init
    add  x30, x0, #4
    add  sp, sp, #0x10
    mov  x4, sp
    mov  sp, x18
    msr  fpcr, xzr
    ldrb w17, [x18, #0x170]
    tbz  w17, #1, Lpthread_fpcr_done
    mov  w17, #6
    msr  fpcr, x17
Lpthread_fpcr_done:
    mov  x17, #0
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  x21, [x18, #0x1A8]
    stp  x23, x22, [x18, #0x40]
    str  x24, [x18, #0x20]
    str  x25, [x18, #0x18]
    stp  x26, x27, [x18, #0x50]
    str  x4, [x18, #0x30]
    str  x30, [x18, #0x8]
    orr  x18, x18, #0x8000000000000000
    sub  x22, x30, #4
    b    runtime_exit_br

// =============================================================================
// runtime_wqthread segment
// =============================================================================
.section runtime_wqthread,runtime_wqthread,regular,pure_instructions
.p2align 2

.globl _runtime_wqthread
_runtime_wqthread:
runtime_wqthread:
    mov  x22, x0
    mov  x23, x1
    mov  x24, x2
    mov  x25, x3
    mov  x26, x4
    mov  x27, x5
    mvn  x0, xzr
    str  x0, [sp, #-0x10]!
    mov  x0, #3
    mov  x1, sp
    mov  x2, sp
    mov  x16, #0x149
    svc  #0x80
    b.cc Lwqthread_ok
    brk  #6
Lwqthread_ok:
    adrp x28, _wqthread_entry_fptr@PAGE
    ldr  x28, [x28, _wqthread_entry_fptr@PAGEOFF]
    mov  x18, #3
    mov  x0, x23
    mov  x1, x28
    ldr  x2, [sp]
    mov  x3, #2
    bl   _runtime_pthread_init
    add  x30, x0, #4
    add  sp, sp, #0x10
    mov  x4, sp
    mov  sp, x18
    msr  fpcr, xzr
    ldrb w17, [x18, #0x170]
    tbz  w17, #1, Lwqthread_fpcr_done
    mov  w17, #6
    msr  fpcr, x17
Lwqthread_fpcr_done:
    mov  x17, #0
    ldr  x29, [x18, #0x198]
    ldp  x19, x29, [x29]
    mov  w20, #1
    lsl  w20, w20, w29
    sub  w20, w20, #1
    ldr  x21, [x18, #0x1A8]
    stp  x23, x22, [x18, #0x40]
    str  x24, [x18, #0x20]
    str  x25, [x18, #0x18]
    stp  x26, x27, [x18, #0x50]
    str  x4, [x18, #0x30]
    str  x30, [x18, #0x8]
    orr  x18, x18, #0x8000000000000000
    sub  x22, x30, #4
    b    runtime_exit_br

// =============================================================================
// runtime_syscall segment
// =============================================================================
.section runtime_syscall,runtime_syscall,regular,pure_instructions
.p2align 2

.globl _runtime_syscall
_runtime_syscall:
runtime_syscall:
tail_syscall_handler:
    and  w23, w0, #0x7000000
    lsr  w23, w23, #24
    cmp  w23, #1
    b.eq Lsyscall_class1
    cmp  w23, #2
    b.eq Lsyscall_class2
    cmp  w23, #3
    b.eq Lsyscall_class3
    b    syscall_trap

// BSD syscall class 1 (128-entry jump table)
Lsyscall_class1:
    and  w16, w0, #0xFFFF
    cmp  w16, #0x7F
    b.hi syscall_trap
    adr  x22, jpt_sysent
    ldrsw x23, [x22, x16, lsl #2]
    add  x23, x23, x22
    br   x23

// Default BSD syscall: negate syscall number, pass args, SVC
syscall_default:
    neg  x16, x16
mach_default:
    mov  x22, x4
    mov  x0, x7
    mov  x1, x6
    mov  x3, x10
    mov  x4, x8
    mov  x5, x9
    ldr  x6, [x22, #8]
    ldp  x7, x8, [x22, #0x10]
    mov  x22, #-1
    str  x22, [x18, #0x1B8]
Lsyscall_svc:
    svc  #0x80
// Post-SVC: the syscall has been issued and cannot be restarted.  sa_tramp reads
// AbiKind_Syscall's subkind across this boundary (reference: syscall_post_svc at
// 0x22AE0, bounded above by syscall_sigreturn_case = our sysent_case31).
.globl _syscall_post_svc
_syscall_post_svc:
Lsyscall_svc_ret:
    mov  x2, x1
    b    runtime_exit_sys_nzcv

.globl _syscall_sigreturn_case
_syscall_sigreturn_case:
sysent_case31:
    and  w22, w6, #3
    cmp  w22, #3
    b.ne syscall_default
    ldr  w22, [x7, #0x14]
    sub  x23, x22, #0xD48
    cmp  x23, #0x32
    b.ls Lsysent31_ioctl_check
    sub  x23, x22, #0xE10
    cmp  x23, #0x1B
    b.ls Lsysent31_kext_path
    mov  x23, #0x12C0
    sub  x23, x22, x23
    cmp  x23, #0x14
    b.ls Lsysent31_ioctl_check
    mov  x23, #0x1F40
    cmp  x22, x23
    b.eq Lsysent31_ioctl_check
    b    syscall_default

Lsysent31_ioctl_check:
    ldr  w24, [x7, #8]
    ldr  w25, [x18, #0x190]
    cmp  x24, x25
    b.ne syscall_default
    mov  x22, x4
    mov  x0, x7
    mov  x1, x6
    mov  x3, x10
    mov  x4, x8
    mov  x5, x9
    ldr  x6, [x22, #8]
    ldp  x7, x8, [x22, #0x10]
    ldr  x29, [x18]
    ldr  x29, [x29, #0xB8]
    blr  x29
    cbz  x1, Lsysent31_fallback
    b    runtime_exit_sys_nzcv

Lsysent31_kext_path:
    mov  x22, x4
    mov  x0, x7
    mov  x1, x6
    mov  x3, x10
    mov  x4, x8
    mov  x5, x9
    ldr  x6, [x22, #8]
    ldp  x7, x8, [x22, #0x10]
    ldr  x29, [x18]
    ldr  x29, [x29, #0xC0]
    blr  x29
    cbz  x1, Lsysent31_fallback
    b    runtime_exit_sys_nzcv

Lsysent31_fallback:
    ldp  x1, x0, [x18, #0x40]
    ldr  x2, [x18, #0x20]
    ldr  x3, [x18, #0x60]
    ldp  x4, x5, [x18, #0x50]
    ldr  x22, [x18, #0x30]
    ldr  x6, [x22, #8]
    mov  x22, #-1
    str  x22, [x18, #0x1B8]
    mov  x16, #-31
    b    Lsyscall_svc

sysent_case47:
    tbz  x6, #33, syscall_default
    and  x22, x6, #3
    cmp  x22, #3
    b.ne syscall_default
    lsr  x22, x8, #32
    sub  x23, x22, #0xD48
    cmp  x23, #0x32
    b.ls Lsysent47_ioctl_check
    sub  x23, x22, #0xE10
    cmp  x23, #0x1B
    b.ls Lsysent47_kext_path
    mov  x23, #0x12C0
    sub  x23, x22, x23
    cmp  x23, #0x14
    b.ls Lsysent47_ioctl_check
    mov  x23, #0x1F40
    cmp  x22, x23
    b.eq Lsysent47_ioctl_check
    b    syscall_default

Lsysent47_ioctl_check:
    ldr  w25, [x18, #0x190]
    cmp  w10, w25
    b.ne syscall_default
    mov  x22, x4
    mov  x0, x7
    mov  x1, x6
    mov  x3, x10
    mov  x4, x8
    mov  x5, x9
    ldr  x6, [x22, #8]
    ldp  x7, x8, [x22, #0x10]
    ldr  x29, [x18]
    ldr  x29, [x29, #0xC8]
    blr  x29
    cbz  x1, Lsysent47_fallback
    b    runtime_exit_sys_nzcv

Lsysent47_kext_path:
    mov  x22, x4
    mov  x0, x7
    mov  x1, x6
    mov  x3, x10
    mov  x4, x8
    mov  x5, x9
    ldr  x6, [x22, #8]
    ldp  x7, x8, [x22, #0x10]
    ldr  x29, [x18]
    ldr  x29, [x29, #0xD0]
    blr  x29
    cbz  x1, Lsysent47_fallback
    b    runtime_exit_sys_nzcv

Lsysent47_fallback:
    ldp  x1, x0, [x18, #0x40]
    ldr  x2, [x18, #0x20]
    ldr  x3, [x18, #0x60]
    ldp  x4, x5, [x18, #0x50]
    ldr  x22, [x18, #0x30]
    ldp  x6, x7, [x22, #8]
    mov  x22, #-1
    str  x22, [x18, #0x1B8]
    mov  x16, #-47
    b    Lsyscall_svc

sysent_case89:
    mov  w22, #1
    stp  w22, w22, [x7]
    mov  w0, #0
    b    runtime_exit_sys_nzcv

// Mach trap class 2 (537-entry jump table)
Lsyscall_class2:
    and  w16, w0, #0xFFFF
    cmp  w16, #0x218
    b.hi mach_default
    adr  x22, jpt_mach
    ldrsw x23, [x22, x16, lsl #2]
    add  x23, x23, x22
    br   x23

mach_case0:
    and  w22, w7, #0x7000000
    lsr  w22, w22, #24
    cmp  w22, #7
    b.eq Lmach_case0_class7
    mov  w0, w7
    mov  x7, x6
    mov  x6, x2
    mov  x2, x10
    mov  x10, x8
    mov  x8, x9
    ldr  x9, [x4, #8]
    ldp  x23, x24, [x4, #0x10]
    stp  x23, x24, [x18, #-0x10]
    sub  x4, x18, #0x18
    b    Lsyscall_class2

Lmach_case0_class7:
    and  w0, w7, #0xFFFF
    cmp  w0, #9
    b.hi syscall_trap
    adr  x22, jpt_bsd7
    ldrsw x23, [x22, x0, lsl #2]
    add  x23, x23, x22
    br   x23

mach_case361:
    mov  x22, #1
    strb w22, [x18, #0x221]
    b    mach_default

mach_case184:
    cmp  x6, #0x1E
    b.eq Lmach_case184_sigreturn
    mov  x1, x7
    mov  x3, x2
    mov  x2, x6
    mov  x4, x10
    mov  x5, x8
    mov  x6, x9
    ldr  x29, [x18]
    ldr  x29, [x29, #0x98]
    mov  x0, x18
    blr  x29
    b    runtime_exit_sys_nzcv

Lmach_case184_sigreturn:
    mov  x22, x7
    mov  x23, x6
    mov  x24, x2
    mov  x0, #3
    adr  x1, Lsyscall_sentinel
    mov  x2, xzr
    mov  x16, #0x149
    svc  #0x80
    b.cc Lmach_case184_ok
    brk  #6
Lmach_case184_ok:
    sub  sp, sp, #0x450
    mov  x1, x22
    mov  x2, x23
    mov  x3, x24
    add  x4, sp, #0x68
    add  x5, sp, #0xA0
    mov  x6, x21
    ldr  x29, [x18]
    ldr  x29, [x29, #0x90]
    mov  x0, x18
    blr  x29
    add  x22, sp, #0x68
    b    runtime_exitsigr

// Machine-dependent class 3 (7-entry jump table)
Lsyscall_class3:
    and  w23, w0, #0xFFFF
    cmp  w23, #6
    b.hi syscall_trap
    adr  x22, jpt_mdep
    ldrsw x23, [x22, x23, lsl #2]
    add  x23, x23, x22
    br   x23

mdep_default:
    mov  x0, #4
    mov  x22, #0x20000000
    msr  nzcv, x22
    b    runtime_exit_sys_nzcv

mdep_case3:
    mov  x0, x7
    mov  x3, #2
    mov  x16, #0x80000000
    svc  #0x80
    b    runtime_exit_sys_nzcv

syscall_trap:
    brk  #5

j_runtime_exit_ret:
    b    runtime_exit_ret

// =============================================================================
// Jump tables (32-bit PC-relative offsets)
// =============================================================================

jpt_sysent:
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long sysent_case12 - jpt_sysent
    .long syscall_default - jpt_sysent
    .long sysent_case14 - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long sysent_case31 - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long sysent_case47 - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long sysent_case89 - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent
    .long syscall_default - jpt_sysent

jpt_mdep:
    .long mdep_default - jpt_mdep
    .long mdep_default - jpt_mdep
    .long mdep_default - jpt_mdep
    .long mdep_case3 - jpt_mdep
    .long mdep_default - jpt_mdep
    .long mdep_case5 - jpt_mdep
    .long mdep_case6 - jpt_mdep

jpt_mach:
    .long mach_case0 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case2 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case46 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case53 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case59 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case66 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case73 - jpt_mach
    .long mach_case74 - jpt_mach
    .long mach_case75 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case184 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case197 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case244 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case294 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case360 - jpt_mach
    .long mach_case361 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case366 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case361 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case59 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case438 - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_default - jpt_mach
    .long mach_case536 - jpt_mach

jpt_bsd7:
    .long bsd7_case0 - jpt_bsd7
    .long bsd7_case1 - jpt_bsd7
    .long bsd7_case2 - jpt_bsd7
    .long bsd7_case3 - jpt_bsd7
    .long bsd7_case4 - jpt_bsd7
    .long bsd7_case5 - jpt_bsd7
    .long bsd7_case6 - jpt_bsd7
    .long bsd7_case7 - jpt_bsd7
    .long bsd7_case8 - jpt_bsd7
    .long bsd7_case9 - jpt_bsd7

Lsyscall_sentinel:
    .long 0xFFFFFFFF

// =============================================================================
// End of the mapped blob.
//
// Paired with _runtime_blob_start (at _stub_far_jmp).  ExecutableHeap.cpp sizes
// the runtime-routines region as round_up(_runtime_blob_end - _runtime_blob_start,
// 16 KB), so adding stubs grows the mapped page automatically instead of
// silently overflowing a hand-maintained constant.
//
// This label must remain in the LAST section of this file and be the last thing
// emitted: the size is an end-minus-start span, so anything placed after it is
// outside the region that gets copied to the heap.
//
// Note the span is only meaningful because the linker lays these sections out
// contiguously and in order; ExecutableHeap.cpp range-checks the computed size
// rather than trusting it blindly.
.globl _runtime_blob_end
_runtime_blob_end:

