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

// FCOS is dispatched through an in-blob fast path (see _stub_fcos_fast at the
// end of this section) instead of the prologue/vtable/C++ route.  The slot
// keeps its historical 0x34-byte footprint so every following stub stays at
// its reference offset; the nops are dead padding, never executed.
// ExecutableHeap.cpp patches the first word to `b _stub_fcos_slow` when
// ROSETTA_X87_DISABLE_FCOS_FAST=1.
.globl _stub_fcos
_stub_fcos:
    b    _stub_fcos_fast
    .rept 12
    nop
    .endr

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
// FCOS fast path
//
// Computes ST(0) = cos(ST(0)) entirely in the blob for |x| < 2^20*(pi/2),
// skipping STUB_PROLOGUE, the vtable dispatch, x87_fcos (C++ +
// SIMDGuardFullAndX0X7 + openlibm) and runtime_exitinst.  Ported from the
// openlibm sources this runtime already ships (s_cos.h, k_cos.h, k_sin.h and
// the medium branch of e_rem_pio2.h) — same constants, same operation order
// for the exactness-critical cancellation steps.
//
// Fallback (_stub_fcos_slow = the historical stub body) handles:
//   - |x| >= 2^20*(pi/2), Inf, NaN  (Payne-Hanek reduction stays in C++)
//   - debug/single-step sessions    (flag byte at [x18, #0x1C8])
// so behaviour there is bit-identical to before.
//
// Register contract (must match what translated code can rely on across a
// kRuntimeRoutine BL — see OPT-KA / test_keepalive):
//   clobbered:  x27, x29            (already clobbered by the classic path)
//   preserved:  x0-x15, x17, x19-x26, x28, x30, sp, NZCV, FPCR, v0-v15
//   q16-q23 are used as scratch but saved/restored on the native stack —
//   stricter than the classic path, which clobbers v16-v31 outright.
// NZCV is never written: all control flow is cbz/tbz/tbnz on integer values.
//
// X87State layout at x18+0xA0 (x87_state_offset, verified against the JIT's
// own inline lowering: `add x22, x18, #0xa0` / `ldrh w23, [x18, #0xA2]`, and
// guarded at init_library — see RuntimeLibrary.cpp):
//   +0xA0 controlWord  +0xA2 statusWord  +0xA4 tagWord  +0xA8 st[8]
//
// Semantics reproduced = current x87_fcos (X87.cpp), NOT the Intel C2 rule:
//   statusWord &= ~(C1|C2); ST(0) = cos(ST(0)) for all inputs; tag of the
//   physical ST(0) slot -> kValid (00); TOP unchanged.
// =============================================================================

.globl _stub_fcos_fast
_stub_fcos_fast:
    // Debug/single-step: take the classic path so exitinst's callback runs.
    ldrb w29, [x18, #0x1C8]
    cbnz w29, _stub_fcos_slow
    sub  sp, sp, #0x90
    stp  x25, x26, [sp, #0x80]
    ldrh w29, [x18, #0xA2]           // statusWord
    ubfx w26, w29, #11, #3           // x26 = TOP
    add  x25, x18, #0xA0             // X87State base
    add  x25, x25, x26, lsl #3       // x25 = base + TOP*8 (ST(0) at [x25, #8])
    ldr  x29, [x25, #8]              // ST(0) bits (integer side; no FP touched yet)
    ubfx x27, x29, #32, #31          // x27 = high word & 0x7fffffff
    // Eligible iff |x| < 2^20*(pi/2)  <=>  hi31 < 0x413921fb  (also excludes
    // Inf/NaN).  Classify before any FP register is dirtied so the bail path
    // enters the classic stub with pristine state.
    mov  w29, #0x21fb
    movk w29, #0x4139, lsl #16
    sub  w29, w27, w29
    tbz  w29, #31, Lfcos_bail
    stp  q16, q17, [sp]
    stp  q18, q19, [sp, #0x20]
    stp  q20, q21, [sp, #0x40]
    stp  q22, q23, [sp, #0x60]
    ldr  d16, [x25, #8]              // x = ST(0)
    // |x| ~< pi/4  <=>  hi31 <= 0x3fe921fb
    mov  w29, #0x21fc
    movk w29, #0x3fe9, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfcos_small

    // -------------------------------------------------------------------------
    // Medium argument reduction (e_rem_pio2 medium branch, 33-bit pi chunks):
    //   fn = rnint(x * 2/pi);  r = x - fn*pio2_1;  w = fn*pio2_1t
    // with up to two more Cody-Waite iterations when leading bits cancel.
    // fn*pio2_1 is exact (|fn| <= 2^20, pio2_1 has 33 mantissa bits), so the
    // FMSUB matches the C code bit for bit.
    // -------------------------------------------------------------------------
Lfcos_medium:
    lsr  w27, w27, #20               // j = biased exponent of x
    ldr  d17, Lfcos_invpio2
    fmul d17, d16, d17
    frintn d17, d17                  // fn (round-to-nearest-even, FPCR-independent)
    ldr  d20, Lfcos_pio2_1
    fmsub d18, d17, d20, d16         // r = x - fn*pio2_1
    ldr  d20, Lfcos_pio2_1t
    fmul d19, d17, d20               // w = fn*pio2_1t
    fsub d22, d18, d19               // y0 = r - w
    fmov x29, d22
    ubfx x29, x29, #52, #11          // biased exponent of y0
    sub  w29, w27, w29               // i = j - exp(y0)
    sub  w29, w29, #17
    tbnz w29, #31, Lfcos_red_done    // i <= 16: 1st round good to 85 bits
    // 2nd iteration (good to 118 bits)
    fmov d20, d18                    // t = r
    ldr  d21, Lfcos_pio2_2
    fmul d19, d17, d21               // w = fn*pio2_2
    fsub d18, d20, d19               // r = t - w
    fsub d20, d20, d18               // t - r
    fsub d20, d20, d19               // (t - r) - w
    ldr  d21, Lfcos_pio2_2t
    fmul d21, d17, d21
    fsub d19, d21, d20               // w = fn*pio2_2t - ((t-r)-w)
    fsub d22, d18, d19               // y0 = r - w
    fmov x29, d22
    ubfx x29, x29, #52, #11
    sub  w29, w27, w29
    sub  w29, w29, #50
    tbnz w29, #31, Lfcos_red_done    // i <= 49
    // 3rd iteration (151 bits, covers all medium cases)
    fmov d20, d18
    ldr  d21, Lfcos_pio2_3
    fmul d19, d17, d21
    fsub d18, d20, d19
    fsub d20, d20, d18
    fsub d20, d20, d19
    ldr  d21, Lfcos_pio2_3t
    fmul d21, d17, d21
    fsub d19, d21, d20
    fsub d22, d18, d19
Lfcos_red_done:
    fsub d23, d18, d22
    fsub d23, d23, d19               // y1 = (r - y0) - w
    fcvtzs w27, d17                  // n (fn is integral -> exact)
    // n & 3 selects: 0 +cos, 1 -sin, 2 -cos, 3 +sin
    tbz  w27, #0, Lfcos_kcos

    // -------------------------------------------------------------------------
    // __kernel_sin(y0, y1, 1):
    //   z = x*x; w = z*z; r = S2+z*(S3+z*S4) + z*w*(S5+z*S6); v = z*x
    //   sin = x - ((z*(half*y - v*r) - y) - v*S1)
    // -------------------------------------------------------------------------
Lfcos_ksin:
    fmul d17, d22, d22               // z
    fmul d18, d17, d17               // w = z*z
    ldr  d20, Lfcos_S4
    ldr  d21, Lfcos_S3
    fmadd d20, d17, d20, d21         // S3 + z*S4
    ldr  d21, Lfcos_S2
    fmadd d20, d17, d20, d21         // S2 + z*(S3+z*S4)
    ldr  d19, Lfcos_S6
    ldr  d21, Lfcos_S5
    fmadd d19, d17, d19, d21         // S5 + z*S6
    fmul d21, d17, d18               // z*w
    fmadd d20, d21, d19, d20         // r
    fmul d19, d17, d22               // v = z*x
    fmov d21, #0.5
    fmul d21, d21, d23               // half*y
    fmsub d21, d19, d20, d21         // half*y - v*r
    fnmsub d21, d17, d21, d23        // z*(half*y - v*r) - y
    ldr  d18, Lfcos_S1
    fmsub d21, d19, d18, d21         // ... - v*S1
    fsub d16, d22, d21               // x - (...)
    b    Lfcos_negmaybe

    // -------------------------------------------------------------------------
    // __kernel_cos(y0, y1):
    //   z = x*x; w = z*z; r = z*(C1+z*(C2+z*C3)) + w*w*(C4+z*(C5+z*C6))
    //   hz = 0.5*z; w' = 1-hz
    //   cos = w' + (((1-w') - hz) + (z*r - x*y))
    // The 1-hz / (1-w')-hz cancellation steps stay unfused to match the C.
    // -------------------------------------------------------------------------
Lfcos_kcos:
    fmul d17, d22, d22               // z
    fmul d18, d17, d17               // w = z*z
    ldr  d20, Lfcos_C3
    ldr  d21, Lfcos_C2
    fmadd d20, d17, d20, d21         // C2 + z*C3
    ldr  d21, Lfcos_C1
    fmadd d20, d17, d20, d21         // C1 + z*(...)
    fmul d19, d17, d20               // z*(C1+...)
    ldr  d20, Lfcos_C6
    ldr  d21, Lfcos_C5
    fmadd d20, d17, d20, d21         // C5 + z*C6
    ldr  d21, Lfcos_C4
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
    fmul d17, d22, d23               // x*y
    fsub d19, d19, d17               // z*r - x*y
    fadd d21, d21, d19
    fadd d16, d18, d21               // result

Lfcos_negmaybe:
    // negate iff (n&1) != ((n>>1)&1), i.e. quadrants 1 and 2
    eor  w29, w27, w27, lsr #1
    tbz  w29, #0, Lfcos_store
    fneg d16, d16

Lfcos_store:
    str  d16, [x25, #8]              // ST(0) = result
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
    ldp  q16, q17, [sp]
    ldp  q18, q19, [sp, #0x20]
    ldp  q20, q21, [sp, #0x40]
    ldp  q22, q23, [sp, #0x60]
    ldp  x25, x26, [sp, #0x80]
    add  sp, sp, #0x90
    ret

Lfcos_small:
    // |x| < 2^-27 * sqrt(2): cos(x) = 1.0 exactly (openlibm short-circuit)
    mov  w29, #0xa09e
    movk w29, #0x3e46, lsl #16
    sub  w29, w27, w29
    tbnz w29, #31, Lfcos_one
    fmov d22, d16                    // y0 = x
    fmov d23, xzr                    // y1 = 0
    mov  w27, wzr                    // n = 0: +cos, no negate
    b    Lfcos_kcos
Lfcos_one:
    fmov d16, #1.0
    b    Lfcos_store

Lfcos_bail:
    // Classification bailed before any FP/flag state was touched; undo the
    // GPR spill and enter the classic stub exactly as translated code would.
    ldp  x25, x26, [sp, #0x80]
    add  sp, sp, #0x90
.globl _stub_fcos_slow
_stub_fcos_slow:
    STUB_PROLOGUE
    b    tail_fcos

// Literal pool — IEEE-754 doubles from openlibm e_rem_pio2.h / k_cos.h /
// k_sin.h.  PC-relative LDR (literal), so per-chunk blob copies need no
// relocation.
.p2align 3
Lfcos_invpio2:  .quad 0x3FE45F306DC9C883   // 2/pi, 53 bits
Lfcos_pio2_1:   .quad 0x3FF921FB54400000   // first 33 bits of pi/2
Lfcos_pio2_1t:  .quad 0x3DD0B4611A626331   // pi/2 - pio2_1
Lfcos_pio2_2:   .quad 0x3DD0B4611A600000   // second 33 bits of pi/2
Lfcos_pio2_2t:  .quad 0x3BA3198A2E037073   // pi/2 - (pio2_1+pio2_2)
Lfcos_pio2_3:   .quad 0x3BA3198A2E000000   // third 33 bits of pi/2
Lfcos_pio2_3t:  .quad 0x397B839A252049C1   // pi/2 - (pio2_1+pio2_2+pio2_3)
Lfcos_C1:       .quad 0x3FA555555555554C
Lfcos_C2:       .quad 0xBF56C16C16C15177
Lfcos_C3:       .quad 0x3EFA01A019CB1590
Lfcos_C4:       .quad 0xBE927E4F809C52AD
Lfcos_C5:       .quad 0x3E21EE9EBDB4B1C4
Lfcos_C6:       .quad 0xBDA8FAE9BE8838D4
Lfcos_S1:       .quad 0xBFC5555555555549
Lfcos_S2:       .quad 0x3F8111111110F8A6
Lfcos_S3:       .quad 0xBF2A01A019C161D5
Lfcos_S4:       .quad 0x3EC71DE357B1FE7D
Lfcos_S5:       .quad 0xBE5AE5E68A2B9CEB
Lfcos_S6:       .quad 0x3DE5D93A5ACFD57C


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

