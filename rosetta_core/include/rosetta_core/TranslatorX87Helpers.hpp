#pragma once

#include <cstdint>

#include "rosetta_core/AssemblerHelpers.hpp"
#include "rosetta_core/Register.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorHelpers.hpp"
#include "rosetta_core/X87State.h"

// =============================================================================
// X87State layout constants  (all offsets within X87State, relative to Xbase)
//
//   X87State (packed, 0x56 bytes)
//   +0x00  uint16_t  control_word
//   +0x02  uint16_t  status_word    ← TOP in bits [13:11]
//   +0x04  int16_t   tag_word
//   +0x06  X87Float80 st[8]         ← stride 0x0A bytes each
//
//   st[i] mantissa offset = 0x06 + i * 0x0A
//   Stride is 10 — no clean power-of-two shift, use LSL#3 + LSL#1 + 6
//
//   X18 = thread context pointer (Apple AArch64 ABI, always valid, never clobber)
//   Xbase = X18 + result.thread_context_offsets->x87_state_offset
// =============================================================================

static constexpr int kX87ThreadReg = GPR::X18;                                   // X18
static constexpr int16_t kX87StatusWordOff = offsetof(X87State, status_word);    // 0x02;
static constexpr int16_t kX87ControlWordOff = offsetof(X87State, control_word);  // 0x00;
static constexpr int16_t kX87TagWordOff = offsetof(X87State, tag_word);          // 0x04;
static constexpr int16_t kX87RegFileOff = offsetof(X87State, st);                // 0x08
static constexpr int kX87RegStride = sizeof(double);                             // 0x08

static_assert(kX87ThreadReg == GPR::X18, "kX87ThreadReg must be X18");
static_assert(kX87StatusWordOff == 0x02, "Invalid offset for status_word");
static_assert(kX87ControlWordOff == 0x00, "Invalid offset for control_word");
static_assert(kX87TagWordOff == 0x04, "Invalid offset for tag_word");
static_assert(kX87RegFileOff == 0x08, "Invalid offset for st[] base");
static_assert(kX87RegStride == 0x08, "Invalid stride for st[] registers");

static constexpr int kX87TopShift = 11;  // TOP LSB position in status_word
static constexpr int kX87TopMask = 0x7;
// x87 condition code bit positions in status_word
static constexpr int kX87C0Bit = 8;
static constexpr int kX87C2Bit = 10;
static constexpr int kX87C3Bit = 14;

// =============================================================================
// 2a — X87State base address
//
// Emits:  ADD Xd, X18, #x87_state_offset
//
// x87_state_offset is read from result at translation time — constant for the
// emitted code. Must be called at the top of every translate_f*() function.
// =============================================================================

auto emit_x87_base(AssemblerBuffer& buf, const TranslationResult& translation, int Xd) -> void;

void emit_x87_base_and_top(AssemblerBuffer& buf, const TranslationResult& translation, int Xbase,
                           int Wd_top);

// =============================================================================
// 2b — TOP load
//
// Emits:
//   LDRH  Wd, [Xbase, #0x02]   ; load status_word
//   LSR   Wd, Wd, #11          ; shift TOP field down to bit 0
//   AND   Wd, Wd, #7           ; mask to 3 bits, result in [0..7]
//
// Xbase must already hold the X87State base address (from emit_x87_base).
// =============================================================================
void emit_load_top(AssemblerBuffer& buf, const TranslationResult& translation, int Xbase,
                   int Wd_top);

// =============================================================================
// 2c — TOP write-back
//
// Emits:
//   LDRH  Wd_tmp, [Xbase, #0x02]        ; reload status_word
//   BFI   Wd_tmp, Wd_new_top, #11, #3   ; insert TOP into bits [13:11]
//   STRH  Wd_tmp, [Xbase, #0x02]        ; write back
//
// Wd_tmp must be distinct from Wd_new_top.
// =============================================================================

auto emit_store_top(AssemblerBuffer& buf, int Xbase, int Wd_new_top, int Wd_tmp) -> void;

// =============================================================================
// 2d — ST(i) byte offset computation
//
// Computes into Wd_offset: 0x06 + Wd_index * 0x0A
//
// Emits (multiply-by-10 via shifts):
//   LSL   Wd_offset, Wd_index, #3            ; * 8
//   ADD   Wd_offset, Wd_offset, Wd_index, LSL #1  ; + * 2  =  * 10
//   ADD   Wd_offset, Wd_offset, #0x06        ; + st[] base offset
//
// Wd_index and Wd_offset may be the same register.
// =============================================================================

// =============================================================================
// 2d — Physical register index for ST(i)
//
// Computes into Wd_out: (Wd_top + stack_depth) & 7
//
// For stack_depth == 0 and Wd_out != Wd_top: emits MOV.
// For stack_depth == 0 and Wd_out == Wd_top: no instructions.
// For stack_depth > 0: ADD + AND (2 instructions).
// =============================================================================

auto emit_phys_index(AssemblerBuffer& buf, int Wd_top, int stack_depth, int Wd_out) -> void;

// =============================================================================
// 2f — Load ST(i) mantissa into a D register
//
// Stride-8 layout: when Xbase_st >= 0 (pointer to &st[0]), uses AArch64
// scaled register-offset addressing: LDR Dd, [Xbase_st, Widx, SXTW #3].
// This is 1 instruction for depth=0, 3 for depth>0 (phys_index + LDR).
//
// When Xbase_st < 0 (uncached): computes byte offset from Xbase and uses
// unscaled register-offset addressing (2–4 instructions).
//
// After return, the function returns the "key register" for use with
// emit_store_st_at_offset:
//   - Wd_top when depth=0 and Xbase_st >= 0 (no MOV emitted — 1 insn saved)
//   - Wd_tmp otherwise
// =============================================================================

auto emit_load_st(AssemblerBuffer& buf, int Xbase, int Wd_top, int stack_depth, int Wd_tmp, int Dd,
                  int Xbase_st = -1) -> int;

// =============================================================================
// 2g — Store a D register into ST(i) mantissa
//
// Same dual-mode as emit_load_st.  Wd_tmp is clobbered.
// =============================================================================

auto emit_store_st(AssemblerBuffer& buf, int Xbase, int Wd_top, int stack_depth, int Wd_tmp, int Dd,
                   int Xbase_st = -1) -> void;

// =============================================================================
// 2g-reuse — Store using the index/offset left in Wd_key by a prior load/store
//
// When Xbase_st >= 0: Wd_key is a physical index → STR [Xbase_st, Wd_key, SXTW #3]
// When Xbase_st < 0:  Wd_key is a byte offset    → STR [Xbase, Wd_key, SXTW]
// =============================================================================

void emit_store_st_at_offset(AssemblerBuffer& buf, int Xbase, int Wd_key, int Dd,
                             int Xbase_st = -1);
// =============================================================================
// 2h — x87 stack push  (TOP decrement)
//
// new_TOP = (TOP - 1) & 7, written back into status_word bits [13:11].
//
// Emits:
//   SUB   Wd_top, Wd_top, #1
//   AND   Wd_top, Wd_top, #7
//   <emit_store_top>
//
// Wd_top is updated in place and holds new TOP on return.
// Wd_tmp is scratch for the status_word read-modify-write inside emit_store_top.
// =============================================================================

// =============================================================================
// 2h — x87 stack push  (TOP decrement + tag word clear)
//
// Mirrors X87State::push() exactly:
//   newTop = (TOP - 1) & 7
//   statusWord[13:11] = newTop
//   tagWord[newTop*2 +: 2] = 0b00   (kValid — clears kEmpty so getSt() works)
//
// Why three scratch registers:
//   Clearing bits at a variable position requires LSLV, which needs the tagWord
//   value, the shift amount (newTop*2), and the mask (3 << shift) all live
//   simultaneously. Wd_tmp and Wd_tmp2 serve those roles; Wd_top holds newTop
//   and is readable by callers on return.
//
// On return: Wd_top = newTop. Wd_tmp and Wd_tmp2 are clobbered.
// =============================================================================
auto emit_x87_push(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2) -> void;

// OPT-C: Push without status_word writeback. Caller must ensure writeback
// before any path that reads status_word (e.g. via pop or explicit store_top).
auto emit_x87_push_deferred(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2)
    -> void;

// =============================================================================
// 2i — x87 stack pop  (TOP increment)
//
// new_TOP = (TOP + 1) & 7, written back into status_word bits [13:11].
//
// Emits:
//   ADD   Wd_top, Wd_top, #1
//   AND   Wd_top, Wd_top, #7
//   <emit_store_top>
//
// Wd_top is updated in place and holds new TOP on return.
// Wd_tmp is scratch for the status_word read-modify-write inside emit_store_top.
// =============================================================================

auto emit_x87_pop(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp) -> void;

// Fused multi-pop: TOP += n with a single status_word RMW (OPT-A).
auto emit_x87_pop_n(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int n) -> void;

// =============================================================================
// 2j — FCMP result → x87 condition codes in status_word
//
// Must be called immediately after emit_fcmp_f64. Reads NZCV via MRS and
// maps AArch64 flags to x87 C0/C2/C3 bits in status_word:
//
//   FCMP outcome    NZCV        C3(b14) C2(b10) C0(b8)
//   ─────────────── ─────────── ─────── ─────── ──────
//   ST(0) > src     Z=0,C=0,N=0    0       0      0
//   ST(0) < src     Z=0,C=1,N=0    0       0      1
//   ST(0) == src    Z=1,C=1,N=0    1       0      0
//   Unordered/NaN   Z=1,C=1,V=1    1       1      1
//
// Wd_tmp1 and Wd_tmp2 are scratch registers, both clobbered.
//
// Note: the most complex Layer 2 function. Safe to defer and keep FCOM
// as a helper call initially until the rest of Layer 2 is validated.
// =============================================================================

auto emit_fcom_flags_to_sw(AssemblerBuffer& buf, int Xbase, int Wd_tmp1, int Wd_tmp2) -> void;