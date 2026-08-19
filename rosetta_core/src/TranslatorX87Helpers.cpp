#include "rosetta_core/TranslatorX87Helpers.hpp"

#include "rosetta_core/AssemblerHelpers.hpp"
#include "rosetta_core/TranslationResult.h"

// emit_ldr_str_imm with size=1 (LDRH/STRH) uses a halfword-scaled imm12:
// byte_offset = imm12 * 2.  Pass byte_offset/2 for all LDRH/STRH calls.
// kX87StatusWordOff = 0x02  →  imm12 = 0x01
static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;  // = 1
// kX87TagWordOff = 0x04 → imm12 = 2  (LDRH/STRH scale by 2)
static constexpr int16_t kX87TagWordImm12 = kX87TagWordOff / 2;  // = 2

// =============================================================================
// 2a — X87State base address
// =============================================================================

void emit_x87_base(AssemblerBuffer& buf, const TranslationResult& translation, int Xd) {
    const uint32_t offset = translation.thread_context_offsets->x87_state_offset;

    if (offset <= 0xFFF) {
        // Single ADD Xd, X18, #offset
        emit_add_imm(buf, /*is_64bit=*/1, /*is_sub=*/0, /*is_set_flags=*/0,
                     /*shift=*/0, offset, kX87ThreadReg, Xd);
    } else {
        // offset > 4095 — use shifted form (ADD with shift=1 encodes imm12<<12)
        if ((offset & 0xFFF) == 0) {
            emit_add_imm(buf, /*is_64bit=*/1, /*is_sub=*/0, /*is_set_flags=*/0,
                         /*shift=*/1, offset >> 12, kX87ThreadReg, Xd);
        } else {
            // Two instructions: ADD Xd, X18, #(offset & ~0xFFF), LSL#12
            //                   ADD Xd, Xd,  #(offset & 0xFFF)
            emit_add_imm(buf, 1, 0, 0, /*shift=*/1, offset >> 12, kX87ThreadReg, Xd);
            emit_add_imm(buf, 1, 0, 0, /*shift=*/0, offset & 0xFFF, Xd, Xd);
        }
    }
}

// =============================================================================
// 2b — TOP load
// =============================================================================

// Opt 1: fuse LSR #11 + AND #7 into a single UBFX (UBFM immr=11, imms=13).
//   UBFX Wd, Wn, #lsb, #width  =  UBFM immr=lsb, imms=lsb+width-1
//   lsb=11, width=3 (bits[13:11])  →  immr=11, imms=13
//   Extracts 3 bits at position 11 and places them at bits[2:0].
//   Replaces the previous LSR+AND pair (3 instructions → 2).
//
// Opt 6: decouple TOP load from Xbase to enable parallel issue.
//   When (x87_state_offset + kX87StatusWordOff) fits in a LDRH-scaled imm12
//   (byte offset even, ≤ 8190), emit the LDRH directly relative to the thread
//   register (X18) rather than relative to Xbase.  Because X18 is always live
//   and requires no prior computation, this instruction is independent of the
//   ADD Xbase emitted by emit_x87_base, allowing the CPU to issue both in the
//   same cycle on a superscalar core (Apple M-series: 4-wide issue, ~4-cycle
//   load latency).
//
//   Signature adds const TranslationResult& translation so the function can
//   read x87_state_offset and check the condition at JIT-compile time.
//   All callers already hold a TranslationResult reference.
//
//   Fallback (offset too large or misaligned): use Xbase as before.
void emit_load_top(AssemblerBuffer& buf, const TranslationResult& translation, int Xbase,
                   int Wd_top) {
    const uint32_t offset = translation.thread_context_offsets->x87_state_offset;
    const uint32_t sw_byte_off = offset + kX87StatusWordOff;  // byte offset of status_word from X18

    // Opt 6: choose base register for the LDRH.
    // LDRH imm12 encodes halfword units (imm12 * 2 = byte offset).
    // Maximum byte offset representable: 4095 * 2 = 8190.
    // Condition: byte offset even AND fits in scaled imm12.
    const bool use_x18_direct = ((sw_byte_off & 1u) == 0u) && (sw_byte_off <= 0x1FFEu);
    const int base_reg = use_x18_direct ? kX87ThreadReg : Xbase;
    const int16_t imm12 =
        use_x18_direct ? static_cast<int16_t>(sw_byte_off / 2u) : kX87StatusWordImm12;  // = 1

    // LDRH  Wd_top, [base_reg, #imm12]   ; load status_word (16-bit)
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/1, imm12, base_reg, Wd_top);

    // Opt 1: UBFX  Wd_top, Wd_top, #11, #3
    // UBFM immr=kX87TopShift(11), imms=kX87TopShift+2(13)
    // Extracts bits[13:11] (TOP field) into bits[2:0] of Wd_top.
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/2 /*UBFM*/,
                  /*N=*/0, /*immr=*/kX87TopShift, /*imms=*/kX87TopShift + 2, Wd_top, Wd_top);
}

// =============================================================================
// 2c — TOP write-back
// =============================================================================

void emit_store_top(AssemblerBuffer& buf, int Xbase, int Wd_new_top, int Wd_tmp) {
    // LDRH  Wd_tmp, [Xbase, #0x02]
    // imm12=1: byte offset = 1*2 = 2 = status_word
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/1, kX87StatusWordImm12, Xbase, Wd_tmp);

    // BFI   Wd_tmp, Wd_new_top, #11, #3
    // BFM immr=(32-11)%32=21, imms=width-1=2
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/1 /*BFM*/,
                  /*N=*/0, /*immr=*/21, /*imms=*/2, Wd_new_top, Wd_tmp);

    // STRH  Wd_tmp, [Xbase, #0x02]
    // imm12=1: byte offset = 1*2 = 2 = status_word
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/0, kX87StatusWordImm12, Xbase, Wd_tmp);
}

// =============================================================================
// 2d — Physical register index for ST(i)
// =============================================================================

void emit_phys_index(AssemblerBuffer& buf, int Wd_top, int stack_depth, int Wd_out) {
    if (stack_depth == 0) {
        if (Wd_out != Wd_top)
            emit_mov_reg(buf, /*is_64bit=*/0, Wd_out, Wd_top);
        return;
    }

    // ADD   Wd_out, Wd_top, #stack_depth
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, stack_depth, Wd_top, Wd_out);

    // AND   Wd_out, Wd_out, #7   (N=0, immr=0, imms=2)
    emit_and_imm(buf, /*is_64bit=*/0, Wd_out,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_out);
}

// =============================================================================
// 2f — Load ST(i) mantissa — stride-8 dual-mode
//
// Cached path (Xbase_st >= 0):
//   depth=0:  MOV Wd_tmp, Wd_top  +  LDR Dd, [Xbase_st, Wd_tmp, SXTW #3]  (2 insns)
//   depth>0:  ADD+AND(phys_index)  +  LDR Dd, [Xbase_st, Wd_tmp, SXTW #3]  (3 insns)
//   Wd_tmp contains the physical index (0..7) for reuse by emit_store_st_at_offset.
//
// Uncached path (Xbase_st < 0):
//   depth=0:  LSL+ADD  +  LDR Dd, [Xbase, Wd_tmp, SXTW]  (3 insns)
//   depth>0:  ADD+AND+LSL+ADD  +  LDR                     (5 insns)
//   Wd_tmp contains a byte offset for reuse by emit_store_st_at_offset.
// =============================================================================

int emit_load_st(AssemblerBuffer& buf, int Xbase, int Wd_top, int stack_depth, int Wd_tmp, int Dd,
                 int Xbase_st) {
    if (Xbase_st >= 0) {
        if (stack_depth == 0) {
            // Depth-0 fast path: use Wd_top directly as the scaled index.
            // Saves 1 MOV instruction.  Returns Wd_top as the key for
            // emit_store_st_at_offset reuse.
            emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/1, Wd_top, /*shift=*/1, Xbase_st,
                             Dd);
            return Wd_top;
        }
        // Depth>0: compute phys index into Wd_tmp, use it as scaled index.
        emit_phys_index(buf, Wd_top, stack_depth, Wd_tmp);
        emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/1, Wd_tmp, /*shift=*/1, Xbase_st,
                         Dd);
        return Wd_tmp;
    }

    // Uncached path: compute byte offset into Wd_tmp.
    emit_phys_index(buf, Wd_top, stack_depth, Wd_tmp);
    // LSL Wd_tmp, Wd_tmp, #3   (index * 8)
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 29, /*imms*/ 28, Wd_tmp, Wd_tmp);
    // ADD Wd_tmp, Wd_tmp, #8   (+ st[] base offset)
    emit_add_imm(buf, /*is_64=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, kX87RegFileOff, Wd_tmp, Wd_tmp);
    // LDR Dd, [Xbase, Wd_tmp, SXTW]
    emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/1, Wd_tmp, /*shift=*/0, Xbase, Dd);
    return Wd_tmp;
}

// =============================================================================
// 2g — Store a D register into ST(i) mantissa — stride-8 dual-mode
// =============================================================================

void emit_store_st(AssemblerBuffer& buf, int Xbase, int Wd_top, int stack_depth, int Wd_tmp, int Dd,
                   int Xbase_st) {
    if (Xbase_st >= 0) {
        if (stack_depth == 0) {
            // Depth-0 fast path: use Wd_top directly as scaled index.
            emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/0, Wd_top, /*shift=*/1, Xbase_st,
                             Dd);
            return;
        }
        emit_phys_index(buf, Wd_top, stack_depth, Wd_tmp);
        emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/0, Wd_tmp, /*shift=*/1, Xbase_st,
                         Dd);
        return;
    }

    // Uncached path
    emit_phys_index(buf, Wd_top, stack_depth, Wd_tmp);
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 29, /*imms*/ 28, Wd_tmp, Wd_tmp);
    emit_add_imm(buf, /*is_64=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, kX87RegFileOff, Wd_tmp, Wd_tmp);
    emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/0, Wd_tmp, /*shift=*/0, Xbase, Dd);
}

// =============================================================================
// 2g-reuse — Store using the key left in Wd_key by a prior emit_load_st
//
// Cached (Xbase_st >= 0): Wd_key = physical index → STR [Xbase_st, Wd_key, SXTW #3]
// Uncached (Xbase_st < 0): Wd_key = byte offset   → STR [Xbase, Wd_key, SXTW]
// =============================================================================

void emit_store_st_at_offset(AssemblerBuffer& buf, int Xbase, int Wd_key, int Dd, int Xbase_st) {
    if (Xbase_st >= 0) {
        emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/0, Wd_key, /*shift=*/1, Xbase_st,
                         Dd);
    } else {
        emit_ldr_str_reg(buf, /*size=*/3, /*is_fp=*/1, /*opc=*/0, Wd_key, /*shift=*/0, Xbase, Dd);
    }
}

// =============================================================================
// 2h — x87 stack push  (TOP decrement + tag word clear)
// =============================================================================

// OPT-2 REVERTED: Tag word maintenance is required.
//
// Testing revealed that something in the runtime or guest code depends on
// correct tag word state — newly pushed slots must be marked kValid, otherwise
// values are treated as empty and computations produce zero.
//
// The tag word clear sequence uses Wd_tmp2 as an additional scratch register
// to hold the bit position while Wd_tmp serves as the mask/RMW scratch.
void emit_x87_push(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2) {
    // ── Compute newTop = (TOP - 1) & 7 ───────────────────────────────────────

    // SUB  Wd_top, Wd_top, #1
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/1, /*is_set_flags=*/0,
                 /*shift=*/0, 1, Wd_top, Wd_top);
    // AND  Wd_top, Wd_top, #7
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    // ── Write newTop into statusWord[13:11] ──────────────────────────────────

    emit_store_top(buf, Xbase, Wd_top, Wd_tmp);  // Wd_tmp clobbered, now free

    // ── tagWord &= ~(3 << (newTop * 2))  →  mark new slot kValid ─────────────

    // LSL   Wd_tmp2, Wd_top, #1       ; bit_pos = newTop * 2
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp2);

    // MOVZ  Wd_tmp, #3                ; mask seed
    emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp);

    // LSLV  Wd_tmp, Wd_tmp, Wd_tmp2  ; mask = 3 << bit_pos
    emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);

    // LDRH  Wd_tmp2, [Xbase, #4]      ; tagWord
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);

    // BIC   Wd_tmp2, Wd_tmp2, Wd_tmp  ; tagWord &= ~mask
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*AND*/ 0, /*N=invert*/ 1,
                             /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0, Wd_tmp2, Wd_tmp2);

    // STRH  Wd_tmp2, [Xbase, #4]      ; write back tagWord
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);

    // Wd_top still holds newTop — no restore needed.
}

// =============================================================================
// 2h-deferred — x87 stack push WITHOUT status_word writeback (OPT-C)
//
// Same as emit_x87_push but skips the 3-instruction emit_store_top call.
// The caller is responsible for ensuring status_word is written before any
// code path that reads it (via emit_store_top or emit_x87_pop).
//
// Saves 3 emitted instructions per push when the next instruction pops
// (the pop's emit_store_top writes the correct TOP regardless).
// =============================================================================
void emit_x87_push_deferred(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2) {
    // SUB  Wd_top, Wd_top, #1
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/1, /*is_set_flags=*/0,
                 /*shift=*/0, 1, Wd_top, Wd_top);
    // AND  Wd_top, Wd_top, #7
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    // NOTE: emit_store_top SKIPPED — caller manages writeback (OPT-C)

    // ── tagWord &= ~(3 << (newTop * 2)) ──────────────────────────────────

    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp2);
    emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp);
    emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*AND*/ 0, /*N=invert*/ 1,
                             /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0, Wd_tmp2, Wd_tmp2);
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);
}

// =============================================================================
// 2i — x87 stack pop  (TOP increment + tag word set-empty)
//
// Mirrors the inverse of emit_x87_push: marks the popped slot as kEmpty
// (tag bits = 0b11) so that subsequent pushes from the runtime helpers see
// a free slot and do not raise a stack overflow fault.
//
// Sequence:
//   1. Mark old TOP's tag bits as kEmpty:  tagWord |= (3 << (oldTop * 2))
//   2. Compute newTop = (oldTop + 1) & 7
//   3. Write newTop into statusWord[13:11]
//
// The tag update is done BEFORE incrementing TOP so that Wd_top still holds
// oldTop and can be used for the bit position calculation.  Wd_tmp and
// Wd_tmp2 are scratch registers for the tag word RMW.
//
// On return: Wd_top = newTop.  Wd_tmp and Wd_tmp2 are clobbered.
// =============================================================================

void emit_x87_pop(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2) {
    // ── tagWord |= (3 << (oldTop * 2))  →  mark popped slot kEmpty ──────────

    // LSL   Wd_tmp2, Wd_top, #1       ; bit_pos = oldTop * 2
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp2);

    // MOVZ  Wd_tmp, #3                ; mask seed
    emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp);

    // LSLV  Wd_tmp, Wd_tmp, Wd_tmp2  ; mask = 3 << bit_pos
    emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);

    // LDRH  Wd_tmp2, [Xbase, #4]      ; tagWord
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);

    // ORR   Wd_tmp2, Wd_tmp2, Wd_tmp  ; tagWord |= mask  (set kEmpty = 0b11)
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*ORR*/ 1, /*N=*/0,
                             /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0, Wd_tmp2, Wd_tmp2);

    // STRH  Wd_tmp2, [Xbase, #4]      ; write back tagWord
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);

    // ── Compute newTop = (oldTop + 1) & 7 ────────────────────────────────────

    // ADD   Wd_top, Wd_top, #1
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, 1, Wd_top, Wd_top);

    // AND   Wd_top, Wd_top, #7   (N=0, immr=0, imms=2)
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
}

// =============================================================================
// 2i-deferred — x87 stack pop WITHOUT status_word writeback (OPT-C)
//
// Same as emit_x87_pop but skips the 3-instruction emit_store_top call.
// The caller is responsible for ensuring status_word is written before any
// code path that reads it (via x87_flush_top or x87_end).
//
// Saves 3 emitted instructions per pop when the cache is active and the
// next instruction will read TOP from the register, not memory.
//
// On return: Wd_top = newTop (register only — memory is stale).
//            Wd_tmp and Wd_tmp2 are clobbered.
// =============================================================================
void emit_x87_pop_deferred(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2) {
    // ── tagWord |= (3 << (oldTop * 2))  →  mark popped slot kEmpty ──────────

    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp2);
    emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp);
    emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*ORR*/ 1, /*N=*/0,
                             /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0, Wd_tmp2, Wd_tmp2);
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);

    // ── Compute newTop = (oldTop + 1) & 7  (register only) ──────────────────

    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, 1, Wd_top, Wd_top);
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    // NOTE: emit_store_top SKIPPED — caller manages writeback (OPT-C)
}

// =============================================================================
// 2i-fast — x87 fused multi-pop  (TOP += n, single status_word RMW)
//
// Marks n consecutive slots starting from old TOP as kEmpty in the tag word,
// then increments TOP by n with a single status_word RMW.
//
// For n=1, equivalent to emit_x87_pop.  For n=2 (FCOMPP), marks both
// old ST(0) and old ST(1) as empty.
//
// Each popped slot gets its own tag word load-ORR-store pass.  n is small
// (1–2 in practice) so the extra memory traffic is negligible.
//
// On return: Wd_top = newTop.  Wd_tmp and Wd_tmp2 are clobbered.
// =============================================================================

void emit_x87_pop_n(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2, int n) {
    // ── Mark all n popped slots as kEmpty ─────────────────────────────────────

    for (int i = 0; i < n; i++) {
        // Compute bit_pos = ((oldTop + i) & 7) * 2 → Wd_tmp2
        if (i == 0) {
            // oldTop is already in Wd_top
            emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                          /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp2);
        } else {
            // phys = (oldTop + i) & 7
            emit_add_imm(buf, /*is_64=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                         /*shift=*/0, i, Wd_top, Wd_tmp2);
            emit_and_imm(buf, /*is_64=*/0, Wd_tmp2,
                         /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_tmp2);
            // bit_pos = phys * 2
            emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                          /*immr*/ 31, /*imms*/ 30, Wd_tmp2, Wd_tmp2);
        }

        // mask = 3 << bit_pos → Wd_tmp
        emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp);
        emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);

        // tagWord |= mask  (LDRH, ORR, STRH)
        emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);
        emit_logical_shifted_reg(buf, /*is_64=*/0, /*ORR*/ 1, /*N=*/0,
                                 /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0, Wd_tmp2, Wd_tmp2);
        emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);
    }

    // ── Compute newTop = (oldTop + n) & 7 ────────────────────────────────────

    // ADD   Wd_top, Wd_top, #n
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, n, Wd_top, Wd_top);

    // AND   Wd_top, Wd_top, #7
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
}

// =============================================================================
// 2i-fast-deferred — x87 fused multi-pop WITHOUT status_word writeback (OPT-C)
//
// Same as emit_x87_pop_n but skips the emit_store_top call.
// =============================================================================

void emit_x87_pop_n_deferred(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2,
                             int n) {
    for (int i = 0; i < n; i++) {
        if (i == 0) {
            emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                          /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp2);
        } else {
            emit_add_imm(buf, /*is_64=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                         /*shift=*/0, i, Wd_top, Wd_tmp2);
            emit_and_imm(buf, /*is_64=*/0, Wd_tmp2,
                         /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_tmp2);
            emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                          /*immr*/ 31, /*imms*/ 30, Wd_tmp2, Wd_tmp2);
        }

        emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp);
        emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);

        emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1,
                         kX87TagWordImm12, Xbase, Wd_tmp2);
        emit_logical_shifted_reg(buf, /*is_64=*/0, /*ORR*/ 1, /*N=*/0,
                                 /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0,
                                 Wd_tmp2, Wd_tmp2);
        emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0,
                         kX87TagWordImm12, Xbase, Wd_tmp2);
    }

    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, n, Wd_top, Wd_top);
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    // NOTE: emit_store_top SKIPPED — caller manages writeback (OPT-C)
}

// =============================================================================
// 2h-fully-deferred — x87 stack push: TOP decrement ONLY (OPT-D)
//
// Emits only the 2-instruction TOP decrement (SUB + AND).  Both the
// status_word writeback (store_top) AND the tag word update (mark kValid)
// are deferred.  The caller sets top_dirty = 1 and deferred_push_count = 1
// on x87_cache.
//
// The pending tag must be resolved before any code that reads the tag word:
// - Cancelled by a subsequent pop on the same slot (emit_x87_pop_top_only)
// - Flushed by emit_x87_tag_clear if the push is consumed by non-pop code
// =============================================================================
void emit_x87_push_fully_deferred(AssemblerBuffer& buf, int Wd_top) {
    // SUB  Wd_top, Wd_top, #1
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/1, /*is_set_flags=*/0,
                 /*shift=*/0, 1, Wd_top, Wd_top);
    // AND  Wd_top, Wd_top, #7
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);
}

// =============================================================================
// 2i-top-only — x87 stack pop: TOP increment ONLY (OPT-D)
//
// Emits only the 2-instruction TOP increment (ADD + AND).  No tag word
// update, no store_top.  Used for push-pop cancellation where both the
// push's tag-clear and the pop's tag-set operate on the same slot and cancel.
// =============================================================================
void emit_x87_pop_top_only(AssemblerBuffer& buf, int Wd_top) {
    // ADD   Wd_top, Wd_top, #1
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, 1, Wd_top, Wd_top);
    // AND   Wd_top, Wd_top, #7
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);
}

// =============================================================================
// 2h-tag — Emit deferred tag-valid update for a prior push (OPT-D)
//
// This is the 6-instruction tag word portion of emit_x87_push, factored out
// for lazy emission.  Marks the slot at Wd_top (the current TOP, which is
// the slot the push decremented into) as kValid in the tag word.
//
// tagWord &= ~(3 << (Wd_top * 2))
// =============================================================================
void emit_x87_tag_clear(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int Wd_tmp2) {
    // LSL   Wd_tmp2, Wd_top, #1
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp2);
    // MOVZ  Wd_tmp, #3
    emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp);
    // LSLV  Wd_tmp, Wd_tmp, Wd_tmp2
    emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);
    // LDRH  Wd_tmp2, [Xbase, #4]  (tagWord)
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);
    // BIC   Wd_tmp2, Wd_tmp2, Wd_tmp  (tagWord &= ~mask → kValid)
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*AND*/ 0, /*N=invert*/ 1,
                             /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0, Wd_tmp2, Wd_tmp2);
    // STRH  Wd_tmp2, [Xbase, #4]
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);
}

// =============================================================================
// OPT-D2: Batched tag-set-empty for multiple deferred pops.
//
// Emits a single LDRH/ORR-chain/STRH to mark `count` consecutive popped
// slots as kEmpty in the tag word.  The slots are:
//   (Wd_top - count) & 7, (Wd_top - count + 1) & 7, ..., (Wd_top - 1) & 7
//
// This replaces N separate LDRH+compute+ORR+STRH sequences (6 instructions
// each) with a single memory round-trip, eliminating N-1 store-forwarding
// stalls on Apple M-series (~4 cycles each).
// =============================================================================

void emit_x87_tag_set_empty_batch(AssemblerBuffer& buf, int Xbase, int Wd_top,
                                   int Wd_tmp, int Wd_tmp2, int Wd_tagw, int count) {
    // LDRH  Wd_tagw, [Xbase, #4]  — load tag word once
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tagw);

    for (int i = 0; i < count; i++) {
        // Compute slot = (Wd_top - count + i) & 7 → Wd_tmp
        const int offset_from_top = count - i;  // positive offset back from current TOP
        // SUB Wd_tmp, Wd_top, #offset_from_top
        emit_add_imm(buf, /*is_64=*/0, /*is_sub=*/1, /*is_set_flags=*/0,
                     /*shift=*/0, offset_from_top, Wd_top, Wd_tmp);
        // AND Wd_tmp, Wd_tmp, #7
        emit_and_imm(buf, /*is_64=*/0, Wd_tmp,
                     /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_tmp);
        // LSL Wd_tmp, Wd_tmp, #1  (bit_pos = slot * 2)
        emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                      /*immr*/ 31, /*imms*/ 30, Wd_tmp, Wd_tmp);
        // MOVZ Wd_tmp2, #3
        emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, 3, Wd_tmp2);
        // LSLV Wd_tmp2, Wd_tmp2, Wd_tmp  → mask = 3 << bit_pos
        emit_lslv(buf, 0, Wd_tmp, Wd_tmp2, Wd_tmp2);
        // ORR Wd_tagw, Wd_tagw, Wd_tmp2
        emit_logical_shifted_reg(buf, /*is_64=*/0, /*ORR*/ 1, /*N=*/0,
                                 /*LSL*/ 0, Wd_tmp2, /*shift_amt*/ 0, Wd_tagw, Wd_tagw);
    }

    // STRH  Wd_tagw, [Xbase, #4]  — write tag word once
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tagw);
}

// =============================================================================
// 2i-b — Batched tag-set-valid for net pushes (IR epilogue)
//
// Marks `count` consecutive pushed slots as kValid with a constant-cost
// sequence: LDRH + mask-shift + wrap-fold + BIC + STRH (7 instructions
// regardless of count).  The slots are:
//   Wd_top & 7, (Wd_top + 1) & 7, ..., (Wd_top + count - 1) & 7
//
// The combined mask (1 << 2*count) - 1 covers `count` adjacent 2-bit pairs.
// An ORR with LSR #16 folds any bits that shifted past the 16-bit tag word
// boundary back to the low bits, handling the circular wrap case.
// =============================================================================

void emit_x87_tag_set_valid_batch(AssemblerBuffer& buf, int Xbase, int Wd_top,
                                   int Wd_tmp, int Wd_tmp2, int Wd_tagw, int count) {
    // LDRH  Wd_tagw, [Xbase, #4]  — load tag word once
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tagw);

    // bit_pos = top * 2  (LSL #1 via UBFM)
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0,
                  /*immr*/ 31, /*imms*/ 30, Wd_top, Wd_tmp);

    // mask = (1 << (2 * count)) - 1  — covers count adjacent 2-bit pairs
    const uint16_t mask = static_cast<uint16_t>((1u << (2 * count)) - 1);
    emit_movn(buf, /*is_64=*/0, /*MOVZ opc*/ 2, /*hw*/ 0, mask, Wd_tmp2);

    // LSLV Wd_tmp2, Wd_tmp2, Wd_tmp  — shift mask into position
    emit_lslv(buf, 0, Wd_tmp, Wd_tmp2, Wd_tmp2);

    // Handle circular wrap: fold overflow bits back into low 16
    // ORR Wd_tmp2, Wd_tmp2, Wd_tmp2, LSR #16
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*ORR*/ 1, /*N=*/0,
                             /*LSR*/ 1, Wd_tmp2, /*shift_amt*/ 16, Wd_tmp2, Wd_tmp2);

    // BIC Wd_tagw, Wd_tagw, Wd_tmp2  — clear all tag bits at once (kValid = 0b00)
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*AND*/ 0, /*N=1→BIC*/ 1,
                             /*LSL*/ 0, Wd_tmp2, /*shift_amt*/ 0, Wd_tagw, Wd_tagw);

    // STRH  Wd_tagw, [Xbase, #4]  — write tag word once
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tagw);
}

// =============================================================================
// 2j — FCMP result → x87 condition codes in status_word
// =============================================================================

void emit_fcom_flags_to_sw(AssemblerBuffer& buf, int Xbase, int Wd_tmp1, int Wd_tmp2) {
    // Read NZCV into Wd_tmp1.
    // N=bit31, Z=bit30, C=bit29, V=bit28
    //
    // x87 condition code mapping:
    //   GT (Z=0,C=0,V=0): C3=0, C2=0, C0=0
    //   LT (Z=0,C=1,V=0): C3=0, C2=0, C0=1
    //   EQ (Z=1,C=1,V=0): C3=1, C2=0, C0=0
    //   UN (Z=1,C=1,V=1): C3=1, C2=1, C0=1
    //
    // status_word bit positions: C0=8, C2=10, C3=14
    //
    // Build Wd_tmp2 with the three CC bits, then RMW status_word.
    // Wd_tmp1 holds NZCV throughout until we need to reload status_word.

    emit_mrs_nzcv(buf, Wd_tmp1);

    // --- C0 from C flag: NZCV bit29 → sw bit8 ---
    // LSR #21: bit29 → bit8; AND isolates bit8.
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/2 /*UBFM*/,
                  /*N=*/0, /*immr=*/21, /*imms=*/31, Wd_tmp1, Wd_tmp2);
    // AND Wd_tmp2, Wd_tmp2, #(1<<8): N=0, immr=24, imms=0
    emit_and_imm(buf, /*is_64bit=*/0, Wd_tmp2,
                 /*N=*/0, /*immr=*/24, /*imms=*/0, Wd_tmp2);

    // --- C3 from Z flag: NZCV bit30 → sw bit14 ---
    // --- C2 from V flag: NZCV bit28 → sw bit10 ---
    // LSR #16 on Wd_tmp1: bit30→bit14, bit28→bit12
    // (C flag at bit29 already consumed into Wd_tmp2; safe to clobber Wd_tmp1)
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/2 /*UBFM*/,
                  /*N=*/0, /*immr=*/16, /*imms=*/31, Wd_tmp1, Wd_tmp1);

    // BFI Wd_tmp2, Wd_tmp1, #14, #1 — insert bit14 of Wd_tmp1 into bit14 of Wd_tmp2
    // BFM immr=(32-14)%32=18, imms=0
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/1 /*BFM*/,
                  /*N=*/0, /*immr=*/18, /*imms=*/0, Wd_tmp1, Wd_tmp2);

    // UBFX bit12 of Wd_tmp1 → bit0: UBFM immr=12, imms=12
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/2 /*UBFM*/,
                  /*N=*/0, /*immr=*/12, /*imms=*/12, Wd_tmp1, Wd_tmp1);

    // BFI Wd_tmp2, Wd_tmp1, #10, #1 — insert bit0 of Wd_tmp1 into bit10 of Wd_tmp2
    // BFM immr=(32-10)%32=22, imms=0
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/1 /*BFM*/,
                  /*N=*/0, /*immr=*/22, /*imms=*/0, Wd_tmp1, Wd_tmp2);

    // Wd_tmp2 now holds C0(bit8), C2(bit10), C3(bit14).

    // RMW status_word: load, clear old CC bits, OR in new ones, store.

    // LDRH Wd_tmp1, [Xbase, #0x02]  (imm12=1, byte offset=2)
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/1, kX87StatusWordImm12, Xbase, Wd_tmp1);

    // Clear C0/C2 bits [10:8] (3 bits): BFI from WZR, lsb=8, width=3
    // BFM immr=(32-8)%32=24, imms=2
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/1 /*BFM*/,
                  /*N=*/0, /*immr=*/24, /*imms=*/2,
                  /*Rn=*/GPR::XZR, Wd_tmp1);

    // Clear C3 bit14: BFI from WZR, lsb=14, width=1
    // BFM immr=(32-14)%32=18, imms=0
    emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/1 /*BFM*/,
                  /*N=*/0, /*immr=*/18, /*imms=*/0,
                  /*Rn=*/GPR::XZR, Wd_tmp1);

    // ORR Wd_tmp1, Wd_tmp1, Wd_tmp2
    emit_logical_shifted_reg(buf, /*is_64bit=*/0, /*opc=*/1 /*ORR*/,
                             /*n=*/0, /*shift_type=*/0,
                             /*Rm=*/Wd_tmp2, /*shift_amount=*/0,
                             /*Rn=*/Wd_tmp1, /*Rd=*/Wd_tmp1);

    // STRH Wd_tmp1, [Xbase, #0x02]  (imm12=1, byte offset=2)
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/0, kX87StatusWordImm12, Xbase, Wd_tmp1);
}

// =============================================================================
// OPT-G: Permutation flush — materialize a non-identity perm map via memory
// swaps using cycle decomposition.
//
// For each cycle of length > 1 in the permutation, we rotate the values using
// 2 temp FPRs: Dd_save holds the first value in the cycle, Dd_chain is used
// for intermediate loads.
//
// In practice, the permutation is almost always a single 2-cycle (swap of two
// elements from one FXCH ST(1)), requiring exactly 2 loads + 2 stores.
//
// Dd_save and Dd_chain are temp FPRs provided by the caller (already allocated).
// Wd_tmp is scratch for phys_index computation (clobbered by emit_load/store_st).
// =============================================================================
void emit_x87_perm_flush(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp,
                          const int8_t perm[8], int Xst_base, int Dd_save, int Dd_chain) {
    bool visited[8] = {};

    for (int i = 0; i < 8; i++) {
        if (visited[i] || perm[i] == i)
            continue;

        // Cycle rotation using 2 temp FPRs:
        //   Dd_save ← ST(cycle[0])              // save first element
        //   ST(cycle[0]) ← ST(cycle[1])          // load into Dd_chain, store
        //   ST(cycle[1]) ← ST(cycle[2])          // ...
        //   ST(cycle[n-1]) ← Dd_save             // close with saved value

        // Save ST(i)
        emit_load_st(buf, Xbase, Wd_top, i, Wd_tmp, Dd_save, Xst_base);
        visited[i] = true;

        int j = i;
        int next = perm[j];
        while (next != i) {
            // ST(j) ← ST(next)
            emit_load_st(buf, Xbase, Wd_top, next, Wd_tmp, Dd_chain, Xst_base);
            emit_store_st(buf, Xbase, Wd_top, j, Wd_tmp, Dd_chain, Xst_base);
            visited[next] = true;
            j = next;
            next = perm[j];
        }

        // Close the cycle: ST(j) ← Dd_save
        emit_store_st(buf, Xbase, Wd_top, j, Wd_tmp, Dd_save, Xst_base);
    }
}

// =============================================================================
// OPT-L: Branchless FCMP NZCV → packed x87 CC bits.
//
// AArch64 FCMP sets NZCV:
//   GT: N=0, Z=0, C=1, V=0
//   LT: N=1, Z=0, C=0, V=0
//   EQ: N=0, Z=1, C=1, V=0
//   UN: N=0, Z=0, C=1, V=1
//
// x87 CC derivation:
//   C0 (bit 8)  = CC | VS  = (C==0) | (V==1)   → 1 for LT and UN
//   C2 (bit 10) = VS       = (V==1)             → 1 for UN only
//   C3 (bit 14) = EQ | VS  = (Z==1) | (V==1)   → 1 for EQ and UN
//
// All three CSET instructions must execute before MSR restores NZCV.
// =============================================================================
void emit_fcom_cc_pack(AssemblerBuffer& buf, TranslationResult& a1,
                        int Wd_result, int Wd_save) {
    const int Wd_cc = alloc_free_gpr(a1);
    const int Wd_vs = alloc_free_gpr(a1);

    // Extract individual flag conditions (all 3 must precede MSR)
    emit_cset(buf, /*is_64bit=*/0, /*CC=*/3, Wd_cc);    // 1 if carry clear (LT)
    emit_cset(buf, /*is_64bit=*/0, /*VS=*/6, Wd_vs);    // 1 if overflow (UN)
    emit_cset(buf, /*is_64bit=*/0, /*EQ=*/0, Wd_result); // 1 if equal

    // MSR NZCV, Wd_save — restore saved x86 EFLAGS (all CSETs done)
    emit_msr_nzcv(buf, Wd_save);
    free_gpr(a1, Wd_save);

    // C0 = CC | VS
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_vs, 0, Wd_cc, Wd_cc);
    // C3 = EQ | VS
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_vs, 0, Wd_result, Wd_result);

    // Pack: Wd_result = (C0 << 8) | (C2 << 10) | (C3 << 14)
    // Step 1: C0 << 8
    emit_bitfield(buf, /*is_64=*/0, /*UBFM=*/2, /*N=*/0,
                  /*immr=*/24, /*imms=*/23, Wd_cc, Wd_cc);  // LSL #8
    // Step 2: ORR with C2(=VS) << 10
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_vs, 10, Wd_cc, Wd_cc);
    // Step 3: ORR with C3 << 14, result in Wd_result
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_result, 14, Wd_cc, Wd_result);

    free_gpr(a1, Wd_vs);
    free_gpr(a1, Wd_cc);
}

// =============================================================================
// NZCV-hoisted variant of emit_fcom_cc_pack: identical CC packing but does
// NOT restore NZCV.  Used when the caller saves/restores NZCV once around a
// whole group of compares (IR run) instead of per-compare.
// =============================================================================
void emit_fcom_cc_pack_hoisted(AssemblerBuffer& buf, TranslationResult& a1,
                                int Wd_result) {
    const int Wd_cc = alloc_free_gpr(a1);
    const int Wd_vs = alloc_free_gpr(a1);

    emit_cset(buf, /*is_64bit=*/0, /*CC=*/3, Wd_cc);     // 1 if carry clear (LT)
    emit_cset(buf, /*is_64bit=*/0, /*VS=*/6, Wd_vs);     // 1 if overflow (UN)
    emit_cset(buf, /*is_64bit=*/0, /*EQ=*/0, Wd_result); // 1 if equal

    // C0 = CC | VS
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_vs, 0, Wd_cc, Wd_cc);
    // C3 = EQ | VS
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_vs, 0, Wd_result, Wd_result);

    // Pack: Wd_result = (C0 << 8) | (C2 << 10) | (C3 << 14)
    emit_bitfield(buf, /*is_64=*/0, /*UBFM=*/2, /*N=*/0,
                  /*immr=*/24, /*imms=*/23, Wd_cc, Wd_cc);  // LSL #8
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_vs, 10, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_result, 14, Wd_cc, Wd_result);

    free_gpr(a1, Wd_vs);
    free_gpr(a1, Wd_cc);
}

// =============================================================================
// OPT-L: RMW status_word — clear C0/C1/C2/C3, OR in packed CC bits, store.
//
// C1 (bit 9) is cleared per Intel SDM for all FCOM variants.
// =============================================================================
int emit_fcom_cc_write_sw_keep(AssemblerBuffer& buf, TranslationResult& a1,
                                int Xbase, int Wd_packed) {
    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;

    const int Wd_sw = alloc_free_gpr(a1);

    // LDRH Wd_sw, [Xbase, #0x02]
    emit_ldr_str_imm(buf, 1, 0, 1, kX87StatusWordImm12, Xbase, Wd_sw);

    // OPT-F1: Clear bits [10:8] (C0, C1, C2) with a single BFI, then bit 14 (C3).
    emit_bitfield(buf, 0, 1, 0, 24, 2, GPR::XZR, Wd_sw);   // clear bits [10:8]
    emit_bitfield(buf, 0, 1, 0, 18, 0, GPR::XZR, Wd_sw);   // clear bit 14

    // ORR Wd_sw, Wd_sw, Wd_packed
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_packed, 0, Wd_sw, Wd_sw);

    // STRH Wd_sw, [Xbase, #0x02]
    emit_ldr_str_imm(buf, 1, 0, 0, kX87StatusWordImm12, Xbase, Wd_sw);

    return Wd_sw;
}

void emit_fcom_cc_write_sw(AssemblerBuffer& buf, TranslationResult& a1,
                            int Xbase, int Wd_packed) {
    free_gpr(a1, emit_fcom_cc_write_sw_keep(buf, a1, Xbase, Wd_packed));
}
// =============================================================================
// RC dispatch — binary tree over pre-extracted RC bits [1:0] in Wd_rc.
//
// Wd_rc is only read (never written), so cached RC values survive dispatch.
//
// _fcvt uses speculation: the FCVT into the Wd_int scratch has no side
// effects, so each subtree converts with its first candidate mode and only
// re-converts when the low RC bit says otherwise.  This keeps branch
// instructions 8 bytes apart (back-to-back branch pairs measurably stall the
// M-series front end when the second one is taken) with at most 2 taken
// branches on any path:
//
//   [0] TBNZ Wd_rc, #1, +5 → [5]   ; RC ∈ {2,3}
//   [1] FCVTNS                      ; speculative RC=0
//   [2] TBZ  Wd_rc, #0, +6 → [8]   ; RC=0 done
//   [3] FCVTMS                      ; RC=1 floor
//   [4] B +4 → [8]
//   [5] FCVTPS                      ; speculative RC=2 ceil
//   [6] TBZ  Wd_rc, #0, +2 → [8]   ; RC=2 done
//   [7] FCVTZS                      ; RC=3 truncate
//   [8] done
// =============================================================================

void emit_x87_rc_dispatch_fcvt(AssemblerBuffer& buf, int Wd_rc, int Wd_int,
                                int Dd_val, int is_64bit_int) {
    // FCVT*S rmode field: NS=0 (nearest), PS=1 (ceil), MS=2 (floor), ZS=3 (trunc)
    emit_tbz(buf, /*TBNZ*/1, /*bit*/1, Wd_rc, 5);
    emit_fcvt_fp_to_int(buf, is_64bit_int, /*ftype=f64*/1, /*rmode=NS*/0, Wd_int, Dd_val);
    emit_tbz(buf, /*TBZ*/0, /*bit*/0, Wd_rc, 6);
    emit_fcvt_fp_to_int(buf, is_64bit_int, /*ftype=f64*/1, /*rmode=MS*/2, Wd_int, Dd_val);
    emit_b(buf, 4);
    emit_fcvt_fp_to_int(buf, is_64bit_int, /*ftype=f64*/1, /*rmode=PS*/1, Wd_int, Dd_val);
    emit_tbz(buf, /*TBZ*/0, /*bit*/0, Wd_rc, 2);
    emit_fcvt_fp_to_int(buf, is_64bit_int, /*ftype=f64*/1, /*rmode=ZS*/3, Wd_int, Dd_val);
}

void emit_x87_rc_dispatch_frint(AssemblerBuffer& buf, int Wd_rc, int Dd, int Dn) {
    // FRINT* fp_dp1 opcode: FRINTN=8, FRINTP=9, FRINTM=10, FRINTZ=11
    emit_tbz(buf, /*TBNZ*/1, /*bit*/1, Wd_rc, 6);
    emit_tbz(buf, /*TBNZ*/1, /*bit*/0, Wd_rc, 3);
    emit_fp_dp1(buf, /*type=f64*/1, /*FRINTN*/8, Dd, Dn);
    emit_b(buf, 7);
    emit_fp_dp1(buf, /*type=f64*/1, /*FRINTM*/10, Dd, Dn);
    emit_b(buf, 5);
    emit_tbz(buf, /*TBNZ*/1, /*bit*/0, Wd_rc, 3);
    emit_fp_dp1(buf, /*type=f64*/1, /*FRINTP*/9, Dd, Dn);
    emit_b(buf, 2);
    emit_fp_dp1(buf, /*type=f64*/1, /*FRINTZ*/11, Dd, Dn);
}

void emit_x87_tag_mark_valid(AssemblerBuffer& buf, int Xbase, int Wd_top, int depth,
                             int Wd_tmp, int Wd_tmp2) {
    // Wd_tmp2 = ((TOP + depth) & 7) * 2   — bit position of this slot's tag pair
    if (depth)
        emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                     /*shift=*/0, depth & 7, Wd_top, Wd_tmp2);
    else  // MOV Wd_tmp2, Wd_top   (ORR Wd_tmp2, WZR, Wd_top)
        emit_logical_shifted_reg(buf, 0, /*ORR=*/1, 0, 0, Wd_top, 0, 31, Wd_tmp2);
    emit_and_imm(buf, /*is_64bit=*/0, Wd_tmp2, /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_tmp2);
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0, /*immr*/ 31, /*imms*/ 30,
                  Wd_tmp2, Wd_tmp2);                       // LSL #1

    emit_movn(buf, /*is_64=*/0, /*MOVZ*/ 2, /*hw*/ 0, 3, Wd_tmp);   // mask seed = 0b11
    emit_lslv(buf, 0, Wd_tmp2, Wd_tmp, Wd_tmp);                     // mask = 3 << pos

    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*AND*/ 0, /*N=invert (BIC)*/ 1,
                             /*LSL*/ 0, Wd_tmp, /*shift*/ 0, Wd_tmp2, Wd_tmp2);
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);
}
