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
    buf.emit(0x1AC02000u | (uint32_t(Wd_tmp2) << 16) | (uint32_t(Wd_tmp) << 5) | uint32_t(Wd_tmp));

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
    buf.emit(0x1AC02000u | (uint32_t(Wd_tmp2) << 16) | (uint32_t(Wd_tmp) << 5) | uint32_t(Wd_tmp));
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, kX87TagWordImm12, Xbase, Wd_tmp2);
    emit_logical_shifted_reg(buf, /*is_64=*/0, /*AND*/ 0, /*N=invert*/ 1,
                             /*LSL*/ 0, Wd_tmp, /*shift_amt*/ 0, Wd_tmp2, Wd_tmp2);
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/ 0, kX87TagWordImm12, Xbase, Wd_tmp2);
}

// =============================================================================
// 2i — x87 stack pop  (TOP increment)
// =============================================================================

void emit_x87_pop(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp) {
    // ADD   Wd_top, Wd_top, #1
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, 1, Wd_top, Wd_top);

    // AND   Wd_top, Wd_top, #7   (N=0, immr=0, imms=2)
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
}

// =============================================================================
// 2i-fast — x87 fused multi-pop  (TOP += n, single status_word RMW)
//
// Combines n pops into a single ADD+AND+store_top sequence (5 insns total),
// instead of n separate emit_x87_pop calls (5n insns).
// Saves (n-1)*5 instructions for n>1.  Used by FCOMPP (n=2).
// =============================================================================

void emit_x87_pop_n(AssemblerBuffer& buf, int Xbase, int Wd_top, int Wd_tmp, int n) {
    // ADD   Wd_top, Wd_top, #n
    emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/0, /*is_set_flags=*/0,
                 /*shift=*/0, n, Wd_top, Wd_top);

    // AND   Wd_top, Wd_top, #7
    emit_and_imm(buf, /*is_64bit=*/0, Wd_top,
                 /*N=*/0, /*immr=*/0, /*imms=*/2, Wd_top);

    emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
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