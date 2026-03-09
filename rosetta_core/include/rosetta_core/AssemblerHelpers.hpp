#pragma once

#include <cstdint>

#include "rosetta_core/AssemblerBuffer.h"

// AArch64 logical immediates encode a value as a replicated bitmask:
//   - Pick an element size S ∈ {2,4,8,16,32,64} bits
//   - Within each element, place a contiguous run of 1s (len bits), right-rotated by R
//   - Replicate that element to fill the register width
//
// The encoding is (N, immr, imms):
//   N    : 1 if element size is 64, else 0
//   immr : rotation amount R (right-rotate, mod element_size)
//   imms : encodes element_size and run_length as ~(element_size - 1) | (run_length - 1)
//          i.e. the top bits identify the element size, low bits the run length
//
// Returns false if value cannot be represented as a logical immediate.

struct LogicalImmEncoding {
    bool N;        // extends imms to select 64-bit element size
    uint8_t immr;  // right-rotation amount
    uint8_t imms;  // encodes element size + run length
};

auto is_bitmask_immediate(bool is_64bit, uint64_t value, LogicalImmEncoding& out) -> bool;

// -----------------------------------------------------------------------------
// 1a — GPR Data Processing
// -----------------------------------------------------------------------------

// ADD / SUB / ADDS / SUBS (immediate)
// is_sub=0 → ADD,  is_sub=1 → SUB
// is_set_flags=1 → ADDS / SUBS (writes NZCV)
// shift=0 → imm12 as-is,  shift=1 → imm12 << 12
auto emit_add_imm(AssemblerBuffer& buf, int is_64bit, int is_sub, int is_set_flags, int shift,
                  int64_t imm12, int64_t Rn, int Rd) -> void;

// AND (immediate) — N/immr/imms are pre-encoded logical immediate fields
// Use is_bitmask_immediate() @ 0x2048 to derive these from a raw mask value
auto emit_and_imm(AssemblerBuffer& buf, int is_64bit, int Rd, int N, int64_t immr, int64_t imms,
                  int Rn) -> void;

// BFM / UBFM / SBFM — covers BFI, LSR, LSL, SXTW, UBFX etc.
// opc: 0=SBFM  1=BFM  2=UBFM
// N:   0 for 32-bit operation, 1 for 64-bit
auto emit_bitfield(AssemblerBuffer& buf, int is_64bit, int opc, int N, int8_t immr, int8_t imms,
                   int Rn, int Rd) -> void;

// MOVN / MOVZ / MOVK
// opc: 0=MOVN  2=MOVZ  3=MOVK
// hw:  0..3, effective shift = hw * 16
auto emit_movn(AssemblerBuffer& buf, int is_64bit, int opc, int hw, uint16_t imm16, int Rd) -> void;

// MOV register — emits ADD (SP case) or ORR shifted-reg (general case)
auto emit_mov_reg(AssemblerBuffer& buf, int is_64bit, int Rd, int Rn) -> void;

// SUBS register — always sets flags, arg order is (Rn, Rm, Rd)
auto emit_subs_reg(AssemblerBuffer& buf, int is_64bit, int Rn, int Rm, int Rd) -> void;

// ADD / SUB / ADDS / SUBS shifted register
// shift_type: 0=LSL  1=LSR  2=ASR
auto emit_add_sub_shifted_reg(AssemblerBuffer& buf, int is_64bit, int is_sub, int is_set_flags,
                              int shift_type, int Rm, int8_t shift_amount, int Rn, int Rd) -> void;

// AND / ORR / EOR / ANDS shifted register
// opc: 0=AND  1=ORR  2=EOR  3=ANDS
// n=1 inverts Rm  →  BIC / ORN / EON / BICS
auto emit_logical_shifted_reg(AssemblerBuffer& buf, int is_64bit, int opc, int n, int shift_type,
                              int Rm, int8_t shift_amount, int Rn, int Rd) -> void;

// -----------------------------------------------------------------------------
// 1b — Load / Store (unified GPR + FPR)
// -----------------------------------------------------------------------------

// Unified LDR / STR unsigned-offset immediate (GPR or FPR via is_fp)
// size: 0=8-bit  1=16-bit  2=32-bit  3=64-bit  4=128-bit
// is_fp: 0=GPR  1=FPR/NEON
// opc:   0=STR  1=LDR
auto emit_ldr_str_imm(AssemblerBuffer& buf, int size, int is_fp, int opc, int16_t imm12, int Rn,
                      int Rt) -> void;

// Unified LDR / STR register offset (GPR or FPR via is_fp)
// shift: 0=no LSL,  1=LSL by element size
auto emit_ldr_str_reg(AssemblerBuffer& buf, int size, int is_fp, int opc, int Rm, int shift, int Rn,
                      int Rt) -> void;

// LDR / STR signed 9-bit unscaled offset with pre/post-index
// write_back: 1=pre-index  0=post-index
// extend_mode / opc: 0=STR  1=LDR
auto emit_ldr_str_imm_ext(AssemblerBuffer& buf, int data_size, int write_back, int extend_mode,
                          int16_t offset, int Rn, int Rt) -> void;

// LDR GPR immediate — thin wrapper: is_fp=0, opc=1
auto emit_ldr_imm(AssemblerBuffer& buf, int size, int Rt, int Rn, int16_t imm12) -> void;

// STR GPR immediate — thin wrapper: is_fp=0, opc=0
auto emit_str_imm(AssemblerBuffer& buf, int size, int Rt, int Rn, int16_t imm12) -> void;

// -----------------------------------------------------------------------------
// 1c — Load / Store (FPR convenience wrappers)
//
// All delegate to emit_ldr_str_imm / emit_ldr_str_reg with is_fp=1.
// size: 2=32-bit(S)  3=64-bit(D)  4=128-bit(Q)
// -----------------------------------------------------------------------------

auto emit_fldr_imm(AssemblerBuffer& buf, int size, int Dt, int Rn, int16_t imm12) -> void;

auto emit_fstr_imm(AssemblerBuffer& buf, int size, int Dt, int Rn, int16_t imm12) -> void;

// shift: 0=no LSL,  1=LSL by element size
auto emit_fldr_reg(AssemblerBuffer& buf, int size, int Dt, int Rn, int Rm, int shift) -> void;

auto emit_fstr_reg(AssemblerBuffer& buf, int size, int Dt, int Rn, int Rm, int shift) -> void;

// -----------------------------------------------------------------------------
// 1d — FP Arithmetic (scalar) — all new, no equivalents in the Rosetta binary
// -----------------------------------------------------------------------------

// Scalar FP data-processing, 2 sources
// type:   0=f32  1=f64
// opcode: 0=FMUL  1=FDIV  2=FADD  3=FSUB
auto emit_fp_dp2(AssemblerBuffer& buf, int type, int opcode, int Rd, int Rn, int Rm) -> void;

auto emit_fadd_f64(AssemblerBuffer& buf, int Dd, int Dn, int Dm) -> void;
auto emit_fsub_f64(AssemblerBuffer& buf, int Dd, int Dn, int Dm) -> void;
auto emit_fmul_f64(AssemblerBuffer& buf, int Dd, int Dn, int Dm) -> void;
auto emit_fdiv_f64(AssemblerBuffer& buf, int Dd, int Dn, int Dm) -> void;

// Scalar FP data-processing, 1 source
// type:   0=f32  1=f64
// opcode: 0=FMOV  1=FABS  2=FNEG  3=FSQRT
auto emit_fp_dp1(AssemblerBuffer& buf, int type, int opcode, int Rd, int Rn) -> void;

auto emit_fmov_f64(AssemblerBuffer& buf, int Dd, int Dn) -> void;
auto emit_fabs_f64(AssemblerBuffer& buf, int Dd, int Dn) -> void;
auto emit_fneg_f64(AssemblerBuffer& buf, int Dd, int Dn) -> void;
auto emit_fsqrt_f64(AssemblerBuffer& buf, int Dd, int Dn) -> void;

// FCMP scalar — sets NZCV, no result register
// type: 0=f32  1=f64
auto emit_fp_cmp(AssemblerBuffer& buf, int type, int Rn, int Rm) -> void;
auto emit_fcmp_f64(AssemblerBuffer& buf, int Dn, int Dm) -> void;

// FCVT — FP precision conversion
// dst_type / src_type: 0=f32  1=f64
auto emit_fcvt(AssemblerBuffer& buf, int dst_type, int src_type, int Rd, int Rn) -> void;
auto emit_fcvt_s_to_d(AssemblerBuffer& buf, int Dd, int Sn) -> void;
auto emit_fcvt_d_to_s(AssemblerBuffer& buf, int Sd, int Dn) -> void;

// FMOV GPR <-> FPR (raw bit transfer, no conversion)
// dir: 0=GPR→FPR (Dd=Xn)  1=FPR→GPR (Xd=Dn)
auto emit_fmov_gpr_fpr(AssemblerBuffer& buf, int dir, int gpr, int fpr) -> void;
auto emit_fmov_x_to_d(AssemblerBuffer& buf, int Dd, int Xn) -> void;
auto emit_fmov_d_to_x(AssemblerBuffer& buf, int Xd, int Dn) -> void;

// OPT-5: FP register zero/one without GPR intermediaries
//
// emit_movi_d_zero — MOVI Dd, #0  (Advanced SIMD modified-immediate)
//   Zeroes the D register with no GPR dependency, enabling parallel issue
//   with the ADD Xbase instruction on superscalar cores.
//
// emit_fmov_d_one — FMOV Dd, #1.0  (FP scalar immediate)
//   Loads +1.0 in a single instruction with no GPR intermediate.
//   Replaces the previous MOVZ+FMOV pair (2 insns + cross-domain latency).
auto emit_movi_d_zero(AssemblerBuffer& buf, int Dd) -> void;
auto emit_fmov_d_one(AssemblerBuffer& buf, int Dd) -> void;

// SCVTF — signed integer GPR → FP
// is_64bit_int: 1=64-bit source  0=32-bit
// ftype:        0=f32  1=f64
auto emit_scvtf(AssemblerBuffer& buf, int is_64bit_int, int ftype, int Rd, int Rn) -> void;
auto emit_scvtf_x_to_d(AssemblerBuffer& buf, int Dd, int Xn) -> void;

// FCVTZS — FP → signed integer GPR, truncate toward zero
// ftype:        0=f32  1=f64
// is_64bit_int: 1=64-bit destination  0=32-bit
auto emit_fcvtzs(AssemblerBuffer& buf, int ftype, int is_64bit_int, int Rd, int Rn) -> void;

// -----------------------------------------------------------------------------
// 1e — System / Flags
// -----------------------------------------------------------------------------

// MRS Xd, NZCV — read condition flags into a GPR
// (exists as empty stub in binary @ 0x3a1c — implemented here)
auto emit_mrs_nzcv(AssemblerBuffer& buf, int Xd) -> void;

// ---------------------------------------------------------------------------
// emit_add_reg — mirrors binary at 0x7a8
// Plain register add, handling SP and XZR via extended-reg encoding.
// ---------------------------------------------------------------------------
auto emit_add_reg(AssemblerBuffer& buf, int is_64bit, int dst, int lhs, int rhs) -> void;

// ---------------------------------------------------------------------------
// emit_logical_imm — @ 0xb3c
//
// Encodes AND/ORR/EOR/ANDS (immediate) — the logical immediate instruction class.
// All four share the same encoding, differing only in opc[1:0].
//
// opc:  0=AND  1=ORR  2=EOR  3=ANDS
// N/immr/imms: pre-encoded logical immediate fields from is_bitmask_immediate()
//
// Encoding: sf | opc[1:0] | 100100 | N | immr[5:0] | imms[5:0] | Rn | Rd
//   [31]    = sf  (is_64bit)
//   [30:29] = opc
//   [28:23] = 100100  (fixed)
//   [22]    = N
//   [21:16] = immr
//   [15:10] = imms
//   [9:5]   = Rn
//   [4:0]   = Rd
//
// Note: neither Rn nor Rd may be SP (0x3F). XZR (0x1F) is valid for Rn (source).
// ---------------------------------------------------------------------------
auto emit_logical_imm(AssemblerBuffer& buf, int is_64bit, int opc, int N, int8_t immr, int8_t imms,
                      int Rn, int Rd) -> void;

// ---------------------------------------------------------------------------
// emit_and_imm — @ 0xae0
//
// AND (immediate). Asserts that N==0 when operating in 32-bit mode, since
// the N bit must be 0 for all 32-bit logical immediates per the ARM spec.
//
// Arg order confirmed from disasm: (buf, is_64bit, Rd, N, immr, imms, Rn)
// Call at 0xb08 remaps to emit_logical_imm as: opc=0, N, immr, imms, Rn, Rd
// ---------------------------------------------------------------------------
auto emit_and_imm(AssemblerBuffer& buf, int is_64bit, int Rd, int N, int64_t immr, int64_t imms,
                  int Rn) -> void;

// ---------------------------------------------------------------------------
// emit_orr_imm — @ 0x197c
//
// ORR (immediate). Same N==0 constraint for 32-bit.
//
// Arg order from binary: (buf, is_64bit, Rd, Rn, N, immr, imms)
// Delegates to emit_logical_imm with opc=1.
// ---------------------------------------------------------------------------
auto emit_orr_imm(AssemblerBuffer& buf, int is_64bit, int Rd, int Rn, int N, int64_t immr,
                  int64_t imms) -> void;

auto emit_adr(AssemblerBuffer& buf, int is_adrp, int Rd, uint32_t imm) -> void;

// =============================================================================
// emit_ldrs  (mirrors binary at 0x159c)
//
// Emits a sign-extending load instruction:
//   is_64bit=true  → LDRSW  (loads `size`-byte value, sign-extends to 64 bits)
//   is_64bit=false → LDRSH  (loads `size`-byte value, sign-extends to 32 bits)
//
// Parameters:
//   insn_buf  -- output buffer
//   is_64bit  -- true = LDRSW (opc=S32), false = LDRSH (opc=S64)
//   size      -- source data size (IROperandSize enum value, e.g. S8=0, S16=1, S32=2)
//   dst_gpr   -- destination GPR number (must not be SP or XZR)
//   addr_gpr  -- base address GPR (must not be XZR)
//
// Assertion: data_size (derived from is_64bit) must be >= size, otherwise the
// sign-extension would narrow, which the AArch64 LDRS encoding does not support.
// =============================================================================
auto emit_ldrs(AssemblerBuffer& insn_buf, int is_64bit, unsigned int size, int dst_gpr,
               int addr_gpr) -> void;