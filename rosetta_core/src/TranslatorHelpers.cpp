#include "rosetta_core/TranslatorHelpers.hpp"

#include "rosetta_core/AssemblerHelpers.hpp"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/IROperand.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/RuntimeRoutine.h"

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

int alloc_gpr(TranslationResult& translation, int pool_index) {
    const int reg = kGprScratchPool[pool_index];
    const uint32_t mask = 1u << reg;
    assert((translation.free_gpr_mask & mask) != 0 && "alloc_gpr: pool slot already occupied");
    translation.free_gpr_mask &= ~mask;
    return reg;
}

int alloc_free_gpr(TranslationResult& translation) {
    uint32_t mask = translation.free_gpr_mask;
    assert(mask != 0 && "no temporary GPR available to allocate");
    int reg = __builtin_ctz(mask);  // lowest set bit = binary reverse of __clz(__rbit32)
    translation.free_gpr_mask = mask & ~(1u << reg);
    return reg;
}

auto resolve_hint_gpr(TranslationResult& result, int hint_reg) -> int {
    if (hint_reg == GPR::XZR)
        return alloc_free_gpr(result);
    return hint_reg;
}

void free_gpr(TranslationResult& translation, int reg) {
    assert(reg != 0x3F && "free_gpr: cannot free SP");
    if ((1u << reg) & kGprScratchMask)
        translation.free_gpr_mask |= 1u << reg;
}

int alloc_fpr(TranslationResult& translation, int pool_index) {
    const int reg = kFprScratchPool[pool_index];
    const uint32_t mask = 1u << reg;
    assert((translation.free_fpr_mask & mask) != 0 && "alloc_fpr: pool slot already occupied");
    translation.free_fpr_mask &= ~mask;
    return reg;
}

auto alloc_free_fpr(TranslationResult& translation) -> int {
    uint32_t mask = translation.free_fpr_mask;
    assert(mask != 0 && "no temporary FPR available to allocate");
    int reg = __builtin_ctz(mask);  // lowest set bit = binary reverse of __clz(__rbit32)
    translation.free_fpr_mask = mask & ~(1u << reg);
    return reg;
}

void free_fpr(TranslationResult& translation, int reg) {
    if ((1u << reg) & kFprScratchMask)
        translation.free_fpr_mask |= 1u << reg;
}

auto emit_load_immediate(TranslationResult& result, int is_64bit, uint64_t value, int dst_reg)
    -> int {
    if (value == 0)
        return GPR::XZR;

    int reg = dst_reg;
    if (dst_reg == GPR::XZR)
        reg = alloc_free_gpr(result);

    uint64_t v = is_64bit ? value : (uint32_t)value;
    if (!v) {
        // value was non-zero but truncated to 0 for 32-bit — emit MOVZ #0
        emit_movn(result.insn_buf, is_64bit, /*opc=*/2, 0, 0, reg);
        return reg;
    }

    // Try logical immediate encoding first
    LogicalImmEncoding enc;
    if (is_bitmask_immediate(is_64bit, v, enc)) {
        // ORR Xreg, XZR, #imm
        // extern void emit_orr_imm(AssemblerBuffer*, int, int, int, int, int, int);
        emit_orr_imm(result.insn_buf, is_64bit, reg, GPR::XZR, enc.N, enc.immr, enc.imms & 0x3F);
        return reg;
    }

    // Count zero 16-bit chunks and 0xFFFF chunks to choose MOVZ vs MOVN
    int zeros = 0, ones = 0;
    int chunks = is_64bit ? 4 : 2;
    for (int i = 0; i < chunks; i++) {
        uint16_t chunk = (uint16_t)(v >> (16 * i));
        if (chunk == 0)
            zeros++;
        if (chunk == 0xFFFF)
            ones++;
    }

    bool use_movz = (zeros >= ones);
    uint64_t working = use_movz ? v : ~v;

    // Find the highest non-trivial chunk
    int hi_chunk = 0, lo_chunk = 0;
    for (int i = chunks - 1; i >= 0; i--) {
        uint16_t chunk = (uint16_t)(working >> (16 * i));
        if (chunk) {
            hi_chunk = i;
            break;
        }
    }
    for (int i = 0; i < chunks; i++) {
        uint16_t chunk = (uint16_t)(working >> (16 * i));
        if (chunk) {
            lo_chunk = i;
            break;
        }
    }

    // Emit MOVZ/MOVN for the starting chunk
    uint16_t start_val = (uint16_t)(working >> (16 * hi_chunk));
    uint16_t trivial = use_movz ? 0x0000 : 0xFFFF;
    emit_movn(result.insn_buf, is_64bit, use_movz ? 2 : 0, hi_chunk, start_val, reg);

    // Emit MOVK for remaining non-trivial chunks
    for (int i = hi_chunk - 1; i >= lo_chunk; i--) {
        uint16_t chunk = (uint16_t)(v >> (16 * i));
        if (chunk != trivial)
            emit_movn(result.insn_buf, is_64bit, /*MOVK=*/3, i, chunk, reg);
    }

    return reg;
}

auto emit_load_immediate_no_xzr(TranslationResult& result, int is_64bit, uint64_t value,
                                int dst_reg) -> void {
    int result_reg = emit_load_immediate(result, is_64bit, value, dst_reg);
    if (result_reg == GPR::XZR) {
        emit_movn(result.insn_buf, is_64bit, /*MOVZ=*/2, 0, 0, dst_reg);
    } else {
        assert(result_reg == dst_reg && "unexpected emit_load_immediate result register");
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Mirrors the binary's __clz(__rbit32(mask)) pattern: finds the lowest set bit
// index, clears it in free_gpr_mask, and returns the register number.
// Aborts if no free register is available (matches LABEL_104 / ASSERT3).
static int alloc_scratch_gpr(TranslationResult& result) {
    uint32_t mask = result.free_gpr_mask;
    if (!mask) {
        assert(false && "no temporary GPR available to allocate");
        __builtin_unreachable();
    }
    int r = __builtin_ctz(mask);
    result.free_gpr_mask = mask & ~(1u << r);
    return r;
}

// Returns true if `reg` is any entry in kGprScratchPool (bits 22–29).
// The binary checks this via a linear pool search + special-case for X22.
static bool is_scratch_pool_reg(int reg) {
    return (reg >= 0) && (reg < 32) && (((kGprScratchMask >> reg) & 1u) != 0);
}

// =============================================================================
// compute_mem_operand_address — mirrors binary at 0x20390
//
// Computes the effective address for an IROperand::MemRef into a register.
// The four cases, determined by mem_flags:
//   bit0 = has_base_reg
//   bit1 = has_index_reg
//
//   (3) base + index*scale + disp
//   (1) base + disp
//   (2) index*scale + disp
//   (0) disp only
// =============================================================================
auto compute_mem_operand_address(TranslationResult& result, bool is_64bit, IROperand* operand,
                                 int dst_reg) -> int {
    int result_reg = dst_reg;

    // -------------------------------------------------------------------------
    // Load disp as unsigned — the binary uses unsigned __int64 for all
    // comparisons; a negative int64_t must NOT be treated as a small positive.
    // -------------------------------------------------------------------------
    const uint64_t disp = static_cast<uint64_t>(operand->mem.disp);

    // -------------------------------------------------------------------------
    // Determine if the displacement can be encoded as ADD/SUB imm12 or imm12<<12.
    // Builds (is_add, imm_shift, imm_value) for later emit_add_imm calls.
    // -------------------------------------------------------------------------
    uint64_t imm_value = 0;
    int imm_shift = 0;  // 0 = use as-is, 1 = imm12<<12
    bool is_add = true;
    bool disp_encodable = false;

    if (disp < 0x1000u) {
        imm_value = disp;
        imm_shift = 0;
        is_add = true;
        disp_encodable = true;
    } else if ((disp & 0xFFFFFFFFFF000FFFull) == 0) {
        // Fits in shifted form: value is page-aligned, top bits zero
        imm_value = disp >> 12;
        imm_shift = 1;
        is_add = true;
        disp_encodable = true;
    } else {
        // Try negated (SUB) forms
        const uint64_t neg = static_cast<uint64_t>(-static_cast<int64_t>(disp));
        if (neg < 0x1000u) {
            imm_value = neg;
            imm_shift = 0;
            is_add = false;
            disp_encodable = true;
        } else if ((neg & 0xFFFFFFFFFF000FFFull) == 0) {
            imm_value = neg >> 12;
            imm_shift = 1;
            is_add = false;
            disp_encodable = true;
        }
        // else: disp_encodable stays false — must use emit_load_immediate_no_xzr
    }

    // -------------------------------------------------------------------------
    // Decode mem_flags
    // -------------------------------------------------------------------------
    const uint8_t mem_flags = operand->mem.mem_flags;
    const bool has_base = (mem_flags & 1) != 0;   // bit0
    const bool has_index = (mem_flags & 2) != 0;  // bit1

    // =========================================================================
    // Case (3): has_base AND has_index
    //   Condition in binary: (mem_flags & 2) != 0 && ((mem_flags ^ 1) & 1) == 0
    // =========================================================================
    if (has_base && has_index) {
        const uint32_t base_enc = operand->mem.base_reg;
        const uint32_t index_enc = operand->mem.index_reg;

        // Both must be GPRs (encoded byte < 0x50)
        if (base_enc >= 0x50 || index_enc >= 0x50) {
            assert(false && "translate_gpr called on non-GPR");
            __builtin_unreachable();
        }

        const int base_idx = (int)(base_enc & 0xF);
        const int index_idx = (int)(index_enc & 0xF);

        if (disp) {
            // We need one scratch register.
            // Strategy (mirrors binary pool-search logic):
            //   If dst_reg is already a scratch-pool register, reuse it directly.
            //   Otherwise allocate a new one; if dst_reg==XZR use the new one as
            //   both result_reg and scratch_reg, else use dst_reg as scratch_reg.
            int scratch_reg;
            if (is_scratch_pool_reg(dst_reg)) {
                scratch_reg = dst_reg;
                result_reg = dst_reg;
            } else {
                const int alloc = alloc_scratch_gpr(result);
                result_reg = alloc;
                scratch_reg = (dst_reg == GPR::XZR) ? alloc : dst_reg;
            }

            if (disp_encodable) {
                // result_reg = base + disp  (ADD or SUB immediate)
                emit_add_imm(result.insn_buf, is_64bit, /*is_sub=*/!is_add, 0, imm_shift,
                             (int64_t)imm_value, base_idx, result_reg);
                // scratch_reg = result_reg + index*scale
                emit_add_sub_shifted_reg(result.insn_buf, is_64bit,
                                         /*is_sub=*/0, /*set_flags=*/0,
                                         /*shift_type=*/0 /*LSL*/, index_idx,
                                         operand->mem.shift_amount, result_reg, scratch_reg);
            } else {
                // result_reg = disp  (full 64-bit immediate load)
                emit_load_immediate_no_xzr(result, is_64bit, disp, result_reg);
                // result_reg = result_reg + index*scale  = disp + index*scale
                emit_add_sub_shifted_reg(result.insn_buf, is_64bit, 0, 0, 0, index_idx,
                                         operand->mem.shift_amount, result_reg, result_reg);
                // scratch_reg = base + result_reg  = base + disp + index*scale
                emit_add_reg(result.insn_buf, is_64bit, scratch_reg, base_idx, result_reg);
            }

            // result_reg was an intermediate; if it differs from the output
            // register, free it and return the output.
            if (result_reg != scratch_reg) {
                free_gpr(result, result_reg);
                return scratch_reg;
            }
            return result_reg;
        } else {
            // No displacement: result = base + index*scale
            if (dst_reg == GPR::XZR)
                result_reg = alloc_scratch_gpr(result);

            emit_add_sub_shifted_reg(result.insn_buf, is_64bit, 0, 0, 0, index_idx,
                                     operand->mem.shift_amount, base_idx, result_reg);
            return result_reg;
        }
    }

    // =========================================================================
    // Case (1): has_base only
    //   In binary: outer-if (has_index||!has_base) is FALSE here, so this is
    //   the outer-else branch at 0x2046c.
    // =========================================================================
    if (has_base && !has_index) {
        const uint32_t base_enc = operand->mem.base_reg;
        if (base_enc >= 0x50) {
            assert(false && "translate_gpr called on non-GPR");
            __builtin_unreachable();
        }
        const int base_idx = (int)(base_enc & 0xF);

        if (disp) {
            if (!disp_encodable) {
                // Need a scratch to hold the immediate, then ADD base
                int scratch_reg;
                if (is_scratch_pool_reg(dst_reg)) {
                    scratch_reg = dst_reg;
                    result_reg = dst_reg;
                } else {
                    const int alloc = alloc_scratch_gpr(result);
                    result_reg = alloc;
                    scratch_reg = (dst_reg == GPR::XZR) ? alloc : dst_reg;
                }
                emit_load_immediate_no_xzr(result, is_64bit, disp, result_reg);
                // scratch_reg = base + result_reg
                emit_add_reg(result.insn_buf, is_64bit, scratch_reg, base_idx, result_reg);
                if (result_reg != scratch_reg) {
                    free_gpr(result, result_reg);
                    return scratch_reg;
                }
                return result_reg;
            }

            // disp fits in imm12 (possibly shifted)
            if (dst_reg == GPR::XZR)
                result_reg = alloc_scratch_gpr(result);

            emit_add_imm(result.insn_buf, is_64bit, /*is_sub=*/!is_add, 0, imm_shift,
                         (int64_t)imm_value, base_idx, result_reg);
            return result_reg;
        } else {
            // No displacement
            if (!is_64bit) {
                // 32-bit: must emit a W-register MOV to zero-extend properly.
                // Returning the source register directly is incorrect here.
                if (dst_reg == GPR::XZR)
                    result_reg = alloc_scratch_gpr(result);

                emit_mov_reg(result.insn_buf, /*is_64bit=*/0, result_reg, base_idx);
                return result_reg;
            }
            // 64-bit: can return the register number directly — no instruction needed.
            return base_idx;
        }
    }

    // =========================================================================
    // Cases (2) and (0): has_index only, or neither.
    //   Binary reaches here via the outer-if (has_index||!has_base) being TRUE.
    // =========================================================================

    if (!has_base && has_index) {
        // =====================================================================
        // Case (2): has_index only
        // =====================================================================
        const uint32_t index_enc = operand->mem.index_reg;
        if (index_enc >= 0x50) {
            assert(false && "translate_gpr called on non-GPR");
            __builtin_unreachable();
        }
        const int index_idx = (int)(index_enc & 0xF);

        if (disp) {
            // Need a register to hold the displacement, then add index*scale.
            int disp_reg;
            if (is_scratch_pool_reg(dst_reg)) {
                disp_reg = dst_reg;
                result_reg = dst_reg;
            } else {
                const int alloc = alloc_scratch_gpr(result);
                disp_reg = alloc;
                result_reg = (dst_reg == GPR::XZR) ? alloc : dst_reg;
            }

            emit_load_immediate_no_xzr(result, is_64bit, disp, disp_reg);
            // result_reg = disp_reg + index * scale
            emit_add_sub_shifted_reg(result.insn_buf, is_64bit, 0, 0, 0, index_idx,
                                     operand->mem.shift_amount, disp_reg, result_reg);
            if (disp_reg != result_reg)
                free_gpr(result, disp_reg);
            return result_reg;
        }

        // No displacement
        const uint8_t shift = operand->mem.shift_amount;
        if (shift) {
            // Emit a LSL via UBFM: immr = (width - shift), imms = (width - shift - 1)
            if (dst_reg == GPR::XZR)
                result_reg = alloc_scratch_gpr(result);

            const int reg_width = is_64bit ? 64 : 32;
            // N bit must equal is_64bit for UBFM
            emit_bitfield(result.insn_buf, is_64bit, /*opc=*/2 /*UBFM*/,
                          /*N=*/is_64bit ? 1 : 0,
                          /*immr=*/(int8_t)(reg_width - shift),
                          /*imms=*/(int8_t)(reg_width - shift - 1), index_idx, result_reg);
            return result_reg;
        }

        // No displacement, no shift
        if (is_64bit) {
            // 64-bit: can return the index register directly
            return index_idx;
        }
        // 32-bit: must emit a W-register MOV (zero-extension)
        if (dst_reg == GPR::XZR)
            result_reg = alloc_scratch_gpr(result);

        emit_mov_reg(result.insn_buf, /*is_64bit=*/0, result_reg, index_idx);
        return result_reg;
    }

    // =========================================================================
    // Case (0): neither base nor index — displacement only
    // =========================================================================
    {
        // Sanity check: must truly have neither
        if (has_base || has_index) {
            assert(false && "unexpected memory operand");
            __builtin_unreachable();
        }

        if (disp) {
            // emit_load_immediate handles XZR dst_reg and returns the register used.
            return emit_load_immediate(result, is_64bit, disp, dst_reg);
        }

        // Zero displacement, no base, no index.
        // Binary emits MOVZ W<result_reg>, #0 — does NOT return XZR.
        if (dst_reg == GPR::XZR)
            result_reg = alloc_scratch_gpr(result);

        emit_movn(result.insn_buf, /*is_64bit=*/0, /*opc=*/2 /*MOVZ*/,
                  /*hw=*/0, /*imm16=*/0, result_reg);
        return result_reg;
    }
}

// =============================================================================
// compute_operand_address — mirrors binary at 0x1fffc
//
// Public entry point. Dispatches on operand kind:
//   MemRef    → compute_mem_operand_address
//   AbsMem    → emit_load_immediate_no_xzr (absolute address constant)
//   Immediate → ADRP+ADD pair with external fixups (+ optional addend)
//
// CRITICAL: addr_size_is_64 is DERIVED from the operand's own addr_size field,
// gated by the caller's is_64bit flag. The raw is_64bit is never forwarded
// directly to callees. If is_64bit==0, addr_size_is_64 is forced false.
// =============================================================================
auto compute_operand_address(TranslationResult& result, int is_64bit, IROperand* op, int dst_reg)
    -> int {
    // -------------------------------------------------------------------------
    // Derive address width from the operand's own addr_size field.
    // Reading op->mem.addr_size is safe for all relevant kinds (MemRef, AbsMem,
    // Immediate) because addr_size lives at offset +2 in every union member.
    // -------------------------------------------------------------------------
    bool addr_size_is_64 = false;
    if (is_64bit) {
        const IROperandSize addr_size = op->mem.addr_size;
        if (addr_size >= IROperandSize::S128) {
            assert(false && "OperandSize does not correspond to a DataSize");
            __builtin_unreachable();
        }
        addr_size_is_64 = (addr_size == IROperandSize::S64);
    }

    // -------------------------------------------------------------------------
    // Segment override handling (FS=1, GS/TLS=2).
    // Recurse with a seg_override-cleared copy to get the base address, then
    // add the segment base on top.
    // -------------------------------------------------------------------------
    if (op->mem.seg_override) {
        // Recursive call with seg_override cleared — uses addr_size_is_64, not is_64bit
        IROperand op_copy = *op;
        op_copy.reg.seg_override = 0;
        const int inner_reg =
            compute_operand_address(result, (int)addr_size_is_64, &op_copy, dst_reg);

        // Allocate a scratch GPR for the segment base register
        const int seg_reg = alloc_scratch_gpr(result);

        const int seg_override = op->mem.seg_override;

        if (seg_override == 1) {
            // FS segment: load 32-bit selector base from thread context at X18
            // field_8 is a byte offset; divide by 4 for the imm12 of a 32-bit LDR.
            emit_ldr_imm(result.insn_buf, /*size=*/2 /*32-bit*/, seg_reg, GPR::X18,
                         (int16_t)(result.thread_context_offsets->field_8 >> 2));
            emit_add_reg(result.insn_buf, addr_size_is_64, seg_reg, seg_reg, inner_reg);
        } else if (seg_override == 2) {
            // GS / TLS segment: call get_tls_base runtime routine.
            // Must use pool slot 7 (X29) specifically — NOT alloc_free_gpr.
            const int tls_tmp = alloc_gpr(result, 7);  // kGprScratchPool[7] = X29

            // Emit BL #0 patched by a Branch26 fixup to kRuntimeRoutine_get_tls_base
            result._fixups.push_back(Fixup{FixupKind::Branch26, (uint32_t)result.insn_buf.end,
                                           (uint32_t)kRuntimeRoutine_get_tls_base});
            result.insn_buf.emit(0x94000000u);  // BL placeholder

            // In JIT mode (translator_variant==1): dereference the TLS block pointer
            // at offset 6*8=48 into tls_tmp before adding inner_reg.
            int tls_base = tls_tmp;
            if (result.translator_variant == 1) {
                emit_ldr_imm(result.insn_buf, /*size=*/3 /*64-bit*/, seg_reg, tls_tmp,
                             /*imm12=*/6);  // byte offset = 6*8 = 48
                tls_base = seg_reg;
            }

            emit_add_reg(result.insn_buf, /*is_64bit=*/1, seg_reg, tls_base, inner_reg);

            free_gpr(result, tls_tmp);
        } else {
            assert(false && "expected segment override");
            __builtin_unreachable();
        }

        // Free the intermediate inner_reg if it isn't the original dst_reg
        if (inner_reg != dst_reg)
            free_gpr(result, inner_reg);

        return seg_reg;
    }

    // -------------------------------------------------------------------------
    // Dispatch on operand kind
    // -------------------------------------------------------------------------
    const IROperandKind kind = op->kind;

    // --- MemRef: normal base/index/disp address computation ------------------
    if (kind == IROperandKind::MemRef) {
        // Forward addr_size_is_64, NOT the raw is_64bit.
        return compute_mem_operand_address(result, addr_size_is_64, op, dst_reg);
    }

    // --- AbsMem: absolute 64-bit constant address ----------------------------
    if (kind == IROperandKind::AbsMem) {
        int out_reg = dst_reg;
        if (dst_reg == GPR::XZR)
            out_reg = alloc_scratch_gpr(result);

        emit_load_immediate_no_xzr(result, addr_size_is_64, op->abs_mem.value, out_reg);
        return out_reg;
    }

    // --- Immediate: ADRP+ADD pair with fixup, optional addend ----------------
    if (kind == IROperandKind::Immediate) {
        int out_reg = dst_reg;
        if (dst_reg == GPR::XZR)
            out_reg = alloc_scratch_gpr(result);

        // fixup_target: use imm.value as the target id when mem_flags != 0,
        // otherwise 0 (no fixup target — anonymous address).
        const int32_t fixup_target = op->imm.mem_flags ? (int32_t)op->imm.value : 0;

        // Emit ADRP out_reg, <page>   [patched by Arm64Page21 fixup]
        result.external_fixups.push_back(
            Fixup{FixupKind::Arm64Page21, (uint32_t)result.insn_buf.end, (uint32_t)fixup_target});
        emit_adr(result.insn_buf, /*is_adrp=*/1, out_reg, 0);

        // Emit ADD out_reg, out_reg, #<page_offset>   [patched by Arm64PageOffset12]
        result.external_fixups.push_back(Fixup{
            FixupKind::Arm64PageOffset12, (uint32_t)result.insn_buf.end, (uint32_t)fixup_target});
        emit_add_imm(result.insn_buf, addr_size_is_64, 0, 0, 0, 0, out_reg, out_reg);

        // If bit0 of mem_flags is CLEAR, the immediate also carries a runtime
        // addend in imm.value that must be added to out_reg at run time.
        // (bit0 set means "has_addend is already baked into the fixup target".)
        if ((op->imm.mem_flags & 1) == 0) {
            const int addend_reg = alloc_scratch_gpr(result);
            emit_load_immediate_no_xzr(result, /*is_64bit=*/1, op->imm.value, addend_reg);
            emit_add_reg(result.insn_buf, addr_size_is_64, out_reg, out_reg, addend_reg);
            free_gpr(result, addend_reg);
        }
        return out_reg;
    }

    assert(false && "invalid OperandKind");
    __builtin_unreachable();
}

// =============================================================================
// translate_gpr  (mirrors binary at 0x20e14)
//
// Translates a source GPR operand into a target GPR, inserting any extension
// or truncation moves required by the register's sub-size encoding.
//
// The `reg` byte encodes both which architectural register and what size slice:
//   bits[3:0] = register index (0–15)
//   bits[7:4] = size class:
//     0 = full width (use index directly, no move needed)
//     1 = 8-bit low  (BFX byte from reg, e.g. AL/CL/DL)
//     2 = 8-bit high (BFX high byte, e.g. AH/CH)
//     3 = 16-bit     (BFX word)
//
// Parameters:
//   result      -- translation state (for scratch GPR allocation)
//   is_64bit    -- true = 64-bit context (affects bitfield width in extend ops)
//   reg         -- encoded register byte (index | size_class<<4)
//   extend_mode -- 0 = no extend (raw index only)
//                  1 = zero-extend narrower sub-register into dst
//                  2 = sign-extend narrower sub-register into dst
//   hint_reg    -- preferred destination GPR; XZR means "allocate one"
//
// Returns the GPR number that holds the result. The caller is responsible for
// freeing it with free_gpr() if it was freshly allocated.
// =============================================================================
auto translate_gpr(TranslationResult* result, int is_64bit, uint8_t reg, unsigned int extend_mode,
                   int hint_reg) -> int {
    assert((reg & 0xFF) < 0x50 && "translate_gpr: called on non-GPR register");

    const int index = (int)(reg & 0xF);
    const int size_class = (int)((reg >> 4) & 0xF);

    // -------------------------------------------------------------------------
    // Branch to BFX block (loc_20E9C) when:
    //   extend_mode==0, OR reg<0x10 (full-width), OR size_class==1 (byte-high)
    //
    // Binary: CCMP W9, #0x10, #2, NE  then B.CC → also B.EQ for size_class==1
    // -------------------------------------------------------------------------
    const bool needs_extend = (extend_mode != 0) && (reg >= 0x10);
    const bool go_to_bfx = !needs_extend || (size_class == 1);

    if (go_to_bfx) {
        // Fast-path: full-width register with no extension — just return index.
        // Condition: !needs_extend AND size_class is not byte-high (1).
        if (!needs_extend && size_class != 1)
            return index;

        // BFX path for size_class 0 or 1.
        // immr = size_class * 8:
        //   size_class 0 → immr=0, imms=7  → UBFX[7:0]  (full-width byte context)
        //   size_class 1 → immr=8, imms=15 → UBFX[15:8] (high byte: AH/BH/CH/DH)
        int dst = (hint_reg == GPR::XZR) ? alloc_free_gpr(*result) : hint_reg;
        const int8_t immr = (int8_t)(size_class * 8);
        const int8_t imms = (int8_t)(immr | 7);
        // opc: extend_mode>1 → SBFX(0), else → UBFX(2)
        // is_64bit passed as N and as the is_64bit arg
        const int opc = (extend_mode > 1) ? 0 : 2;
        const int N = (is_64bit != 0) ? 1 : 0;
        emit_bitfield(result->insn_buf, is_64bit != 0, opc, N, immr, imms, index, dst);
        return dst;
    }

    // -------------------------------------------------------------------------
    // size_class == 2: byte-low (AL/BL/CL/DL)
    // Binary at 0x20e50–0x20e54: CMP W8, #2 / B.NE loc_20EF0
    // immr=0, imms=7 — but this is the sign/zero extend of a full low byte.
    // Reaches here only when extend_mode!=0 AND reg>=0x10 AND size_class==2.
    // Binary loc_20F50: CMP W3, #1 / B.HI → opc=0 (SBFX) if extend>1 else UBFX
    // -------------------------------------------------------------------------
    if (size_class == 2) {
        // Binary at 0x20f50:
        //   CMP W1, #0 / CSET W1, NE  → is_64bit = (is_64bit != 0)
        //   ORR W5, W4, #7            → imms = immr|7, but immr=0 here (class 2 * 8... wait)
        // Actually loc_20F50 is reached from the size_class<=1 block via B.HI on extend_mode>1.
        // For size_class==2 we go to loc_20EF0 which then falls to size_class==3 check.
        // size_class==2 with extend_mode!=0: same BFX block as class 0/1 but via loc_20F50.
        // immr = size_class*8 = 16? No — re-read: loc_20F50 is entered from the SAME
        // BFX block (loc_20E9C) when extend_mode > 1. Let's re-trace:
        //
        // loc_20E9C is entered for size_class==0 OR size_class==1 OR !needs_extend.
        // For size_class==2: needs_extend=true, size_class!=1 → does NOT go to loc_20E9C.
        // For size_class==2: goes to loc_20EF0.
        // loc_20EF0: CBZ W3 → if extend_mode==0 → loc_20F6C (return index)
        //            CMP W1,#1 / B.NE → if !is_64bit → loc_20F6C
        //            CMP W8,#3 / B.NE → if size_class!=3 → loc_20F6C
        // So size_class==2 always falls to loc_20F6C regardless!
        // loc_20F6C: CBZ W3 → extend_mode==0: return index (loc_20FD0 = MOV X19,X6)
        //            CMP W8,#3 / B.NE → size_class!=3: return index
        //            CBNZ W1 → is_64bit!=0: return index
        //            CMP W19,#0x1F / B.EQ → hint_reg==XZR: return index
        //            → emit_mov_reg(hint_reg, index)
        //
        // So size_class==2: returns index OR emits MOV, never BFX.
        // Fall through to the size_class==3/fallthrough logic below.
    }

    // -------------------------------------------------------------------------
    // loc_20EF0: reached for size_class==2 or size_class==3 (with needs_extend)
    // Also reached for size_class>=4 (undefined, falls to loc_20F6C)
    // -------------------------------------------------------------------------

    // size_class == 3, extend_mode!=0, is_64bit==1 → sign-extend word → 64-bit
    if (size_class == 3 && extend_mode != 0 && is_64bit == 1) {
        // Binary at 0x20f04: allocate hint_reg if XZR (Bug 3 fix)
        int dst = (hint_reg == GPR::XZR) ? alloc_free_gpr(*result) : hint_reg;

        if (extend_mode == 2) {
            // SBFX: sign-extend 32-bit → 64-bit
            // Binary: is_64bit=1, opc=0, N=1, immr=0, imms=0x1F, rn=index, rd=dst
            emit_bitfield(result->insn_buf, /*is_64bit=*/1,
                          /*opc=*/0, /*N=*/1,
                          /*immr=*/0, /*imms=*/0x1F, index, dst);
            return dst;
        }
        // extend_mode==1: zero-extend — W-register read already zero-extends on
        // AArch64. Return index directly (no allocation consumed).
        return index;
    }

    // -------------------------------------------------------------------------
    // loc_20F6C: fallthrough for size_class 2, size_class 3 with extend_mode==0
    // or !is_64bit, or undefined size_class.
    //
    // Binary:
    //   CBZ W3, loc_20FD0         → extend_mode==0: return index
    //   CMP W8,#3 / B.NE loc_20FD0 → size_class!=3: return index
    //   CBNZ W1, loc_20FD0        → is_64bit!=0: return index
    //   CMP W19,#0x1F / B.EQ loc_20FD0 → hint_reg==XZR: return index
    //   → emit_mov_reg(hint_reg, index); return hint_reg
    // -------------------------------------------------------------------------
    if (extend_mode == 0 || size_class != 3 || is_64bit != 0 || hint_reg == GPR::XZR) {
        return index;
    }

    // Only case remaining: size_class==3, extend_mode!=0, is_64bit==0,
    // hint_reg is a real register. Emit plain 32-bit MOV.
    emit_mov_reg(result->insn_buf, /*is_64bit=*/0, hint_reg, index);
    return hint_reg;
}

auto read_operand_to_gpr(TranslationResult& result, bool is_64bit, IROperand* operand,
                         int extend_mode, int hint_reg) -> int {
    if (operand->kind == IROperandKind::Register) {
        return translate_gpr(&result, (int)is_64bit, operand->reg.reg.value, extend_mode, hint_reg);
    }

    if (operand->kind == IROperandKind::BranchOffset) {
        return emit_load_immediate(result, is_64bit, (uint64_t)operand->branch.value, hint_reg);
    }

    if (operand->kind == IROperandKind::Immediate) {
        return emit_load_immediate(result, is_64bit, (uint64_t)operand->imm.value, hint_reg);
    }

    if (operand->kind == IROperandKind::MemRef) {
        const int dst_reg = resolve_hint_gpr(result, hint_reg);

        const IROperandSize addr_size = operand->mem.addr_size;
        assert(addr_size < IROperandSize::S128 && "OperandSize does not correspond to a DataSize");

        const int addr_reg = compute_operand_address(result, (int)(addr_size == IROperandSize::S64),
                                                     operand, (int64_t)dst_reg);

        const uint32_t mem_size = (uint32_t)operand->mem.size;
        assert(mem_size < (uint32_t)IROperandSize::S256 && "invalid OperandSize for memory load");

        const uint32_t natural_size =
            is_64bit ? (uint32_t)IROperandSize::S32 : (uint32_t)IROperandSize::S16;
        if (extend_mode == 2 && natural_size >= mem_size)
            emit_ldrs(result.insn_buf, (int)is_64bit, mem_size, dst_reg, addr_reg);
        else
            emit_ldr_str_imm(result.insn_buf, (int)mem_size,
                             /*is_fp=*/0, /*opc=*/1,
                             /*imm12=*/0, addr_reg, dst_reg);

        return dst_reg;
    }

    if (operand->kind == IROperandKind::AbsMem) {
        const int out_reg = resolve_hint_gpr(result, hint_reg);

        const int addr_reg = compute_operand_address(result,
                                                     /*is_64bit=*/1, operand, (int64_t)out_reg);

        const uint32_t mem_size = (uint32_t)operand->abs_mem.size;
        assert(mem_size < (uint32_t)IROperandSize::S256 && "invalid OperandSize for AbsMem load");

        const uint32_t natural_size =
            is_64bit ? (uint32_t)IROperandSize::S32 : (uint32_t)IROperandSize::S16;
        if (extend_mode == 2 && natural_size >= mem_size)
            emit_ldrs(result.insn_buf, (int)is_64bit, mem_size, out_reg, addr_reg);
        else
            emit_ldr_str_imm(result.insn_buf, (int)mem_size,
                             /*is_fp=*/0, /*opc=*/1,
                             /*imm12=*/0, addr_reg, out_reg);

        return out_reg;
    }

    assert(false && "read_operand_to_gpr: invalid OperandKind");
    __builtin_unreachable();
}