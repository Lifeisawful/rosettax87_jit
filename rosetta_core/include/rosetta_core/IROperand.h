#pragma once

#include <cstddef>
#include <cstdint>

#include "rosetta_core/Register.h"

enum class IROperandKind : uint8_t {
    Register = 0x0,
    MemRef = 0x1,
    AbsMem = 0x2,
    Immediate = 0x3,
    BranchOffset = 0x4,
    ConditionCode = 0x5,
    SegmentRegister = 0x6,
};

enum class IROperandSize : uint8_t {
    S8 = 0x0,
    S16 = 0x1,
    S32 = 0x2,
    S64 = 0x3,
    S128 = 0x4,
    S256 = 0x5,
    S80 = 0xFF,  // x87 80-bit extended precision (long double)
};

struct IROperandRegister {
    IROperandKind kind;    // +0
    IROperandSize size;    // +1
    Register reg;          // +2   encoded register byte
    uint8_t seg_override;  // +3
    uint8_t _pad[4];       // +4
    int64_t _unused;       // +8   (value not used for registers)
};

static_assert(sizeof(IROperandRegister) == 16, "IROperandRegister must be 16 bytes");
static_assert(offsetof(IROperandRegister, kind) == 0,
              "IROperandRegister::kind must be at offset 0");
static_assert(offsetof(IROperandRegister, size) == 1,
              "IROperandRegister::size must be at offset 1");
static_assert(offsetof(IROperandRegister, reg) == 2, "IROperandRegister::reg must be at offset 2");
static_assert(offsetof(IROperandRegister, seg_override) == 3,
              "IROperandRegister::seg_override must be at offset 3");

struct IROperandMemRef {
    IROperandKind kind;       // +0
    IROperandSize size;       // +1
    IROperandSize addr_size;  // +2  ← used by compute_operand_address
    uint8_t seg_override;     // +3
    uint8_t mem_flags;        // +4   bit0=has_base_reg, bit1=has_index_reg
    uint8_t base_reg;         // +5   encoded register byte
    uint8_t index_reg;        // +6   encoded register byte
    uint8_t shift_amount;     // +7
    int64_t disp;             // +8
};

static_assert(sizeof(IROperandMemRef) == 16, "IROperandMemRef must be 16 bytes");
static_assert(offsetof(IROperandMemRef, kind) == 0, "IROperandMemRef::kind must be at offset 0");
static_assert(offsetof(IROperandMemRef, size) == 1, "IROperandMemRef::size must be at offset 1");
static_assert(offsetof(IROperandMemRef, addr_size) == 2,
              "IROperandMemRef::addr_size must be at offset 2");
static_assert(offsetof(IROperandMemRef, seg_override) == 3,
              "IROperandMemRef::seg_override must be at offset 3");
static_assert(offsetof(IROperandMemRef, mem_flags) == 4,
              "IROperandMemRef::mem_flags must be at offset 4");
static_assert(offsetof(IROperandMemRef, base_reg) == 5,
              "IROperandMemRef::base_reg must be at offset 5");
static_assert(offsetof(IROperandMemRef, index_reg) == 6,
              "IROperandMemRef::index_reg must be at offset 6");
static_assert(offsetof(IROperandMemRef, shift_amount) == 7,
              "IROperandMemRef::shift_amount must be at offset 7");
static_assert(offsetof(IROperandMemRef, disp) == 8, "IROperandMemRef::disp must be at offset 8");

struct IROperandAbsMem {
    IROperandKind kind;       // +0
    IROperandSize size;       // +1
    IROperandSize addr_size;  // +2  ← used by compute_operand_address
    uint8_t _pad[5];          // +3
    int64_t value;            // +8
};

static_assert(sizeof(IROperandAbsMem) == 16, "IROperandAbsMem must be 16 bytes");
static_assert(offsetof(IROperandAbsMem, kind) == 0, "IROperandAbsMem::kind must be at offset 0");
static_assert(offsetof(IROperandAbsMem, size) == 1, "IROperandAbsMem::size must be at offset 1");
static_assert(offsetof(IROperandAbsMem, addr_size) == 2,
              "IROperandAbsMem::addr_size must be at offset 2");
static_assert(offsetof(IROperandAbsMem, value) == 8, "IROperandAbsMem::value must be at offset 8");

struct IROperandImmediate {
    IROperandKind kind;       // +0
    IROperandSize size;       // +1
    IROperandSize addr_size;  // +2
    uint8_t _pad;             // +3
    uint8_t mem_flags;        // +4  bit0=has_addend, non-zero=has_fixup_target
    uint8_t _pad2[3];         // +5
    int64_t value;            // +8  fixup target_id and/or addend
};

static_assert(sizeof(IROperandImmediate) == 16, "IROperandImmediate must be 16 bytes");
static_assert(offsetof(IROperandImmediate, kind) == 0,
              "IROperandImmediate::kind must be at offset 0");
static_assert(offsetof(IROperandImmediate, size) == 1,
              "IROperandImmediate::size must be at offset 1");
static_assert(offsetof(IROperandImmediate, addr_size) == 2,
              "IROperandImmediate::addr_size must be at offset 2");
static_assert(offsetof(IROperandImmediate, mem_flags) == 4,
              "IROperandImmediate::mem_flags must be at offset 4");
static_assert(offsetof(IROperandImmediate, value) == 8,
              "IROperandImmediate::value must be at offset 8");

struct IROperandBranchOffset {
    IROperandKind kind;  // +0
    uint8_t _pad[7];     // +1   layout TBD
    int64_t value;       // +8   branch target offset (likely)
};

static_assert(sizeof(IROperandBranchOffset) == 16, "IROperandBranchOffset must be 16 bytes");
static_assert(offsetof(IROperandBranchOffset, kind) == 0,
              "IROperandBranchOffset::kind must be at offset 0");
static_assert(offsetof(IROperandBranchOffset, value) == 8,
              "IROperandBranchOffset::value must be at offset 8");

struct IROperandConditionCode {
    IROperandKind kind;  // +0
    uint8_t cc;          // +1   condition code index in low nibble [3:0]
    uint8_t _pad[6];     // +2
    int64_t _unused;     // +8
};

static_assert(sizeof(IROperandConditionCode) == 16, "IROperandConditionCode must be 16 bytes");
static_assert(offsetof(IROperandConditionCode, kind) == 0,
              "IROperandConditionCode::kind must be at offset 0");
static_assert(offsetof(IROperandConditionCode, cc) == 1,
              "IROperandConditionCode::cc must be at offset 1");

struct IROperandSegmentRegister {
    IROperandKind kind;  // +0
    uint8_t _pad;        // +1
    uint8_t seg_idx;     // +2   segment register index (0–5)
    uint8_t _pad2[5];    // +3
    int64_t _unused;     // +8
};

static_assert(sizeof(IROperandSegmentRegister) == 16, "IROperandSegmentRegister must be 16 bytes");
static_assert(offsetof(IROperandSegmentRegister, kind) == 0,
              "IROperandSegmentRegister::kind must be at offset 0");
static_assert(offsetof(IROperandSegmentRegister, seg_idx) == 2,
              "IROperandSegmentRegister::seg_idx must be at offset 2");

union IROperand {  // sizeof = 16
    IROperandKind kind;
    IROperandRegister reg;
    IROperandMemRef mem;
    IROperandAbsMem abs_mem;
    IROperandImmediate imm;
    IROperandBranchOffset branch;
    IROperandConditionCode cc;
    IROperandSegmentRegister seg;
};

static_assert(sizeof(IROperand) == 16, "IROperand must be 16 bytes");
