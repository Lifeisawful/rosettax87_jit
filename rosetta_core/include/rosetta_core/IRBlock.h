#pragma once

#include <cstdint>

#include "rosetta_core/IRInstr.h"

enum TerminatorKind : uint8_t {
    TK_JMP = 0x0,
    TK_JMP_IND = 0x1,
    TK_DYLD_STUB = 0x2,
    TK_RET = 0x3,
    TK_JCC = 0x4,
    TK_MOV_TO_SEG = 0x5,
    TK_MOV_FROM_SEG = 0x6,
    TK_LEA = 0x7,
    TK_RET_NEAR = 0x8,
    TK_RET_NEAR_IMM = 0x9,
    TK_RET_FAR = 0xA,
    TK_RET_FAR_IMM = 0xB,
    TK_FALLTHROUGH = 0xC,
    TK_LOOP = 0xD,
    TK_LOOP_CC = 0xE,
    TK_INVALID = 0xF,
    TK_BAD_ACCESS = 0x10,
    TK_INT = 0x11,
    TK_NOP_TERM = 0x12,
};

struct IRBlock {
    IRInstr* instrs;
    IRBlock** preds;
    uint8_t terminator_kind;
    uint8_t term_subkind;
    uint8_t term_size;
    uint8_t _pad13;
    uint32_t term_flags;
    uint64_t term_target;
    uint64_t term_alt;
    uint64_t term_extra;
    uint32_t end_pc;
    uint32_t num_instrs;
    uint32_t num_preds;
    uint32_t block_index;
    uint32_t start_pc;
    uint32_t code_size;
    uint8_t flag_liveness;
    uint8_t live_flags_in;
    uint8_t is_entry;
    uint8_t is_sequential;
    uint32_t _pad4C;
};
