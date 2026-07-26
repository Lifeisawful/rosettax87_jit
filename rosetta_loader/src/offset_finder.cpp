#include "offset_finder.hpp"

#include <optional>

#include "rosetta_shared/LoaderTypes.h"
#include "rosetta_shared/MachoLoader.h"
#include "rosetta_shared/MachoScan.h"

using rosetta_shared::findPattern;
namespace aarch64 = rosetta_shared::aarch64;

auto OffsetFinder::scanRuntime() -> bool {
    MachoLoader loader;
    if (!loader.open("/usr/libexec/rosetta/runtime")) {
        fprintf(stderr, "Failed to open rosetta runtime Mach-O to determine offsets.\n");
        return false;
    }

    auto findSvcCall = [&]() -> std::optional<uint64_t> {
        // MOV X16, #197; SVC 0x80; CSET X1, CS; RET
        return findPattern(loader.buffer_, "B0 18 80 D2 01 10 00 D4 E1 37 9F 9A C0 03 5F D6",
                           "svcCall");
    };

    auto findDisableAot = [&]() -> std::optional<uint64_t> {
        // ADD X29, SP, #0x1D0; STR X4, [SP,#0x50]
        // (followed by ADRP+LDRB that encode g_disable_aot address)
        auto match = findPattern(loader.buffer_, "FD 43 07 91 E4 2B 00 F9", "disableAot");
        if (!match)
            return std::nullopt;
        uint64_t adrpOffset = *match + 8;
        uint32_t adrpInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[adrpOffset]);
        uint32_t ldrbInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[adrpOffset + 4]);
        return aarch64::decodeAdrp(adrpInsn, adrpOffset) + aarch64::decodeLdrbImm(ldrbInsn);
    };

    auto findClassifyArmPc = [&]() -> std::optional<uint64_t> {
        // LDR X2, [X26,#0x110]; LDR W1, [X25,#0x194]
        // ADD X0, SP, #imm; BL classify_arm_pc  <-- we decode the BL
        auto match = findPattern(loader.buffer_, "42 8B 40 F9 21 97 41 B9", "classifyArmPc");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match + 0x0C;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto findSysCsrctl = [&]() -> std::optional<uint64_t> {
        // MOV X16, #0x1E3; SVC 0x80; MOV X1, #-1; CSEL X0, X1, X0, CS; RET
        return findPattern(loader.buffer_,
                           "70 3C 80 D2 01 10 00 D4 01 00 80 92 20 20 80 9A C0 03 5F D6",
                           "sysCsrctl");
    };

    auto findRuntimeRoutinesForAddress = [&]() -> std::optional<uint64_t> {
        // LDR X2, [X19,#0x58]; MOV X0, X21; MOV X1, X20
        // BL runtime_routines_for_address  <-- we decode the BL (3 insns / 0x0C after match)
        auto match = findPattern(loader.buffer_, "62 2E 40 F9 E0 03 15 AA E1 03 14 AA",
                                 "runtimeRoutinesForAddress");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match + 0x0C;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto findAllocateChunk = [&]() -> std::optional<uint64_t> {
        // BL allocate_chunk  <-- the BL we want, the instruction BEFORE the match (match - 4)
        // ADD X8, X20, #imm; ADRP X9, #page; STR X8, [X9,#imm]
        auto match = findPattern(loader.buffer_, "? ? 15 91 ? 01 00 ? 28 ? ? ?", "allocateChunk");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match - 4;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto findTraceWriteMappingRecord = [&]() -> std::optional<uint64_t> {
        // MOV X1, X19; MOV W2, #0x4000
        // BL trace_write_mapping_record  <-- we decode the BL (2 insns / 8 after match)
        auto match = findPattern(loader.buffer_, "E1 03 13 AA 02 00 88 52",
                                 "traceWriteMappingRecord");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match + 8;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto findBindLibraryStubs = [&]() -> std::optional<uint64_t> {
        // MOV W1, #3
        // BL bind_library_stubs  <-- we decode the BL (1 insn / 4 after match)
        // The MOV W1, #3 alone is not unique; anchor on the following BL (high
        // byte 94) to pin the single call site.
        auto match = findPattern(loader.buffer_, "61 00 80 52 ? ? ? 94", "bindLibraryStubs");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match + 4;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto svcCall = findSvcCall();
    auto disableAot = findDisableAot();
    auto classifyArmPc = findClassifyArmPc();
    auto sysCsrctl = findSysCsrctl();
    auto runtimeRoutinesForAddress = findRuntimeRoutinesForAddress();
    auto allocateChunk = findAllocateChunk();
    auto traceWriteMappingRecord = findTraceWriteMappingRecord();
    auto bindLibraryStubs = findBindLibraryStubs();

    if (!svcCall || !disableAot || !classifyArmPc || !sysCsrctl ||
        !runtimeRoutinesForAddress || !allocateChunk || !traceWriteMappingRecord ||
        !bindLibraryStubs)
        return false;

    offsetSvcCallEntry_ = *svcCall;
    offsetSvcCallRet_ = *svcCall + 0xC;
    offsetDisableAot_ = *disableAot;
    offsetClassifyArmPc_ = *classifyArmPc;
    offsetSysCsrctl_ = *sysCsrctl;
    offsetRuntimeRoutinesForAddress_ = *runtimeRoutinesForAddress;
    offsetAllocateChunk_ = *allocateChunk;
    offsetTraceWriteMappingRecord_ = *traceWriteMappingRecord;
    offsetBindLibraryStubs_ = *bindLibraryStubs;

    return true;
}

auto OffsetFinder::scanLibRosettaRuntime() -> bool {
    MachoLoader loader;
    if (!loader.open("/Library/Apple/usr/libexec/oah/libRosettaRuntime")) {
        fprintf(stderr, "Failed to open libRosettaRuntime Mach-O to determine offsets.\n");
        return false;
    }

    auto findTransactionResultSize = [&]() -> std::optional<uint64_t> {
        // MOV W1, #0x268
        return findPattern(loader.buffer_, "01 4D 80 52", "transactionResultSize");
    };

    auto findTranslateInsn = [&]() -> std::optional<uint64_t> {
        // translate_insn function prologue
        return findPattern(loader.buffer_,
                           "FF 43 03 D1 FC 6F 07 A9 FA 67 08 A9 "
                           "F8 5F 09 A9 F6 57 0A A9 F4 4F 0B A9 "
                           "FD 7B 0C A9 FD 03 03 91 F3 03 00 AA",
                           "translateInsn");
    };

    auto findDecodeOpcode = [&]() -> std::optional<uint64_t> {
        auto match = findPattern(loader.buffer_, "E2 ? 08 91 E3 ? 08 91 E1 03 ? ?", "decodeOpcode");
        if (!match)
            return std::nullopt;
        uint64_t blOffset = *match + 0x0C;
        uint32_t blInsn = *reinterpret_cast<uint32_t*>(&loader.buffer_[blOffset]);
        return aarch64::decodeBl(blInsn, blOffset);
    };

    auto findInitLibrary = [&]() -> std::optional<uint64_t> {
        auto exportsSection = loader.getSection("__DATA", "exports");
        if (!exportsSection) {
            fprintf(stderr,
                    "initLibrary: __DATA.exports section not found in libRosettaRuntime.\n");
            return std::nullopt;
        }
        auto* exports = reinterpret_cast<Exports*>(loader.buffer_.data() + exportsSection->offset);
        // Capture the runtime's version (Exports field 0) while we have the
        // section parsed — it feeds our kImports.version (see main.cpp).
        runtimeVersion_ = exports->version;
        auto x87ExportsRva = exports->x87Exports & 0xFFFFFFFF;
        return (*reinterpret_cast<uint64_t*>(loader.buffer_.data() + x87ExportsRva)) & 0xFFFFFFFF;
    };

    auto findDefaultFreeGPRMask = [&]() -> std::optional<uint64_t> {
        // BL sub_2DC78 (tail); MOV W8, #0x3FC00000; STR W8, [X19,#0x210];
        // LDR W8, [X19,#0x218]  <-- we return the address of the STR W8, [X19,#0x210]
        auto match = findPattern(loader.buffer_, "00 94 08 F8 A7 52 68 12 02 B9 68 1A 42 B9",
                                 "defaultFreeGPRMask");
        if (!match)
            return std::nullopt;
        return *match + 6;  // skip BL tail (2) + MOV (4) to reach the STR
    };

    auto transactionResultSize = findTransactionResultSize();
    auto translateInsn = findTranslateInsn();
    auto decodeOpcode = findDecodeOpcode();
    auto initLibrary = findInitLibrary();
    auto defaultFreeGPRMask = findDefaultFreeGPRMask();

    if (!transactionResultSize || !translateInsn || !decodeOpcode || !initLibrary ||
        !defaultFreeGPRMask)
        return false;

    offsetTransactionResultSize_ = *transactionResultSize;
    offsetTranslateInsn_ = *translateInsn;
    offsetDecodeOpcode_ = *decodeOpcode;
    offsetInitLibrary_ = *initLibrary;
    offsetDefaultFreeGPRMask_ = *defaultFreeGPRMask;

    return true;
}
