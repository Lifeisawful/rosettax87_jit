#pragma once

#include <cstdint>

struct OffsetFinder {
    auto scanRuntime() -> bool;
    auto scanLibRosettaRuntime() -> bool;

    uint64_t offsetSvcCallEntry_{};
    uint64_t offsetSvcCallRet_{};
    uint64_t offsetDisableAot_{};
    uint64_t offsetClassifyArmPc_{};

    uint64_t offsetSysCsrctl_{};

    uint64_t offsetRuntimeRoutinesForAddress_{};
    uint64_t offsetAllocateChunk_{};
    uint64_t offsetTraceWriteMappingRecord_{};
    uint64_t offsetBindLibraryStubs_{};

    // The three helpers our full classify_arm_pc_objc replacement calls. All are
    // internal (non-exported) runtime functions — see TranslationCacheAbi.h.
    uint64_t offsetAbiInfoForRuntime_{};
    uint64_t offsetThreadEntryForPort_{};
    uint64_t offsetInstructionExtentsForArmAddress_{};

    uint64_t offsetTransactionResultSize_{};
    uint64_t offsetTranslateInsn_{};
    uint64_t offsetInitLibrary_{};
    uint64_t offsetDecodeOpcode_{};
    uint64_t offsetDefaultFreeGPRMask_{};

    // The libRosettaRuntime Exports.version value (not an offset). Read from the
    // on-disk __DATA,exports and written into our runtime image's kImports.version
    // so rosetta_core_runtime_version() gates opcode compat correctly.
    uint64_t runtimeVersion_{};
};
