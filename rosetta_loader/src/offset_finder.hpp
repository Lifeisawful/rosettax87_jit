#pragma once

#include <cstdint>

struct OffsetFinder {
    auto scanRuntime() -> bool;
    auto scanLibRosettaRuntime() -> bool;

    uint64_t offsetExportsFetch_{};
    uint64_t offsetSvcCallEntry_{};
    uint64_t offsetSvcCallRet_{};
    uint64_t offsetDisableAot_{};
    uint64_t offsetClassifyArmPc_{};

    uint64_t offsetSysCsrctl_{};

    uint64_t offsetRuntimeRoutinesForAddress_{};
    uint64_t offsetAllocateChunk_{};
    uint64_t offsetTraceWriteMappingRecord_{};

    uint64_t offsetTransactionResultSize_{};
    uint64_t offsetTranslateInsn_{};
    uint64_t offsetInitLibrary_{};
    uint64_t offsetDecodeOpcode_{};
    uint64_t offsetDefaultFreeGPRMask_{};
};
