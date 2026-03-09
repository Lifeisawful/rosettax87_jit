#pragma once

#include <iostream>

struct OffsetFinder {
	auto setDefaultOffsets() -> void;
	auto determineOffsets() -> bool;
	auto determineRuntimeOffsets() -> bool;

	std::uint64_t offsetExportsFetch_ = 0;
	std::uint64_t offsetSvcCallEntry_ = 0;
	std::uint64_t offsetSvcCallRet_ = 0;
	std::uint64_t offsetDisableAot_ = 0;

	std::uint64_t offsetTransactionResultSize_ = 0;
	std::uint64_t offsetTranslateInsn_ = 0;
	std::uint64_t offsetInitLibrary_ = 0;
};
