#pragma once

#include <iostream>

struct OffsetFinder {
	auto setDefaultOffsets() -> void;
	auto determineOffsets() -> bool;
	auto determineRuntimeOffsets() -> bool;

	std::uint64_t offsetExportsFetch_;
	std::uint64_t offsetSvcCallEntry_;
	std::uint64_t offsetSvcCallRet_;
	std::uint64_t offsetDisableAot_;

	std::uint64_t offsetTransactionResultSize_;
	std::uint64_t offsetTranslateInsn_;
	std::uint64_t offsetInitLibrary_;
};
