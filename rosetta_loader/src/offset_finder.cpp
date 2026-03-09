#include "offset_finder.hpp"
#include "macho_loader.hpp"
#include "types.h"
#include <fstream>
#include <functional>

auto OffsetFinder::setDefaultOffsets() -> void {
	// These are the default offsets for the rosetta runtime that matches MD5 hash: d7819a04355cd77ff24031800a985c13

	offsetExportsFetch_ = 0xFA8C; // Just before fetching 'exports' structure pointed by X19 and just after checking rosetta runtime version from header
	//               LDR X8, [X19]  - X19 'exports' structure address
	//               MOV X9, #1
	//               MOVK X9, #0x6A00,LSL#32
	//               MOVK X9, #1,LSL#48
	//               CMP X8, X9  // if [X19] < 0x16A0000000001
	//               B.CS <error version flow>
	// 62 06 40 F9 - LDR X2, [X19,#8]  <--- halt point for override X19 with new 'export' structure address
	// 63 12 40 B9 - LDR W3, [X19,#0x10]

	offsetSvcCallEntry_ = 0x1998; // The entry point of a function that trigger BSD syscall 'mmap'
	// B0 18 80 D2 - MOV X16, #197 <--- start for mmap wrapper
	// 01 10 00 D4 - SVC 0x80
	// E1 37 9F 9A - CSET X1, CS
	// offset: 0x19A4:
	// C0 03 5F D6 - RET <--- end of function
	offsetSvcCallRet_ = offsetSvcCallEntry_ + 0xC; // The return point of the above function

	offsetDisableAot_ = 0x3B27C;

	offsetTransactionResultSize_ = 0x0BA44;
	offsetTranslateInsn_ = 0x01A654;
}

/*
__text:0000000000016720 28 01 00 B0                             ADRP            X8, #g_disable_aot@PAGE
__text:0000000000016724 08 F1 4F 39                             LDRB            W8, [X8,#g_disable_aot@PAGEOFF]
__text:0000000000016728 88 00 00 36                             TBZ             W8, #0, loc_16738
__text:000000000001672C
__text:000000000001672C                         loc_1672C                               ; CODE XREF: sub_16654+C8↑j
__text:000000000001672C 21 00 80 52                             MOV             W1, #1
__text:0000000000016730 C0 02 80 52                             MOV             W0, #0x16

search for 88 00 00 36 21 00 80 52 C0 02 80 52 
*/

// Decode an ADRP+LDRB instruction pair to compute the target address.
// adrp_offset is the file offset of the ADRP instruction.
static bool decodeAdrpLdrb(const std::vector<unsigned char>& buffer, uint64_t adrp_offset, uintptr_t& result) {
	if (adrp_offset + 8 > buffer.size()) return false;

	uint32_t adrp_instruction = reinterpret_cast<const uint32_t*>(&buffer[adrp_offset])[0];
	uint32_t ldrb_instruction = reinterpret_cast<const uint32_t*>(&buffer[adrp_offset + 4])[0];

	// Verify ADRP (mask: 0x9F000000, value: 0x90000000)
	if ((adrp_instruction & 0x9F000000) != 0x90000000) return false;
	// Verify LDRB unsigned offset (mask: 0xFFC00000, value: 0x39400000)
	if ((ldrb_instruction & 0xFFC00000) != 0x39400000) return false;

	// Decode ADRP: PC-relative page address
	// immlo = bits [30:29], immhi = bits [23:5]
	uint64_t immlo = (adrp_instruction >> 29) & 0x3;
	uint64_t immhi = (adrp_instruction >> 5) & 0x7FFFF;
	int64_t imm = (int64_t)((immhi << 2) | immlo) << 12;
	// Sign-extend from 33 bits
	if (imm & (1ULL << 32))
		imm |= ~((1ULL << 33) - 1);

	uint64_t adrp_page = (adrp_offset & ~0xFFF) + imm;

	// Decode LDRB (unsigned offset): pageoff = imm12 (bits [21:10]), no shift for byte access
	uint64_t ldrb_imm12 = (ldrb_instruction >> 10) & 0xFFF;

	result = adrp_page + ldrb_imm12;
	return true;
}

auto OffsetFinder::determineOffsets() -> bool {
	// byte patterns in hex for the functions we need to find.
	const std::vector<unsigned char> exportsFetch = {0x62, 0x06, 0x40, 0xF9, 0x63, 0x12, 0x40, 0xB9 };
	const std::vector<unsigned char> svcCall = { 0xB0, 0x18, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4, 0xE1, 0x37, 0x9F, 0x9A, 0xC0, 0x03, 0x5F, 0xD6 };
	// For svc_call we need to check where this bitpattern starts in the code and also where it ends (we can just add 0xC to the start to get the end)

	// Load rosetta runtime into an ifstream
	std::ifstream file{"/usr/libexec/rosetta/runtime", std::ios::binary};

	// Check if we were successfully able to load the file, if not abort and use default offsets
	if (!file) {
		fprintf(stderr, "Problem accessing rosetta runtime to determine offsets automatically.\nFalling back to macOS 26.0 defaults (This WILL crash your app if they are not correct!)\n");
		return false;
	}

	// Determine size of rosetta runtime file
	file.seekg(0, std::ios::end);
	std::streampos size = file.tellg();
	file.seekg(0, std::ios::beg);

	// Set our buffer to the size of the file
	std::vector<unsigned char> buffer(size);

	// read into the buffer
	if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
		fprintf(stderr, "Problem reading rosetta runtime to determine offsets automatically.\nFalling back to macOS 26.0 defaults (This WILL crash your app if they are not correct!)\n");
		return false;
	}

	// Search for exportsFetch pattern
	{
		const std::boyer_moore_searcher searcher(exportsFetch.begin(), exportsFetch.end());
		const auto it = std::search(buffer.begin(), buffer.end(), searcher);
		if (it == buffer.end()) {
			fprintf(stderr, "exportsFetch pattern not found in rosetta runtime binary\n");
			return false;
		}
		offsetExportsFetch_ = (std::uint64_t)std::distance(buffer.begin(), it);
	}

	// Search for svcCall pattern
	{
		const std::boyer_moore_searcher searcher(svcCall.begin(), svcCall.end());
		const auto it = std::search(buffer.begin(), buffer.end(), searcher);
		if (it == buffer.end()) {
			fprintf(stderr, "svcCall pattern not found in rosetta runtime binary\n");
			return false;
		}
		offsetSvcCallEntry_ = (std::uint64_t)std::distance(buffer.begin(), it);
		offsetSvcCallRet_ = offsetSvcCallEntry_ + 0xC;
	}

	// Find g_disable_aot address.
	// Strategy 1 (macOS 26.0): search for TBZ+MOV+MOV pattern, ADRP+LDRB is 8 bytes before.
	// Strategy 2 (macOS 26.4+): search for MOV W1,#1 + MOV W0,#0x16, scan nearby for ADRP+LDRB.
	bool foundDisableAot = false;

	// Strategy 1: old pattern (TBZ W8, #0 + MOV W1, #1 + MOV W0, #0x16)
	const std::vector<unsigned char> disableAotOld = { 0x88, 0x00, 0x00, 0x36, 0x21, 0x00, 0x80, 0x52, 0xC0, 0x02, 0x80, 0x52 };
	{
		const std::boyer_moore_searcher searcher(disableAotOld.begin(), disableAotOld.end());
		const auto it = std::search(buffer.begin(), buffer.end(), searcher);
		if (it != buffer.end()) {
			uint64_t patternOffset = (std::uint64_t)std::distance(buffer.begin(), it);
			uintptr_t result;
			if (patternOffset >= 8 && decodeAdrpLdrb(buffer, patternOffset - 8, result)) {
				offsetDisableAot_ = result;
				foundDisableAot = true;
			}
		}
	}

	// Strategy 2: search for MOV W1,#1 + MOV W0,#0x16 and scan nearby for ADRP+LDRB
	if (!foundDisableAot) {
		const std::vector<unsigned char> movPair = { 0x21, 0x00, 0x80, 0x52, 0xC0, 0x02, 0x80, 0x52 };
		const std::boyer_moore_searcher searcher(movPair.begin(), movPair.end());
		auto it = std::search(buffer.begin(), buffer.end(), searcher);
		while (it != buffer.end() && !foundDisableAot) {
			uint64_t movOffset = (uint64_t)std::distance(buffer.begin(), it);
			// Scan both before (-12, -8) and after (+8, +12, +16, +20) the MOV pair
			for (int32_t scan : {-12, -8, 8, 12, 16, 20}) {
				int64_t checkOffset = (int64_t)movOffset + scan;
				if (checkOffset < 0 || (uint64_t)checkOffset + 8 > buffer.size()) continue;
				uintptr_t result;
				if (decodeAdrpLdrb(buffer, (uint64_t)checkOffset, result)) {
					// Sanity check: g_disable_aot should be in BSS (high offset, > 0x30000)
					if (result > 0x30000) {
						offsetDisableAot_ = result;
						foundDisableAot = true;
						break;
					}
				}
			}
			it = std::search(it + 1, buffer.end(), searcher);
		}
	}

	if (!foundDisableAot) {
		fprintf(stderr, "Warning: could not determine g_disable_aot offset, using default 0x%llx\n",
				(unsigned long long)offsetDisableAot_);
	}

	return true;
}


auto OffsetFinder::determineRuntimeOffsets() -> bool {
	const std::vector<unsigned char> translation_result_size_pattern = { 0x01, 0x4D, 0x80, 0x52 };
	const std::vector<unsigned char> translation_pattern = { 0xFF, 0x43, 0x03, 0xD1, 0xFC, 0x6F, 0x07, 0xA9, 0xfa, 0x67, 0x08, 0xa9, 0xF8, 0x5F, 0x09, 0xA9, 0xF6, 0x57, 0x0A, 0xA9, 0xF4, 0x4F, 0x0B, 0xA9, 0xFD, 0x7B, 0x0C, 0xA9, 0xFD, 0x03, 0x03, 0x91, 0xF3, 0x03, 0x00, 0xAA };

	#if 0
	std::ifstream file{"/Library/Apple/usr/libexec/oah/libRosettaRuntime", std::ios::binary};
	if (!file) {
		fprintf(stderr, "Problem accessing rosetta libRosettaRuntime to determine runtime offsets automatically.\n");
		return false;
	}
	
	// Determine size of rosetta runtime file
	file.seekg(0, std::ios::end);
	std::streampos size = file.tellg();
	file.seekg(0, std::ios::beg);

	// Set our buffer to the size of the file
	std::vector<unsigned char> buffer(size);

	// read into the buffer
	if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
		fprintf(stderr, "Problem reading libRosettaRuntime to determine runtime offsets automatically.\n");
		return false;
	}


	#endif

	MachoLoader libRosettaRuntimeLoader;
	if (!libRosettaRuntimeLoader.open("/Library/Apple/usr/libexec/oah/libRosettaRuntime")) {
		fprintf(stderr, "Failed to open libRosettaRuntime Mach-O file to determine runtime offsets automatically.\n");
		return false;
	}


	auto text_section = libRosettaRuntimeLoader.getSection("__TEXT", "__text");
	if (!text_section) {
		fprintf(stderr, "Failed to find __TEXT.__text section in libRosettaRuntime Mach-O file to determine runtime offsets automatically.\n");
		return false;
	}

	std::vector<std::uint64_t> results;
	for (const auto offset : { translation_result_size_pattern, translation_pattern }) {
		const std::boyer_moore_searcher searcher(offset.begin(), offset.end());
		const auto it = std::search(libRosettaRuntimeLoader.buffer_.begin(), libRosettaRuntimeLoader.buffer_.end(), searcher);
		if (it == libRosettaRuntimeLoader.buffer_.end()) {
			fprintf(stderr, "Offset not found in libRosettaRuntime binary\n");
			results.push_back(-1);
		} else {
			results.push_back((std::uint64_t)std::distance(libRosettaRuntimeLoader.buffer_.begin(), it));
		}
	}

	// If we've stored -1 in any offset, error out and fall back to non-accelerated x87 handles.
	if ((int)results[0] <= -1 || (int)results[1] <= -1) {
		fprintf(stderr, "Problem searching libRosettaRuntime to determine runtime offsets automatically.\n");
		return false;
	}

	offsetTransactionResultSize_ = results[0];
	offsetTranslateInsn_ = results[1];

	auto exports_section = libRosettaRuntimeLoader.getSection("__DATA", "exports");
	if (!exports_section) {
		fprintf(stderr, "Failed to find __DATA.exports section in libRosettaRuntime Mach-O file to determine runtime offsets automatically.\n");
		return false;
	}

	Exports* exports = (Exports*)(libRosettaRuntimeLoader.buffer_.data() + exports_section->offset);

	auto x87_exports_rva = exports->x87Exports & 0xFFFFFFFF; // cut off the upper bits which are used by dyld_chained_ptr_64_rebase
	offsetInitLibrary_ = (*(uint64_t*) (libRosettaRuntimeLoader.buffer_.data() + x87_exports_rva)) & 0xFFFFFFFF;

	return true;
}
