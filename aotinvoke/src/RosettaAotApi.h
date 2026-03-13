#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "rosetta_core/AssemblerBuffer.h"
#include "rosetta_core/IRBlock.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/IROperand.h"
#include "rosetta_core/ModuleResult.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/ThreadContextOffsets.h"
#include "rosetta_core/TranslationResult.h"

struct DataInCodeEntry;
template <typename T>
struct Interval;
struct ExternalFixups;

struct RosettaAotApi {
    void* handle = nullptr;
    uintptr_t base_addr = 0;
    uintptr_t translate_insn_addr = 0;
    uintptr_t transaction_result_size_addr = 0;

    using version_fn = std::uint64_t (*)();
    using translate_fn = TranslationResult* (*)(ModuleResult const*);
    using module_free_fn = void (*)(ModuleResult const*);
    using module_print_fn = void (*)(ModuleResult const*, int);
    using module_get_size_fn = std::uint64_t (*)(ModuleResult const*);
    using translator_free_fn = void (*)(TranslationResult const*);
    using translator_get_size_fn = std::uint64_t (*)(TranslationResult const*);
    using translator_get_data_fn = const std::uint8_t* (*)(TranslationResult*);
    using get_external_fixups_fn = ExternalFixups* (*)(TranslationResult*);
    using free_fixups_fn = void (*)(ExternalFixups const*);
    using apply_external_fixups_fn = void (*)(ExternalFixups const*, std::uint64_t, std::uint64_t,
                                              std::uint8_t*);
    using apply_internal_fixups_fn = void (*)(TranslationResult*, std::uint64_t, std::uint8_t*);
    using get_data_segment_fixups_fn = void* (*)(TranslationResult*);
    using translator_get_segments_fn = void* (*)(TranslationResult const*);
    using apply_runtime_routine_fixups_fn = void (*)(TranslationResult*, std::uint64_t,
                                                     std::uint64_t, std::uint8_t*);
    using find_arm_offset_for_x86_offset_fn = bool (*)(TranslationResult const*, std::uint32_t,
                                                       std::uint32_t*);
    using register_thread_context_offsets_fn = void (*)(ThreadContextOffsets const*);
    using register_runtime_routine_offsets_fn = void (*)(std::uint32_t const*, char const**,
                                                         std::uint64_t);
    using apply_segmented_runtime_routine_fixups_fn = void (*)(TranslationResult*, std::uint8_t*,
                                                               std::uint32_t);
    using use_t8027_codegen_fn = void (*)(bool);
    using ir_create_fn = ModuleResult* (*)(uintptr_t absolute_insts_range_low, uint64_t min_vmaddr,
                                           uint64_t max_vmaddr, uint64_t text_vmaddr_range,
                                           uint64_t data_vmaddr_range, uint64_t insts_fileoff_range,
                                           uint64_t a7_null, uint64_t a8_negative_1,
                                           uint64_t stubs_fileoff_range, unsigned int stub_size,
                                           std::vector<uint32_t>& inst_targets,
                                           std::vector<uint64_t>& data_in_code);

    version_fn version = nullptr;
    translate_fn translate = nullptr;
    module_free_fn module_free = nullptr;
    module_print_fn module_print = nullptr;
    module_get_size_fn module_get_size = nullptr;
    translator_free_fn translator_free = nullptr;
    translator_get_size_fn translator_get_size = nullptr;
    translator_get_data_fn translator_get_data = nullptr;
    get_external_fixups_fn get_external_fixups = nullptr;
    free_fixups_fn free_fixups = nullptr;
    apply_external_fixups_fn apply_external_fixups = nullptr;
    apply_internal_fixups_fn apply_internal_fixups = nullptr;
    get_data_segment_fixups_fn get_data_segment_fixups = nullptr;
    translator_get_segments_fn translator_get_segments = nullptr;
    apply_runtime_routine_fixups_fn apply_runtime_routine_fixups = nullptr;
    find_arm_offset_for_x86_offset_fn find_arm_offset_for_x86_offset = nullptr;
    register_thread_context_offsets_fn register_thread_context_offsets = nullptr;
    register_runtime_routine_offsets_fn register_runtime_routine_offsets = nullptr;
    apply_segmented_runtime_routine_fixups_fn apply_segmented_runtime_routine_fixups = nullptr;
    use_t8027_codegen_fn use_t8027_codegen = nullptr;
    ir_create_fn ir_create = nullptr;

    ~RosettaAotApi();
};

inline constexpr std::uint64_t kAotVersion = 0x15d0000000000ULL;

extern RosettaAotApi g_rosetta_aot;
extern std::array<std::uint32_t, 0x62> g_runtime_routine_offsets;
extern std::array<const char*, 0x62> g_runtime_routine_names;
extern ThreadContextOffsets g_thread_context_offsets;

bool load_rosetta_aot();