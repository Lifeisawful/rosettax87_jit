#include <sys/mman.h>

#include <bit>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <print>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "RosettaAotApi.h"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CustomTranslationHook.h"
#include "rosetta_core/IRBlock.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/ModuleResult.h"
#include "rosetta_core/RosettaCore.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/X87BackEdge.h"
#include "rosetta_core/X87Cache.h"
#include "rosetta_core/hook.h"
#include <rosetta_config/Config.h>

int main(int argc, char** argv) {
    RosettaConfig cfg = parse_config_from_env();
    rosetta_set_config(&cfg);

    if (argc < 3 || argc > 5) {
        std::print("Usage: aotinvoke <input.bin> <output.bin> [--verbose] [--demand]\n");
        return 1;
    }

    // --verbose: print the IR dump.
    // --demand (implies --verbose): additionally instrument the translation
    // for the bridge-demand workflow — binary-patch the allocator
    // (free_temporary_gpr RET, free-GPR-mask reset NOP), sample the mask
    // around every instruction, and annotate each IR row with
    // `gpr_demand actual=N est=M|refuse`. Without it, aotinvoke translates
    // with the same allocator behavior as the runtime hook path.
    bool verbose = false;
    bool demand = false;
    for (int i = 3; i < argc; i++) {
        const std::string_view arg(argv[i]);
        if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--demand") {
            demand = true;
            verbose = true;
        } else {
            std::print("Unknown flag: {}\n", arg);
            return 1;
        }
    }

    if (!load_rosetta_aot()) {
        std::print("Failed to load libRosettaAot.dylib\n");
        return 1;
    }

    // free_gpr_mask captured around each IRInstr's translation, keyed by the
    // stable IRInstr* address (the same storage annotate_instr later sees).
    struct GprMaskSample {
        uint32_t before;
        uint32_t after;
    };
    std::unordered_map<const IRInstr*, GprMaskSample> gpr_mask_samples;

    // Observer fired around each instruction's translation. Must outlive
    // translate() below — hence a stack local in main.
    CustomTranslationHook translation_hook;
    if (demand) {
        translation_hook.before = [&](TranslationResult* result, IRBlock*,
                                      IRInstr* instrs, int64_t, int64_t idx) {
            gpr_mask_samples[&instrs[idx]].before = result->free_gpr_mask;
        };
        translation_hook.after = [&](TranslationResult* result, IRBlock*,
                                     IRInstr* instrs, int64_t, int64_t idx,
                                     int64_t /*new_idx*/) {
            gpr_mask_samples[&instrs[idx]].after = result->free_gpr_mask;
        };
    }

    auto version = g_rosetta_aot.version();
    rosetta_core_init({
        .runtime_version = version,
        .translate_insn_addr = g_rosetta_aot.translate_insn_addr,
        .transaction_result_size_addr = g_rosetta_aot.transaction_result_size_addr,
        .decode_opcode_addr = g_rosetta_aot.decode_opcode_addr,
        .default_free_gpr_mask_addr = demand ? g_rosetta_aot.default_free_gpr_mask_addr : 0,
        .free_temporary_gpr_addr = demand ? g_rosetta_aot.free_temporary_gpr_addr : 0,
        .translation_hook = demand ? &translation_hook : nullptr,
    });

    int offset_size = version >= kAotVersion ? g_runtime_routine_offsets.size() : g_runtime_routine_offsets.size() - 2;

    g_rosetta_aot.register_runtime_routine_offsets(g_runtime_routine_offsets.data(),
                                                   g_runtime_routine_names.data(),
                                                   offset_size);

    g_rosetta_aot.register_thread_context_offsets(&g_thread_context_offsets);

    const std::filesystem::path blob_path(argv[1]);
    const std::filesystem::path out_path(argv[2]);

    std::ifstream blob_file(blob_path, std::ios::binary | std::ios::ate);
    if (!blob_file) {
        std::print("Failed to open blob file: {}\n", blob_path.string());
        return 1;
    }

    const auto blob_size = blob_file.tellg();
    if (blob_size <= 0) {
        std::print("Blob file is empty: {}\n", blob_path.string());
        return 1;
    }

    std::vector<std::uint8_t> code(static_cast<size_t>(blob_size));
    blob_file.seekg(0, std::ios::beg);
    blob_file.read(reinterpret_cast<char*>(code.data()), static_cast<std::streamsize>(code.size()));
    if (!blob_file) {
        std::print("Failed to read blob file: {}\n", blob_path.string());
        return 1;
    }

    const size_t code_len = code.size();

    // 2. Map it readable (the disassembler reads directly through the pointer)
    void* blob = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    std::memcpy(blob, code.data(), code_len);

    int64_t insts_fileoff_range = ((int64_t)code_len << 32) | 0;

    std::vector<std::uint32_t> inst_targets = {0};
    std::vector<std::uint64_t> data_in_code;

    auto* module_result =
        g_rosetta_aot.ir_create((uintptr_t)blob,  // absolute mapped base = "file offset 0"
                                0,                // min_vmaddr   — irrelevant
                                0,                // max_vmaddr   — irrelevant
                                0,                // text_vmaddr_range — irrelevant
                                0,                // data_vmaddr_range — irrelevant
                                insts_fileoff_range,
                                0,   // a7_null
                                -1,  // a8_negative_1
                                0,   // stubs_fileoff_range — no stubs
                                0,   // stub_size           — no stubs
                                inst_targets, data_in_code);


    auto translate_result = g_rosetta_aot.translate(module_result);

    // OPT-BE post-module hook. aotinvoke calls libRosettaAot's translate
    // directly (no runtime-dylib export in the path), so invoke the shared
    // post-pass explicitly — same point in the pipeline as the production
    // translator_translate wrapper: after all blocks, before get_data/fixups.
    x87_backedge_module_post(translate_result);

    if (demand) {
        ModulePrintHooks hooks;
        hooks.annotate_block = [](const IRBlock& block) {
            return std::format("; code_size={}", block.code_size);
        };
        hooks.annotate_instr = [&](const IRBlock&, const IRInstr& instr,
                                   uint32_t) {
            auto it = gpr_mask_samples.find(&instr);
            if (it == gpr_mask_samples.end())
                return std::string{};
            // Actual GPR demand = scratch regs free before but consumed after
            // (bit set in `before`, cleared in `after`).
            uint32_t consumed = it->second.before & ~it->second.after;
            int actual = std::popcount(consumed);
            // Estimated demand from the bridge-demand model (nullopt = refuse
            // to bridge, i.e. no audited estimate for this form).
            std::optional<int> est = X87Cache::gap_gpr_demand(&instr);
            std::string est_str = est ? std::to_string(*est) : "refuse";
            return std::format("; gpr_demand actual={} est={}", actual, est_str);
        };
        module_print(module_result, &hooks);
    } else if (verbose) {
        g_rosetta_aot.module_print(module_result, 1);
    }


    auto translate_data_size = g_rosetta_aot.translator_get_size(translate_result);
    auto translate_data = g_rosetta_aot.translator_get_data(translate_result);

    g_rosetta_aot.apply_internal_fixups(translate_result, 0x1000, (std::uint8_t*)translate_data);
    g_rosetta_aot.apply_segmented_runtime_routine_fixups(translate_result,
                                                         (std::uint8_t*)translate_data, 0x1000);

    // OPT-BE G0.4 audit (AOT flavor): did the fixup passes rewrite any
    // backward conditional branch in the published copy?
    x87_backedge_apply_fixups_audit(translate_result, (std::uint8_t*)translate_data);

    auto out = std::ofstream(out_path, std::ios::binary);
    out.write((const char*)translate_data, translate_data_size);
    out.close();
    std::print("Written {} bytes -> {}\n", translate_data_size, out_path.string());

    return 0;
}