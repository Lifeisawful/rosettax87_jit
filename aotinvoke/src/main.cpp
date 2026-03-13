#include <sys/mman.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <print>
#include <string_view>
#include <vector>

#include "RosettaAotApi.h"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CustomTranslationHook.h"
#include "rosetta_core/hook.h"
#include <rosetta_config/Config.h>

int main(int argc, char** argv) {
    RosettaConfig cfg = parse_config_from_env();
    rosetta_set_config(&cfg);

    if (argc < 3 || argc > 4) {
        std::print("Usage: aotinvoke <input.bin> <output.bin> [--verbose]\n");
        return 1;
    }

    const bool verbose = (argc == 4 && std::string_view(argv[3]) == "--verbose");

    if (!load_rosetta_aot()) {
        std::print("Failed to load libRosettaAot.dylib\n");
        return 1;
    }

    init_custom_translation_hook(g_rosetta_aot.translate_insn_addr, 
        g_rosetta_aot.transaction_result_size_addr);

    g_rosetta_aot.register_runtime_routine_offsets(g_runtime_routine_offsets.data(),
                                                   g_runtime_routine_names.data(),
                                                   g_runtime_routine_offsets.size());

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


    if (verbose) {
        g_rosetta_aot.module_print(module_result, 1);
    }

    auto translate_result = g_rosetta_aot.translate(module_result);


    auto translate_data_size = g_rosetta_aot.translator_get_size(translate_result);
    auto translate_data = g_rosetta_aot.translator_get_data(translate_result);

    g_rosetta_aot.apply_internal_fixups(translate_result, 0x1000, (std::uint8_t*)translate_data);
    g_rosetta_aot.apply_segmented_runtime_routine_fixups(translate_result,
                                                         (std::uint8_t*)translate_data, 0x1000);

    auto out = std::ofstream(out_path, std::ios::binary);
    out.write((const char*)translate_data, translate_data_size);
    out.close();
    std::print("Written {} bytes -> {}\n", translate_data_size, out_path.string());

    return 0;
}