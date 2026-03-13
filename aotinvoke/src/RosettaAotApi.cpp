#include "RosettaAotApi.h"

#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach/vm_page_size.h>

#include <array>
#include <print>
#include <stdexcept>
#include <string_view>

RosettaAotApi g_rosetta_aot;

namespace {
constexpr std::string_view kRosettaAotPath = "/Library/Apple/usr/lib/libRosettaAot.dylib";
}  // namespace

RosettaAotApi::~RosettaAotApi() {
    if (handle != nullptr) {
        dlclose(handle);
    }
}

template <typename T>
T load_symbol(void* handle, const char* name) {
    dlerror();
    void* sym = dlsym(handle, name);
    const char* err = dlerror();
    if (err == nullptr && sym != nullptr) {
        return reinterpret_cast<T>(sym);
    }

    if (err != nullptr) {
        throw std::runtime_error(err);
    }
    throw std::runtime_error("symbol not found");
}

bool find_patterns(uintptr_t aot_base, uintptr_t& trans_insn_addr,
                   uintptr_t& transaction_result_size_addr) {
    static const std::array<uint8_t, 36> translate_insn_pattern = {
        0xFF, 0x43, 0x03, 0xD1, 0xFC, 0x6F, 0x07, 0xA9, 0xFA, 0x67, 0x08, 0xA9,
        0xF8, 0x5F, 0x09, 0xA9, 0xF6, 0x57, 0x0A, 0xA9, 0xF4, 0x4F, 0x0B, 0xA9,
        0xFD, 0x7B, 0x0C, 0xA9, 0xFD, 0x03, 0x03, 0x91, 0xF3, 0x03, 0x00, 0xAA};
    static const std::array<uint8_t, 4> transaction_result_size_pattern = {0x00, 0x51, 0x80, 0x52};
    // look up __TEXT, __text section

    mach_header_64* header = (mach_header_64*)aot_base;
    load_command* cmd = (load_command*)(header + 1);
    section_64* text_section = nullptr;

    for (auto i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            auto seg = (segment_command_64*)cmd;

            if (strcmp(seg->segname, "__TEXT") == 0) {
                section_64* sections =
                    (section_64*)(uintptr_t(seg) + sizeof(segment_command_64));
                for (auto j = 0; j < seg->nsects; j++) {
                    auto& sect = sections[j];
                    if (strcmp(sect.sectname, "__text") == 0) {
                        text_section = &sect;
                        break;
                    }
                }
            }
        }
        cmd = (load_command*)((uintptr_t)cmd + cmd->cmdsize);
    }

    if (!text_section) {
        return false;
    }

    trans_insn_addr = 0;
    transaction_result_size_addr = 0;

    for (size_t offset = 0; offset < text_section->size; offset++) {
        if (trans_insn_addr == 0) {
            if (std::memcmp((void*)(aot_base + text_section->offset + offset),
                            translate_insn_pattern.data(), translate_insn_pattern.size()) == 0) {
                trans_insn_addr = aot_base + text_section->offset + offset;
            }
        }

        if (transaction_result_size_addr == 0) {
            if (std::memcmp((void*)(aot_base + text_section->offset + offset),
                            transaction_result_size_pattern.data(),
                            transaction_result_size_pattern.size()) == 0) {
                transaction_result_size_addr = aot_base + text_section->offset + offset;
            }
        }

        if (trans_insn_addr != 0 && transaction_result_size_addr != 0) {
            break;
        }
    }

    return trans_insn_addr != 0 && transaction_result_size_addr != 0;
}

bool load_rosetta_aot() {
    if (g_rosetta_aot.handle != nullptr) {
        return true;
    }

    g_rosetta_aot.handle = dlopen(kRosettaAotPath.data(), RTLD_NOW | RTLD_LOCAL);
    if (g_rosetta_aot.handle == nullptr) {
        std::print("dlopen failed: {}\n", dlerror());
        return false;
    }

    try {
        g_rosetta_aot.free_fixups = load_symbol<RosettaAotApi::free_fixups_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot11free_fixupsEPKNS0_14ExternalFixupsE");
        g_rosetta_aot.module_free = load_symbol<RosettaAotApi::module_free_fn>(
            g_rosetta_aot.handle, "_ZN7rosetta14librosetta_aot11module_freeEPKNS0_12ModuleResultE");
        g_rosetta_aot.module_print = load_symbol<RosettaAotApi::module_print_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot12module_printEPKNS0_12ModuleResultEi");
        g_rosetta_aot.module_get_size = load_symbol<RosettaAotApi::module_get_size_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot15module_get_sizeEPKNS0_12ModuleResultE");
        g_rosetta_aot.translator_free = load_symbol<RosettaAotApi::translator_free_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot15translator_freeEPKNS0_17TranslationResultE");
        g_rosetta_aot.use_t8027_codegen = load_symbol<RosettaAotApi::use_t8027_codegen_fn>(
            g_rosetta_aot.handle, "_ZN7rosetta14librosetta_aot17use_t8027_codegenEb");
        g_rosetta_aot.get_external_fixups = load_symbol<RosettaAotApi::get_external_fixups_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot19get_external_fixupsEPNS0_17TranslationResultE");
        g_rosetta_aot.translator_get_data = load_symbol<RosettaAotApi::translator_get_data_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot19translator_get_dataEPNS0_17TranslationResultE");
        g_rosetta_aot.translator_get_size = load_symbol<RosettaAotApi::translator_get_size_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot19translator_get_sizeEPKNS0_17TranslationResultE");
        g_rosetta_aot.apply_external_fixups = load_symbol<RosettaAotApi::apply_external_fixups_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot21apply_external_fixupsEPKNS0_14ExternalFixupsEyyPh");
        g_rosetta_aot.apply_internal_fixups = load_symbol<RosettaAotApi::apply_internal_fixups_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot21apply_internal_fixupsEPNS0_17TranslationResultEyPh");
        g_rosetta_aot.get_data_segment_fixups =
            load_symbol<RosettaAotApi::get_data_segment_fixups_fn>(
                g_rosetta_aot.handle,
                "_ZN7rosetta14librosetta_aot23get_data_segment_fixupsEPNS0_17TranslationResultE");
        g_rosetta_aot.translator_get_segments =
            load_symbol<RosettaAotApi::translator_get_segments_fn>(
                g_rosetta_aot.handle,
                "_ZN7rosetta14librosetta_aot23translator_get_segmentsEPKNS0_17TranslationResultE");
        g_rosetta_aot.apply_runtime_routine_fixups =
            load_symbol<RosettaAotApi::apply_runtime_routine_fixups_fn>(
                g_rosetta_aot.handle,
                "_ZN7rosetta14librosetta_aot28apply_runtime_routine_fixupsEPNS0_"
                "17TranslationResultEyyPh");
        g_rosetta_aot.find_arm_offset_for_x86_offset =
            load_symbol<RosettaAotApi::find_arm_offset_for_x86_offset_fn>(
                g_rosetta_aot.handle,
                "_ZN7rosetta14librosetta_aot30find_arm_offset_for_x86_offsetEPKNS0_"
                "17TranslationResultEjPj");
        g_rosetta_aot.register_thread_context_offsets =
            load_symbol<RosettaAotApi::register_thread_context_offsets_fn>(
                g_rosetta_aot.handle,
                "_ZN7rosetta14librosetta_aot31register_thread_context_offsetsEPKNS_"
                "20ThreadContextOffsetsE");
        g_rosetta_aot.register_runtime_routine_offsets =
            load_symbol<RosettaAotApi::register_runtime_routine_offsets_fn>(
                g_rosetta_aot.handle,
                "_ZN7rosetta14librosetta_aot32register_runtime_routine_offsetsEPKjPPKcm");
        g_rosetta_aot.apply_segmented_runtime_routine_fixups =
            load_symbol<RosettaAotApi::apply_segmented_runtime_routine_fixups_fn>(
                g_rosetta_aot.handle,
                "_ZN7rosetta14librosetta_aot38apply_segmented_runtime_routine_fixupsEPNS0_"
                "17TranslationResultEPhh");
        g_rosetta_aot.version = load_symbol<RosettaAotApi::version_fn>(
            g_rosetta_aot.handle, "_ZN7rosetta14librosetta_aot7versionEv");
        g_rosetta_aot.translate = load_symbol<RosettaAotApi::translate_fn>(
            g_rosetta_aot.handle, "_ZN7rosetta14librosetta_aot9translateEPKNS0_12ModuleResultE");
        g_rosetta_aot.ir_create = load_symbol<RosettaAotApi::ir_create_fn>(
            g_rosetta_aot.handle,
            "_ZN7rosetta14librosetta_aot9ir_createEPKh8IntervalIyES4_S3_IjES4_S5_jNSt3__"
            "16vectorIjNS6_9allocatorIjEEEENS7_INS_5macho15DataInCodeEntryENS8_ISC_EEEE");
    } catch (const std::exception& ex) {
        std::print("dlsym failed: {}\n", ex.what());
        dlclose(g_rosetta_aot.handle);
        g_rosetta_aot.handle = nullptr;
        return false;
    }

    Dl_info dl_info;
    if (dladdr(reinterpret_cast<void*>(g_rosetta_aot.translate), &dl_info) == 0) {
        std::print("dladdr failed: {}\n", dlerror());
        dlclose(g_rosetta_aot.handle);
        g_rosetta_aot.handle = nullptr;
        return false;
    }
    g_rosetta_aot.base_addr = reinterpret_cast<uintptr_t>(dl_info.dli_fbase);

    return find_patterns(g_rosetta_aot.base_addr, g_rosetta_aot.translate_insn_addr,
                         g_rosetta_aot.transaction_result_size_addr);
}

/*
__const:000000010000FA4C runtime_routine_offsets DCD 0x22C8      ; 0branch_slot
__const:000000010000FA50                 DCD 0x138               ; 1 indirect_jmp
__const:000000010000FA54                 DCD 0x1318              ; 2 indirect_jmp_dyld_stub
__const:000000010000FA58                 DCD 0                   ; 3 far_jmp
__const:000000010000FA5C                 DCD 0x19C               ; 4 indirect_call
__const:000000010000FA60                 DCD 0x68                ; 5 far_call
__const:000000010000FA64                 DCD 0x22FC              ; 6 return_stack_miss
__const:000000010000FA68                 DCD 0x34                ; 7 far_ret
__const:000000010000FA6C                 DCD 0x9C                ; 8 far_ret_single_step
__const:000000010000FA70                 DCD 0x200               ; 9 syscall_handler
__const:000000010000FA74                 DCD 0x234               ; 0xA toggle_single_step
__const:000000010000FA78                 DCD 0x1364              ; 0xB cpuid
__const:000000010000FA7C                 DCD 0x27D8              ; 0xC wide_udiv_64
__const:000000010000FA80                 DCD 0x27E0              ; 0xD wide_sdiv_64
__const:000000010000FA84                 DCD 0x39C               ; 0xE pcmpestri
__const:000000010000FA88                 DCD 0x3D0               ; 0xF pcmpestrm
__const:000000010000FA8C                 DCD 0x404               ; 0x10 pcmpistri
__const:000000010000FA90                 DCD 0x438               ; 0x11 pcmpistrm
__const:000000010000FA94                 DCD 0xD0                ; 0x12 mov_segment
__const:000000010000FA98                 DCD 0x104               ; 0x13 mov_segment_and_reg
__const:000000010000FA9C                 DCD 0x134C              ; 0x14 get_cpu_number
__const:000000010000FAA0                 DCD 0x1358              ; 0x15 get_tls_base
__const:000000010000FAA4                 DCD 0x12D8              ; 0x16 read_timer_nanoseconds
__const:000000010000FAA8                 DCD 0x334               ; 0x17 read_mxcsr
__const:000000010000FAAC                 DCD 0x2D0               ; 0x18 mxcsr_to_fpcr_fpsr
__const:000000010000FAB0                 DCD 0x46C               ; 0x19 f2xm1
__const:000000010000FAB4                 DCD 0x4A0               ; 0x1A fabs
__const:000000010000FAB8                 DCD 0x9E8               ; 0x1B fadd_f32
__const:000000010000FABC                 DCD 0xA1C               ; 0x1C fadd_f64
__const:000000010000FAC0                 DCD 0x11A0              ; 0x1D fadd_ST
__const:000000010000FAC4                 DCD 0xF64               ; 0x1E fbld
__const:000000010000FAC8                 DCD 0x848               ; 0x1F fbstp
__const:000000010000FACC                 DCD 0x4D4               ; 0x20 fchs
__const:000000010000FAD0                 DCD 0xFCC               ; 0x21 fcmov
__const:000000010000FAD4                 DCD 0x1000              ; 0x22 fcom_f32
__const:000000010000FAD8                 DCD 0x1034              ; 0x23 fcom_f64
__const:000000010000FADC                 DCD 0x1068              ; 0x24 fcom_ST
__const:000000010000FAE0                 DCD 0x109C              ; 0x25 fcomi
__const:000000010000FAE4                 DCD 0x508               ; 0x26 fcos
__const:000000010000FAE8                 DCD 0x53C               ; 0x27 fdecstp
__const:000000010000FAEC                 DCD 0xA50               ; 0x28 fdiv_f32
__const:000000010000FAF0                 DCD 0xA84               ; 0x29 fdiv_f64
__const:000000010000FAF4                 DCD 0x11D4              ; 0x2A fdiv_ST
__const:000000010000FAF8                 DCD 0xAB8               ; 0x2B fdivr_f32
__const:000000010000FAFC                 DCD 0xAEC               ; 0x2C fdivr_f64
__const:000000010000FB00                 DCD 0x1208              ; 0x2D fdivr_ST
__const:000000010000FB04                 DCD 0xB20               ; 0x2E fiadd
__const:000000010000FB08                 DCD 0x10D0              ; 0x2F ficom
__const:000000010000FB0C                 DCD 0xB54               ; 0x30 fidiv
__const:000000010000FB10                 DCD 0xB88               ; 0x31 fidivr
__const:000000010000FB14                 DCD 0x8B0               ; 0x32 fild
__const:000000010000FB18                 DCD 0xBBC               ; 0x33 fimul
__const:000000010000FB1C                 DCD 0x570               ; 0x34 fincstp
__const:000000010000FB20                 DCD 0xD90               ; 0x35 fist_i16
__const:000000010000FB24                 DCD 0xDC4               ; 0x36 fist_i32
__const:000000010000FB28                 DCD 0xDF8               ; 0x37 fist_i64
__const:000000010000FB2C                 DCD 0xE2C               ; 0x38 fistt_i16
__const:000000010000FB30                 DCD 0xE60               ; 0x39 fistt_i32
__const:000000010000FB34                 DCD 0xE94               ; 0x3A fistt_i64
__const:000000010000FB38                 DCD 0xBF0               ; 0x3B fisub
__const:000000010000FB3C                 DCD 0xC24               ; 0x3C fisubr
__const:000000010000FB40                 DCD 0x94C               ; 0x3D fld_fp32
__const:000000010000FB44                 DCD 0x980               ; 0x3E fld_fp64
__const:000000010000FB48                 DCD 0xF98               ; 0x3F fld_fp80
__const:000000010000FB4C                 DCD 0x918               ; 0x40 fld_constant
__const:000000010000FB50                 DCD 0x8E4               ; 0x41 fld_STi
__const:000000010000FB54                 DCD 0xC58               ; 0x42 fmul_f32
__const:000000010000FB58                 DCD 0xC8C               ; 0x43 fmul_f64
__const:000000010000FB5C                 DCD 0x123C              ; 0x44 fmul_ST
__const:000000010000FB60                 DCD 0x5A4               ; 0x45 fpatan
__const:000000010000FB64                 DCD 0x5D8               ; 0x46 fprem
__const:000000010000FB68                 DCD 0x60C               ; 0x47 fprem1
__const:000000010000FB6C                 DCD 0x640               ; 0x48 fptan
__const:000000010000FB70                 DCD 0x674               ; 0x49 frndint
__const:000000010000FB74                 DCD 0x6A8               ; 0x4A fscale
__const:000000010000FB78                 DCD 0x6DC               ; 0x4B fsin
__const:000000010000FB7C                 DCD 0x710               ; 0x4C fsincos
__const:000000010000FB80                 DCD 0x744               ; 0x4D fsqrt
__const:000000010000FB84                 DCD 0xEC8               ; 0x4E fst_fp32
__const:000000010000FB88                 DCD 0xEFC               ; 0x4F fst_fp64
__const:000000010000FB8C                 DCD 0xF30               ; 0x50 fst_fp80
__const:000000010000FB90                 DCD 0x1104              ; 0x51 fst_STi
__const:000000010000FB94                 DCD 0xCC0               ; 0x52 fsub_f32
__const:000000010000FB98                 DCD 0xCF4               ; 0x53 fsub_f64
__const:000000010000FB9C                 DCD 0x1270              ; 0x54 fsub_ST
__const:000000010000FBA0                 DCD 0xD28               ; 0x55 fsubr_f32
__const:000000010000FBA4                 DCD 0xD5C               ; 0x56 fsubr_f64
__const:000000010000FBA8                 DCD 0x12A4              ; 0x57 fsubr_ST
__const:000000010000FBAC                 DCD 0x1138              ; 0x58 fucom
__const:000000010000FBB0                 DCD 0x116C              ; 0x59 fucomi
__const:000000010000FBB4                 DCD 0x778               ; 0x5A fxam
__const:000000010000FBB8                 DCD 0x9B4               ; 0x5B fxch
__const:000000010000FBBC                 DCD 0x7AC               ; 0x5C fxtract
__const:000000010000FBC0                 DCD 0x7E0               ; 0x5D fyl2x
__const:000000010000FBC4                 DCD 0x814               ; 0x5E fyl2xp1
__const:000000010000FBC8                 DCD 0x87C               ; 0x5F ffree
__const:000000010000FBCC                 DCD 0x268               ; 0x60 load_segment_limit
__const:000000010000FBD0                 DCD 0x29C               ; 0x61 rdrand
*/

std::array<std::uint32_t, 0x62> g_runtime_routine_offsets = {
    // todo ...
    0x22C8, 0x138,  0x1318, 0,      0x19C,  0x68,  0x22FC, 0x34,   0x9C,  0x200,  0x234,
    0x1364, 0x27D8, 0x27E0, 0x39C,  0x3D0,  0x404, 0x438,  0xD0,   0x104, 0x134C, 0x1358,
    0x12D8, 0x334,  0x2D0,  0x46C,  0x4A0,  0x9E8, 0xA1C,  0x11A0, 0xF64, 0x848,  0x4D4,
    0xFCC,  0x1000, 0x1034, 0x1068, 0x109C, 0x508, 0x53C,  0xA50,  0xA84, 0x11D4, 0xAB8,
    0xAEC,  0x1208, 0xB20,  0x10D0, 0xB54,  0xB88, 0x8B0,  0xBBC,  0x570, 0xD90,  0xDC4,
    0xDF8,  0xE2C,  0xE60,  0xE94,  0xBF0,  0xC24, 0x94C,  0x980,  0xF98, 0x918,  0x8E4,
    0xC58,  0xC8C,  0x123C, 0x5A4,  0x5D8,  0x60C, 0x640,  0x674,  0x6A8, 0x6DC,  0x710,
    0x744,  0xEC8,  0xEFC,  0xF30,  0x1104, 0xCC0, 0xCF4,  0x1270, 0xD28, 0xD5C,  0x12A4,
    0x1138, 0x116C, 0x778,  0x9B4,  0x7AC,  0x7E0, 0x814,  0x87C,  0x268, 0x29C,
};

/*

__data:0000000100018070 runtime_routine_names DCQ aBranchSlot         ; 0
__data:0000000100018070                                         ; DATA XREF:
init_translator_context+8C↑o
__data:0000000100018070                                         ; parse_from_dyld_shared_cache+39C↑o
; "branch_slot"
__data:0000000100018078                 DCQ aIndirectJmp        ; 1 ; "indirect_jmp"
__data:0000000100018080                 DCQ aIndirectJmpDyl     ; 2 ; "indirect_jmp_dyld_stub"
__data:0000000100018088                 DCQ aFarJmp             ; 3 ; "far_jmp"
__data:0000000100018090                 DCQ aIndirectCall       ; 4 ; "indirect_call"
__data:0000000100018098                 DCQ aFarCall            ; 5 ; "far_call"
__data:00000001000180A0                 DCQ aReturnStackMis     ; 6 ; "return_stack_miss"
__data:00000001000180A8                 DCQ aFarRet             ; 7 ; "far_ret"
__data:00000001000180B0                 DCQ aFarRetSingleSt     ; 8 ; "far_ret_single_step"
__data:00000001000180B8                 DCQ aSyscallHandler     ; 9 ; "syscall_handler"
__data:00000001000180C0                 DCQ aToggleSingleSt     ; 0xA ; "toggle_single_step"
__data:00000001000180C8                 DCQ aCpuid              ; 0xB ; "cpuid"
__data:00000001000180D0                 DCQ aWideUdiv64         ; 0xC ; "wide_udiv_64"
__data:00000001000180D8                 DCQ aWideSdiv64         ; 0xD ; "wide_sdiv_64"
__data:00000001000180E0                 DCQ aPcmpestri          ; 0xE ; "pcmpestri"
__data:00000001000180E8                 DCQ aPcmpestrm          ; 0xF ; "pcmpestrm"
__data:00000001000180F0                 DCQ aPcmpistri          ; 0x10 ; "pcmpistri"
__data:00000001000180F8                 DCQ aPcmpistrm          ; 0x11 ; "pcmpistrm"
__data:0000000100018100                 DCQ aMovSegment         ; 0x12 ; "mov_segment"
__data:0000000100018108                 DCQ aMovSegmentAndR     ; 0x13 ; "mov_segment_and_reg"
__data:0000000100018110                 DCQ aGetCpuNumber       ; 0x14 ; "get_cpu_number"
__data:0000000100018118                 DCQ aGetTlsBase         ; 0x15 ; "get_tls_base"
__data:0000000100018120                 DCQ aReadTimerNanos     ; 0x16 ; "read_timer_nanoseconds"
__data:0000000100018128                 DCQ aReadMxcsr          ; 0x17 ; "read_mxcsr"
__data:0000000100018130                 DCQ aMxcsrToFpcrFps     ; 0x18 ; "mxcsr_to_fpcr_fpsr"
__data:0000000100018138                 DCQ aF2xm1              ; 0x19 ; "f2xm1"
__data:0000000100018140                 DCQ aFabs               ; 0x1A ; "fabs"
__data:0000000100018148                 DCQ aFaddF32            ; 0x1B ; "fadd_f32"
__data:0000000100018150                 DCQ aFaddF64            ; 0x1C ; "fadd_f64"
__data:0000000100018158                 DCQ aFaddSt             ; 0x1D ; "fadd_ST"
__data:0000000100018160                 DCQ aFbld               ; 0x1E ; "fbld"
__data:0000000100018168                 DCQ aFbstp              ; 0x1F ; "fbstp"
__data:0000000100018170                 DCQ aFchs               ; 0x20 ; "fchs"
__data:0000000100018178                 DCQ aFcmov              ; 0x21 ; "fcmov"
__data:0000000100018180                 DCQ aFcomF32            ; 0x22 ; "fcom_f32"
__data:0000000100018188                 DCQ aFcomF64            ; 0x23 ; "fcom_f64"
__data:0000000100018190                 DCQ aFcomSt             ; 0x24 ; "fcom_ST"
__data:0000000100018198                 DCQ aFcomi              ; 0x25 ; "fcomi"
__data:00000001000181A0                 DCQ aFcos               ; 0x26 ; "fcos"
__data:00000001000181A8                 DCQ aFdecstp            ; 0x27 ; "fdecstp"
__data:00000001000181B0                 DCQ aFdivF32            ; 0x28 ; "fdiv_f32"
__data:00000001000181B8                 DCQ aFdivF64            ; 0x29 ; "fdiv_f64"
__data:00000001000181C0                 DCQ aFdivSt             ; 0x2A ; "fdiv_ST"
__data:00000001000181C8                 DCQ aFdivrF32           ; 0x2B ; "fdivr_f32"
__data:00000001000181D0                 DCQ aFdivrF64           ; 0x2C ; "fdivr_f64"
__data:00000001000181D8                 DCQ aFdivrSt            ; 0x2D ; "fdivr_ST"
__data:00000001000181E0                 DCQ aFiadd              ; 0x2E ; "fiadd"
__data:00000001000181E8                 DCQ aFicom              ; 0x2F ; "ficom"
__data:00000001000181F0                 DCQ aFidiv              ; 0x30 ; "fidiv"
__data:00000001000181F8                 DCQ aFidivr             ; 0x31 ; "fidivr"
__data:0000000100018200                 DCQ aFild               ; 0x32 ; "fild"
__data:0000000100018208                 DCQ aFimul              ; 0x33 ; "fimul"
__data:0000000100018210                 DCQ aFincstp            ; 0x34 ; "fincstp"
__data:0000000100018218                 DCQ aFistI16            ; 0x35 ; "fist_i16"
__data:0000000100018220                 DCQ aFistI32            ; 0x36 ; "fist_i32"
__data:0000000100018228                 DCQ aFistI64            ; 0x37 ; "fist_i64"
__data:0000000100018230                 DCQ aFisttI16           ; 0x38 ; "fistt_i16"
__data:0000000100018238                 DCQ aFisttI32           ; 0x39 ; "fistt_i32"
__data:0000000100018240                 DCQ aFisttI64           ; 0x3A ; "fistt_i64"
__data:0000000100018248                 DCQ aFisub              ; 0x3B ; "fisub"
__data:0000000100018250                 DCQ aFisubr             ; 0x3C ; "fisubr"
__data:0000000100018258                 DCQ aFldFp32            ; 0x3D ; "fld_fp32"
__data:0000000100018260                 DCQ aFldFp64            ; 0x3E ; "fld_fp64"
__data:0000000100018268                 DCQ aFldFp80            ; 0x3F ; "fld_fp80"
__data:0000000100018270                 DCQ aFldConstant        ; 0x40 ; "fld_constant"
__data:0000000100018278                 DCQ aFldSti             ; 0x41 ; "fld_STi"
__data:0000000100018280                 DCQ aFmulF32            ; 0x42 ; "fmul_f32"
__data:0000000100018288                 DCQ aFmulF64            ; 0x43 ; "fmul_f64"
__data:0000000100018290                 DCQ aFmulSt             ; 0x44 ; "fmul_ST"
__data:0000000100018298                 DCQ aFpatan             ; 0x45 ; "fpatan"
__data:00000001000182A0                 DCQ aFprem              ; 0x46 ; "fprem"
__data:00000001000182A8                 DCQ aFprem1             ; 0x47 ; "fprem1"
__data:00000001000182B0                 DCQ aFptan              ; 0x48 ; "fptan"
__data:00000001000182B8                 DCQ aFrndint            ; 0x49 ; "frndint"
__data:00000001000182C0                 DCQ aFscale             ; 0x4A ; "fscale"
__data:00000001000182C8                 DCQ aFsin               ; 0x4B ; "fsin"
__data:00000001000182D0                 DCQ aFsincos            ; 0x4C ; "fsincos"
__data:00000001000182D8                 DCQ aFsqrt              ; 0x4D ; "fsqrt"
__data:00000001000182E0                 DCQ aFstFp32            ; 0x4E ; "fst_fp32"
__data:00000001000182E8                 DCQ aFstFp64            ; 0x4F ; "fst_fp64"
__data:00000001000182F0                 DCQ aFstFp80            ; 0x50 ; "fst_fp80"
__data:00000001000182F8                 DCQ aFstSti             ; 0x51 ; "fst_STi"
__data:0000000100018300                 DCQ aFsubF32            ; 0x52 ; "fsub_f32"
__data:0000000100018308                 DCQ aFsubF64            ; 0x53 ; "fsub_f64"
__data:0000000100018310                 DCQ aFsubSt             ; 0x54 ; "fsub_ST"
__data:0000000100018318                 DCQ aFsubrF32           ; 0x55 ; "fsubr_f32"
__data:0000000100018320                 DCQ aFsubrF64           ; 0x56 ; "fsubr_f64"
__data:0000000100018328                 DCQ aFsubrSt            ; 0x57 ; "fsubr_ST"
__data:0000000100018330                 DCQ aFucom              ; 0x58 ; "fucom"
__data:0000000100018338                 DCQ aFucomi             ; 0x59 ; "fucomi"
__data:0000000100018340                 DCQ aFxam               ; 0x5A ; "fxam"
__data:0000000100018348                 DCQ aFxch               ; 0x5B ; "fxch"
__data:0000000100018350                 DCQ aFxtract            ; 0x5C ; "fxtract"
__data:0000000100018358                 DCQ aFyl2x              ; 0x5D ; "fyl2x"
__data:0000000100018360                 DCQ aFyl2xp1            ; 0x5E ; "fyl2xp1"
__data:0000000100018368                 DCQ aFfree              ; 0x5F ; "ffree"
__data:0000000100018370                 DCQ aLoadSegmentLim     ; 0x60 ; "load_segment_limit"
__data:0000000100018378                 DCQ aRdrand             ; 0x61 ; "rdrand"
__data:0000000100018378 ; __data        ends
*/

std::array<const char*, 0x62> g_runtime_routine_names = {
    "branch_slot",
    "indirect_jmp",
    "indirect_jmp_dyld_stub",
    "far_jmp",
    "indirect_call",
    "far_call",
    "return_stack_miss",
    "far_ret",
    "far_ret_single_step",
    "syscall_handler",
    "toggle_single_step",
    "cpuid",
    "wide_udiv_64",
    "wide_sdiv_64",
    "pcmpestri",
    "pcmpestrm",
    "pcmpistri",
    "pcmpistrm",
    "mov_segment",
    "mov_segment_and_reg",
    "get_cpu_number",
    "get_tls_base",
    "read_timer_nanoseconds",
    "read_mxcsr",
    "mxcsr_to_fpcr_fpsr",
    "f2xm1",
    "fabs",
    "fadd_f32",
    "fadd_f64",
    "fadd_ST",
    "fbld",
    "fbstp",
    "fchs",
    "fcmov",
    "fcom_f32",
    "fcom_f64",
    "fcom_ST",
    "fcomi",
    "fcos",
    "fdecstp",
    "fdiv_f32",
    "fdiv_f64",
    "fdiv_ST",
    "fdivr_f32",
    "fdivr_f64",
    "fdivr_ST",
    "fiadd",
    "ficom",
    "fidiv",
    "fidivr",
    "fild",
    "fimul",
    "fincstp",
    "fist_i16",
    "fist_i32",
    "fist_i64",
    "fistt_i16",
    "fistt_i32",
    "fistt_i64",
    "fisub",
    "fisubr",
    "fld_fp32",
    "fld_fp64",
    "fld_fp80",
    "fld_constant",
    "fld_STi",
    "fmul_f32",
    "fmul_f64",
    "fmul_ST",
    "fpatan",
    "fprem",
    "fprem1",
    "fptan",
    "frndint",
    "fscale",
    "fsin",
    "fsincos",
    "fsqrt",
    "fst_fp32",
    "fst_fp64",
    "fst_fp80",
    "fst_STi",
    "fsub_f32",
    "fsub_f64",
    "fsub_ST",
    "fsubr_f32",
    "fsubr_f64",
    "fsubr_ST",
    "fucom",
    "fucomi",
    "fxam",
    "fxch",
    "fxtract",
    "fyl2x",
    "fyl2xp1",
    "ffree",
    "load_segment_limit",
    "rdrand",
};

// __const:000000010000C168 thread_context_offsets ThreadContextOffsets <0x118, 0x220, 0x180, 0,
// 0x174, 0xA0>

ThreadContextOffsets g_thread_context_offsets = {
    0x118, 0x220, 0x180, 0, 0x174, 0xA0,
};
