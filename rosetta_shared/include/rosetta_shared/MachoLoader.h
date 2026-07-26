#pragma once

#include <mach-o/loader.h>
#include <mach/vm_page_size.h>
#include <mach/arm/thread_status.h>  // arm_thread_state64_t, for LC_UNIXTHREAD entry

#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <vector>

// Header-only Mach-O reader: loads a Mach-O image from disk into buffer_ and
// exposes segment/section lookup. Shared by rosetta_loader and available to
// aotinvoke.
struct MachoLoader {
    auto open(std::filesystem::path const& path) -> bool;
    auto machHeader() const -> mach_header_64*;
    auto imageSize() const -> size_t;
    auto getSection(const char* segment, const char* section) -> section_64*;
    auto getSegment(const char* segment) -> segment_command_64*;
    auto forEachSegment(std::function<void(segment_command_64* segm)>) -> void;
    // Image entry point as a *link-time* vmaddr (add the load slide to get the
    // runtime address). Returns 0 if the image declares neither LC_UNIXTHREAD
    // nor LC_MAIN. libRuntimeRosettax87 is linked with -Wl,-e,_start and is
    // static/-nostdlib, so it carries LC_UNIXTHREAD.
    auto entryPoint() const -> uint64_t;

    std::vector<uint8_t> buffer_;
};

inline auto MachoLoader::open(std::filesystem::path const& path) -> bool {
    if (!std::filesystem::exists(path)) {
        return false;
    }

    auto file = std::ifstream(path, std::ios::binary);

    if (!file.is_open()) {
        return false;
    }

    buffer_ = std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                                   std::istreambuf_iterator<char>());

    return buffer_.empty() == false;
}

inline auto MachoLoader::machHeader() const -> mach_header_64* {
    return (mach_header_64*)buffer_.data();
}

inline auto MachoLoader::imageSize() const -> size_t {
    auto header = machHeader();

    size_t imageSize = 0;

    load_command* cmd = (load_command*)(header + 1);

    for (auto i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            auto seg = (segment_command_64*)cmd;

            uint64_t segEnd = seg->vmaddr + seg->vmsize;
            if (segEnd > imageSize) {
                imageSize = segEnd;
            }
        }

        cmd = (load_command*)((uint8_t*)cmd + cmd->cmdsize);
    }

    imageSize = (imageSize + vm_page_size - 1) & ~(vm_page_size - 1);
    return imageSize;
}

inline auto MachoLoader::entryPoint() const -> uint64_t {
    auto header = machHeader();
    if (!header)
        return 0;

    auto cmd = (load_command*)((uint8_t*)header + sizeof(mach_header_64));
    // LC_MAIN stores an offset from the image base; LC_UNIXTHREAD stores a full
    // register set. Track the lowest segment vmaddr so LC_MAIN can be converted
    // to the same vmaddr space LC_UNIXTHREAD's __pc already lives in.
    uint64_t lowestVmaddr = UINT64_MAX;
    for (auto i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            auto seg = (segment_command_64*)cmd;
            if (seg->filesize > 0 && seg->vmaddr < lowestVmaddr)
                lowestVmaddr = seg->vmaddr;
        }
        cmd = (load_command*)((uint8_t*)cmd + cmd->cmdsize);
    }
    if (lowestVmaddr == UINT64_MAX)
        lowestVmaddr = 0;

    cmd = (load_command*)((uint8_t*)header + sizeof(mach_header_64));
    for (auto i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_UNIXTHREAD) {
            // Layout: load_command, then (flavor, count, state...) tuples.
            auto p = (uint32_t*)((uint8_t*)cmd + sizeof(load_command));
            auto end = (uint32_t*)((uint8_t*)cmd + cmd->cmdsize);
            while (p + 2 <= end) {
                uint32_t flavor = p[0];
                uint32_t count = p[1];
                uint32_t* state = p + 2;
                if (flavor == ARM_THREAD_STATE64 && count >= ARM_THREAD_STATE64_COUNT)
                    return ((arm_thread_state64_t*)state)->__pc;
                p = state + count;
            }
        } else if (cmd->cmd == LC_MAIN) {
            auto ep = (entry_point_command*)cmd;
            return lowestVmaddr + ep->entryoff;
        }
        cmd = (load_command*)((uint8_t*)cmd + cmd->cmdsize);
    }
    return 0;
}

inline auto MachoLoader::getSection(const char* segment, const char* section) -> section_64* {
    auto header = machHeader();

    load_command* cmd = (load_command*)(header + 1);

    for (auto i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            auto seg = (segment_command_64*)cmd;

            if (strcmp(seg->segname, segment) == 0) {
                section_64* sect = (section_64*)(seg + 1);

                for (auto j = 0; j < seg->nsects; j++) {
                    if (strcmp(sect->sectname, section) == 0) {
                        return sect;
                    }

                    sect++;
                }
            }
        }

        cmd = (load_command*)((uint8_t*)cmd + cmd->cmdsize);
    }

    return nullptr;
}

inline auto MachoLoader::getSegment(const char* segment) -> segment_command_64* {
    auto header = machHeader();

    load_command* cmd = (load_command*)(header + 1);

    for (auto i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            auto seg = (segment_command_64*)cmd;

            if (strcmp(seg->segname, segment) == 0) {
                return seg;
            }
        }

        cmd = (load_command*)((uint8_t*)cmd + cmd->cmdsize);
    }

    return nullptr;
}

inline auto MachoLoader::forEachSegment(std::function<void(segment_command_64* segm)> callback)
    -> void {
    auto header = machHeader();

    load_command* cmd = (load_command*)(header + 1);

    for (auto i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            auto seg = (segment_command_64*)cmd;

            // Skip __PAGEZERO and any other unmapped segments (initprot=NONE, no file backing)
            if (seg->initprot != VM_PROT_NONE) {
                callback(seg);
            }
        }

        cmd = (load_command*)((uint8_t*)cmd + cmd->cmdsize);
    }
}
