#include "macho_loader.hpp"

#include <mach-o/loader.h>
#include <mach/vm_page_size.h>

#include <fstream>

auto MachoLoader::open(std::filesystem::path const& path) -> bool {
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

auto MachoLoader::machHeader() const -> mach_header_64* {
    return (mach_header_64*)buffer_.data();
}

auto MachoLoader::imageSize() const -> size_t {
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

auto MachoLoader::getSection(const char* segment, const char* section) -> section_64* {
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

auto MachoLoader::getSegment(const char* segment) -> segment_command_64* {
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

auto MachoLoader::forEachSegment(std::function<void(segment_command_64* segm)> callback) -> void {
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
