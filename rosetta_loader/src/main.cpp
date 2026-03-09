#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

#include <cstdio>
#include <map>
#include <vector>

#include "macho_loader.hpp"
#include "offset_finder.hpp"
#include "types.h"

const char* logsEnabled = nullptr;
const char* jitOnly = nullptr;

#define LOG(fmt, ...)                   \
    do {                                \
        if (logsEnabled) {              \
            printf(fmt, ##__VA_ARGS__); \
        }                               \
    } while (0)

typedef const struct dyld_process_info_base* DyldProcessInfo;

extern "C" DyldProcessInfo _dyld_process_info_create(task_t task, uint64_t timestamp,
                                                     kern_return_t* kernelError);
extern "C" void _dyld_process_info_for_each_image(DyldProcessInfo info,
                                                  void (^callback)(uint64_t machHeaderAddress,
                                                                   const uuid_t uuid,
                                                                   const char* path));
extern "C" void _dyld_process_info_release(DyldProcessInfo info);

class MuhDebugger {
private:
    static const uint32_t AARCH64_BREAKPOINT;  // just declare here

    pid_t childPid_ = -1;
    task_t taskPort_ = MACH_PORT_NULL;
    std::map<uint64_t, uint32_t> breakpoints_;  // addr -> original instruction

    bool waitForStopped() {
        int status;
        if (waitpid(childPid_, &status, 0) == -1) {
            perror("waitpid");
            return false;
        }
        if (WIFSTOPPED(status)) {
            int signal = WSTOPSIG(status);
            LOG("Process stopped signal=%d\n", signal);
            return true;
        }
        return false;
    }

public:
    ~MuhDebugger() {
        if (taskPort_ != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), taskPort_);
        }
    }

    bool attach(pid_t pid) {
        childPid_ = pid;
        LOG("Attempting to attach to %d\n", childPid_);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (ptrace(PT_ATTACH, childPid_, 0, 0) < 0) {
#pragma clang diagnostic pop
            perror("ptrace(PT_ATTACH)");
            return false;
        }

        if (!waitForStopped()) {
            return false;
        }
        LOG("Program stopped due to debugger being attached\n");

        if (!continueExecution()) {
            fprintf(stderr, "Failed to continue execution\n");
            return false;
        }
        if (task_for_pid(mach_task_self(), childPid_, &taskPort_) != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get task port for pid %d\n", childPid_);
            return false;
        }
        LOG("Program stopped due to execv into rosetta process.\n");
        LOG("Started debugging process %d using port %d\n", childPid_, taskPort_);
        return true;
    }

    bool continueExecution() {
        if (ptrace(PT_CONTINUE, childPid_, (caddr_t)1, 0) < 0) {
            perror("ptrace(PT_CONTINUE)");
            return false;
        }

        LOG("continueExecution...\n");

        return waitForStopped();
    }

    bool detach() {
        if (ptrace(PT_DETACH, childPid_, (caddr_t)1, 0) < 0) {
            perror("ptrace(PT_DETACH)");
            return false;
        }
        LOG("Debugger detached.\n");
        return true;
    }

    bool setBreakpoint(uint64_t address) {
        // Verify address is in valid range
        if (address >= MACH_VM_MAX_ADDRESS) {
            fprintf(stderr, "Invalid address 0x%llx\n", address);
            return false;
        }

        // Read the original instruction
        uint32_t original;
        if (!readMemory(address, &original, sizeof(uint32_t))) {
            fprintf(stderr, "Failed to read memory at 0x%llx\n", address);
            return false;
        }

        // First, try to adjust memory protection
        if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                                    sizeof(uint32_t))) {
            return false;
        }

        // Write breakpoint instruction
        if (!writeMemory(address, &AARCH64_BREAKPOINT, sizeof(uint32_t))) {
            fprintf(stderr, "Failed to write breakpoint at 0x%llx\n", address);
            return false;
        }

        if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(uint32_t))) {
            return false;
        }

        breakpoints_[address] = original;
        LOG("Breakpoint set at address 0x%llx\n", address);
        return true;
    }

    bool removeBreakpoint(uint64_t address) {
        auto it = breakpoints_.find(address);
        if (it == breakpoints_.end()) {
            fprintf(stderr, "No breakpoint found at address 0x%llx\n", address);
            return false;
        }

        // First, try to adjust memory protection
        if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_WRITE, sizeof(uint32_t))) {
            return false;
        }

        // Restore original instruction
        if (!writeMemory(address, &it->second, sizeof(uint32_t))) {
            fprintf(stderr, "Failed to restore original instruction at 0x%llx\n", address);
            return false;
        }

        if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(uint32_t))) {
            return false;
        }
        breakpoints_.erase(it);
        LOG("Breakpoint removed from address 0x%llx\n", address);
        return true;
    }

    enum Register {
        X0,
        X1,
        X2,
        X3,
        X4,
        X5,
        X6,
        X7,
        X8,
        X9,
        X10,
        X11,
        X12,
        X13,
        X14,
        X15,
        X16,
        X17,
        X18,
        X19,
        X20,
        X21,
        X22,
        X23,
        X24,
        X25,
        X26,
        X27,
        X28,
        FP,
        LR,
        SP,
        PC,
        CPSR
    };

    uint64_t readRegister(Register reg) {
        thread_act_port_array_t threadList;
        mach_msg_type_number_t threadCount;

        kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
            return 0;
        }

        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state, &count);

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get thread state (error 0x%x: %s)\n", kr,
                    mach_error_string(kr));
            return 0;
        }

        uint64_t value = 0;
        if (reg >= X0 && reg <= X28) {
            value = state.__x[reg];
        } else {
            switch (reg) {
                case FP:
                    value = state.__fp;
                    break;
                case LR:
                    value = state.__lr;
                    break;
                case SP:
                    value = state.__sp;
                    break;
                case PC:
                    value = state.__pc;
                    break;
                case CPSR:
                    value = state.__cpsr;
                    break;
                default: {
                    fprintf(stderr, "Invalid register\n");
                    return 0;
                }
            }
        }

        // Cleanup
        for (unsigned int i = 0; i < threadCount; i++) {
            mach_port_deallocate(mach_task_self(), threadList[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);

        return value;
    }

    bool setRegister(Register reg, uint64_t value) {
        thread_act_port_array_t threadList;
        mach_msg_type_number_t threadCount;

        kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
            return false;
        }

        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state, &count);

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get thread state (error 0x%x: %s)\n", kr,
                    mach_error_string(kr));
            return false;
        }

        if (reg >= X0 && reg <= X28) {
            state.__x[reg] = value;
        } else {
            switch (reg) {
                case FP:
                    state.__fp = value;
                    break;
                case LR:
                    state.__lr = value;
                    break;
                case SP:
                    state.__sp = value;
                    break;
                case PC:
                    state.__pc = value;
                    break;
                case CPSR:
                    state.__cpsr = value;
                    break;
                default: {
                    fprintf(stderr, "Invalid register\n");
                    return false;
                }
            }
        }

        kr = thread_set_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state,
                              ARM_THREAD_STATE64_COUNT);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to set thread state (error 0x%x: %s)\n", kr,
                    mach_error_string(kr));
            return false;
        }

        // Cleanup
        for (uint i = 0; i < threadCount; i++) {
            mach_port_deallocate(mach_task_self(), threadList[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);

        return true;
    }

    bool adjustMemoryProtection(uint64_t address, vm_prot_t protection, mach_vm_size_t size) {
        // 4KB page size in rosetta process
        vm_size_t pageSize = 0x1000;
        // align to page boundary
        mach_vm_address_t region = address & ~(pageSize - 1);
        size = ((address + size + pageSize - 1) & ~(pageSize - 1)) - region;

        LOG("Adjusting memory protection at 0x%llx - 0x%llx\n", (uint64_t)region,
            (uint64_t)(region + size));

        kern_return_t kr = mach_vm_protect(taskPort_, region, size, false, protection);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr,
                    "Failed to adjust memory protection at 0x%llx - 0x%llx (error 0x%x: %s)\n",
                    (uint64_t)region, (uint64_t)(region + size), kr, mach_error_string(kr));
            return false;
        }
        return true;
    }

    bool readMemory(uint64_t address, void* buffer, size_t size) {
        mach_vm_size_t readSize;

        kern_return_t kr =
            mach_vm_read_overwrite(taskPort_, address, size, (mach_vm_address_t)buffer, &readSize);

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to read memory at 0x%llx (error 0x%x: %s)\n", address, kr,
                    mach_error_string(kr));
            return false;
        }

        return readSize == size;
    }

    bool writeMemory(uint64_t address, const void* buffer, size_t size) {
        kern_return_t kr = mach_vm_write(taskPort_, address, (vm_offset_t)buffer, size);

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to write memory at 0x%llx (error 0x%x: %s)\n", address, kr,
                    mach_error_string(kr));
            return false;
        }

        return true;
    }

    bool copyThreadState(arm_thread_state64_t& state) {
        thread_act_port_array_t threadList;
        mach_msg_type_number_t threadCount;

        kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
            return false;
        }

        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state, &count);

        // Cleanup
        for (uint i = 0; i < threadCount; i++) {
            mach_port_deallocate(mach_task_self(), threadList[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get thread state (error 0x%x: %s)\n", kr,
                    mach_error_string(kr));
            return false;
        }

        return true;
    }

    bool restoreThreadState(const arm_thread_state64_t& state) {
        thread_act_port_array_t threadList;
        mach_msg_type_number_t threadCount;

        kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
            return false;
        }

        kr = thread_set_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state,
                              ARM_THREAD_STATE64_COUNT);

        // Cleanup
        for (uint i = 0; i < threadCount; i++) {
            mach_port_deallocate(mach_task_self(), threadList[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to set thread state (error 0x%x: %s)\n", kr,
                    mach_error_string(kr));
            return false;
        }

        return true;
    }

    auto findRuntime() -> uintptr_t {
        mach_vm_address_t address = 0;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName;
        kern_return_t kr;
        __block std::vector<uintptr_t> moduleList;

        auto processInfo = _dyld_process_info_create(taskPort_, 0, &kr);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get dyld process info (error 0x%x: %s)\n", kr,
                    mach_error_string(kr));
            return 0;
        }
        _dyld_process_info_for_each_image(processInfo,
                                          ^(uint64_t address, const uuid_t uuid, const char* path) {
                                            LOG("Module: 0x%llx - %s\n", address, path);
                                            moduleList.push_back(address);
                                          });
        _dyld_process_info_release(processInfo);

        while (true) {
            if (mach_vm_region(taskPort_, &address, &size, VM_REGION_BASIC_INFO_64,
                               (vm_region_info_t)&info, &count, &objectName) != KERN_SUCCESS) {
                break;
            }

            if (info.protection & (VM_PROT_EXECUTE | VM_PROT_READ)) {
                if (std::find_if(moduleList.begin(), moduleList.end(),
                                 [address](const uintptr_t& moduleAddress) {
                                     return address == moduleAddress;
                                 }) == moduleList.end()) {
                    uint32_t magicBytes;
                    if (readMemory(address, &magicBytes, sizeof(magicBytes)) &&
                        magicBytes == MH_MAGIC_64) {
                        return address;
                    }
                }
            }

            address += size;
        }

        return 0;
    }
};

// Define the static constant outside the class
const unsigned int MuhDebugger::AARCH64_BREAKPOINT = 0xD4200000;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "%s <path to program>\n", argv[0]);
        return 1;
    }

    logsEnabled = getenv("ROSETTA_X87_LOGS");
    jitOnly = getenv("ROSETTA_X87_JIT_ONLY");

    LOG("Launching debugger.\n");

    // Fork and execute new instance
    pid_t child = fork();

    // the debugger will be this process debugging its child
    if (child == 0) {
        // the fresh child waiting to be debugged
        if (ptrace(PT_TRACE_ME, 0, nullptr, 0) == -1) {
            perror("child: ptrace(PT_TRACE_ME)");
            return 1;
        }
        LOG("child: launching into program: %s\n", argv[1]);
        execv(argv[1], &argv[1]);
        return 1;
    }

    MuhDebugger dbg;
    if (!dbg.attach(child)) {
        fprintf(stderr, "Failed to attach to process\n");
        return 1;
    }
    LOG("Attached successfully\n");

    // Set up offsets dynamically
    OffsetFinder offsetFinder;
    // Set default offsets temporarily (or just in case we need to fall back)
    offsetFinder.setDefaultOffsets();
    // Search the rosetta runtime binary for offsets.
    if (offsetFinder.determineOffsets()) {
        LOG("Found rosetta runtime offsets successfully!\n");
        LOG("offset_exports_fetch=%llx offset_svc_call_entry=%llx offset_svc_call_ret=%llx\n",
            offsetFinder.offsetExportsFetch_, offsetFinder.offsetSvcCallEntry_,
            offsetFinder.offsetSvcCallRet_);
    }
    if (offsetFinder.determineRuntimeOffsets()) {
        LOG("Found additional rosetta runtime offsets successfully!\n");
        LOG("offset_translate_insn=%llx offset_transaction_result_size=%llx\n",
            offsetFinder.offsetTranslateInsn_, offsetFinder.offsetTransactionResultSize_);
    }

    const auto runtimeBase = dbg.findRuntime();

    LOG("Rosetta runtime base: 0x%lx\n", runtimeBase);

    if (runtimeBase == 0) {
        fprintf(stderr, "Failed to find Rosetta runtime\n");
        return 1;
    }

    // disable ahead of time compiler to always force JIT
    uint8_t g_disable_aot_value = 1;

    dbg.writeMemory(runtimeBase + offsetFinder.offsetDisableAot_, &g_disable_aot_value,
                    sizeof(g_disable_aot_value));

    dbg.setBreakpoint(runtimeBase + offsetFinder.offsetExportsFetch_);
    dbg.continueExecution();
    dbg.removeBreakpoint(runtimeBase + offsetFinder.offsetExportsFetch_);

    auto rosettaRuntimeExportsAddress = dbg.readRegister(MuhDebugger::Register::X19);
    LOG("Rosetta runtime exports: 0x%llx\n", rosettaRuntimeExportsAddress);

    Exports exports;
    dbg.readMemory(rosettaRuntimeExportsAddress, &exports, sizeof(exports));

    LOG("Rosetta version: %llx\n", exports.version);

    char path[PATH_MAX];
    uint32_t pathSize = sizeof(path);
    if (_NSGetExecutablePath(path, &pathSize) != 0) {
        fprintf(stderr, "Failed to get executable path\n");
        return 1;
    }

    // get the directory of the current executable
    std::filesystem::path executablePath(path);
    std::filesystem::path executableDir = executablePath.parent_path();

    MachoLoader machoLoader;
    if (!machoLoader.open(executableDir / "libRuntimeRosettax87")) {
        fprintf(stderr, "Failed to open Mach-O file\n");
        return 1;
    }

    // first we store the original state of the thread
    arm_thread_state64_t backupThreadState;
    dbg.copyThreadState(backupThreadState);

    // now we prepare the registers for the mmap call
    arm_thread_state64_t mmapThreadState;
    memcpy(&mmapThreadState, &backupThreadState, sizeof(arm_thread_state64_t));

    mmapThreadState.__x[0] = 0LL;                                      // addr
    mmapThreadState.__x[1] = machoLoader.imageSize();                  // size
    mmapThreadState.__x[2] = VM_PROT_READ | VM_PROT_WRITE;             // prot
    mmapThreadState.__x[3] = MAP_ANON | MAP_TRANSLATED_ALLOW_EXECUTE;  // flags
    mmapThreadState.__x[4] = -1;                                       // fd
    mmapThreadState.__x[5] = 0;                                        // offset
    mmapThreadState.__pc = runtimeBase + offsetFinder.offsetSvcCallEntry_;

    dbg.restoreThreadState(mmapThreadState);

    // setup a breakpoint after mmap syscall
    dbg.setBreakpoint(runtimeBase + offsetFinder.offsetSvcCallRet_);
    dbg.continueExecution();
    dbg.removeBreakpoint(runtimeBase + offsetFinder.offsetSvcCallRet_);

    uint64_t machoBase = dbg.readRegister(MuhDebugger::Register::X0);

    LOG("Allocated memory at 0x%llx\n", machoBase);

    dbg.restoreThreadState(backupThreadState);

    // Calculate the Mach-O's preferred base (lowest vmaddr) so we can rebase segments correctly
    uint64_t machoPreferredBase = UINT64_MAX;
    machoLoader.forEachSegment([&](segment_command_64* segm) {
        if (segm->vmaddr < machoPreferredBase)
            machoPreferredBase = segm->vmaddr;
    });
    if (machoPreferredBase == UINT64_MAX)
        machoPreferredBase = 0;

    // Pass 1: write all segment data while the mmap'd region is still uniformly rw-.
    // Protections must NOT be applied until all segments are written, because page-aligned
    // protection changes for one segment can overlap adjacent segments.
    // __LINKEDIT is skipped: it contains only linker metadata, is not needed at runtime,
    // and its vmaddr range overlaps __DATA in this binary's layout.
    machoLoader.forEachSegment([&](segment_command_64* segm) {
        if (strncmp(segm->segname, "__LINKEDIT", 16) == 0)
            return;

        uint64_t segOffset = segm->vmaddr - machoPreferredBase;
        uint64_t dest = machoBase + segOffset;

        LOG("Copying segment %s: fileoff=0x%llx filesize=0x%llx vmaddr=0x%llx vmsize=0x%llx -> "
            "dest=0x%llx\n",
            segm->segname, (uint64_t)segm->fileoff, (uint64_t)segm->filesize,
            (uint64_t)segm->vmaddr, (uint64_t)segm->vmsize, dest);

        // Zero-fill vmsize bytes, then overwrite the first filesize bytes from the file.
        // vmsize >= filesize; the tail (BSS-like) must stay zero.
        std::vector<uint8_t> segData(segm->vmsize, 0);
        if (segm->filesize > 0) {
            memcpy(segData.data(), machoLoader.buffer_.data() + segm->fileoff, segm->filesize);
        }

        dbg.writeMemory(dest, segData.data(), segm->vmsize);
    });

    // Pass 2: apply chained fixup rebases from __TEXT,__chain_starts.
    // Must happen after all segment data is written but before protections are applied
    // (while the entire region is still uniformly rw-).
    {
        uint64_t rebaseSlide = machoBase - machoPreferredBase;
        LOG("Rebase slide: 0x%llx\n", rebaseSlide);

        auto* chainStartsSect = machoLoader.getSection("__TEXT", "__chain_starts");
        if (!chainStartsSect) {
            LOG("WARNING: no __chain_starts section found, skipping rebase\n");
        } else if (rebaseSlide == 0) {
            LOG("Rebase slide is 0, skipping rebase\n");
        } else {
            uint8_t* sectData = machoLoader.buffer_.data() + chainStartsSect->offset;

            // dyld_chained_starts_offsets layout:
            //   uint32_t pointer_format
            //   uint32_t starts_count
            //   uint32_t chain_starts[starts_count]  <- file offsets to first chain entry
            uint32_t pointerFormat = *(uint32_t*)(sectData + 0);
            uint32_t startsCount = *(uint32_t*)(sectData + 4);

            LOG("chain_starts: pointer_format=%u starts_count=%u\n", pointerFormat, startsCount);

            if (pointerFormat != 6) {
                // 6 = DYLD_CHAINED_PTR_64_OFFSET
                LOG("WARNING: unsupported chain pointer format %u, skipping rebase\n",
                    pointerFormat);
            } else {
                for (uint32_t i = 0; i < startsCount; i++) {
                    uint32_t chainFileOffset = *(uint32_t*)(sectData + 8 + i * 4);
                    LOG("  chain[%u] file offset: 0x%x\n", i, chainFileOffset);

                    uint64_t curFileOffset = chainFileOffset;

                    while (true) {
                        uint64_t raw = *(uint64_t*)(machoLoader.buffer_.data() + curFileOffset);

                        // dyld_chained_ptr_64_rebase bitfield:
                        //   [35: 0] target   (36 bits) runtimeOffset from image base
                        //   [43:36] high8    ( 8 bits) top 8 bits of target
                        //   [50:44] reserved ( 7 bits)
                        //   [62:51] next     (12 bits) 4-byte stride to next entry, 0 = end
                        //   [63:63] bind     ( 1 bit)  0 = rebase, 1 = bind (ignored for static)
                        uint64_t target = (raw >> 0) & 0xFFFFFFFFFULL;
                        uint64_t high8 = (raw >> 36) & 0xFFULL;
                        uint64_t next = (raw >> 51) & 0xFFFULL;  // starts at bit 51, not 52
                        uint64_t bind = (raw >> 63) & 0x1ULL;

                        if (bind == 0) {
                            uint64_t fullTarget = target | (high8 << 56);
                            uint64_t rebased = fullTarget + rebaseSlide;

                            // Find which segment owns this file offset to compute dest address
                            uint64_t destAddr = 0;
                            machoLoader.forEachSegment([&](segment_command_64* segm) {
                                if (curFileOffset >= segm->fileoff &&
                                    curFileOffset < segm->fileoff + segm->filesize) {
                                    uint64_t offsetInSeg = curFileOffset - segm->fileoff;
                                    destAddr = machoBase + (segm->vmaddr - machoPreferredBase) +
                                               offsetInSeg;
                                }
                            });

                            if (destAddr != 0) {
                                LOG("  Rebase: fileoff=0x%llx target=0x%llx -> 0x%llx "
                                    "dest=0x%llx\n",
                                    curFileOffset, fullTarget, rebased, destAddr);
                                dbg.writeMemory(destAddr, &rebased, sizeof(rebased));
                            } else {
                                LOG("  WARNING: could not map fileoff=0x%llx to any segment\n",
                                    curFileOffset);
                            }
                        }

                        if (next == 0)
                            break;
                        curFileOffset += next * 4;  // 4-byte stride
                    }
                }
            }
        }
    }

    // Pass 3: apply per-segment memory protections now that all data and rebases are in place.
    machoLoader.forEachSegment([&](segment_command_64* segm) {
        if (strncmp(segm->segname, "__LINKEDIT", 16) == 0)
            return;

        uint64_t segOffset = segm->vmaddr - machoPreferredBase;
        uint64_t dest = machoBase + segOffset;
        dbg.adjustMemoryProtection(dest, segm->initprot, segm->vmsize);
    });

    // Write the offsets we found to __DATA,offsets
    uint64_t machoOffsetsAddress = machoBase + machoLoader.getSection("__DATA", "offsets")->addr;
    Offsets machoOffsets = {
        .init_library_rva = offsetFinder.offsetInitLibrary_,
        .translate_insn_addr = offsetFinder.offsetTranslateInsn_,
        .transaction_result_size_addr = offsetFinder.offsetTransactionResultSize_};

    dbg.writeMemory(machoOffsetsAddress, &machoOffsets, sizeof(machoOffsets));

    // fix up Exports segment of mapped macho
    uint64_t machoExportsAddress = machoBase + machoLoader.getSection("__DATA", "exports")->addr;
    Exports machoExports;

    dbg.readMemory(machoExportsAddress, &machoExports, sizeof(machoExports));
    // x87Exports and runtimeExports are already correct absolute addresses
    // after chain fixup rebasing — do NOT add machoBase again.

    std::vector<Export> x87Exports(machoExports.x87ExportCount);
    std::vector<Export> runtimeExports(machoExports.runtimeExportCount);

    dbg.readMemory(machoExports.x87Exports, x87Exports.data(), x87Exports.size() * sizeof(Export));
    dbg.readMemory(machoExports.runtimeExports, runtimeExports.data(),
                   runtimeExports.size() * sizeof(Export));

    // address and name fields are already correct absolute addresses
    // after chain fixup rebasing — do NOT add machoBase again.

    dbg.writeMemory(machoExports.x87Exports, x87Exports.data(), x87Exports.size() * sizeof(Export));
    dbg.writeMemory(machoExports.runtimeExports, runtimeExports.data(),
                    runtimeExports.size() * sizeof(Export));

    LOG("machoExports_address: 0x%llx\n", machoExportsAddress);
    LOG("machoExports.x87Exports: 0x%llx\n", machoExports.x87Exports);
    LOG("machoExports.runtimeExports: 0x%llx\n", machoExports.runtimeExports);

    // match the running system's Rosetta version and export count
    auto libRosettaRuntimeExportsAddress = dbg.readRegister(MuhDebugger::Register::X19);
    Exports libRosettaRuntimeExports;
    dbg.readMemory(libRosettaRuntimeExportsAddress, &libRosettaRuntimeExports,
                   sizeof(libRosettaRuntimeExports));

    machoExports.version = libRosettaRuntimeExports.version;
    if (libRosettaRuntimeExports.x87ExportCount < machoExports.x87ExportCount) {
        LOG("Capping x87ExportCount from %llu to %llu to match system\n",
            machoExports.x87ExportCount, libRosettaRuntimeExports.x87ExportCount);
        machoExports.x87ExportCount = libRosettaRuntimeExports.x87ExportCount;
    }

    dbg.writeMemory(machoExportsAddress, &machoExports, sizeof(machoExports));

    // look up imports section of mapped macho
    auto machoImportsAddress = machoBase + machoLoader.getSection("__DATA", "imports")->addr;
    LOG("machoImportsAddress: 0x%llx\n", machoImportsAddress);

    LOG("libRosettaRuntimeExportsAddress: 0x%llx\n", libRosettaRuntimeExportsAddress);

    LOG("libRosettaRuntimeExports.version = 0x%llx\n", libRosettaRuntimeExports.version);
    LOG("libRosettaRuntimeExports.x87Exports = 0x%llx\n", libRosettaRuntimeExports.x87Exports);
    LOG("libRosettaRuntimeExports.x87Export_count = 0x%llx\n",
        libRosettaRuntimeExports.x87ExportCount);
    LOG("libRosettaRuntimeExports.runtimeExports = 0x%llx\n",
        libRosettaRuntimeExports.runtimeExports);
    LOG("libRosettaRuntimeExports.runtimeExportCount = 0x%llx\n",
        libRosettaRuntimeExports.runtimeExportCount);

    dbg.writeMemory(machoImportsAddress, &libRosettaRuntimeExports,
                    sizeof(libRosettaRuntimeExports));

    // replace the exports in X19 register with the address of the mapped macho
    dbg.setRegister(MuhDebugger::Register::X19, machoExportsAddress);

    // calculate base of rosetta  libRosettaRuntime
    uint64_t rosettaRuntimeBase = libRosettaRuntimeExportsAddress - 0x6A4F8;
    LOG("Calculated rosetta runtime base: 0x%llx\n", rosettaRuntimeBase);

    // calculate address of where our trampoline jumps to
    uint64_t trampolineTarget = rosettaRuntimeBase + 0x1a664;
    // 64 c6 f8 0a 01 00 00 00
    // dbg.setBreakpoint(trampolineTarget);

    dbg.detach();
    // dbg.continueExecution();

    // LOG("Hit breakpoint at trampoline target: 0x%llx\n", trampolineTarget);

    // block until the child exits
    int status;
    waitpid(child, &status, 0);

    return 0;
}
