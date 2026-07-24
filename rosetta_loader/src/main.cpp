#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach_vm.h>
#include <mach/vm_attributes.h>
#include <rosetta_config/Config.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/event.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>  // detach diagnostics: read tracee p_stat
#include <sys/wait.h>
#include <sched.h>

#include <csignal>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "mach_exception.hpp"
#include "offset_finder.hpp"
#include "rosetta_shared/LoaderTypes.h"
#include "rosetta_shared/MachoLoader.h"
#include "rosetta_shared/Offsets.h"

const char* logsEnabled = nullptr;

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

    // Debug events arrive as Mach exception messages on a port we own (see
    // mach_exception.hpp). While an event is held (unreplied) the tracee is
    // stopped; replying resumes it. This replaces the PT_ATTACH +
    // waitpid/WSTOPSIG signal path, whose EXC_BREAKPOINT delivery raced
    // libRosettaRuntime's own handler and leaked our planted BRK to the parent
    // as a fatal SIGTRAP (the flaky exit=133).
    MachExceptionSession exc_;
    MachExceptionSession::Event lastEvent_{};

    // Read the tracee's BSD p_stat via sysctl (drives the post-detach SSTOP
    // watch). SRUN=2 SSLEEP=3 SSTOP=4 SZOMB=5; -1 = sysctl failed (e.g. proc gone).
    static int readPstat(pid_t pid) {
        struct kinfo_proc kp;
        size_t len = sizeof(kp);
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        if (sysctl(mib, 4, &kp, &len, nullptr, 0) != 0 || len == 0) {
            return -1;
        }
        return kp.kp_proc.p_stat;
    }

    // Receive the next event, suppressing soft-signal stops other than
    // expectedSignal (0 = return on any stop), mirroring the old
    // suppress-and-continue loop. An EXC_BREAKPOINT is always a stop. An
    // unexpected non-signal exception is a genuine fault: forward it to the
    // task's default disposition and fail.
    bool waitForStopped(int expectedSignal = 0) {
        while (true) {
            lastEvent_ = exc_.waitForEvent();
            if (!lastEvent_.valid) {
                return false;
            }
            if (lastEvent_.isBreakpoint()) {
                LOG("Stopped at EXC_BREAKPOINT\n");
                return true;
            }
            int sig = lastEvent_.softSignal();
            if (sig != 0) {
                LOG("Process stopped signal=%d\n", sig);
                if (expectedSignal == 0 || sig == expectedSignal) {
                    return true;
                }
                LOG("Suppressing unexpected signal %d (waiting for %d)\n", sig, expectedSignal);
                if (!exc_.reply(0)) {
                    return false;
                }
                continue;
            }
            fprintf(stderr, "Unexpected exception type=%d during setup; forwarding\n",
                    lastEvent_.type);
            exc_.forward();
            return false;
        }
    }

    // Wait specifically for the planted BRK (EXC_BREAKPOINT), suppressing any
    // soft signals that arrive first. Under PT_ATTACHEXC a hardware breakpoint
    // is delivered as EXC_BREAKPOINT directly (the old code caught it as
    // SIGTRAP via ptrace).
    bool waitForBreakpoint() {
        while (true) {
            lastEvent_ = exc_.waitForEvent();
            if (!lastEvent_.valid) {
                return false;
            }
            if (lastEvent_.isBreakpoint()) {
                LOG("Stopped at EXC_BREAKPOINT\n");
                return true;
            }
            int sig = lastEvent_.softSignal();
            if (sig != 0) {
                LOG("Suppressing signal %d while waiting for breakpoint\n", sig);
                if (!exc_.reply(0)) {
                    return false;
                }
                continue;
            }
            fprintf(stderr, "Unexpected exception type=%d before breakpoint; forwarding\n",
                    lastEvent_.type);
            exc_.forward();
            return false;
        }
    }

public:
    ~MuhDebugger() {
        if (taskPort_ != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), taskPort_);
        }
    }

    task_t taskPort() const { return taskPort_; }
    mach_port_t stoppedThread() const { return lastEvent_.thread; }

    bool attach(pid_t pid) {
        childPid_ = pid;
        LOG("Attempting to attach to %d\n", childPid_);

        // Grab the task port up front (pre-exec) so we can install our Mach
        // exception port before attaching. The loader already holds the
        // debugger entitlement / runs as root, and already task_for_pid's the
        // harder post-exec Rosetta process below.
        if (task_for_pid(mach_task_self(), childPid_, &taskPort_) != KERN_SUCCESS) {
            fprintf(stderr, "attach: task_for_pid(%d) failed\n", childPid_);
            return false;
        }
        // Install the exception port BEFORE attaching so every debug event is
        // routed to us and can never fall through to the parent's fatal signal
        // disposition.
        if (!exc_.install(childPid_, taskPort_)) {
            return false;
        }
        // PT_ATTACHEXC: a ptrace attach (sibling of PT_ATTACH) that delivers
        // debug events as Mach exceptions to our port instead of as BSD
        // signals. Sends SIGSTOP, delivered as EXC_SOFT_SIGNAL(SIGSTOP).
        if (ptrace(PT_ATTACHEXC, childPid_, nullptr, 0) == -1) {
            perror("ptrace(PT_ATTACHEXC)");
            return false;
        }
        if (!waitForStopped()) {  // consume the attach-stop
            return false;
        }
        LOG("Attached to %d (attach-stop)\n", childPid_);
        return true;
    }

    // Resume from the attach-stop, let the parent execv, and stop at the exec
    // SIGTRAP. execve can hand back a different task port and resets thread
    // state, so re-fetch the task port and make sure our exception port covers
    // the post-exec task before the breakpoint window.
    bool waitForExecStop() {
        if (!exc_.reply(0)) {  // resume, suppressing SIGSTOP
            fprintf(stderr, "waitForExecStop: failed to resume from attach-stop\n");
            return false;
        }
        if (!waitForStopped(SIGTRAP)) {
            return false;
        }
        LOG("Program stopped due to execv\n");

        if (task_for_pid(mach_task_self(), childPid_, &taskPort_) != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get task port for pid %d\n", childPid_);
            return false;
        }
        if (!exc_.reinstall(taskPort_) || !exc_.verifyInstalled()) {
            fprintf(stderr, "Failed to (re)install exception port after exec\n");
            return false;
        }
        LOG("Started debugging process %d using port %d\n", childPid_, taskPort_);
        return true;
    }

    bool continueExecution() {
        if (!exc_.reply(0)) {  // resume from the held stop
            fprintf(stderr, "continueExecution: resume failed\n");
            return false;
        }
        LOG("continueExecution...\n");
        // ARM64 BRK does not advance PC; removeBreakpoint restores the original
        // instruction, so replying (in detach) later re-executes it correctly.
        return waitForBreakpoint();
    }

    bool detach() {
        // Literal 1:1 port of lldb debugserver's MachProcess::Detach()
        // (llvm lldb/tools/debugserver/source/MacOSX/MachProcess.mm), in its
        // exact order:
        //
        //   DoSIGSTOP(clear_bps, allow_running=true)   // run, then SIGSTOP-stop
        //     -> PrivateResume(): reply held exception + task run
        //     -> Signal(SIGSTOP, timeout=2s): kill(SIGSTOP), wait once for stop
        //   ReplyToAllExceptions()   // reply, forwarding signal=-1 per thread
        //   ShutDownExceptionThread()// restore original exception ports
        //   ::ptrace(PT_DETACH)      // best-effort: logged, never fatal
        //   m_task.Resume()          // task_resume only if suspend_count > 0

        LOG("[detach] enter: p_stat=%d (SRUN=2 SSTOP=4)\n", readPstat(childPid_));

        // 1. DoSIGSTOP / PrivateResume: reply to the held BRK so the task runs.
        exc_.release();

        // 2. Signal(SIGSTOP): kill(SIGSTOP) on the running task, then wait ONCE
        //    with a 2-second timeout for the SIGSTOP to come back as
        //    EXC_SOFT_SIGNAL — matching debugserver's Signal(SIGSTOP, 2s). Any
        //    other soft signal is suppressed and a genuine fault forwarded;
        //    proceed regardless of whether the stop arrived (best-effort).
        kill(childPid_, SIGSTOP);

        bool gotSigstop = false;
        lastEvent_ = exc_.waitForEvent(2000);
        if (lastEvent_.valid) {
            int sig = lastEvent_.softSignal();
            if (sig == SIGSTOP) {
                gotSigstop = true;
            } else if (sig != 0) {
                exc_.reply(0);
            } else {
                exc_.forward();
            }
        }
        if (!gotSigstop) {
            fprintf(stderr, "detach: SIGSTOP not received within 2s (proceeding)\n");
        }
        LOG("[detach] after SIGSTOP-wait: gotSigstop=%d p_stat=%d\n", gotSigstop,
            readPstat(childPid_));

        // 3. ReplyToAllExceptions: reply to the held SIGSTOP exception forwarding
        //    signal = -1.
        //
        //    We must NOT let this SRUN the proc: PT_DETACH (step 5) is gated on
        //    p_stat == SSTOP and returns EBUSY otherwise, leaving P_LTRACED set
        //    (the worst failure — a still-traced tracee forces SIG_DFL on every
        //    signal, freezing signal-driven apps, and no SIGCONT can fix it).
        //    On this XNU, PT_THUPDATE bounds-checks `(unsigned)data >= NSIG`, so
        //    -1 EINVALs and its `t->p_stat = SRUN` is skipped — the proc stays
        //    SSTOP, PT_DETACH passes its gate and clears P_LTRACED. (data = 0
        //    would instead succeed, SRUN the proc, and make PT_DETACH EBUSY —
        //    verified.) The cost of keeping SSTOP is that the now-untraced tracee
        //    can re-enter a job-control stop after detach; step 7 lifts that with
        //    SIGCONT.
        exc_.reply(-1);
        LOG("[detach] after reply(-1): p_stat=%d\n", readPstat(childPid_));

        // 4. ShutDownExceptionThread: restore original exception ports, drop ours.
        exc_.restoreAndTearDown();

        // 5. PT_DETACH — best-effort, exactly as debugserver treats it: it logs
        //    the return but never requires success, never retries, never branches.
        errno = 0;
        int pstatBeforeDetach = logsEnabled ? readPstat(childPid_) : -1;
        int detachRet = ptrace(PT_DETACH, childPid_, (caddr_t)1, 0);
        int detachErrno = errno;
        // Always warn on a real PT_DETACH failure; the full p_stat trace is
        // gated behind ROSETTA_X87_LOGS.
        if (detachRet != 0) {
            fprintf(stderr, "ptrace(PT_DETACH, %d, (caddr_t)1, 0) = %d: %s\n", childPid_, detachRet,
                    strerror(detachErrno));
        }
        LOG("[detach] PT_DETACH: p_stat_before=%d ret=%d errno=%d (%s) p_stat_after=%d\n",
            pstatBeforeDetach, detachRet, detachErrno,
            detachRet != 0 ? strerror(detachErrno) : "OK", readPstat(childPid_));

        // 6. m_task.Resume(): mirror MachTask::Resume — read the live suspend
        //    count and task_resume only if suspend_count > 0 (task_resume is not
        //    ref-counted like task_suspend, so resuming a running task errors).
        //    No manual task_suspend precedes this: debugserver does not suspend in
        //    Detach().
        struct task_basic_info taskInfo;
        mach_msg_type_number_t infoCount = TASK_BASIC_INFO_COUNT;
        bool resumed = false;
        int suspendCount = -1;
        if (task_info(taskPort_, TASK_BASIC_INFO, (task_info_t)&taskInfo, &infoCount) ==
            KERN_SUCCESS) {
            suspendCount = taskInfo.suspend_count;
            if (taskInfo.suspend_count > 0) {
                task_resume(taskPort_);
                resumed = true;
            }
        }
        LOG("[detach] resume: suspend_count=%d resumed=%d\n", suspendCount, resumed);

        // 7. The tracee may re-enter a BSD job-control stop (p_stat == SSTOP,
        //    "suspended (signal)") AFTER detach() returns.
        //
        //    We are forced to reply(-1) so PT_DETACH runs while the proc is still
        //    SSTOP (else it EBUSYs and P_LTRACED is never cleared). The price is
        //    that -1 EINVALs PT_THUPDATE, so its `p_stat = SRUN` is skipped and
        //    the now-untraced tracee, on Golden Gate, INTERMITTENTLY re-enters a
        //    job-control stop via SIGSTOP's default SA_STOP disposition. This
        //    re-stop fires ASYNC and, as observed on a wedged process, AFTER this
        //    function has already returned (the loader is by then parked in its
        //    final kevent wait). So it cannot be lifted here — only SIGCONT lifts
        //    a BSD SSTOP, and it must be sent whenever the stop actually fires.
        //    That watch lives in main()'s post-detach wait loop (which polls the
        //    tracee's p_stat and SIGCONTs any SSTOP for the tracee's lifetime),
        //    since the loader is alive and idle there anyway. On Sequoia the proc
        //    is SRUN throughout and no SIGCONT is ever sent.

        LOG("Debugger detached.\n");
        return true;
    }

    // Public p_stat probe for the post-detach SSTOP watch loop in main().
    static int tracePstat(pid_t pid) { return readPstat(pid); }

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

    // Read a register from a specific thread port. Used to read X19 from the
    // exact thread reported by the breakpoint exception message — correct even
    // if libRosettaRuntime has spawned other threads by then (task_threads[0]
    // is not guaranteed to be the one that hit the BRK).
    uint64_t readRegister(mach_port_t thread, Register reg) {
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kern_return_t kr =
            thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Failed to get thread state (error 0x%x: %s)\n", kr,
                    mach_error_string(kr));
            return 0;
        }

        if (reg >= X0 && reg <= X28) {
            return state.__x[reg];
        }
        switch (reg) {
            case FP:
                return state.__fp;
            case LR:
                return state.__lr;
            case SP:
                return state.__sp;
            case PC:
                return state.__pc;
            case CPSR:
                return state.__cpsr;
            default:
                fprintf(stderr, "Invalid register\n");
                return 0;
        }
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

        // Flush the target's instruction cache for the written range. ARM64 I/D
        // caches are not coherent: mach_vm_write lands in the D-cache path only,
        // so a core that has already executed (and cached) this line keeps
        // running the stale bytes. That is fatal for the one breakpoint we plant
        // at exports_fetch: we plant a BRK, catch it, restore the original
        // instruction, then RESUME the held thread — which re-fetches the same
        // PC (ARM64 BRK does not advance PC). If the stale BRK is still in the
        // I-cache at that re-fetch, it re-traps after we have detached and torn
        // down our exception handler → an unhandled SIGTRAP kills the tracee
        // (the flaky post-detach exit=133). Flushing here makes the restore (and
        // every __TEXT patch) coherent, exactly as lldb's debugserver does after
        // writing to a tracee. Best-effort: a failure only regresses to the old
        // behaviour, so log and continue.
        vm_machine_attribute_val_t flush = MATTR_VAL_ICACHE_FLUSH;
        kern_return_t fkr = mach_vm_machine_attribute(taskPort_, address, size, MATTR_CACHE, &flush);
        if (fkr != KERN_SUCCESS) {
            LOG("Warning: i-cache flush at 0x%llx failed (error 0x%x: %s)\n", address, fkr,
                mach_error_string(fkr));
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
    const char* disableSip = getenv("ROSETTA_X87_DISABLE_SIP");

    LOG("Launching debugger.\n");

    // Reverse fork: parent execs into wine (keeps original PID for macOS
    // dock/activation tracking), child becomes the debugger.
    pid_t parentPid = getpid();
    int syncPipe[2];
    if (pipe(syncPipe) == -1) {
        perror("pipe");
        return 1;
    }

    pid_t child = fork();

    if (child == -1) {
        perror("fork");
        return 1;
    }

    if (child != 0) {
        // PARENT: will exec into wine-preloader (keeps original PID)
        close(syncPipe[1]);
        // Wait for child debugger to attach to us
        char buf;
        read(syncPipe[0], &buf, 1);
        close(syncPipe[0]);
        // Child has attached and will catch our exec's SIGTRAP
        waitpid(child, nullptr, WNOHANG);  // reap intermediate double-fork child
        LOG("parent: launching into program: %s\n", argv[1]);
        execv(argv[1], &argv[1]);
        perror("parent: execv");
        return 1;
    }

    // CHILD: double-fork to orphan the debugger process.
    // This prevents a PID cycle (child->parent->child via ptrace) in the
    // process table that crashes Terminal.app's recursive process-tree walker.
    close(syncPipe[0]);
    pid_t intermediatePid = getpid();   // valid in C; G inherits via fork copy
    pid_t grandchild = fork();
    if (grandchild == -1) {
        perror("fork (double-fork)");
        _exit(1);
    }
    if (grandchild != 0) {
        _exit(0);  // intermediate child exits; grandchild reparented to PID 1
    }

    // GRANDCHILD: wait for the intermediate child to exit before PT_ATTACH.
    // PT_ATTACH would otherwise reparent R under G while C is still alive
    // with G as its child, briefly creating a children-list cycle (R↔G via
    // PT_ATTACH plus G's original ppid=C still in C.children) that crashes
    // Terminal.app's proc_listchildpids walker. NOTE_EXIT fires from xnu's
    // proc_exit after G has already been reparented to launchd and C has
    // been removed from R.children — kernel state is then guaranteed
    // cycle-free.
    {
        int kq = kqueue();
        if (kq >= 0) {
            struct kevent ev;
            EV_SET(&ev, intermediatePid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
                   NOTE_EXIT, 0, nullptr);
            struct kevent out;
            struct timespec ts = {2, 0};   // generous; C's path is ~2 insns
            (void)kevent(kq, &ev, 1, &out, 1, &ts);
            close(kq);
        }
        // Cover the case where C exited before kevent could register.
        while (getppid() != 1) {
            sched_yield();
        }
    }

    MuhDebugger dbg;
    if (!dbg.attach(parentPid)) {
        fprintf(stderr, "Failed to attach to parent process\n");
        return 1;
    }
    // Signal parent to proceed with execv
    write(syncPipe[1], "x", 1);
    close(syncPipe[1]);

    // Wait for parent's execv to trigger SIGTRAP
    if (!dbg.waitForExecStop()) {
        fprintf(stderr, "Failed to catch parent's exec\n");
        return 1;
    }
    LOG("Attached successfully\n");

    OffsetFinder offsetFinder;
    if (!offsetFinder.scanRuntime()) {
        fprintf(stderr, "Fatal: failed to scan rosetta runtime for offsets.\n");
        return 1;
    }
    LOG("Found rosetta runtime offsets successfully!\n");
    LOG("offset_exports_fetch=%llx offset_svc_call_entry=%llx offset_svc_call_ret=%llx "
        "offset_classify_arm_pc=%llx offset_sys_csrctl=%llx\n",
        offsetFinder.offsetExportsFetch_, offsetFinder.offsetSvcCallEntry_,
        offsetFinder.offsetSvcCallRet_, offsetFinder.offsetClassifyArmPc_,
        offsetFinder.offsetSysCsrctl_);

    if (!offsetFinder.scanLibRosettaRuntime()) {
        fprintf(stderr, "Fatal: failed to scan libRosettaRuntime for offsets.\n");
        return 1;
    }
    LOG("Found libRosettaRuntime offsets successfully!\n");
    LOG("offset_translate_insn=%llx offset_transaction_result_size=%llx "
        "offset_decode_opcode=%llx\n",
        offsetFinder.offsetTranslateInsn_, offsetFinder.offsetTransactionResultSize_,
        offsetFinder.offsetDecodeOpcode_);

    const auto runtimeBase = dbg.findRuntime();

    LOG("Rosetta runtime base: 0x%lx\n", runtimeBase);

    if (runtimeBase == 0) {
        fprintf(stderr, "Failed to find Rosetta runtime\n");
        return 1;
    }
    uint8_t g_disable_aot_value = 1;

    dbg.writeMemory(runtimeBase + offsetFinder.offsetDisableAot_, &g_disable_aot_value,
                    sizeof(g_disable_aot_value));

    // Bypass SIP so injected ROSETTA_* apple[] vars are accepted by the
    // runtime's env loop. Opt-in via ROSETTA_X87_DISABLE_SIP. Two steps, only
    // meaningful together: scrub the kernel-mirrored ROSETTA_X87_* apple[]
    // entries (the runtime would otherwise reject them as "invalid ROSETTA_
    // environment variable" once the SIP check passes), then patch sys_csrctl
    // to always return 0 so that check does pass.
    if (disableSip) {
        // Scrub ROSETTA_X87_* entries from existing apple[] — the kernel mirrors
        // ROSETTA_* env vars into apple[]. NUL the first byte of each matching
        // string so the runtime skips it.
        arm_thread_state64_t state;
        dbg.copyThreadState(state);
        uint64_t oldSP = state.__sp;

        uint64_t count;
        dbg.readMemory(oldSP + 0x20, &count, sizeof(count));
        uint64_t headerSize = (count + 6) * 8;
        uint64_t oldAppleBase = oldSP + headerSize;

        LOG("apple[]: SP=0x%llx count=%llu headerSize=%llu appleBase=0x%llx\n",
            oldSP, count, headerSize, oldAppleBase);

        uint64_t ptr;
        for (uint64_t addr = oldAppleBase; ; addr += 8) {
            dbg.readMemory(addr, &ptr, 8);
            if (ptr == 0) break;
            char prefix[13] = {};
            dbg.readMemory(ptr, prefix, 12);
            if (strncmp(prefix, "ROSETTA_X87_", 12) == 0) {
                uint8_t nul = 0;
                dbg.writeMemory(ptr, &nul, 1);
                LOG("apple[]: scrubbed ROSETTA_X87_* entry at 0x%llx\n", ptr);
            }
        }

        // Patch sys_csrctl to always return 0, bypassing the SIP check.
        // Original: MOV X16,#0x1E3; SVC 0x80; MOV X1,#-1; CSEL X0,X1,X0,CS; RET
        // Patched:  MOV X0, #0; RET
        uint32_t patch[] = {0xD2800000, 0xD65F03C0};  // MOV X0, #0; RET
        uint64_t csrctlAddr = runtimeBase + offsetFinder.offsetSysCsrctl_;
        dbg.adjustMemoryProtection(csrctlAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                                   sizeof(patch));
        dbg.writeMemory(csrctlAddr, patch, sizeof(patch));
        dbg.adjustMemoryProtection(csrctlAddr, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(patch));
        LOG("Patched sys_csrctl at 0x%llx to return 0\n", csrctlAddr);
    }

    // Plant the one BRK at exports_fetch. Our EXC_MASK_ALL task-level port
    // catches the resulting EXC_BREAKPOINT (mirroring lldb debugserver, which
    // registers at task level for all exception types).
    dbg.setBreakpoint(runtimeBase + offsetFinder.offsetExportsFetch_);
    dbg.continueExecution();
    // Read X19 (Exports struct addr) from the thread that hit the BRK, then
    // restore the original instruction. The process stays stopped (we hold the
    // breakpoint exception reply) through the stub install below until detach.
    auto rosettaRuntimeExportsAddress =
        dbg.readRegister(dbg.stoppedThread(), MuhDebugger::Register::X19);
    dbg.removeBreakpoint(runtimeBase + offsetFinder.offsetExportsFetch_);
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

    // Plant the second BRK after the mmap syscall; our EXC_MASK_ALL task-level
    // port catches the resulting EXC_BREAKPOINT.
    dbg.setBreakpoint(runtimeBase + offsetFinder.offsetSvcCallRet_);
    dbg.continueExecution();

    uint64_t machoBase = dbg.readRegister(dbg.stoppedThread(), MuhDebugger::Register::X0);
    dbg.removeBreakpoint(runtimeBase + offsetFinder.offsetSvcCallRet_);

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
                                // LOG("  Rebase: fileoff=0x%llx target=0x%llx -> 0x%llx "
                                //     "dest=0x%llx\n",
                                //     curFileOffset, fullTarget, rebased, destAddr);
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
        .transaction_result_size_addr = offsetFinder.offsetTransactionResultSize_,
        .runtime_base = runtimeBase,
        .rosettax87_base = machoBase,
        .rosettax87_size = machoLoader.imageSize(),
        .classify_arm_pc_rva = offsetFinder.offsetClassifyArmPc_,
        .decode_opcode_rva = offsetFinder.offsetDecodeOpcode_,
    };

    dbg.writeMemory(machoOffsetsAddress, &machoOffsets, sizeof(machoOffsets));

    // Write runtime feature config to __DATA,config
    if (auto* configSection = machoLoader.getSection("__DATA", "config")) {
        RosettaConfig runtimeConfig = parse_config_from_env();
        uint64_t machoConfigAddress = machoBase + configSection->addr;
        dbg.writeMemory(machoConfigAddress, &runtimeConfig, sizeof(runtimeConfig));
    }

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
    auto libRosettaRuntimeExportsAddress =
        dbg.readRegister(dbg.stoppedThread(), MuhDebugger::Register::X19);
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
    dbg.detach();

    // Wait for the parent (wine) to exit, and — for its whole lifetime — lift any
    // leftover BSD job-control stop on it.
    //
    // The tracee we detached from IS parentPid (the loader attached to the parent,
    // which then exec'd wine). On Golden Gate, detach() is forced to reply(-1) so
    // PT_DETACH succeeds from SSTOP (see detach() step 3/7); the cost is that the
    // now-untraced tracee INTERMITTENTLY re-enters a job-control stop
    // ("suspended (signal)") AFTER detach returns — asynchronously, past any
    // in-detach window. Only SIGCONT lifts a BSD SSTOP. Rather than block
    // indefinitely in kevent, we fold that watch into this wait: poll the tracee's
    // p_stat on a short timeout and SIGCONT any SSTOP, until NOTE_EXIT fires. On
    // Sequoia the proc is never SSTOP, so no SIGCONT is ever sent (a plain wait).
    int kq = kqueue();
    if (kq != -1) {
        struct kevent ev;
        EV_SET(&ev, parentPid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, nullptr);
        kevent(kq, &ev, 1, nullptr, 0, nullptr);

        // 20ms timeout: wake often enough to lift a re-stop promptly, but idle
        // (no busy-spin) between wakeups. Loop until the parent exits.
        struct timespec timeout = {0, 20 * 1000 * 1000};  // 20ms
        while (true) {
            struct kevent out;
            int n = kevent(kq, nullptr, 0, &out, 1, &timeout);
            if (n > 0) {
                // NOTE_EXIT delivered — parent gone.
                break;
            }
            // Timeout (n == 0) or EINTR (n < 0): probe the tracee and lift any
            // job-control stop. p_stat == -1 means the proc is gone.
            int ps = MuhDebugger::tracePstat(parentPid);
            if (ps == -1) {
                break;
            }
            if (ps == 4 /* SSTOP */) {
                kill(parentPid, SIGCONT);
                LOG("post-detach watch: tracee SSTOP -> SIGCONT\n");
            }
        }
        close(kq);
    }

    return 0;
}
