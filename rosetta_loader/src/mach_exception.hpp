#ifndef X87SIDECAR_MACH_EXCEPTION_HPP
#define X87SIDECAR_MACH_EXCEPTION_HPP

#include <mach/mach.h>
#include <sys/types.h>

#include <cstdint>

// MachExceptionSession — receive the loader's ptrace debug events (attach-stop,
// exec-stop and the one planted BRK) as Mach exception messages on a port WE
// own, instead of as BSD signals via waitpid/WSTOPSIG.
//
// Why this exists: the loader attaches with ptrace(PT_ATTACHEXC) rather than the
// deprecated PT_ATTACH. PT_ATTACHEXC routes every debug event to a Mach
// exception port. A debugger-owned exception port takes precedence over the
// target's own handlers, so libRosettaRuntime's __TEXT EXC_BREAKPOINT handling
// can no longer win the race and let our planted BRK leak to the parent as a
// fatal SIGTRAP (the CI `exit=133` flake). An event delivered as a Mach message
// to our port structurally cannot fall through to the tracee's default (fatal)
// signal disposition.
//
// Model on lldb debugserver's MachException/MachTask. This class is a small,
// synchronous, single-session variant: the loader's setup runs on one thread
// and there is only ever one tracee, so there is no separate exception thread
// and no locking. Holding an unreplied exception message == "tracee stopped";
// replying == "continue".
class MachExceptionSession {
public:
    // Decoded exception message. Not replied to yet — while an event is
    // outstanding the faulting thread is stopped in the kernel awaiting our
    // reply.
    struct Event {
        exception_type_t type = 0;
        mach_port_t thread = MACH_PORT_NULL;
        mach_port_t task = MACH_PORT_NULL;
        int64_t codes[2] = {0, 0};
        int codeCount = 0;
        bool valid = false;

        // The BSD signal folded into an EXC_SOFTWARE/EXC_SOFT_SIGNAL, or 0.
        // Attach-stop surfaces as SIGSTOP, exec-stop as SIGTRAP.
        [[nodiscard]] int softSignal() const {
            if (type == EXC_SOFTWARE && codeCount == 2 && codes[0] == EXC_SOFT_SIGNAL) {
                return static_cast<int>(codes[1]);
            }
            return 0;
        }
        [[nodiscard]] bool isBreakpoint() const { return type == EXC_BREAKPOINT; }
    };

    // Allocate a receive right, insert a send right, and atomically install our
    // port as the task's EXC_MASK_ALL handler (EXCEPTION_DEFAULT |
    // MACH_EXCEPTION_CODES), saving the previous ports for restore/forward.
    // Mirrors lldb debugserver's MachTask::StartExceptionThread: we claim every
    // exception type at task level, so both the PT_ATTACHEXC signal-stops (folded
    // into EXC_SOFT_SIGNAL) and the one planted BRK (EXC_BREAKPOINT) arrive on
    // this port. pid is the tracee pid (needed for PT_THUPDATE on reply).
    bool install(pid_t pid, task_t task);

    // Re-install on a (possibly new) task port. execve resets a task's
    // exception ports, so this must run after the exec-stop and before the BRK.
    bool reinstall(task_t task);

    // True if our port is currently among the task's registered handlers.
    // Used to prove the port is live before continuing into the BRK window.
    [[nodiscard]] bool verifyInstalled() const;

    // Block until an exception message arrives (or timeout). Runs the MIG
    // server, which decodes the message and builds the reply we will later
    // send. The returned Event is left UNREPLIED (the faulting thread stays
    // blocked in the kernel awaiting our reply).
    Event waitForEvent(uint32_t timeoutMs = 30000);

    // Send the reply for the held event, releasing the faulting thread. For a
    // soft-signal stop, PT_THUPDATE first forwards `signalToForward` to the
    // tracee (0 == suppress, matching the old suppress-and-continue path).
    bool reply(int signalToForward = 0);

    // Reply "not handled" (KERN_FAILURE) for the held event so a genuine,
    // unexpected fault takes its default disposition instead of being swallowed
    // by a resume-reply. Only our own attach/exec/BRK events are ever replied
    // with success.
    bool forward();

    // Send the reply message alone (no PT_THUPDATE), unblocking the faulting
    // thread from the exception. Used to release the tracee AFTER PT_DETACH,
    // when ptrace can no longer be called on it.
    bool release();

    // Restore the task's original exception ports and release our rights.
    void restoreAndTearDown();

    ~MachExceptionSession() { restoreAndTearDown(); }

    // Called by the MIG-dispatched catch_mach_exception_raise trampoline to
    // record the decoded event into the active session. Not for external use.
    void recordFromCatch(mach_port_t thread, mach_port_t task, exception_type_t exception,
                         const int64_t* code, int codeCnt);

private:
    bool swapPorts(task_t task);
    bool sendReply();

    static constexpr int kMaxExcPorts = 32;  // >= EXC_TYPES_COUNT

    mach_port_t exceptionPort_ = MACH_PORT_NULL;
    task_t task_ = TASK_NULL;
    pid_t pid_ = -1;
    bool haveHeld_ = false;

    // Saved previous TASK-level exception ports (for restore / default
    // forwarding). Covers EXC_MASK_ALL.
    exception_mask_t savedMasks_[kMaxExcPorts] = {};
    mach_port_t savedPorts_[kMaxExcPorts] = {};
    exception_behavior_t savedBehaviors_[kMaxExcPorts] = {};
    thread_state_flavor_t savedFlavors_[kMaxExcPorts] = {};
    mach_msg_type_number_t savedCount_ = 0;
    bool haveSaved_ = false;

    // Message buffers. 1024 bytes comfortably holds a 64-bit exception message
    // and its reply (mirrors debugserver's MachMessage union).
    union Buffer {
        mach_msg_header_t hdr;
        char data[1024];
    };
    Buffer excMsg_{};
    Buffer replyMsg_{};
    Event current_{};
};

#endif  // X87SIDECAR_MACH_EXCEPTION_HPP
