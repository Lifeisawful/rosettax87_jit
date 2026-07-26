#include "Lock.h"

#include <errno.h>
#include <stdlib.h>

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"  // maps __ulock_wait/__ulock_wake → rt_*
#else
// Private libsystem_kernel entry points; no public declaration exists.
extern "C" int __ulock_wait(uint32_t operation, void* addr, uint64_t value, uint32_t timeout_us);
extern "C" int __ulock_wake(uint32_t operation, void* addr, uint64_t wake_value);
#endif

namespace {

// <sys/ulock.h>
constexpr uint32_t UL_UNFAIR_LOCK = 0x00000002;
constexpr uint32_t ULF_NO_ERRNO = 0x01000000;

using os_ulock_value_t = uint32_t;

constexpr os_ulock_value_t OS_LOCK_NO_OWNER = 0;  // MACH_PORT_NULL
constexpr os_ulock_value_t OS_ULOCK_NOWAITERS_BIT = 1;

// Both entry points strip the top byte off the lock address before handing it
// to the kernel (AND Xn, Xn, #0xFFFFFFFFFFFFFF).
constexpr uintptr_t kUlockAddrMask = 0x00FFFFFFFFFFFFFFull;

os_ulock_value_t* ulock_addr(os_unfair_lock_t lock) {
    return reinterpret_cast<os_ulock_value_t*>(reinterpret_cast<uintptr_t>(lock) & kUlockAddrMask);
}

// Stands in for __LIBPLATFORM_INTERNAL_CRASH__ / the runtime's ERROR(), both
// of which log and then trap.
[[noreturn]] void lock_crash() {
    abort();
}

void _os_unfair_lock_lock_slow(os_unfair_lock_t l, os_unfair_lock_options_t options,
                               os_ulock_value_t self) {
    os_ulock_value_t* const value = ulock_addr(l);
    os_ulock_value_t current, next, waiters_mask = 0;
    int ret;

    while ((current = __atomic_load_n(value, __ATOMIC_RELAXED)) != OS_LOCK_NO_OWNER) {
    _retry:
        next = current & ~OS_ULOCK_NOWAITERS_BIT;
        if (current != next) {
            // Clear nowaiters bit in lock value before waiting
            if (!__atomic_compare_exchange_n(value, &current, next, /*weak=*/false,
                                             __ATOMIC_RELAXED, __ATOMIC_RELAXED))
                continue;
            current = next;
        }

        ret = __ulock_wait(UL_UNFAIR_LOCK | ULF_NO_ERRNO | options, value, current, 0);
        if (ret < 0) {
            switch (-ret) {
                case EINTR:
                case EFAULT:
                    continue;
                default:
                    lock_crash();  // ERROR("ulock_wait failure: %d", -ret)
            }
        }
        if (ret > 0) {
            // If there are more waiters, unset nowaiters bit when acquiring lock
            waiters_mask = OS_ULOCK_NOWAITERS_BIT;
        }
    }

    next = self & ~waiters_mask;
    current = OS_LOCK_NO_OWNER;
    if (!__atomic_compare_exchange_n(value, &current, next, /*weak=*/false, __ATOMIC_ACQUIRE,
                                     __ATOMIC_ACQUIRE))
        goto _retry;
}

void _os_unfair_lock_unlock_slow(os_unfair_lock_t l, os_ulock_value_t current) {
    if (current & OS_ULOCK_NOWAITERS_BIT) {
        lock_crash();  // ERROR("unfair_lock_unlock_slow with no waiters")
    }
    for (;;) {
        const int ret = __ulock_wake(UL_UNFAIR_LOCK | ULF_NO_ERRNO, ulock_addr(l), 0);
        if (ret < 0) {
            switch (-ret) {
                case EINTR:
                    continue;
                case ENOENT:
                    break;
                default:
                    lock_crash();  // ERROR("ulock_wake failure: %d", -ret)
            }
        }
        break;
    }
}

}  // namespace

void os_unfair_lock_lock_no_tsd(os_unfair_lock_t lock, os_unfair_lock_options_t options,
                                uint32_t self) {
    os_ulock_value_t expected = OS_LOCK_NO_OWNER;
    if (__atomic_compare_exchange_n(&lock->_os_unfair_lock_opaque, &expected, self, /*weak=*/false,
                                    __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
        return;
    return _os_unfair_lock_lock_slow(lock, options, self);
}

void os_unfair_lock_unlock_no_tsd(os_unfair_lock_t lock, uint32_t self) {
    const os_ulock_value_t current =
        __atomic_exchange_n(&lock->_os_unfair_lock_opaque, OS_LOCK_NO_OWNER, __ATOMIC_RELEASE);
    if (current == self)
        return;
    return _os_unfair_lock_unlock_slow(lock, current);
}
