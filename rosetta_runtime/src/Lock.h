#pragma once

#include <cstdint>

// Re-implementation of the os_unfair_lock primitives the runtime was built
// with.  Reference: libplatform-2512ffd8 src/os/lock.c + include/os/lock.h
// (https://github.com/apple-oss-distributions/libplatform).
//
// The runtime threads the holder's mach thread port through every entry point
// as `lock_owner` instead of reading it from the TSD, so the two functions it
// links against are the _no_tsd variants:
//
//   0x1D500  os_unfair_lock_lock_no_tsd(l, OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION, self)
//   0x1D5C8  os_unfair_lock_unlock_no_tsd(l, self)
//
// Both have _os_unfair_lock_{lock,unlock}_slow inlined into them, and the
// lock's `options` argument is constant-folded to DATA_SYNCHRONIZATION (the
// ULF_WAIT_WORKQ_DATA_CONTENTION bit in the observed 0x1010002 wait opcode).
//
// Lock word states:
//   0                 unlocked (OS_LOCK_NO_OWNER)
//   self              locked, no waiters
//   self & ~1         locked, at least one waiter parked in ulock
//
// Bit 0 is OS_ULOCK_NOWAITERS_BIT.  It works because mach port names always
// have the low bit set, so clearing it is how a waiter tells unlock that a
// __ulock_wake is owed.
//
// Rosetta's copy predates the revision linked above: it calls __ulock_wait
// (not __ulock_wait2) and omits the recursive-lock and unowned-owner aborts,
// keeping only the "no waiters" crash.  Its assertion strings are
// "ulock_wait failure: %d", "ulock_wake failure: %d" and
// "unfair_lock_unlock_slow with no waiters".

struct os_unfair_lock {
    uint32_t _os_unfair_lock_opaque;
};

using os_unfair_lock_t = os_unfair_lock*;

static_assert(sizeof(os_unfair_lock) == 4);

#define OS_UNFAIR_LOCK_INIT (os_unfair_lock{})

enum os_unfair_lock_options_t : uint32_t {
    OS_UNFAIR_LOCK_NONE = 0x00000000,
    // _Static_assert'd equal to ULF_WAIT_WORKQ_DATA_CONTENTION in lock.c
    OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION = 0x00010000,
    // _Static_assert'd equal to ULF_WAIT_ADAPTIVE_SPIN in lock.c
    OS_UNFAIR_LOCK_ADAPTIVE_SPIN = 0x00040000,
};

// `self` is a mach_port_t: the caller's mach thread port name.
void os_unfair_lock_lock_no_tsd(os_unfair_lock_t lock, os_unfair_lock_options_t options,
                                uint32_t self);
void os_unfair_lock_unlock_no_tsd(os_unfair_lock_t lock, uint32_t self);
