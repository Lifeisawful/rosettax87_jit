#include "ThreadSelfRestrict.h"

// The commpage at 0x7FFFFFE00FE0 holds the XPRR/SPRR configuration:
//   +0x00: variant (byte) — 0=none, 1=APRR, 2/3=SPRR
//   +0x08: rwx_to_rw value (qword)
//   +0x10: rwx_to_rx value (qword)

struct CommpageXPRR {
    uint8_t variant;
    uint8_t pad[7];
    uint64_t rwx_to_rw;
    uint64_t rwx_to_rx;
};

static volatile CommpageXPRR* const kCommpage =
    reinterpret_cast<volatile CommpageXPRR*>(0x7FFFFFE00FE0);

// APRR (variant 1): S3_4_C15_C2_7
// SPRR (variant 2,3): S3_6_C15_C1_5

void thread_self_restrict_rwx_to_rx() {
    uint64_t val = kCommpage->rwx_to_rx;
    uint8_t variant = kCommpage->variant;

    if (variant >= 2 && variant <= 3) {
        __asm__ volatile("dsb ish\n"
                         "msr s3_6_c15_c1_5, %0\n"
                         "isb" : : "r"(val) : "memory");
    } else if (variant == 1) {
        __asm__ volatile("dsb ish\n"
                         "msr s3_4_c15_c2_7, %0\n"
                         "isb" : : "r"(val) : "memory");
    } else if (variant != 0) {
        __builtin_trap();
    }
}

void thread_self_restrict_rwx_to_rw() {
    uint64_t val = kCommpage->rwx_to_rw;
    uint8_t variant = kCommpage->variant;

    if (variant >= 2 && variant <= 3) {
        __asm__ volatile("dsb ish\n"
                         "msr s3_6_c15_c1_5, %0\n"
                         "isb" : : "r"(val) : "memory");
    } else if (variant == 1) {
        __asm__ volatile("dsb ish\n"
                         "msr s3_4_c15_c2_7, %0\n"
                         "isb" : : "r"(val) : "memory");
    } else if (variant != 0) {
        __builtin_trap();
    }
}
