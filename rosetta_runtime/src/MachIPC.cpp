#include "MachIPC.h"

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

constexpr uint32_t MACH_SEND_MSG = 0x1;
constexpr uint32_t MACH_RCV_MSG  = 0x2;

constexpr uint32_t MACH_SEND_INTERRUPTED = 0x10000007;
constexpr uint32_t MACH_RCV_BODY_ERROR   = 0x10004005;

constexpr uint64_t MACH64_SEND_INTERRUPT = 0x040;
constexpr uint64_t MACH64_RCV_INTERRUPT  = 0x400;

constexpr uint32_t MSGH_BITS_SIMPLE  = 0x1513;
constexpr uint32_t MSGH_BITS_COMPLEX = 0x80001513;

// Reply-port slot inside the ThreadContext, reached via x18.  Reference
// mach_vm_remap_msg 0x1CE9C-0x1CEB4:
//
//     MOV  X8,  X18
//     AND  X25, X8, #~3        ; slot base = x18 with the mode tag masked off
//     AND  W8,  W8, #3         ; low 2 bits of x18 are a mode tag
//     CMP  W8,  #1
//     B.GT ...                 ; tag >= 2: use x18 & ~3 as-is
//     CBNZ W8,  ...            ; tag == 1: likewise
//     ADD  X25, X25, #0x330    ; tag == 0: slot sits at +0x330
//
// then `LDR W4, [X25]` — a cached 32-bit port name, lazily created with
// mach_reply_port() and stored back.
//
// Getting this right matters: allocate_chunk runs from the reference main() at
// 0x12620, and x18 is only set later by create_from_mach_thread (0x1348C, called
// at 0x1294C), so the tag/slot arithmetic — not a fresh port per call — is what
// the runtime expects here.
constexpr uintptr_t kReplyPortSlotOffset = 0x330;

static inline uint32_t* reply_port_slot() {
    uintptr_t x18;
    __asm__ volatile("mov %0, x18" : "=r"(x18));

    const uintptr_t base = x18 & ~static_cast<uintptr_t>(3);
    const uint32_t tag = static_cast<uint32_t>(x18) & 3;

    // A null/unset x18 would make this a low-address dereference; refuse rather
    // than fault, and let the caller fall back to a fresh port.
    if (base == 0)
        return nullptr;

    return reinterpret_cast<uint32_t*>(tag == 0 ? base + kReplyPortSlotOffset : base);
}

static uint32_t mach_msg2_with_retry(void* data, uint64_t option,
                                     uint64_t bits_and_send_size,
                                     uint64_t remote_and_local,
                                     uint64_t voucher_and_id,
                                     uint64_t desc_count_and_rcv_name,
                                     uint64_t rcv_size_and_priority,
                                     uint64_t timeout) {
    uint32_t ret = rt_mach_msg2(data, option, bits_and_send_size,
                                remote_and_local, voucher_and_id,
                                desc_count_and_rcv_name,
                                rcv_size_and_priority, timeout);
    if (!ret)
        return 0;

    if (!(option & MACH64_SEND_INTERRUPT) && ret == MACH_SEND_INTERRUPTED) {
        uint64_t cleared = option & ~MACH64_SEND_INTERRUPT;
        do {
            ret = rt_mach_msg2(data, cleared, bits_and_send_size,
                               remote_and_local, voucher_and_id,
                               desc_count_and_rcv_name,
                               rcv_size_and_priority, timeout);
        } while (ret == MACH_SEND_INTERRUPTED);
    }

    if (!(option & MACH64_RCV_INTERRUPT) && ret == MACH_RCV_BODY_ERROR) {
        if ((~(uint8_t)option & 3) == 0)
            option &= 0xFFFFFFFFFFFFBBBEULL;
        uint64_t cleared = option & 0xFFFFFFFFFFFFFBBEULL;
        do {
            ret = rt_mach_msg2(data, cleared, bits_and_send_size,
                               remote_and_local, voucher_and_id,
                               desc_count_and_rcv_name,
                               rcv_size_and_priority, timeout);
        } while (ret == MACH_RCV_BODY_ERROR);
    }

    return ret;
}

static uint32_t mach_msg2_send_receive(uint32_t* msg_buf, uint32_t option,
                                       uint32_t send_size, uint32_t rcv_size,
                                       uint32_t reply_port, int mode) {
    uint32_t msgh_bits = msg_buf[0];
    uint32_t desc_count = 0;

    if ((option & MACH_SEND_MSG) && (msgh_bits & 0x80000000))
        desc_count = msg_buf[6];

    uint64_t mach64_flag = (mode == 1) ? 0x400000000ULL : 0x200000000ULL;

    uint64_t bits_and_send_size = (uint64_t)msgh_bits | ((uint64_t)send_size << 32);

    uint64_t remote_and_local;
    __builtin_memcpy(&remote_and_local, &msg_buf[2], 8);

    uint64_t voucher_and_id;
    __builtin_memcpy(&voucher_and_id, &msg_buf[4], 8);

    uint64_t desc_and_rcv_name = (uint64_t)desc_count | ((uint64_t)reply_port << 32);
    uint64_t opt64 = mach64_flag | option;

    return mach_msg2_with_retry(msg_buf, opt64, bits_and_send_size,
                                remote_and_local, voucher_and_id,
                                desc_and_rcv_name, rcv_size, 0);
}

uint32_t mach_vm_remap_msg(uint32_t task_port, void* msg_buf, int has_complex,
                           int expect_complex_reply, uint32_t send_size,
                           uint32_t rcv_size, int32_t msg_id, int mode) {
    uint32_t* buf = static_cast<uint32_t*>(msg_buf);

    buf[0] = has_complex ? MSGH_BITS_COMPLEX : MSGH_BITS_SIMPLE;
    buf[2] = task_port;

    // Reuse the ThreadContext's cached reply port (reference 0x1CEDC-0x1CEEC):
    // load it, and only mint a new one if the slot is empty. Allocating a fresh
    // port per call — as this used to — is not what the runtime expects and left
    // mach_vm_remap failing with 0x10004004 on every call, silently forcing the
    // memmove fallback.
    uint32_t* slot = reply_port_slot();
    uint32_t reply_port = slot ? *slot : 0;
    const bool owned = (reply_port == 0);
    if (reply_port == 0) {
        reply_port = rt_mach_reply_port();
        if (slot)
            *slot = reply_port;
    }

    buf[4] = 0;
    buf[5] = static_cast<uint32_t>(msg_id);
    buf[3] = reply_port;

    uint32_t ret = mach_msg2_send_receive(buf, MACH_SEND_MSG | MACH_RCV_MSG,
                                          send_size, rcv_size, reply_port, mode);

    uint32_t result;
    if (ret) {
        result = ret;
    } else {
        int32_t reply_id = static_cast<int32_t>(buf[5]);
        if (reply_id == msg_id + 100) {
            bool is_complex = static_cast<int32_t>(buf[0]) < 0;
            if ((expect_complex_reply != 1) != is_complex)
                result = 0;
            else if (buf[1] == 0x24)
                result = buf[8];
            else
                result = 0xFFFFFED4;
        } else if (reply_id == 0x47) {
            result = 0xFFFFFECC;
        } else {
            result = 0xFFFFFED3;
        }
    }

    // Only tear the port down if it is NOT the ThreadContext's cached one —
    // destroying that would defeat the cache and break the next call. The
    // reference likewise only mod_refs on the failure path (0x1CF18-0x1CF34).
    if (owned && !slot)
        rt_mach_port_mod_refs(task_port, reply_port, 1, -1);
    else if (result != 0 && slot) {
        // Send/receive failed: drop the cached port and clear the slot so the
        // next call allocates a fresh one (reference 0x1CF30).
        rt_mach_port_mod_refs(task_port, reply_port, 1, -1);
        *slot = 0;
    }
    return result;
}
