#pragma once

#include <cstdint>

// Generic MIG send/receive wrapper (matches reference mach_vm_remap_msg @ 0x1ce6c).
// Builds a mach_msg header in msg_buf, sends the request via mach_msg2 with retry,
// and parses the MIG reply.
//
// has_complex: 1 if the request carries OOL descriptors (sets MACH_MSGH_BITS_COMPLEX).
// expect_complex_reply: 1 if the reply should have the complex bit set.
// send_size / rcv_size: byte sizes of the request / reply messages.
// msg_id: MIG message ID (e.g. 0x12CD for mach_vm_remap).
// mode: selects MACH64 option flag (0 → 0x200000000, 1 → 0x400000000).
//
// Returns 0 on success, nonzero mach/MIG error on failure.
uint32_t mach_vm_remap_msg(uint32_t task_port, void* msg_buf, int has_complex,
                           int expect_complex_reply, uint32_t send_size,
                           uint32_t rcv_size, int32_t msg_id, int mode);

// thread_get_state MIG call (thread_act subsystem, msgid 0xE13 = 3600 + 3).
//
// A transcription of the reference thread_get_state (0x1D0F4), which is itself
// nothing but mach_vm_remap_msg with a different msgid — the generic sender
// above is what both are built on, so this needs no new machinery.
//
// `state` receives `*state_count` 32-bit words; on return *state_count holds how
// many the kernel actually wrote.  Counts above THREAD_STATE_MAX (0x266) are
// clamped, matching the reference.  Returns 0 on success, otherwise the kernel's
// kern_return_t or MIG_TYPE_ERROR (0xFFFFFED4) for a malformed reply.
//
// Costs ~0x9C8 bytes of stack for the message buffer, exactly as the reference
// does; that is comfortable on the ThreadContext page's 0x3A70-byte runtime
// stack.
uint32_t mach_thread_get_state(uint32_t thread, uint32_t flavor, void* state,
                               uint32_t* state_count);
