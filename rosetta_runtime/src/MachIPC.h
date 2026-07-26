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
