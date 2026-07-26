#include "RuntimeRoutineOffsets.h"

#include "rosetta_core/CoreLog.h"

#include "rosetta_core/RuntimeRoutine.h"

// Entry stubs in our own runtime_entry.S, in RuntimeRoutine enum order.
//
// These are link-time addresses in the library image.  The blob is copied
// verbatim into each heap chunk's stub page by ExecutableHeap::allocate_chunk,
// so a label's offset from stub_far_jmp is identical in the image and in the
// mapped region — which is exactly what the offset table wants.
extern "C" {
extern char stub_branch_slot[];
extern char stub_indirect_jmp[];
extern char stub_indirect_jmp_dyld_stub[];
extern char stub_far_jmp[];
extern char stub_indirect_call[];
extern char stub_far_call[];
extern char stub_return_stack_miss[];
extern char stub_far_ret[];
extern char stub_far_ret_single_step[];
extern char stub_syscall_handler[];
extern char stub_toggle_single_step[];
extern char stub_cpuid[];
extern char stub_wide_udiv_64[];
extern char stub_wide_sdiv_64[];
extern char stub_pcmpestri[];
extern char stub_pcmpestrm[];
extern char stub_pcmpistri[];
extern char stub_pcmpistrm[];
extern char stub_mov_segment[];
extern char stub_mov_segment_and_reg[];
extern char stub_get_cpu_number[];
extern char stub_get_tls_base[];
extern char stub_read_timer_nanoseconds[];
extern char stub_read_mxcsr[];
extern char stub_mxcsr_to_fpcr_fpsr[];
extern char stub_f2xm1[];
extern char stub_fabs[];
extern char stub_fadd_f32[];
extern char stub_fadd_f64[];
extern char stub_fadd_ST[];
extern char stub_fbld[];
extern char stub_fbstp[];
extern char stub_fchs[];
extern char stub_fcmov[];
extern char stub_fcom_f32[];
extern char stub_fcom_f64[];
extern char stub_fcom_ST[];
extern char stub_fcomi[];
extern char stub_fcos[];
extern char stub_fdecstp[];
extern char stub_fdiv_f32[];
extern char stub_fdiv_f64[];
extern char stub_fdiv_ST[];
extern char stub_fdivr_f32[];
extern char stub_fdivr_f64[];
extern char stub_fdivr_ST[];
extern char stub_fiadd[];
extern char stub_ficom[];
extern char stub_fidiv[];
extern char stub_fidivr[];
extern char stub_fild[];
extern char stub_fimul[];
extern char stub_fincstp[];
extern char stub_fist_i16[];
extern char stub_fist_i32[];
extern char stub_fist_i64[];
extern char stub_fistt_i16[];
extern char stub_fistt_i32[];
extern char stub_fistt_i64[];
extern char stub_fisub[];
extern char stub_fisubr[];
extern char stub_fld_fp32[];
extern char stub_fld_fp64[];
extern char stub_fld_fp80[];
extern char stub_fld_constant[];
extern char stub_fld_STi[];
extern char stub_fmul_f32[];
extern char stub_fmul_f64[];
extern char stub_fmul_ST[];
extern char stub_fpatan[];
extern char stub_fprem[];
extern char stub_fprem1[];
extern char stub_fptan[];
extern char stub_frndint[];
extern char stub_fscale[];
extern char stub_fsin[];
extern char stub_fsincos[];
extern char stub_fsqrt[];
extern char stub_fst_fp32[];
extern char stub_fst_fp64[];
extern char stub_fst_fp80[];
extern char stub_fst_STi[];
extern char stub_fsub_f32[];
extern char stub_fsub_f64[];
extern char stub_fsub_ST[];
extern char stub_fsubr_f32[];
extern char stub_fsubr_f64[];
extern char stub_fsubr_ST[];
extern char stub_fucom[];
extern char stub_fucomi[];
extern char stub_fxam[];
extern char stub_fxch[];
extern char stub_fxtract[];
extern char stub_fyl2x[];
extern char stub_fyl2xp1[];
extern char stub_ffree[];
extern char stub_load_segment_limit[];
extern char stub_rdrand[];
extern char stub_xrstor[];
extern char stub_xsave[];
}

namespace {

// Indexed by RuntimeRoutine.  Order is load-bearing: it must match both
// RuntimeRoutine.h and the reference's g_runtime_routine_names (verified
// identical for indices 0x00..0x61; we additionally carry xrstor/xsave).
char* const kStubs[kRuntimeRoutine_MAX] = {
    stub_branch_slot,   // 0x00 branch_slot
    stub_indirect_jmp,   // 0x01 indirect_jmp
    stub_indirect_jmp_dyld_stub,   // 0x02 indirect_jmp_dyld_stub
    stub_far_jmp,   // 0x03 far_jmp
    stub_indirect_call,   // 0x04 indirect_call
    stub_far_call,   // 0x05 far_call
    stub_return_stack_miss,   // 0x06 return_stack_miss
    stub_far_ret,   // 0x07 far_ret
    stub_far_ret_single_step,   // 0x08 far_ret_single_step
    stub_syscall_handler,   // 0x09 syscall_handler
    stub_toggle_single_step,   // 0x0a toggle_single_step
    stub_cpuid,   // 0x0b cpuid
    stub_wide_udiv_64,   // 0x0c wide_udiv_64
    stub_wide_sdiv_64,   // 0x0d wide_sdiv_64
    stub_pcmpestri,   // 0x0e pcmpestri
    stub_pcmpestrm,   // 0x0f pcmpestrm
    stub_pcmpistri,   // 0x10 pcmpistri
    stub_pcmpistrm,   // 0x11 pcmpistrm
    stub_mov_segment,   // 0x12 mov_segment
    stub_mov_segment_and_reg,   // 0x13 mov_segment_and_reg
    stub_get_cpu_number,   // 0x14 get_cpu_number
    stub_get_tls_base,   // 0x15 get_tls_base
    stub_read_timer_nanoseconds,   // 0x16 read_timer_nanoseconds
    stub_read_mxcsr,   // 0x17 read_mxcsr
    stub_mxcsr_to_fpcr_fpsr,   // 0x18 mxcsr_to_fpcr_fpsr
    stub_f2xm1,   // 0x19 f2xm1
    stub_fabs,   // 0x1a fabs
    stub_fadd_f32,   // 0x1b fadd_f32
    stub_fadd_f64,   // 0x1c fadd_f64
    stub_fadd_ST,   // 0x1d fadd_ST
    stub_fbld,   // 0x1e fbld
    stub_fbstp,   // 0x1f fbstp
    stub_fchs,   // 0x20 fchs
    stub_fcmov,   // 0x21 fcmov
    stub_fcom_f32,   // 0x22 fcom_f32
    stub_fcom_f64,   // 0x23 fcom_f64
    stub_fcom_ST,   // 0x24 fcom_ST
    stub_fcomi,   // 0x25 fcomi
    stub_fcos,   // 0x26 fcos
    stub_fdecstp,   // 0x27 fdecstp
    stub_fdiv_f32,   // 0x28 fdiv_f32
    stub_fdiv_f64,   // 0x29 fdiv_f64
    stub_fdiv_ST,   // 0x2a fdiv_ST
    stub_fdivr_f32,   // 0x2b fdivr_f32
    stub_fdivr_f64,   // 0x2c fdivr_f64
    stub_fdivr_ST,   // 0x2d fdivr_ST
    stub_fiadd,   // 0x2e fiadd
    stub_ficom,   // 0x2f ficom
    stub_fidiv,   // 0x30 fidiv
    stub_fidivr,   // 0x31 fidivr
    stub_fild,   // 0x32 fild
    stub_fimul,   // 0x33 fimul
    stub_fincstp,   // 0x34 fincstp
    stub_fist_i16,   // 0x35 fist_i16
    stub_fist_i32,   // 0x36 fist_i32
    stub_fist_i64,   // 0x37 fist_i64
    stub_fistt_i16,   // 0x38 fistt_i16
    stub_fistt_i32,   // 0x39 fistt_i32
    stub_fistt_i64,   // 0x3a fistt_i64
    stub_fisub,   // 0x3b fisub
    stub_fisubr,   // 0x3c fisubr
    stub_fld_fp32,   // 0x3d fld_fp32
    stub_fld_fp64,   // 0x3e fld_fp64
    stub_fld_fp80,   // 0x3f fld_fp80
    stub_fld_constant,   // 0x40 fld_constant
    stub_fld_STi,   // 0x41 fld_STi
    stub_fmul_f32,   // 0x42 fmul_f32
    stub_fmul_f64,   // 0x43 fmul_f64
    stub_fmul_ST,   // 0x44 fmul_ST
    stub_fpatan,   // 0x45 fpatan
    stub_fprem,   // 0x46 fprem
    stub_fprem1,   // 0x47 fprem1
    stub_fptan,   // 0x48 fptan
    stub_frndint,   // 0x49 frndint
    stub_fscale,   // 0x4a fscale
    stub_fsin,   // 0x4b fsin
    stub_fsincos,   // 0x4c fsincos
    stub_fsqrt,   // 0x4d fsqrt
    stub_fst_fp32,   // 0x4e fst_fp32
    stub_fst_fp64,   // 0x4f fst_fp64
    stub_fst_fp80,   // 0x50 fst_fp80
    stub_fst_STi,   // 0x51 fst_STi
    stub_fsub_f32,   // 0x52 fsub_f32
    stub_fsub_f64,   // 0x53 fsub_f64
    stub_fsub_ST,   // 0x54 fsub_ST
    stub_fsubr_f32,   // 0x55 fsubr_f32
    stub_fsubr_f64,   // 0x56 fsubr_f64
    stub_fsubr_ST,   // 0x57 fsubr_ST
    stub_fucom,   // 0x58 fucom
    stub_fucomi,   // 0x59 fucomi
    stub_fxam,   // 0x5a fxam
    stub_fxch,   // 0x5b fxch
    stub_fxtract,   // 0x5c fxtract
    stub_fyl2x,   // 0x5d fyl2x
    stub_fyl2xp1,   // 0x5e fyl2xp1
    stub_ffree,   // 0x5f ffree
    stub_load_segment_limit,   // 0x60 load_segment_limit
    stub_rdrand,   // 0x61 rdrand
    stub_xrstor,   // 0x62 xrstor
    stub_xsave,   // 0x63 xsave
};

}  // namespace

// Rewrite the offset table the reference built for ITS blob so it points at OUR
// stubs instead.
//
// main() (0x1299C-0x129C4) fills g_runtime_routine_offsets with
//     g_rt_branch_slot[i] - stub_far_jmp
// for a hardcoded 0x62 entries, then calls
// register_runtime_routine_offsets(offsets, names, 0x62).  Those deltas describe
// the reference runtime_entry layout; we map our own blob over the stub page, so
// every one of them lands on the wrong stub.  Recomputing them against our labels
// is what actually makes our stubs reachable.
//
// Consumers add the table entry to the region base returned by
// ExecutableHeap::runtime_routines_for_address (remove_fragment 0xC664:
// `LDR X8,[g_runtime_routine_offsets]; ADD X8, X8, X0`), so an offset relative to
// stub_far_jmp is precisely the right quantity.
//
// We loop on the caller's `count`, never on kRuntimeRoutine_MAX: this runtime
// build only knows 0x62 routines (through rdrand), and a newer one may pass more.
// Writing kRuntimeRoutine_MAX entries into a 0x62-entry array would corrupt
// whatever follows it.  Entries beyond what we know are left untouched.
void rewrite_runtime_routine_offsets(intptr_t* offsets, int32_t count) {
    if (!offsets || count <= 0)
        return;

    int32_t n = count;
    if (n > kRuntimeRoutine_MAX) {
        // A future runtime with routines we have no stub for.  Rewrite the ones
        // we know and leave the tail as the reference computed it — wrong, but
        // no worse than not hooking, and it keeps us in bounds.
        CORE_LOG("register_runtime_routine_offsets: count=%d exceeds known %d; "
                 "rewriting first %d only",
                 count, (int)kRuntimeRoutine_MAX, (int)kRuntimeRoutine_MAX);
        n = kRuntimeRoutine_MAX;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(stub_far_jmp);
    for (int32_t i = 0; i < n; i++) {
        offsets[i] = static_cast<intptr_t>(reinterpret_cast<uintptr_t>(kStubs[i]) - base);
    }

    CORE_LOG("register_runtime_routine_offsets: rewrote %d/%d offsets to our stubs", n, count);
}
