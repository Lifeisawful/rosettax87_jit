#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Hook `target`, redirecting execution to `hook_fn`.
 * On success, `*trampoline` is set to a callable pointer that invokes
 * the original function.
 *
 * @param target      Function to hook.
 * @param hook_fn     Your replacement function (same signature).
 * @param trampoline  Out-param: cast to the original function's type and call it.
 * @return            0 on success, -1 on failure (check errno).
 *
 * Example:
 *
 *   static int (*orig_foo)(int, const char *);
 *
 *   int my_foo(int a, const char *b) {
 *       printf("hooked! a=%d\n", a);
 *       return orig_foo(a, b);
 *   }
 *
 *   // Install:
 *   hook_install((void *)foo, (void *)my_foo, (void **)&orig_foo);
 */
int hook_install(void* target, void* hook_fn, void** trampoline);

int create_ret(void** trampoline);

int make_page_executable(void* addr);

/**
 * Patch a MOVZ Wd, #imm (32-bit, hw=0) instruction in place.
 *
 * The target instruction must be encoded as:
 *   MOVZ  Wd, #<imm16>          ; i.e.  MOV  Wd, #<imm16 < 0x10000>
 *
 * @param addr     Exact address of the 4-byte instruction to patch.
 * @param new_imm  New 16-bit immediate to write into the instruction.
 * @return         0 on success, -1 on failure (check errno).
 *                 EINVAL if the instruction at addr is not MOVZ Wd, #imm.
 *                 EPERM  if the memory protection change fails.
 *
 * Example:
 *
 *   // Patch:  MOV W1, #0x268  ->  MOV W1, #0x400
 *   patch_movz_imm((void *)0x000000000000BA44, 0x400);
 */
int patch_movz_imm(void* addr, unsigned short new_imm);

#ifdef __cplusplus
}  // extern "C"
#endif