#pragma once
#ifdef ROSETTA_RUNTIME

#include <cstdarg>
#include <cstddef>
#include <cstdint>

// Memory
void* rt_mmap(void* addr, size_t len, int prot, int flags, int fd, long offset);
int rt_munmap(void* addr, size_t len);
// void* rt_mmap_anonymous_rw(size_t size, int tag);
void* rt_calloc(size_t count, size_t size);
void* rt_memcpy(void* dst, const void* src, size_t n);
void* rt_memset(void* dst, int c, size_t n);
int rt_memcmp(const void* a, const void* b, size_t n);
void* rt_memmove(void* dst, const void* src, size_t n);

// String
size_t rt_strlen(const char* s);
int rt_strcmp(const char* a, const char* b);
char* rt_strcpy(char* dst, const char* src);

// I/O (stubbed out or routed to write syscall)
int rt_printf(const char* fmt, ...);
int rt_snprintf(char* buf, size_t size, const char* fmt, ...);
int rt_vsnprintf(char* buf, size_t size, const char* fmt, va_list ap);

// Assert
[[noreturn]] void rt_assert_fail(const char* expr, const char* file, int line);

#define RT_ASSERT(expr) ((expr) ? (void)0 : rt_assert_fail(#expr, __FILE__, __LINE__))

// Process
[[noreturn]] void rt_abort(void);
int* rt_errno_location(void);

// Mach / VM  (own typedefs to avoid dragging in <mach/mach.h>)
typedef unsigned int rt_mach_port_t;
typedef int rt_kern_return_t;
typedef unsigned int rt_vm_prot_t;
typedef unsigned long rt_vm_size_t;
typedef unsigned long rt_vm_address_t;

rt_mach_port_t rt_mach_task_self(void);
rt_kern_return_t rt_vm_protect(rt_mach_port_t task, rt_vm_address_t addr, rt_vm_size_t size,
                               int set_max, rt_vm_prot_t prot);

// Cache / JIT
void rt_sys_dcache_flush(void* addr, size_t len);
void rt_sys_icache_invalidate(void* addr, size_t len);
void rt_pthread_jit_write_protect_np(int enabled);

// ── Aliases ──────────────────────────────────────────────────────────────────
// Include this header AFTER all system headers so the #defines here override
// the system macros without interfering with system header declarations.

#define mmap_anonymous_rw rt_mmap_anonymous_rw
#define mmap rt_mmap
#define munmap rt_munmap
#define calloc rt_calloc
#define memcpy rt_memcpy
#define memset rt_memset
#define memcmp rt_memcmp
#define memmove rt_memmove
#define strlen rt_strlen
#define strcmp rt_strcmp
#define strcpy rt_strcpy
#define printf rt_printf
#define snprintf rt_snprintf

#ifdef abort
#undef abort
#endif
#define abort rt_abort

// errno: "__error" is what the system #define errno (*__error()) calls.
// Providing our own __error() is enough; no alias needed.

// mach_task_self() is a macro (#define mach_task_self() mach_task_self_) from
// <mach/mach.h>.  Override it so we never reference the mach_task_self_ global.
#ifdef mach_task_self
#undef mach_task_self
#endif
#define mach_task_self() rt_mach_task_self()

// vm_protect is a plain extern function — just redirect calls.
#define vm_protect(task, addr, size, set_max, prot)                                      \
    rt_vm_protect((rt_mach_port_t)(task), (rt_vm_address_t)(addr), (rt_vm_size_t)(size), \
                  (set_max), (rt_vm_prot_t)(prot))

#define sys_dcache_flush rt_sys_dcache_flush
#define sys_icache_invalidate rt_sys_icache_invalidate
#define pthread_jit_write_protect_np rt_pthread_jit_write_protect_np

#ifdef assert
#undef assert
#endif
#define assert RT_ASSERT

#endif
