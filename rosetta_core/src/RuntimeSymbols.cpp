// RuntimeSymbols.cpp
// Provides original-name libc/mach/pthread symbols for -nostdlib -static builds.
// Compiled only when ROSETTA_RUNTIME=1.
// Do NOT include RuntimeLibC.h here — that header's #define aliases would
// rename the very symbols this file is trying to define.

#ifdef ROSETTA_RUNTIME

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

// ── Forward-declare rt_ implementations (defined in RuntimeLibC.cpp) ─────────

void* rt_mmap(void* addr, size_t len, int prot, int flags, int fd, long offset);
int rt_munmap(void* addr, size_t len);
void* rt_calloc(size_t count, size_t size);
void* rt_memcpy(void* dst, const void* src, size_t n);
void* rt_memset(void* dst, int c, size_t n);
int rt_memcmp(const void* a, const void* b, size_t n);
void* rt_memmove(void* dst, const void* src, size_t n);
size_t rt_strlen(const char* s);
int rt_strcmp(const char* a, const char* b);
char* rt_strcpy(char* dst, const char* src);
int rt_printf(const char* fmt, ...);
int rt_snprintf(char* buf, size_t size, const char* fmt, ...);
int rt_vsnprintf(char* buf, size_t size, const char* fmt, va_list ap);
[[noreturn]] void rt_abort(void);
int* rt_errno_location(void);

typedef unsigned int rt_mach_port_t;
typedef int rt_kern_return_t;
typedef unsigned int rt_vm_prot_t;
typedef unsigned long rt_vm_size_t;
typedef unsigned long rt_vm_address_t;

rt_mach_port_t rt_mach_task_self(void);
rt_kern_return_t rt_vm_protect(rt_mach_port_t, rt_vm_address_t, rt_vm_size_t, int, rt_vm_prot_t);
void rt_sys_dcache_flush(void* addr, size_t len);
void rt_sys_icache_invalidate(void* addr, size_t len);
void rt_pthread_jit_write_protect_np(int enabled);

// ── Memory ────────────────────────────────────────────────────────────────────

extern "C" {

void* mmap(void* addr, size_t len, int prot, int flags, int fd, long offset) {
    return rt_mmap(addr, len, prot, flags, fd, offset);
}

int munmap(void* addr, size_t len) {
    return rt_munmap(addr, len);
}

void* calloc(size_t count, size_t size) {
    return rt_calloc(count, size);
}

void* memcpy(void* dst, const void* src, size_t n) {
    return rt_memcpy(dst, src, n);
}

void* memset(void* dst, int c, size_t n) {
    return rt_memset(dst, c, n);
}

int memcmp(const void* a, const void* b, size_t n) {
    return rt_memcmp(a, b, n);
}

void* memmove(void* dst, const void* src, size_t n) {
    return rt_memmove(dst, src, n);
}

// ── String ────────────────────────────────────────────────────────────────────

size_t strlen(const char* s) {
    return rt_strlen(s);
}
int strcmp(const char* a, const char* b) {
    return rt_strcmp(a, b);
}
char* strcpy(char* dst, const char* src) {
    return rt_strcpy(dst, src);
}

// ── I/O ───────────────────────────────────────────────────────────────────────
// Minimal stdio shims.  We define our own FILE tag bytes so fputc/fputs can
// route to the right fd without pulling in the full __sFILE layout.

struct _rt_file_tag {
    unsigned char fd;
};

static _rt_file_tag _rt_stdin_tag = {0};
static _rt_file_tag _rt_stdout_tag = {1};
static _rt_file_tag _rt_stderr_tag = {2};

// macOS's stdio globals; type-erased to void* to avoid needing <stdio.h>.
void* __stdinp = &_rt_stdin_tag;
void* __stdoutp = &_rt_stdout_tag;
void* __stderrp = &_rt_stderr_tag;

static int _fd_from_file(void* fp) {
    if (!fp)
        return 2;
    return static_cast<_rt_file_tag*>(fp)->fd;
}

static long _write_fd(int fd, const char* buf, size_t n) {
    register long x16 __asm__("x16") = SYS_write | (1ULL << 24);
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

// fputc(int c, FILE* fp)
int fputc(int c, void* fp) {
    char ch = (char)c;
    _write_fd(_fd_from_file(fp), &ch, 1);
    return c;
}

// fputs(const char* s, FILE* fp)
int fputs(const char* s, void* fp) {
    size_t n = rt_strlen(s);
    return (int)_write_fd(_fd_from_file(fp), s, n);
}

// fprintf(FILE* fp, const char* fmt, ...)
int fprintf(void* fp, const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int r = rt_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    _write_fd(_fd_from_file(fp), buf, (size_t)r);
    return r;
}

int printf(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int r = rt_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    _write_fd(1, buf, (size_t)r);
    return r;
}

int snprintf(char* buf, size_t size, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = rt_vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return r;
}

// ── Process ───────────────────────────────────────────────────────────────────

[[noreturn]] void abort(void) {
    rt_abort();
}

// __error() is already defined in RuntimeLibC.cpp; don't redefine here.

// ── Mach / VM ─────────────────────────────────────────────────────────────────

// mach_task_self_ global
typedef unsigned int mach_port_t;
mach_port_t mach_task_self_ = 0;

// A constructor-like initialiser: called explicitly from init_library or via
// the entry point.  For now we fall back to calling the mach trap on every
// access via the inline below; the global just needs to exist for the linker.

int vm_protect(unsigned int task, unsigned long addr, unsigned long size, int set_max,
               unsigned int prot) {
    return (int)rt_vm_protect((rt_mach_port_t)task, (rt_vm_address_t)addr, (rt_vm_size_t)size,
                              set_max, (rt_vm_prot_t)prot);
}

// ── Cache / JIT ───────────────────────────────────────────────────────────────

void sys_dcache_flush(void* addr, size_t len) {
    rt_sys_dcache_flush(addr, len);
}

void sys_icache_invalidate(void* addr, size_t len) {
    rt_sys_icache_invalidate(addr, len);
}

void pthread_jit_write_protect_np(int enabled) {
    rt_pthread_jit_write_protect_np(enabled);
}

}  // extern "C"

#endif  // ROSETTA_RUNTIME
