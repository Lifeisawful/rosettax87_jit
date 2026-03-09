#ifdef ROSETTA_RUNTIME

// System headers MUST come before RuntimeLibC.h so that the #define aliases
// in RuntimeLibC.h don't interfere with system declarations.

#include <stdarg.h>
#include <sys/mman.h>
#include <sys/syscall.h>

// clang-format off
#include "rosetta_core/RuntimeLibC.h"
// clang-format on

static long _syscall3(long n, long a, long b, long c) {
    register long x16 __asm__("x16") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

static long _syscall6(long n, long a, long b, long c, long d, long e, long f) {
    register long x16 __asm__("x16") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}

// ── Memory ───────────────────────────────────────────────────────────────────

void* rt_mmap(void* addr, size_t len, int prot, int flags, int fd, long offset) {
    return reinterpret_cast<void*>(
        _syscall6(SYS_mmap, (long)addr, (long)len, prot, flags, fd, offset));
}

int rt_munmap(void* addr, size_t len) {
    return (int)_syscall3(SYS_munmap, (long)addr, (long)len, 0);
}

// void* rt_mmap_anonymous_rw(size_t size, int tag) {
//     return rt_mmap(reinterpret_cast<void*>(0x100000000LL), size,
//                    PROT_READ | PROT_WRITE,
//                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
//                    tag << 0x18, 0);
// }

void* rt_calloc(size_t count, size_t size) {
    size_t total = count * size;
    void* p = rt_mmap(nullptr, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? nullptr : p;
}

void* rt_memcpy(void* dst, const void* src, size_t n) {
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);
    for (size_t i = 0; i < n; i++)
        d[i] = s[i];
    return dst;
}

void* rt_memset(void* dst, int c, size_t n) {
    auto* d = static_cast<unsigned char*>(dst);
    for (size_t i = 0; i < n; i++)
        d[i] = static_cast<unsigned char>(c);
    return dst;
}

int rt_memcmp(const void* a, const void* b, size_t n) {
    const auto* p = static_cast<const unsigned char*>(a);
    const auto* q = static_cast<const unsigned char*>(b);
    for (size_t i = 0; i < n; i++) {
        if (p[i] != q[i])
            return p[i] - q[i];
    }
    return 0;
}

void* rt_memmove(void* dst, const void* src, size_t n) {
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);
    if (d < s) {
        for (size_t i = 0; i < n; i++)
            d[i] = s[i];
    } else {
        for (size_t i = n; i-- > 0;)
            d[i] = s[i];
    }
    return dst;
}

// ── String ───────────────────────────────────────────────────────────────────

size_t rt_strlen(const char* s) {
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

int rt_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

char* rt_strcpy(char* dst, const char* src) {
    char* p = dst;
    while ((*p++ = *src++))
        ;
    return dst;
}

// ── I/O ──────────────────────────────────────────────────────────────────────

static int _vsnprintf(char* buf, size_t size, const char* fmt, va_list ap) {
    size_t pos = 0;
    for (; *fmt && pos < size - 1; fmt++) {
        if (*fmt != '%') {
            buf[pos++] = *fmt;
            continue;
        }
        fmt++;

        // Flags
        char pad_char = ' ';
        int flag_hash = 0;
        int flag_left = 0;
        bool parsing_flags = true;
        while (parsing_flags) {
            switch (*fmt) {
                case '0':
                    pad_char = '0';
                    fmt++;
                    break;
                case '#':
                    flag_hash = 1;
                    fmt++;
                    break;
                case '-':
                    flag_left = 1;
                    fmt++;
                    break;
                default:
                    parsing_flags = false;
                    break;
            }
        }
        // left-align overrides zero-pad
        if (flag_left)
            pad_char = ' ';

        // Width
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt++ - '0');
        }

        // Length modifier (l, ll, z) — consume but track
        int is_long = 0, is_longlong = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
            if (*fmt == 'l') {
                is_longlong = 1;
                fmt++;
            }
        } else if (*fmt == 'z') {
            is_long = (sizeof(size_t) == sizeof(long));
            is_longlong = (sizeof(size_t) == sizeof(long long));
            fmt++;
        }

        // Format a number into a temp buffer, then pad/emit into buf.
        // prefix_len: number of leading prefix chars already emitted (e.g. '-', "0x")
        // that should be counted against width when zero-padding.
        auto emit_num = [&](unsigned long long v, int base, const char* digits, const char* prefix,
                            int prefix_len) {
            char tmp[64];
            int len = 0;
            if (v == 0) {
                tmp[len++] = '0';
            } else {
                while (v) {
                    tmp[len++] = digits[v % base];
                    v /= base;
                }
            }

            int total = len + prefix_len;  // chars we will output
            if (!flag_left) {
                // right-align: pad first
                if (pad_char == '0') {
                    // emit prefix before zeros
                    for (int i = 0; prefix[i] && pos < size - 1; i++)
                        buf[pos++] = prefix[i];
                    for (int i = total; i < width && pos < size - 1; i++)
                        buf[pos++] = '0';
                } else {
                    for (int i = total; i < width && pos < size - 1; i++)
                        buf[pos++] = ' ';
                    for (int i = 0; prefix[i] && pos < size - 1; i++)
                        buf[pos++] = prefix[i];
                }
            } else {
                // left-align: prefix then digits then spaces
                for (int i = 0; prefix[i] && pos < size - 1; i++)
                    buf[pos++] = prefix[i];
            }
            for (int i = len - 1; i >= 0 && pos < size - 1; i--)
                buf[pos++] = tmp[i];
            if (flag_left) {
                for (int i = total; i < width && pos < size - 1; i++)
                    buf[pos++] = ' ';
            }
        };

        switch (*fmt) {
            case 'd':
            case 'i': {
                long long v = is_longlong ? va_arg(ap, long long)
                              : is_long   ? va_arg(ap, long)
                                          : va_arg(ap, int);
                char sign_prefix[2] = {'\0', '\0'};
                if (v < 0) {
                    sign_prefix[0] = '-';
                    v = -v;
                }
                emit_num((unsigned long long)v, 10, "0123456789", sign_prefix,
                         sign_prefix[0] ? 1 : 0);
                break;
            }
            case 'u': {
                unsigned long long v = is_longlong ? va_arg(ap, unsigned long long)
                                       : is_long   ? va_arg(ap, unsigned long)
                                                   : va_arg(ap, unsigned);
                emit_num(v, 10, "0123456789", "", 0);
                break;
            }
            case 'x': {
                unsigned long long v = is_longlong ? va_arg(ap, unsigned long long)
                                       : is_long   ? va_arg(ap, unsigned long)
                                                   : va_arg(ap, unsigned);
                const char* prefix = flag_hash ? "0x" : "";
                emit_num(v, 16, "0123456789abcdef", prefix, flag_hash ? 2 : 0);
                break;
            }
            case 'X': {
                unsigned long long v = is_longlong ? va_arg(ap, unsigned long long)
                                       : is_long   ? va_arg(ap, unsigned long)
                                                   : va_arg(ap, unsigned);
                const char* prefix = flag_hash ? "0X" : "";
                emit_num(v, 16, "0123456789ABCDEF", prefix, flag_hash ? 2 : 0);
                break;
            }
            case 'p': {
                // always emit "0x" prefix, use pointer width if no explicit width
                const char* prefix = "0x";
                int ptr_width = (width > 0) ? width : (int)(sizeof(void*) * 2 + 2);
                width = ptr_width;
                pad_char = '0';
                emit_num((unsigned long long)va_arg(ap, void*), 16, "0123456789abcdef", prefix, 2);
                break;
            }
            case 's': {
                const char* s = va_arg(ap, const char*);
                if (!s)
                    s = "(null)";
                int slen = 0;
                for (const char* p = s; *p; p++)
                    slen++;
                if (!flag_left)
                    for (int i = slen; i < width && pos < size - 1; i++)
                        buf[pos++] = pad_char;
                while (*s && pos < size - 1)
                    buf[pos++] = *s++;
                if (flag_left)
                    for (int i = slen; i < width && pos < size - 1; i++)
                        buf[pos++] = ' ';
                break;
            }
            case 'c': {
                char c = (char)va_arg(ap, int);
                if (!flag_left)
                    for (int i = 1; i < width && pos < size - 1; i++)
                        buf[pos++] = ' ';
                if (pos < size - 1)
                    buf[pos++] = c;
                if (flag_left)
                    for (int i = 1; i < width && pos < size - 1; i++)
                        buf[pos++] = ' ';
                break;
            }
            case '%':
                buf[pos++] = '%';
                break;
            default:
                buf[pos++] = *fmt;
                break;
        }
    }
    buf[pos] = '\0';
    return (int)pos;
}

int rt_snprintf(char* buf, size_t size, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = _vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return r;
}

int rt_vsnprintf(char* buf, size_t size, const char* fmt, va_list ap) {
    return _vsnprintf(buf, size, fmt, ap);
}

int rt_printf(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int r = _vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    _syscall3(SYS_write, 1, (long)buf, r);
    return r;
}

[[noreturn]] void rt_assert_fail(const char* expr, const char* file, int line) {
    char buf[512];
    int n = rt_snprintf(buf, sizeof(buf), "Assertion failed: %s (%s:%d)\n", expr, file, line);
    _syscall3(SYS_write, 2 /*stderr*/, (long)buf, n);
    long pid = _syscall3(SYS_getpid, 0, 0, 0);
    _syscall3(SYS_kill, pid, 6 /*SIGABRT*/, 0);
    __builtin_unreachable();
}

// ── Process ───────────────────────────────────────────────────────────────────

[[noreturn]] void rt_abort(void) {
    long pid = _syscall3(SYS_getpid, 0, 0, 0);
    _syscall3(SYS_kill, pid, 6 /*SIGABRT*/, 0);
    __builtin_unreachable();
}

// errno: provide __error() so the system #define errno (*__error()) just works.
static int _rt_errno_val = 0;

int* rt_errno_location(void) {
    return &_rt_errno_val;
}

extern "C" int* __error(void) {
    return &_rt_errno_val;
}

// ── Mach / VM ────────────────────────────────────────────────────────────────
// Mach traps use svc #0x80 with x16 = negative trap number.

static long _mach_trap(long trap, long a0, long a1, long a2, long a3, long a4) {
    register long x16 __asm__("x16") = trap;  // negative number = mach trap
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                     : "memory", "cc");
    return x0;
}

// task_self_trap = mach trap 28
rt_mach_port_t rt_mach_task_self(void) {
    return (rt_mach_port_t)_mach_trap(-28, 0, 0, 0, 0, 0);
}

// vm_protect = mach trap 14
rt_kern_return_t rt_vm_protect(rt_mach_port_t task, rt_vm_address_t addr, rt_vm_size_t size,
                               int set_max, rt_vm_prot_t prot) {
    return (rt_kern_return_t)_mach_trap(-14, task, addr, size, set_max, prot);
}

// ── Cache / JIT ───────────────────────────────────────────────────────────────

void rt_sys_dcache_flush(void* addr, size_t len) {
    const size_t line = 64;
    uintptr_t p = (uintptr_t)addr & ~(line - 1);
    uintptr_t e = (uintptr_t)addr + len;
    for (; p < e; p += line)
        __asm__ volatile("dc cvau, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish" : : : "memory");
}

void rt_sys_icache_invalidate(void* addr, size_t len) {
    const size_t line = 64;
    uintptr_t p = (uintptr_t)addr & ~(line - 1);
    uintptr_t e = (uintptr_t)addr + len;
    for (; p < e; p += line)
        __asm__ volatile("ic ivau, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish\nisb" : : : "memory");
}

// pthread_jit_write_protect_np:
// On Apple Silicon, toggle the APRR Write permission bit (bit 54 of S3_6_C15_C1_5).
//   enabled=1 → write-protect ON  (execute allowed, write disallowed) → clear bit 54
//   enabled=0 → write-protect OFF (write allowed, execute disallowed) → set bit 54
void rt_pthread_jit_write_protect_np(int enabled) {
    uint64_t val;
    __asm__ volatile("mrs %0, s3_6_c15_c1_5" : "=r"(val));
    if (enabled)
        val &= ~(1ULL << 54);  // re-enable execute protection
    else
        val |= (1ULL << 54);  // allow writes
    __asm__ volatile("msr s3_6_c15_c1_5, %0\nisb" : : "r"(val) : "memory");
}

#endif  // ROSETTA_RUNTIME
