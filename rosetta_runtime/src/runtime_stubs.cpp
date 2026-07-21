#include <cstdint>

extern "C" {

__attribute__((used))
uintptr_t pthread_entry_fptr = 0;

__attribute__((used))
uintptr_t wqthread_entry_fptr = 0;

__attribute__((used, naked))
void sa_tramp() {
    __asm__ volatile("brk #0xdead");
}

__attribute__((used, naked))
void runtime_thread_init() {
    __asm__ volatile("brk #0xdead");
}

__attribute__((used, naked))
void runtime_pthread_init() {
    __asm__ volatile("brk #0xdead");
}

}
