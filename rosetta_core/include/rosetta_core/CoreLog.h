#pragma once

// Logging abstraction for rosetta_core.
//
// Defaults to printf. Override g_core_log_fn before any core code runs if you
// need a different sink (e.g. os_log inside a dylib injected into a daemon).
//
// The function receives an already-formatted, null-terminated string so that
// os_log consumers don't have to deal with runtime format strings.

#include <stdio.h>

using core_log_fn_t = void (*)(const char* msg);

extern core_log_fn_t g_core_log_fn;

// Formats msg into a temporary buffer, then dispatches through g_core_log_fn.
#define CORE_LOG(fmt, ...)                                                  \
    do {                                                                    \
        char _core_log_buf[512];                                            \
        snprintf(_core_log_buf, sizeof(_core_log_buf), fmt, ##__VA_ARGS__); \
        if (g_core_log_fn)                                                  \
            g_core_log_fn(_core_log_buf);                                   \
    } while (0)
