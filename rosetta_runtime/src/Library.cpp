#include "Library.h"

#include "Export.h"
#include "rosetta_core/hook.h"

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

namespace {

using bind_library_stubs_t = void (*)(Export*, uint64_t, const Export*, uint32_t);

bind_library_stubs_t g_original_bind_library_stubs = nullptr;

void bind_library_stubs(Export* target, uint64_t target_count, const Export* source,
                        uint32_t source_count) {
    if (target_count == 3) {
        kImports.runtimeExports = source;
        kImports.runtimeExportCount = source_count;
        memcpy((void*)target, (const void*)kExports.runtimeExports, sizeof(Export) * target_count);
    } else {
        // memcpy((void*) kImports.x87Exports, (const void*) source, sizeof(Export) * target_count);
        kImports.x87Exports = source;
        kImports.x87ExportCount = source_count;
        memcpy((void*)target, (const void*)kExports.x87Exports, sizeof(Export) * target_count);
    }

    if (kImports.runtimeExports && kImports.x87Exports) {
        exportsInit();
    }
}

}  // namespace

void init_bind_library_stubs_hook(uintptr_t bind_library_stubs_addr) {
    g_original_bind_library_stubs = reinterpret_cast<bind_library_stubs_t>(bind_library_stubs_addr);
    hook_install(reinterpret_cast<void*>(g_original_bind_library_stubs),
                 reinterpret_cast<void*>(&bind_library_stubs),
                 reinterpret_cast<void**>(&g_original_bind_library_stubs));
}
