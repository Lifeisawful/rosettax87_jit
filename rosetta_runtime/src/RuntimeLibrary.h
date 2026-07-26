#pragma once

#include <cstdint>

struct SymbolList;
struct ThreadContextOffsets;

// Early init run from _start by the loader, before the Rosetta runtime's main().
// Must only touch loader-written __DATA (kOffsets / kConfig) — kImports is not
// populated until the export swap, which happens much later.
void runtime_early_init();

void* init_library(SymbolList const*, uint64_t, ThreadContextOffsets const*);
using init_library_t = decltype(&init_library);

void register_runtime_routine_offsets(intptr_t* runtime_routine_offsets, const char** runtime_routine_names, int32_t count);
using register_runtime_routine_offsets_t = decltype(&register_runtime_routine_offsets);
