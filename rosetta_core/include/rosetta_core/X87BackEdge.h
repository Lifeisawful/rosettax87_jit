#pragma once

struct TranslationResult;

// Design B (OPT-BE): post-module patch point.
//
// Runs after translate_block has translated every block of a module and
// before the result is published (translator_get_data / apply-fixups) — the
// only point that can see and rewrite block TERMINATORS, which the per-block
// instr_array excludes.  Reached from:
//   - production: the translator_translate wrapper in rosetta_runtime/X87.cpp
//     (our own export, the sole route to translate_block — verified against
//     the runtime binary's single BL site in translate_code_region);
//   - aotinvoke: called explicitly from main() right after
//     g_rosetta_aot.translate().
//
// Translation-time code: must not touch FP/SIMD state (guest FP state is
// live). Behavior is inert unless an OPT-BE config flag is set.
void x87_backedge_module_post(TranslationResult* result);

// Stage-0 G0.4 audit: called AFTER the original fixup application, with the
// published destination buffer. Compares dest against the pre-publication
// internal buffer and logs which words fixups changed — specifically whether
// any backward conditional branch (the back-edge form OPT-BE patches) was
// rewritten. Inert unless ROSETTA_X87_LOG_BACKEDGE=1.
void x87_backedge_apply_fixups_audit(TranslationResult* result,
                                     unsigned char* dest);
