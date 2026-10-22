# RosettaHack x87 + JIT

## Overview

An experimental project that hooks into Apple's Rosetta to replace x87 instruction handlers with faster implementations, and patches the translation pipeline to emit AArch64 instructions directly for improved performance.

## Prerequisites

- macOS 15 or later
- C compiler (clang)
- CMake

## Building

### Main Project

```
cmake -B build
cmake --build build
```

### Testing & Benchmarks

Tests and benchmarks are built automatically as part of the CMake build.

Run the test suite:
```bash
bash scripts/run_tests.sh              # build + test (native Rosetta & runtime_loader)
bash scripts/run_tests.sh --no-build   # skip build
bash scripts/run_tests.sh --native-only # native Rosetta only
bash scripts/run_tests.sh test_arith   # run a specific test
```

Run benchmarks (compares native Rosetta, loader with optimizations disabled, and loader with full optimizations):
```bash
bash scripts/run_benchmarks.sh            # build + benchmark
bash scripts/run_benchmarks.sh --no-build # skip build
```

### Other scripts

- `scripts/inspect_function.sh <binary> <symbol>` — dump the x86 IR and lowered AArch64 for one function; `--opcode`/`--fusion` isolate a single translation
- `scripts/run_opcode_sweep.sh`, `scripts/run_fusion_sweep.sh` — enable opcodes/fusions one at a time to find broken translations
- `scripts/check_simd_guards.py` — build-time check that translation-time codegen never clobbers live guest FP state
- `scripts/audit_trig_value_clobbers.sh` — audit the trig value-call clobber sets

You will see a popup asking you to authorize debugging. Once approved, the process is granted a debug session.
Reference: [Debugging tool entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)

Alternatively (Not Recommended), you can disable `Debugging Restrictions` part of System Integrity Protection (SIP) by running `csrutil enable --without debug` in macOS Recovery.

Warning: This reduces system security. NOT recommended.

## Configuration

All flags are set via environment variables and read at runtime.

### Optimization & Performance

| Variable | Description |
|----------|-------------|
| `ROSETTA_X87_FAST_ROUND=1` | Skip rounding mode dispatch (faster but unsafe for FLDCW-heavy code) |
| `ROSETTA_X87_EXTENDED_FPR_SCRATCH=1` | Expand FPR scratch register pool from 8 (V24–V31) to 16 (V16–V31) |
| `ROSETTA_X87_RUN_BRIDGE=1` | Keep an active run's pinned cache GPRs across run-transparent integer instructions (`mov`/`lea`/…) instead of breaking the run |
| `ROSETTA_X87_TRANSPARENT_INT=1` | Inline simple register-form `mov`/`lea`/`movzx`/`movsx`/`not` into IR runs (implies `ROSETTA_X87_RUN_BRIDGE`) |
| `ROSETTA_X87_TRANSPARENT_FLAGS=1` | Also inline flag-writing ALU forms (`xor r,r`; `add`/`sub`/`and`/`or`/`xor`/`shl`/`shr`/`sar r,imm`; `inc`/`dec`/`neg r`; `{add,sub,and,or,xor} [m],r`) when flag-liveness analysis proves the flags they define dead (implies `ROSETTA_X87_TRANSPARENT_INT`) |
| `ROSETTA_X87_TRANSPARENT_PUSHPOP=1` | Inline `push`/`pop r32`/`r64` and `push imm` into IR runs (flag-neutral, no liveness gate; implies `ROSETTA_X87_TRANSPARENT_INT`) |
| `ROSETTA_X87_TRANSPARENT_SSE=1` | Consume scalar `movsd`/`movss` (xmm↔mem) into IR runs, collapsing the `fstp`/`movsd` seam to a register move |
| `ROSETTA_X87_BRIDGE_CARRY=1` | Carry the base-address cache + rounding-control GPRs across bridged gaps (implies `ROSETTA_X87_RUN_BRIDGE`) |
| `ROSETTA_X87_RUNTIME_KEEPALIVE=1` | Keep the pinned x87 cache GPRs alive across runtime-routine transcendentals (`fsin`/`fcos`/`fptan`/…) instead of breaking the run; independent of `ROSETTA_X87_RUN_BRIDGE` |
| `ROSETTA_X87_CONST_PROMOTE=1` | Promote FP loads from never-writable (read-only max-protection) absolute addresses to translate-time constants |
| `ROSETTA_X87_F32_NARROW=1` | Rewrite `narrow(op_f64(widen, widen))` sandwiches to single f32 (S-register) operations |
| `ROSETTA_X87_F32_ARITH=1` | Keep f32-sourced arithmetic chains in f32 registers instead of widening intermediates to f64 (not bit-exact vs real x87 f64 intermediates; requires `ROSETTA_X87_F32_NARROW`) |
| `ROSETTA_X87_FAST_RECIP_DIV=1` | Rewrite FDIV by *any* normal constant as FMUL by its reciprocal (up to 1 ulp off; exact power-of-two divisors are always rewritten regardless of this flag) |
| `ROSETTA_X87_TRIG_IR=1` | Translate transcendentals (`fcos`/`fsin`/`fptan`/`fsincos`, `f2xm1`/`fscale`/`fyl2x`/`fyl2xp1`/`fpatan`) as value calls — IR nodes inside runs instead of the classic prologue/vtable stub |

Every flag in this table is opt-in and defaults to off. `FAST_ROUND`, `F32_ARITH` and `FAST_RECIP_DIV` additionally trade fidelity for speed.

### Debugging & Troubleshooting

These flags are primarily useful for narrowing down bugs by selectively disabling features.

| Variable | Description |
|----------|-------------|
| `ROSETTA_X87_DISABLE_CACHE=1` | Disable x87 translation cache |
| `ROSETTA_X87_DISABLE_DEFERRED_FXCH=1` | Disable deferred FXCH optimization |
| `ROSETTA_X87_DISABLE_IR=1` | Disable IR optimization pipeline |
| `ROSETTA_X87_DISABLE_ADDR_FOLD=1` | Don't fold `[base + disp]` displacements into LDR/STR addressing modes in the singular/fusion translators (materialize the full address instead) |
| `ROSETTA_X87_DISABLE_ALL_OPS=1` | Disable all translated opcodes (fall back to Rosetta default) |
| `ROSETTA_X87_DISABLE_ALL_FUSIONS=1` | Disable all instruction fusions |
| `ROSETTA_X87_DISABLE_OPS=op1,op2,...` | Disable specific opcodes (comma-separated; names = `OpcodeId` entries in `rosetta_config/include/rosetta_config/Config.h`) |
| `ROSETTA_X87_DISABLE_FUSIONS=f1,f2,...` | Disable specific fusions (comma-separated; names = `FusionId` entries in `rosetta_config/include/rosetta_config/Config.h`) |
| `ROSETTA_X87_LOG_IR_DECLINES=1` | Log guest address + reason (`CompileError`) for every x87 run the IR pipeline declines — useful for finding translation gaps in real workloads |
| `ROSETTA_X87_LOG_RUN_BREAKS=1` | Log length + breaking opcode + gap-to-next-x87 for every x87 run — useful for finding what terminates runs in real workloads |
| `ROSETTA_X87_LOG_BACKEDGE=1` | Log every module seen by the post-translate hook |
| `ROSETTA_X87_LOGS=1` | Enable verbose logging output from the loader |
| `ROSETTA_FORCE_CPU_MODE32=1` | Force the decoder into 32-bit mode (test-only; lets `aotinvoke` reach legacy opcodes like ARPL) |

#### Per-opcode fallbacks

| Variable | Description |
|----------|-------------|
| `ROSETTA_X87_DISABLE_STACKOPS=1` | Disable inline `fdecstp`/`fincstp`/`ffree` (family gate — the `OpcodeId` enum is full at 64 bits, so these have no `DISABLE_OPS` name) |
| `ROSETTA_X87_DISABLE_{FCOS,FSIN,FSINCOS,FPTAN}_FAST=1` | Route that op through the classic prologue/vtable stub instead of the in-blob fast path (also disables its `TRIG_IR` value call) |
| `ROSETTA_X87_DISABLE_{FXAM,FXTRACT,FPREM,FPREM1}_FAST=1` | Same, for the non-trig in-blob fast paths |
| `ROSETTA_X87_DISABLE_{F2XM1,FSCALE,FYL2X,FYL2XP1,FPATAN}_VAL=1` | Keep that op on the classic stub even under `TRIG_IR` |

#### Bisection levers

Each of these disables one specific IR or lowering optimization; all default to enabled.

| Variable | Description |
|----------|-------------|
| `ROSETTA_X87_DISABLE_NZCV_LIVENESS=1` | Don't use Rosetta's flag-liveness dataflow to prove NZCV dead at run exit (forward whitelist walk only) |
| `ROSETTA_X87_DISABLE_TRIG_SW_SINK=1` | Keep every trig/pow value call's `C1\|C2` status-word RMW, even when a later full-halfword writer makes it dead |
| `ROSETTA_X87_DISABLE_FCMOV_RAW=1` | `FCSel` reads the packed guest-EFLAGS NZCV from `FComI` instead of remapped raw FCMP conditions |
| `ROSETTA_X87_DISABLE_GUEST_CMP=1` | Don't consume `cmp`/`test r32`/`r64` as in-run guest flag definers (the run ends there instead) |
| `ROSETTA_X87_DISABLE_GUEST_SETCC=1` | Don't consume `setcc r8` after an in-run `cmp`/`test`, and don't absorb the trailing compare tail |
| `ROSETTA_X87_DISABLE_GUEST_SAHF=1` | Don't consume `sahf` as an in-run guest flag definer |
| `ROSETTA_X87_DISABLE_GUEST_ALU_RR=1` | Don't consume reg-reg `add`/`sub`/`and`/`or`/`xor` or `imul r,r[,imm]` into IR runs |
| `ROSETTA_X87_DISABLE_TEST_SHORTCUT=1` | Lower the `fnstsw`/`test` CC-mask idiom through the packed-AX `TST` instead of a raw-FCMP condition |
| `ROSETTA_X87_DISABLE_TEST_CCMN=1` | Lower that shortcut as a `CSET`+`ANDS` pair instead of one integer `CCMN` |
| `ROSETTA_X87_DISABLE_STP_SUPPRESS=1` | Keep forming STPs even when the stored bytes are provably reloaded in the same run (STP-sourced forwarding costs 11 cycles vs 5 on M1) |
| `ROSETTA_X87_DISABLE_X18_STATE=1` | Always materialize `Xbase` at run entry instead of addressing fixed SW/CW halfword fields off `x18` |
| `ROSETTA_X87_DISABLE_LOWER_DC=1` | Disable the Lower dead-code batch: combined pop-pair tag mask, fused-window dead `C2` pair elision, deferred `Xst_base` ADD |
| `ROSETTA_X87_DISABLE_SEAM=1` | Flush TOP/tag state at every run break instead of deferring it across an intra-block seam to the next run |
| `ROSETTA_X87_DISABLE_WINDOW_DEFER=1` | Mid-window runs emit their TOP/tag writeback instead of deferring it to the window-ending member |
| `ROSETTA_X87_DISABLE_PINNED_DEMAND=1` | Charge a flat 4 pinned preamble GPRs in `peak_live_gprs` instead of the demand-derived count |
| `ROSETTA_X87_DISABLE_SSE_LEAD=1` | Don't form x87 windows at leading `movsd`/`movss` ahead of a run |
| `ROSETTA_X87_DISABLE_BACKEDGE=1` | Don't retarget self-loop back edges past the priming `st[]` load in decode-verified accumulator blocks |
| `ROSETTA_X87_BACKEDGE_NOOP_PROBE=1` | Rewrite every backward conditional-branch word with its own value (writability probe; must be a byte-identical no-op) |

### Unlocked Rosetta Runtime Flags

The loader can patch the runtime's SIP check (`sys_csrctl`) to accept `ROSETTA_*` environment variables that are normally blocked. This is **opt-in**: set `ROSETTA_X87_DISABLE_SIP=1` on the loader, or the flags below are ignored. They are Apple's own debugging/diagnostic flags built into `/usr/libexec/rosetta/runtime` — the loader simply makes them accessible.

| Variable | Description |
|----------|-------------|
| `ROSETTA_DISABLE_AOT=1` | Skip AOT (ahead-of-time) shared cache translations; force everything through the JIT path |
| `ROSETTA_PRINT_IR=1` | Print the translator's intermediate representation during compilation |
| `ROSETTA_PRINT_SEGMENTS=1` | Print segment mapping information during process setup |
| `ROSETTA_HARDWARE_TRACING_PATH=/path` | Write a binary trace file to the given path (appends `.<pid>`); records JIT translations, code bytes, and runtime mappings (see `scripts/parse_rosetta_trace.py`) |
| `ROSETTA_SCRIBBLE_TRANSLATIONS=1` | Emit Type 4 (JIT fragment freed) records in the hardware trace; enables tracking translation eviction |
| `ROSETTA_AOT_ERRORS_ARE_FATAL=1` | Abort on AOT translation errors instead of falling back to JIT |
| `ROSETTA_DISABLE_EXCEPTIONS=1` | Disable Rosetta's exception handling machinery |
| `ROSETTA_DISABLE_SIGACTION=1` | Disable Rosetta's `sigaction` interposition |
| `ROSETTA_ALLOW_GUARD_PAGES=1` | Allow guard page mappings in the translated process |
| `ROSETTA_ADVERTISE_AVX=1` | Report AVX support in CPUID (translation of AVX instructions is not implied) |
| `ROSETTA_DEBUGSERVER_PORT=<port>` | Attach Rosetta's internal debug server to the given Mach port |
| `ROSETTA_MEMORY_ACCESS_INSTRUMENTATION=1` | Enable memory access instrumentation in generated code |

## IDA Pro Tooling

Scripts for loading and analyzing Rosetta JIT traces in IDA Pro 9.x.

### Trace Loader (`scripts/ida_rosetta_trace_loader.py`)

IDA loader plugin that imports hardware trace files (produced by `ROSETTA_HARDWARE_TRACING_PATH`) as IDA databases. Symlink to `<IDA>/loaders/`.

### Trace Parser (`scripts/parse_rosetta_trace.py`)

Standalone Python script that parses and pretty-prints Rosetta hardware trace files. Useful for inspecting traces without IDA.

```bash
python3 scripts/parse_rosetta_trace.py tracee.bin.<pid>
```

## Usage with Wine

> **Deprecated:** `wine@devel` removed support for the `ROSETTA_X87_PATH` environment variable, so the integration described below no longer works. There is no replacement at this time. The section is retained for historical reference.

### ~~Windows Applications~~

~~You can use the brew `wine@devel` cask with RosettaHack x87+JIT. It supports launching Windows applications through Wine with an environment variable `ROSETTA_X87_PATH`.~~

~~1. Install `wine@devel` using [Homebrew](https://brew.sh/)~~

~~`brew install --cask wine@devel`~~

~~2. To permanently set the environment variable, add the following to your `~/.bashrc` or `~/.zshrc` file:~~

~~`export ROSETTA_X87_PATH=/Path/To/runtime_loader`~~

3. Run the Windows application

```bash
wine PATH_TO_BINARY.exe
```

## License

This project is licensed under `MIT`.
