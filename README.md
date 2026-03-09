# RosettaHack x87 + JIT

## Overview

An experimental project that hooks into Apple's Rosetta to replace x87 instruction handlers with faster implementations, and patches the translation pipeline to emit AArch64 instructions directly for improved performance.

**⚠️ Warning: This is not ready for end-users. Use at your own risk.**

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

### Sample Test Program

```clang -v -arch x86_64 -mno-sse -mfpmath=387 ./sample/math.c -o ./build/math```

## Running

Run the target program from the build folder:
```
./runtime_loader ./math
```

You will see a popup asking you to authorize debugging. Once approved, the process granted debug session.
Reference: [Debugging tool entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)

Alternatively (Not Recommended), you can disable `Debugging Restrictions` part of System Integrity Protection (SIP) by running `csrutil enable --without debug` in macOS Recovery.

Warning: This reduces system security. NOT recommended.

## Technical Details

### Windows Applications Through Wine

You can use the brew `wine@devel` cask with RosettaHack x87+JIT. It supports launching Windows applications through Wine with an environment variable `ROSETTA_X87_PATH`.

1. Install `wine@devel` using [Homebrew](https://brew.sh/)

```bash
brew install --cask wine@devel
```

2. To permanently set the environment variable, add the following to your `~/.bashrc` or `~/.zshrc` file:
```bash
export ROSETTA_X87_PATH=/Path/To/runtime_loader
```

3. Run the Windows application
```bash
wine PATH_TO_BINARY.exe
```

## License

This project is licensed under `MIT`.
