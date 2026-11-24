# malloc-debug

An educational project exploring Windows executable internals, PE structures, IAT hooking, and memory allocation debugging.

## Overview

This project focuses on understanding the Portable Executable (PE) format and using the Import Address Table (IAT) to monitor memory allocation functions in a running Windows executable.

The implementation:

- Accesses the executable's module base address and reads its DOS and NT headers.
- Locates the PE Import Directory and traverses imported DLLs and functions.
- Identifies `malloc`, `calloc`, `realloc`, and `free` imported from a supported C runtime DLL.
- Uses `VirtualProtect` to replace their IAT entries with custom wrapper functions.
- Tracks allocated memory blocks and reports memory leaks and untracked memory operations.
- Restores the original IAT entries when monitoring ends.

## Implementation details

The program uses `MallocDebug_Init()` to install the hooks and `MallocDebug_Done()` to restore the original function addresses and check for memory leaks.

Allocation information is stored in a fixed-size array, including the memory address, allocation size, and tracking status.

The implementation also handles several edge cases, including:

- `realloc` with NULL or zero size.
- Failed reallocations and untracked pointers.
- Repeated initialization and cleanup.
- Invalid import directory entries and RVAs.
- Restoring previously modified IAT entries if initialization fails.
- IAT entries that are already writable when `VirtualProtect` fails.

Import directory traversal is limited by the directory's `Size` field, while a terminating zero descriptor can end the traversal earlier if present. RVA bounds are also checked against `SizeOfImage`.

Functions are matched using both their names and the DLL they are imported from. The program selects a supported C runtime DLL rather than replacing functions with matching names across unrelated libraries.

During cleanup, the program traverses the import entries again to restore the original addresses, without using a separate array of patched IAT slots.

## Building and running

The project is written in C and uses the Windows API.

**Requirements:**
- Windows
- GCC (MinGW-w64)

Compile using GCC:

```powershell
gcc -Wall -Wextra -O0 iat.c -o iat.exe
```

Run the program:

```powershell
.\iat.exe
```

The included `main()` demonstrates memory allocation tracking and intentionally leaves an allocation unfreed to test leak detection.

Additional test scenarios can be enabled using compile-time flags such as `TEST_ALLOC_EDGES` and `TEST_REPEATED_CALLS`.

## Limitations

- The hooks modify the main executable's IAT, not the IATs of every loaded DLL.
- Allocation tracking uses a fixed-size array.
- Memory operations performed outside an active monitoring session may not be tracked.
- If matching functions within the selected runtime resolve to different original addresses, initialization fails instead of installing incompatible hooks.

## Technical concepts

- Windows PE format
- DOS and NT headers
- Import Directory
- Import Lookup Table (ILT)
- Import Address Table (IAT)
- IAT hooking
- Relative Virtual Addresses (RVAs)
- Function pointers and DLL imports
- Windows memory protection
- Dynamic memory allocation

## Motivation

This project started as part of my reverse engineering studies.

The purpose is to gain practical experience with Windows executable internals, understand how imported functions are resolved at runtime, and explore how IAT modification can be used to detect memory management issues.

## Disclaimer

This is an educational project developed as part of my reverse engineering studies. It is intended for learning and experimentation rather than production use.
