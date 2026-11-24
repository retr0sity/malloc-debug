# malloc-debug

An educational project exploring Windows executable internals, PE structures, IAT hooking, and memory allocation debugging.

## Overview

This project focuses on understanding the Portable Executable (PE) format and using the Import Address Table (IAT) to monitor memory allocation functions in a running Windows executable.

The implementation:

- Accesses the executable's module base address and reads its DOS and NT headers.
- Locates the PE Import Directory and traverses imported DLLs and functions.
- Identifies `malloc`, `calloc`, `realloc`, and `free` in the IAT.
- Uses `VirtualProtect` to replace their IAT entries with custom wrapper functions.
- Tracks allocated memory blocks and reports memory leaks and untracked memory operations.
- Restores the original IAT entries when monitoring ends.

## Implementation details

The program uses `MallocDebug_Init()` to install the hooks and `MallocDebug_Done()` to restore the original function addresses and check for memory leaks.

Allocation information is stored in a fixed-size array, including the memory address, allocation size, and tracking status.

The implementation also handles several edge cases, including:

- `realloc` with NULL or zero size.
- Failed reallocations.
- Repeated initialization and cleanup.
- Invalid import directory entries and RVAs.
- Restoring previously modified IAT entries if initialization fails.

Import descriptors are traversed until the terminating zero descriptor is found, with RVA bounds checked against `SizeOfImage`.

## Building and running

The project is written in C and uses the Windows API.

**Requirements:**
- Windows
- GCC (MinGW-w64)

Compile using GCC

Run the program:

`.\iat.exe`

The included `main()` demonstrates memory allocation tracking and intentionally leaves an allocation unfreed to test leak detection.

## Limitations

- The hooks modify the main executable's IAT, not the IATs of every loaded DLL.
- Allocation tracking uses a fixed-size array.
- Memory operations performed outside an active monitoring session may not be tracked.
- If matching imported functions have different original addresses, initialization fails instead of installing incompatible hooks.

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
