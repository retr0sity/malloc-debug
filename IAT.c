#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#define MAX_ALLOCATIONS 1024

#ifdef IAT_DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do { if (0) printf(__VA_ARGS__); } while (0)
#endif

typedef struct allocation_record {
    void *address;
    size_t size;
    int active;
    int reported;
} allocation_record;

static allocation_record allocations[MAX_ALLOCATIONS];

void *MallocDebug_malloc(size_t size);
void *MallocDebug_calloc(size_t count, size_t size);
void *MallocDebug_realloc(void *ptr, size_t size);
void MallocDebug_free(void *ptr);
int MallocDebug_Done(void);

typedef struct memalloc_patch {
    const char *name;
    void *original_address;
    void *patched_address;
} memalloc_patch;

static memalloc_patch patches[4] = {
    {"malloc", NULL, (void*)MallocDebug_malloc},
    {"calloc", NULL, (void*)MallocDebug_calloc},
    {"realloc", NULL, (void*)MallocDebug_realloc},
    {"free", NULL, (void*)MallocDebug_free}
};

static BYTE *image_base = NULL;
static size_t image_size = 0;
static PIMAGE_IMPORT_DESCRIPTOR import_descriptors = NULL;
static size_t descriptor_limit = 0;
static const char *target_dll = NULL;
static int patch_count = 0;
static int is_initialized = 0;
static int restore_pending = 0;

int imports() {
    char *p = malloc(1);
    if (p == NULL) {
        printf("malloc failed\n");
        return 1;
    }

    void *c = calloc(1, 1);
    if (c == NULL) {
        printf("calloc failed\n");
        free(p);
        return 2;
    }
    free(c);

    char *q = realloc(p, 2);
    if (q == NULL) {
        printf("realloc failed\n");
        free(p);
        return 3;
    }
    free(q);
    return 0;
}

static int FindAllocation(void *ptr) {
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == ptr) {
            return i;
        }
    }
    return -1;
}

static void ClearAllocation(int i) {
    allocations[i].address = NULL;
    allocations[i].size = 0;
    allocations[i].active = 0;
    allocations[i].reported = 0;
}

static void RecordAllocation(void *address, size_t size) {
    int slot = FindAllocation(address);

    if (slot < 0) {
        for (int i = 0; i < MAX_ALLOCATIONS; i++) {
            if (!allocations[i].active) {
                slot = i;
                break;
            }
        }
    }

    if (slot < 0) {
        printf("warning: allocation tracking array is full\n");
        return;
    }

    allocations[slot].address = address;
    allocations[slot].size = size;
    allocations[slot].active = 1;
    allocations[slot].reported = 0;
}

void *MallocDebug_malloc(size_t size) {
    void *(*original)(size_t) = (void *(*)(size_t))patches[0].original_address;
    void *ptr = original(size);
    if (ptr != NULL) RecordAllocation(ptr, size);
    return ptr;
}

void *MallocDebug_calloc(size_t count, size_t size) {
    void *(*original)(size_t, size_t) = (void *(*)(size_t, size_t))patches[1].original_address;
    void *ptr = original(count, size);
    if (ptr != NULL) RecordAllocation(ptr, count * size);
    return ptr;
}

void *MallocDebug_realloc(void *ptr, size_t size) {
    void *(*original)(void *, size_t) = (void *(*)(void *, size_t))patches[2].original_address;

    if (ptr == NULL) {
        void *new_ptr = original(NULL, size);
        if (new_ptr != NULL) RecordAllocation(new_ptr, size);
        return new_ptr;
    }

    // check before realloc, even if it fails
    int record = FindAllocation(ptr);
    if (record < 0) {
        printf("warning: reallocating untracked pointer %p\n", ptr);
    }

    void *new_ptr = original(ptr, size);
    if (size != 0 && new_ptr == NULL) {
        return NULL;
    }

    // ucrt frees the old block for size 0
    if (record >= 0) ClearAllocation(record);
    if (new_ptr != NULL) RecordAllocation(new_ptr, size);
    return new_ptr;
}

void MallocDebug_free(void *ptr) {
    void (*original)(void *) = (void (*)(void *))patches[3].original_address;
    if (ptr != NULL) {
        int record = FindAllocation(ptr);
        if (record >= 0) {
            ClearAllocation(record);
        } else {
            printf("warning: freeing untracked pointer %p (may predate Init)\n", ptr);
        }
    }
    original(ptr);
}

static int FunctionIndex(const char *name) {
    for (int i = 0; i < 4; i++) {
        if (strcmp(name, patches[i].name) == 0) return i;
    }
    return -1;
}

static int IsCRTDll(const char *name) {
    if (_stricmp(name, "ucrtbase.dll") == 0 ||
        _stricmp(name, "msvcrt.dll") == 0) {
        return 1;
    }
    if (_strnicmp(name, "api-ms-win-crt-heap-", 20) == 0) {
        return 1;
    }
    if (_strnicmp(name, "msvcr", 5) == 0) {
        size_t length = strlen(name);
        if (length >= 9 && _stricmp(name + length - 4, ".dll") == 0) {
            return 1;
        }
    }
    return 0;
}

static int IsZeroDescriptor(PIMAGE_IMPORT_DESCRIPTOR desc) {
    return desc->OriginalFirstThunk == 0 && desc->TimeDateStamp == 0 &&
           desc->ForwarderChain == 0 && desc->Name == 0 && desc->FirstThunk == 0;
}

static int PrepareImports(void) {
    HMODULE module = GetModuleHandle(NULL);
    if (module == NULL) {
        printf("failed to get executable module\n");
        return 1;
    }

    MEMORY_BASIC_INFORMATION memoryInfo;
    if (VirtualQuery(module, &memoryInfo, sizeof(memoryInfo)) == 0 ||
        memoryInfo.State != MEM_COMMIT || memoryInfo.Type != MEM_IMAGE ||
        memoryInfo.AllocationBase != module ||
        (memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 ||
        memoryInfo.RegionSize < sizeof(IMAGE_DOS_HEADER)) {
        printf("invalid or unreadable executable headers\n");
        return 1;
    }

    BYTE *base = (BYTE*)module;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)) {
        printf("invalid dos header\n");
        return 1;
    }

    size_t minOptionalSize = offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) +
        (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * sizeof(IMAGE_DATA_DIRECTORY);
    size_t minNTSize = offsetof(IMAGE_NT_HEADERS, OptionalHeader) + minOptionalSize;
    size_t ntOffset = (size_t)dos->e_lfanew;
    if (ntOffset > memoryInfo.RegionSize ||
        minNTSize > memoryInfo.RegionSize - ntOffset) {
        printf("nt headers extend beyond readable header region\n");
        return 1;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
        nt->FileHeader.SizeOfOptionalHeader < minOptionalSize ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
        printf("invalid or incompatible nt headers\n");
        return 1;
    }

    size_t imageSize = (size_t)nt->OptionalHeader.SizeOfImage;
    size_t headersSize = (size_t)nt->OptionalHeader.SizeOfHeaders;
    if (headersSize > imageSize || ntOffset > headersSize ||
        minNTSize > headersSize - ntOffset) {
        printf("invalid pe header sizes\n");
        return 1;
    }

    size_t importRVA = (size_t)nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    size_t importSize = (size_t)nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (importRVA == 0 || importRVA >= imageSize ||
        importSize < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
        imageSize - importRVA < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        printf("invalid import directory\n");
        return 1;
    }

    // size is the bound; zero descriptor may stop the scan earlier
    size_t maxBytes = imageSize - importRVA;
    if (importSize < maxBytes) maxBytes = importSize;
    image_base = base;
    image_size = imageSize;
    import_descriptors = (PIMAGE_IMPORT_DESCRIPTOR)(base + importRVA);
    descriptor_limit = maxBytes / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    DEBUG_PRINT("import directory size: %zu, descriptors: %zu\n", importSize, descriptor_limit);
    return 0;
}

static int WritableIATSlot(PIMAGE_THUNK_DATA thunk) {
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(&thunk->u1.Function, &info, sizeof(info)) == 0 ||
        info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        return 0;
    }
    if (info.Protect != PAGE_READWRITE && info.Protect != PAGE_WRITECOPY &&
        info.Protect != PAGE_EXECUTE_READWRITE && info.Protect != PAGE_EXECUTE_WRITECOPY) {
        return 0;
    }
    size_t offset = (size_t)((BYTE*)&thunk->u1.Function - (BYTE*)info.BaseAddress);
    return offset <= info.RegionSize && sizeof(thunk->u1.Function) <= info.RegionSize - offset;
}

static int WriteIATSlot(PIMAGE_THUNK_DATA thunk, void *address) {
    DWORD oldProtect;
    int protectionChanged = VirtualProtect(&thunk->u1.Function,
        sizeof(thunk->u1.Function), PAGE_READWRITE, &oldProtect) != 0;

    // VirtualProtect can fail even when the slot is already writable
    if (!protectionChanged && !WritableIATSlot(thunk)) {
        printf("failed to make IAT entry writable\n");
        return 1;
    }

    thunk->u1.Function = (ULONG_PTR)address;

    if (protectionChanged) {
        DWORD unused;
        if (!VirtualProtect(&thunk->u1.Function,
            sizeof(thunk->u1.Function), oldProtect, &unused)) {
            printf("warning: could not restore IAT page protection\n");
        }
    }
    return 0;
}

enum { CHECK_IMPORTS, PATCH_IMPORTS, RESTORE_IMPORTS };

static int ProcessImports(int action) {
    for (size_t d = 0; d < descriptor_limit; d++) {
        PIMAGE_IMPORT_DESCRIPTOR desc = &import_descriptors[d];
        if (IsZeroDescriptor(desc)) break;

        size_t nameRVA = (size_t)desc->Name;
        if (nameRVA >= image_size ||
            memchr(image_base + nameRVA, '\0', image_size - nameRVA) == NULL) {
            printf("invalid dll name rva or missing terminator\n");
            return 1;
        }
        const char *dllName = (const char*)(image_base + nameRVA);
        DEBUG_PRINT("dll: %s\n", dllName);

        // an absent ILT cannot give us import names after loading
        if (desc->OriginalFirstThunk == 0) continue;
        if (desc->FirstThunk == 0) {
            printf("missing import address table\n");
            return 1;
        }

        size_t originalRVA = (size_t)desc->OriginalFirstThunk;
        size_t firstRVA = (size_t)desc->FirstThunk;
        if (originalRVA >= image_size || firstRVA >= image_size) {
            printf("invalid thunk table rva\n");
            return 1;
        }

        PIMAGE_THUNK_DATA lookup = (PIMAGE_THUNK_DATA)(image_base + originalRVA);
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(image_base + firstRVA);
        size_t originalCount = (image_size - originalRVA) / sizeof(IMAGE_THUNK_DATA);
        size_t firstCount = (image_size - firstRVA) / sizeof(IMAGE_THUNK_DATA);
        size_t limit = originalCount < firstCount ? originalCount : firstCount;
        int foundEnd = 0;

        for (size_t t = 0; t < limit; t++) {
            if (lookup[t].u1.AddressOfData == 0) {
                foundEnd = 1;
                break;
            }
            if (iat[t].u1.Function == 0) {
                printf("invalid iat entry: null function address\n");
                return 1;
            }
            if (lookup[t].u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

            size_t functionRVA = (size_t)lookup[t].u1.AddressOfData;
            if (functionRVA >= image_size || image_size - functionRVA <= sizeof(WORD)) {
                printf("invalid imported function name rva\n");
                return 1;
            }

            PIMAGE_IMPORT_BY_NAME imported = (PIMAGE_IMPORT_BY_NAME)(image_base + functionRVA);
            size_t maxLength = image_size - functionRVA - sizeof(WORD);
            if (memchr(imported->Name, '\0', maxLength) == NULL) {
                printf("unterminated imported function name\n");
                return 1;
            }

            if (action == CHECK_IMPORTS || target_dll == NULL ||
                _stricmp(dllName, target_dll) != 0) continue;

            int index = FunctionIndex((const char*)imported->Name);
            if (index < 0) continue;
            void *current = (void*)(ULONG_PTR)iat[t].u1.Function;

            if (action == PATCH_IMPORTS) {
                if (current == patches[index].patched_address) continue;
                if (patches[index].original_address != NULL &&
                    patches[index].original_address != current) {
                    printf("different original addresses for %s in %s\n", patches[index].name, dllName);
                    return 1;
                }
                patches[index].original_address = current;
                if (WriteIATSlot(&iat[t], patches[index].patched_address) != 0) return 1;
                patch_count++;
#ifdef TEST_INIT_ROLLBACK
                static int injected_once = 0;
                if (!injected_once && patch_count == 2) {
                    injected_once = 1;
                    printf("test: forcing init failure after two patches\n");
                    return 1;
                }
#endif
                DEBUG_PRINT("patched %s in %s\n", patches[index].name, dllName);
            } else {
                if (current == patches[index].patched_address &&
                    patches[index].original_address != NULL) {
#ifdef TEST_DONE_RETRY
                    static int skipped_once = 0;
                    if (!skipped_once) {
                        skipped_once = 1;
                        printf("test: simulating one failed slot restoration\n");
                        continue;
                    }
#endif
                    if (WriteIATSlot(&iat[t], patches[index].original_address) != 0) return 1;
                    patch_count--;
                    DEBUG_PRINT("restored %s in %s\n", patches[index].name, dllName);
                }
            }
        }

        if (!foundEnd) {
            printf("malformed thunk table: missing terminator\n");
            return 1;
        }
    }

    // no zero descriptor is fine if the directory size was exhausted
    return 0;
}

static const char *ChooseCRTDll(void) {
    const char *best = NULL;
    int bestCount = 0;

    for (size_t d = 0; d < descriptor_limit; d++) {
        PIMAGE_IMPORT_DESCRIPTOR candidate = &import_descriptors[d];
        if (IsZeroDescriptor(candidate)) break;
        const char *candidateName = (const char*)(image_base + candidate->Name);
        if (!IsCRTDll(candidateName)) continue;

        unsigned found = 0;
        for (size_t k = 0; k < descriptor_limit; k++) {
            PIMAGE_IMPORT_DESCRIPTOR desc = &import_descriptors[k];
            if (IsZeroDescriptor(desc)) break;
            const char *dllName = (const char*)(image_base + desc->Name);
            if (_stricmp(candidateName, dllName) != 0 || desc->OriginalFirstThunk == 0) continue;

            PIMAGE_THUNK_DATA lookup = (PIMAGE_THUNK_DATA)(image_base + desc->OriginalFirstThunk);
            for (size_t t = 0; lookup[t].u1.AddressOfData != 0; t++) {
                if (lookup[t].u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME imported = (PIMAGE_IMPORT_BY_NAME)
                    (image_base + (size_t)lookup[t].u1.AddressOfData);
                int index = FunctionIndex((const char*)imported->Name);
                if (index >= 0) found |= 1U << index;
            }
        }

        int count = 0;
        for (int i = 0; i < 4; i++) if (found & (1U << i)) count++;
        if (count > bestCount) {
            best = candidateName;
            bestCount = count;
        }
    }
    return best;
}

static void ClearPatches(void) {
    for (int i = 0; i < 4; i++) patches[i].original_address = NULL;
    target_dll = NULL;
    import_descriptors = NULL;
    image_base = NULL;
    image_size = 0;
    descriptor_limit = 0;
    restore_pending = 0;
}

int MallocDebug_Init(void) {
    if (restore_pending) {
        printf("cannot initialize: previous restoration incomplete\n");
        return 1;
    }
    if (is_initialized) return 0;

    if (PrepareImports() != 0 || ProcessImports(CHECK_IMPORTS) != 0) {
        ClearPatches();
        return 1;
    }

    target_dll = ChooseCRTDll();
    if (target_dll == NULL) {
        printf("no supported CRT memory imports found\n");
        ClearPatches();
        return 1;
    }

    DEBUG_PRINT("hooking CRT: %s\n", target_dll);
    if (ProcessImports(PATCH_IMPORTS) != 0) {
        if (patch_count > 0) {
            printf("init failed; restoring %d IAT entries\n", patch_count);
            if (MallocDebug_Done() != 0) {
                printf("warning: some IAT entries could not be restored\n");
            }
        } else {
            ClearPatches();
        }
        return 1;
    }

    is_initialized = 1;
    return 0;
}

int MallocDebug_Done(void) {
    int failed = 0;
    if (patch_count > 0) {
        if (ProcessImports(RESTORE_IMPORTS) != 0) failed = 1;
    }

    if (patch_count > 0) {
        restore_pending = 1;
        return 1;
    }

    if (is_initialized) {
        printf("\nchecking for memory leaks\n");
        int leak_count = 0;
        int already_reported = 0;
        size_t leaked_bytes = 0;

        for (int i = 0; i < MAX_ALLOCATIONS; i++) {
            if (allocations[i].active && allocations[i].reported) already_reported++;
            if (allocations[i].active && !allocations[i].reported) {
                printf("memory leak: %p (%zu bytes)\n", allocations[i].address, allocations[i].size);
                leak_count++;
                leaked_bytes += allocations[i].size;
                allocations[i].reported = 1;
            }
        }
        if (leak_count == 0 && already_reported == 0) {
            printf("no memory leaks detected.\n");
        } else {
            printf("new leaks: %d blocks, %zu bytes\n", leak_count, leaked_bytes);
            if (already_reported > 0) {
                printf("previously reported records retained (may be stale): %d\n", already_reported);
            }
        }
    }

    is_initialized = 0;
    ClearPatches();
    return failed ? 1 : 0;
}

#ifndef IAT_NO_MAIN
int main(void) {
    if (imports() != 0) return 1;

#ifdef TEST_INIT_ROLLBACK
    printf("\ntest: rollback after a partial Init\n");
    if (MallocDebug_Init() == 0 || patch_count != 0 || is_initialized || restore_pending) {
        printf("FAIL: partial initialization did not roll back\n");
        return 1;
    }
    printf("PASS: partial Init restored the patched slots\n");
#endif

    if (MallocDebug_Init() != 0) {
        printf("initialization failed\n");
        MallocDebug_Done();
        return 1;
    }

    printf("\ntest: realloc(NULL, 100)\n");
    void *p = realloc(NULL, 100);
    if (p != NULL) {
        printf("allocation succeeded: %p\n", p);
        free(p);
    }

    printf("\ntest: realloc(ptr, 0)\n");
    void *q = malloc(100);
    if (q != NULL) {
        void *result = realloc(q, 0);
        printf("realloc(ptr, 0) returned: %p\n", result);
        if (result != NULL) free(result);
        // ucrt frees q if size is 0
    }

#ifdef TEST_ALLOC_EDGES
    printf("\ntest: failed realloc preserves original allocation\n");
    void *keep = malloc(64);
    if (keep != NULL) {
        volatile size_t huge = (size_t)-1;
        void *resized = realloc(keep, huge);
        if (resized == NULL) {
            int record = FindAllocation(keep);
            printf("failed realloc kept original record: %s\n",
                record >= 0 && allocations[record].size == 64 ? "yes" : "no");
            if (record < 0 || allocations[record].size != 64) return 1;
            free(keep);
        } else {
            printf("unexpected: very large realloc succeeded\n");
            free(resized);
        }
    }

    printf("\ntest: full allocation tracking array\n");
    void *blocks[MAX_ALLOCATIONS + 1] = {0};
    for (int i = 0; i < MAX_ALLOCATIONS + 1; i++) blocks[i] = malloc(1);
    for (int i = 0; i < MAX_ALLOCATIONS + 1; i++) free(blocks[i]);
    printf("full array test finished (expected: full array and untracked free warnings)\n");
#endif

#ifdef TEST_CROSS_SESSION
    void *carry = malloc(48);
#endif

#if !defined(TEST_ALLOC_EDGES) && !defined(TEST_CROSS_SESSION) && \
    !defined(TEST_DONE_RETRY) && !defined(TEST_REPEATED_CALLS) && \
    !defined(TEST_STALE_RECORDS) && !defined(TEST_INIT_ROLLBACK)
    void *leak = calloc(1, 100);
    if (leak != NULL) printf("intentionally leaving %p allocated\n", leak);
#endif

#ifdef TEST_DONE_RETRY
    printf("\ntest: first Done leaves one patched slot for retry\n");
    if (MallocDebug_Done() == 0 || patch_count != 1) {
        printf("FAIL: expected one pending IAT slot\n");
        return 1;
    }
    printf("test: retrying Done\n");
#endif

    if (MallocDebug_Done() != 0) {
        printf("restoration failed\n");
        return 1;
    }

#ifdef TEST_CROSS_SESSION
    printf("\ntest: free a previously reported allocation in the next session\n");
    if (MallocDebug_Init() != 0) return 1;
    free(carry);
    if (MallocDebug_Done() != 0) return 1;
#endif

#ifdef TEST_REPEATED_CALLS
    printf("\ntest: Done without Init\n");
    if (MallocDebug_Done() != 0) return 1;

    printf("\ntest: Init twice, allocate, Done twice\n");
    if (MallocDebug_Init() != 0 || MallocDebug_Init() != 0) return 1;
    void *again = malloc(24);
    free(again);
    if (MallocDebug_Done() != 0 || MallocDebug_Done() != 0) return 1;
#endif

#ifdef TEST_STALE_RECORDS
    printf("\ntest: replace a stale record at the same address\n");
    void *old_address = (void*)&patch_count;
    void *target_address = (void*)&is_initialized;

    RecordAllocation(target_address, 11);
    int record = FindAllocation(target_address);
    if (record < 0) return 1;
    allocations[record].reported = 1;
    RecordAllocation(target_address, 22);
    record = FindAllocation(target_address);
    if (record < 0 || allocations[record].size != 22 || allocations[record].reported) {
        printf("FAIL: stale record was not replaced\n");
        return 1;
    }
    printf("PASS: updated size, reported flag reset\n");

    printf("test: realloc-style record move onto a stale address\n");
    RecordAllocation(old_address, 32);
    record = FindAllocation(target_address);
    allocations[record].reported = 1;
    int old_record = FindAllocation(old_address);
    if (old_record < 0) return 1;
    ClearAllocation(old_record);
    RecordAllocation(target_address, 96);
    record = FindAllocation(target_address);
    if (FindAllocation(old_address) >= 0 || record < 0 ||
        allocations[record].size != 96 || allocations[record].reported) {
        printf("FAIL: moved allocation record is wrong\n");
        return 1;
    }
    printf("PASS: old record cleared, destination updated\n");

    printf("test: realloc-style update at the same address\n");
    ClearAllocation(record);
    RecordAllocation(target_address, 64);
    record = FindAllocation(target_address);
    if (record < 0 || allocations[record].size != 64 || allocations[record].reported) {
        printf("FAIL: in-place record update is wrong\n");
        return 1;
    }
    printf("PASS: in-place record updated\n");
    // fake pointers used for the direct record checks
    ClearAllocation(record);

    printf("test: free between Done and Init, then allocate again\n");
    if (MallocDebug_Init() != 0) return 1;
    void *old_block = malloc(80);
    if (old_block == NULL) { MallocDebug_Done(); return 1; }
    if (MallocDebug_Done() != 0) return 1;
    ULONG_PTR saved_address = (ULONG_PTR)old_block;
    free(old_block);

    if (MallocDebug_Init() != 0) return 1;
    void *new_block = malloc(80);
    if (new_block == NULL) { MallocDebug_Done(); return 1; }
    int reused = (ULONG_PTR)new_block == saved_address;
    int new_record = FindAllocation(new_block);
    if (new_record < 0) return 1;
    free(new_block);
    if (MallocDebug_Done() != 0) return 1;

    if (reused) {
        printf("PASS: reused address was tracked and freed\n");
        if (FindAllocation((void*)saved_address) >= 0) return 1;
    } else {
        printf("SKIP: heap did not reuse the address\n");
        // record can remain stale after a free outside monitoring
        int stale = FindAllocation((void*)saved_address);
        if (stale >= 0) ClearAllocation(stale);
    }
#endif

    printf("finished!\n");
    return 0;
}
#endif
