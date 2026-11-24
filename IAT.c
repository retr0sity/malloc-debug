#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#define MAX_PATCHES 64
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

allocation_record allocations[MAX_ALLOCATIONS];

void *MallocDebug_malloc(size_t size);
void *MallocDebug_calloc(size_t count, size_t size);
void *MallocDebug_realloc(void *ptr, size_t size);
void MallocDebug_free(void *ptr);
int MallocDebug_Done(void);

typedef struct memalloc_patch {
    char *name;
    void *original_address;
    void *patched_address;
} memalloc_patch;

typedef struct patch_record {
    void **iat_slot;
    void *original_address;
} patch_record;

patch_record patch_records[MAX_PATCHES];
int patch_count = 0;
int is_initialized = 0;
int restore_pending = 0;

memalloc_patch patches[4] = {
    {"malloc", NULL, (void*)MallocDebug_malloc},
    {"calloc", NULL, (void*)MallocDebug_calloc},
    {"realloc", NULL, (void*)MallocDebug_realloc},
    {"free", NULL, (void*)MallocDebug_free}
};

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

static void RecordAllocation(void *address, size_t size) {
    int record_index = -1;
    int free_index = -1;

    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == address) {
            if (record_index == -1) {
                record_index = i;
            } else {
                allocations[i].active = 0;
                allocations[i].address = NULL;
                allocations[i].size = 0;
                allocations[i].reported = 0;
            }
        } else if (!allocations[i].active && free_index == -1) {
            free_index = i;
        }
    }

    if (record_index == -1) {
        record_index = free_index;
    }
    if (record_index == -1) {
        printf("warning: allocation tracking array is full!\n");
        return;
    }

    allocations[record_index].address = address;
    allocations[record_index].size = size;
    allocations[record_index].active = 1;
    allocations[record_index].reported = 0;
}

static void UpdateReallocationRecord(void *old_address, void *new_address, size_t size) {
    int found = 0;

    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == old_address) {
            allocations[i].active = 0;
            allocations[i].address = NULL;
            allocations[i].size = 0;
            allocations[i].reported = 0;
            found = 1;
        }
    }

    if (!found) {
        printf("warning: reallocating untracked pointer %p\n", old_address);
    }
    if (new_address != NULL) {
        RecordAllocation(new_address, size);
    }
}

void *MallocDebug_malloc(size_t size) {

    void *(*original)(size_t) = (void *(*)(size_t))patches[0].original_address;
    void *ptr = original(size);

    if (ptr != NULL) {
        RecordAllocation(ptr, size);
    }
    return ptr;
}

void *MallocDebug_calloc(size_t count, size_t size) {

    void *(*original)(size_t, size_t) = (void *(*)(size_t, size_t))patches[1].original_address;
    void *ptr = original(count, size);

    if (ptr != NULL) {
        RecordAllocation(ptr, count * size);
    }
    return ptr;
}

void *MallocDebug_realloc(void *ptr, size_t size) {

    void *(*original)(void *, size_t) = (void *(*)(void *, size_t))patches[2].original_address;

    if (ptr == NULL) {
        void *new_ptr = original(NULL, size);
        if (new_ptr != NULL) {
            RecordAllocation(new_ptr, size);
        }
        return new_ptr;
    }

    void *new_ptr = original(ptr, size);

    // A failed nonzero-size realloc leaves ptr allocated.
    if (size != 0 && new_ptr == NULL) {
        return NULL;
    }

    // UCRT frees ptr for realloc(ptr, 0), returning NULL.
    UpdateReallocationRecord(ptr, new_ptr, size);
    return new_ptr;
}

void MallocDebug_free(void *ptr) {

    void (*original)(void *) = (void (*)(void *))patches[3].original_address;

    if (ptr == NULL) {
        original(ptr);
        return;
    }

    for (int i = 0; i < MAX_ALLOCATIONS; i++) {

        if (allocations[i].active && allocations[i].address == ptr) {
            allocations[i].active = 0;
            allocations[i].address = NULL;
            allocations[i].size = 0;
            original(ptr);
            return;
        }
    }

    printf("warning: freeing untracked pointer %p (may have been allocated before Init)\n", ptr);
    original(ptr);
}

int MallocDebug_Init() {

    if (restore_pending) {
        printf("cannot initialize: previous restoration incomplete; call Done again\n");
        return 1;
    }
    if (is_initialized) {
        return 0;
    }

    if (patch_count > 0) {
        printf("cannot initialize: patched slots still need restoring\n");
        goto init_failed;
    }

    HMODULE hPEFile = GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;

    if (pDosHeader == NULL) {
        printf("failed to get executable module\n");
        goto init_failed;
    }

    MEMORY_BASIC_INFORMATION memoryInfo;
    if (VirtualQuery(hPEFile, &memoryInfo, sizeof(memoryInfo)) == 0 || memoryInfo.State != MEM_COMMIT || memoryInfo.Type != MEM_IMAGE || memoryInfo.AllocationBase != hPEFile || (memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 || memoryInfo.RegionSize < sizeof(IMAGE_DOS_HEADER)) {
        printf("invalid or unreadable executable headers\n");
        goto init_failed;
    }

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pDosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)) {
        printf("invalid dos header\n");
        goto init_failed;
    }

    size_t minOptionalSize = offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * sizeof(IMAGE_DATA_DIRECTORY);
    size_t minNTSize = offsetof(IMAGE_NT_HEADERS, OptionalHeader) + minOptionalSize;
    size_t ntOffset = (size_t)pDosHeader->e_lfanew;

    if (ntOffset > memoryInfo.RegionSize || minNTSize > memoryInfo.RegionSize - ntOffset) {
        printf("nt headers extend beyond readable header region\n");
        goto init_failed;
    }

    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + ntOffset);

    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE || pNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC || pNTHeaders->FileHeader.SizeOfOptionalHeader < minOptionalSize || pNTHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
        printf("invalid or incompatible nt headers\n");
        goto init_failed;
    }

    DWORD imageSize = pNTHeaders->OptionalHeader.SizeOfImage;
    DWORD headersSize = pNTHeaders->OptionalHeader.SizeOfHeaders;

    if (headersSize > imageSize || ntOffset > headersSize || minNTSize > headersSize - ntOffset) {
        printf("invalid pe header sizes\n");
        goto init_failed;
    }

    DWORD importRVA = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    DWORD importSize = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (importRVA == 0) {
        printf("no import directory found\n");
        goto init_failed;
    }

    // Import descriptors end with an all-zero entry. Directory Size is not reliable.
    if (importRVA >= imageSize ||
        imageSize - importRVA < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        printf("invalid import directory rva\n");
        goto init_failed;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + importRVA);

    int functionCount = 0, dllCount = 0;

    size_t maxDescriptors = (imageSize - importRVA) / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    DEBUG_PRINT("import directory size: %lu\n", (unsigned long)importSize);
    DEBUG_PRINT("maximum descriptors: %zu\n", maxDescriptors);
    DEBUG_PRINT("descriptor size: %zu\n", sizeof(IMAGE_IMPORT_DESCRIPTOR));

    int foundEnd = 0;

    for (size_t d = 0; d < maxDescriptors; d++) {

        PIMAGE_IMPORT_DESCRIPTOR pCurrentDescriptor = &pImportDescriptor[d];

        DEBUG_PRINT("descriptor %zu: oft=%08lX, name=%08lX, ft=%08lX\n", d, (unsigned long)pCurrentDescriptor->OriginalFirstThunk, (unsigned long)pCurrentDescriptor->Name, (unsigned long)pCurrentDescriptor->FirstThunk);

        if (pCurrentDescriptor->OriginalFirstThunk == 0 && pCurrentDescriptor->TimeDateStamp == 0 && pCurrentDescriptor->ForwarderChain == 0 && pCurrentDescriptor->Name == 0 && pCurrentDescriptor->FirstThunk == 0) {

            foundEnd = 1;
            break;
        }

        dllCount++;

        DWORD dllNameRVA = pCurrentDescriptor->Name;
        if (dllNameRVA >= imageSize || memchr((BYTE*)pDosHeader + dllNameRVA, '\0', imageSize - dllNameRVA) == NULL) {
            printf("invalid dll name rva or missing terminator\n");
            goto init_failed;
        }

        char *pName = (CHAR*)(dllNameRVA + (BYTE*)pDosHeader);

        DEBUG_PRINT("%s\n", pName);

        if (pCurrentDescriptor->OriginalFirstThunk == 0 || pCurrentDescriptor->FirstThunk == 0) {
            printf("missing import thunk table\n");
            goto init_failed;
        }

        DWORD originalRVA = pCurrentDescriptor->OriginalFirstThunk;
        DWORD firstRVA = pCurrentDescriptor->FirstThunk;

        if (originalRVA >= imageSize || firstRVA >= imageSize) {
            printf("invalid thunk table rva\n");
            goto init_failed;
        }

        PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(originalRVA + (BYTE*)pDosHeader);
        PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(firstRVA + (BYTE*)pDosHeader);

        size_t maxOriginalThunks = (imageSize - originalRVA) / sizeof(IMAGE_THUNK_DATA);
        size_t maxFirstThunks = (imageSize - firstRVA) / sizeof(IMAGE_THUNK_DATA);
        size_t maxThunks = maxOriginalThunks;
        if (maxFirstThunks < maxThunks) {
            maxThunks = maxFirstThunks;
        }

        size_t thunkCount = 0;
        int foundThunkEnd = 0;

        while (thunkCount < maxThunks) {

            if (pOriginalThunk->u1.AddressOfData == 0) {
                foundThunkEnd = 1;
                break;
            }

            if (pFirstThunk->u1.Function == 0) {
                printf("invalid iat entry: null function address\n");
                goto init_failed;
            }

            if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                DEBUG_PRINT("ordinal: %u\n\n", (unsigned)(pOriginalThunk->u1.Ordinal & 0xFFFF));
            }
            else {
                ULONGLONG nameRVA = pOriginalThunk->u1.AddressOfData;
                if (nameRVA >= imageSize || imageSize - (DWORD)nameRVA <= sizeof(WORD)) {
                    printf("invalid imported function name rva\n");
                    goto init_failed;
                }

                PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + (size_t)nameRVA);

                size_t maxNameLength = imageSize - (size_t)nameRVA - sizeof(WORD);
                if (memchr(importName->Name, '\0', maxNameLength) == NULL) {
                    printf("unterminated imported function name\n");
                    goto init_failed;
                }

                for (int i = 0; i < 4; i++) {

                    if (strcmp(importName->Name, patches[i].name) == 0) {

                        void **slot = (void**)&pFirstThunk->u1.Function;

                        void *current_address = *slot;

                        if (current_address == patches[i].patched_address) {
                            continue;
                        }

                        // Different original addresses cannot share one wrapper.
                        if (patches[i].original_address != NULL && patches[i].original_address != current_address) {
                            printf("incompatible duplicate import of %s: original addresses differ\n", patches[i].name);
                            goto init_failed;
                        }

                        if (patch_count >= MAX_PATCHES) {
                            printf("error: patch record array is full!\n");
                            goto init_failed;
                        }

                        DWORD oldProtect;

                        if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {

                            printf("failed to change memory protection for %s\n", patches[i].name);
                            goto init_failed;
                        }

                        if (patches[i].original_address == NULL) {
                            patches[i].original_address = current_address;
                        }

                        patch_records[patch_count].iat_slot = slot;
                        patch_records[patch_count].original_address = current_address;

                        *slot = patches[i].patched_address;

                        // Record this patch before operations that can fail.
                        patch_count++;

                        DWORD tempProtect;

                        if (!VirtualProtect(slot, sizeof(void*), oldProtect, &tempProtect)) {

                            printf("failed to restore memory protection for %s (error: %lu)\n", patches[i].name, (unsigned long)GetLastError());
                            goto init_failed;
                        }

#ifdef TEST_INIT_ROLLBACK
                        if (patch_count == 2) {
                            printf("test: forcing init failure after two patches\n");
                            goto init_failed;
                        }
#endif

                        DEBUG_PRINT("\npatched %s:\niat slot: %p\noriginal: %p\nwrapper: %p\n\n", patches[i].name, (void*)slot, current_address, patches[i].patched_address);
                    }
                }
            }

            pOriginalThunk++;
            pFirstThunk++;
            functionCount++;
            thunkCount++;
        }

        if (!foundThunkEnd) {
            printf("malformed thunk table: missing terminator\n");
            goto init_failed;
        }
    }

    if (!foundEnd) {
        printf("malformed import directory: missing terminator\n");
        goto init_failed;
    }

    DEBUG_PRINT("dos header: %p\n", (void*)pDosHeader);
    DEBUG_PRINT("nt headers: %p\n", (void*)pNTHeaders);
    DEBUG_PRINT("dll count: %d\n", dllCount);
    DEBUG_PRINT("function count: %d\n", functionCount);
    DEBUG_PRINT("patch count: %d\n", patch_count);

    is_initialized = 1;
    return 0;

init_failed:
    if (patch_count > 0) {
        printf("init failed; attempting to restore %d patched slots\n", patch_count);
        if (MallocDebug_Done() != 0) {
            printf("warning: some iat slots could not be restored\n");
        }
    }
    return 1;
}

int MallocDebug_Done() {

    if (patch_count == 0) {
        is_initialized = 0;
        return 0;
    }

    int failed = 0;
    int remaining = 0;

    for (int i = 0; i < patch_count; i++) {

        void **slot = patch_records[i].iat_slot;
        void *original_address = patch_records[i].original_address;

#ifdef TEST_DONE_RETRY
        static int skipped_once = 0;
        if (!skipped_once) {
            skipped_once = 1;
            printf("test: simulating one failed slot restoration\n");
            patch_records[remaining++] = patch_records[i];
            failed = 1;
            continue;
        }
#endif

        DWORD oldProtect;

        if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {

            printf("failed to unlock iat slot %p\n", (void*)slot);

            patch_records[remaining] = patch_records[i];
            remaining++;
            failed = 1;
            continue;
        }

        *slot = original_address;

        DWORD tempProtect;

        if (!VirtualProtect(slot, sizeof(void*), oldProtect, &tempProtect)) {
            printf("slot %p restored, but failed to restore page protection\n", (void*)slot);
            failed = 1;
        } else {
            DEBUG_PRINT("restored iat slot %p\n", (void*)slot);
        }
    }

    patch_count = remaining;
    restore_pending = (remaining > 0);

    if (patch_count == 0) {

        if (is_initialized) {
            printf("\nchecking for memory leaks\n");

            int leak_count = 0;
            int previously_reported = 0;
            size_t leaked_bytes = 0;

            for (int i = 0; i < MAX_ALLOCATIONS; i++) {
                if (allocations[i].active && allocations[i].reported) {
                    previously_reported++;
                }
                if (allocations[i].active && !allocations[i].reported) {
                    printf("memory leak: %p (%zu bytes)\n", allocations[i].address, allocations[i].size);

                    leak_count++;
                    leaked_bytes += allocations[i].size;

                    // Keep it available for a later free.
                    allocations[i].reported = 1;
                }
            }

            if (leak_count == 0 && previously_reported == 0) {
                printf("no memory leaks detected.\n");
            } else {
                printf("new leaks: %d blocks, %zu bytes\n", leak_count, leaked_bytes);
                if (previously_reported > 0) {
                    printf("previously reported blocks still live: %d\n", previously_reported);
                }
            }
        }

        is_initialized = 0;

        for (int i = 0; i < 4; i++) {
            patches[i].original_address = NULL;
        }
    }

    return failed ? 1 : 0;
}

int main() {

    if (imports() != 0) {
        return 1;
    }

    if (MallocDebug_Init() != 0) {
        printf("initialization failed\n");
        MallocDebug_Done();
        return 1;
    }

    printf("\ntest: realloc(null, 100)\n");

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
        if (result != NULL) {
            free(result);
        }
        // Do not free q after realloc(q, 0) on UCRT.
    }

#ifdef TEST_ALLOC_EDGES
    printf("\ntest: failed realloc preserves original allocation\n");
    void *keep = malloc(64);
    if (keep != NULL) {
        volatile size_t huge = (size_t)-1;
        void *resized = realloc(keep, huge);
        if (resized == NULL) {
            int stillTracked = 0;
            for (int i = 0; i < MAX_ALLOCATIONS; i++) {
                if (allocations[i].active && allocations[i].address == keep && allocations[i].size == 64) {
                    stillTracked = 1;
                    break;
                }
            }
            printf("failed realloc kept original record: %s\n", stillTracked ? "yes" : "no");
            free(keep);
        } else {
            printf("unexpected: very large realloc succeeded\n");
            free(resized);
        }
    }

    printf("\ntest: full allocation tracking array\n");
    void *blocks[MAX_ALLOCATIONS + 1] = {0};
    for (int i = 0; i < MAX_ALLOCATIONS + 1; i++) {
        blocks[i] = malloc(1);
    }
    for (int i = 0; i < MAX_ALLOCATIONS + 1; i++) {
        free(blocks[i]);
    }
    printf("full array test finished (expected: one full array warning and one untracked free warning).\n");
#endif

#ifdef TEST_CROSS_SESSION
    void *carry = malloc(48);
#endif

#ifdef TEST_DONE_RETRY
    printf("\ntest: first done should fail and keep one patch record\n");
    if (MallocDebug_Done() == 0 || patch_count != 1) {
        printf("test failed: expected one saved patch record\n");
        return 1;
    }
    printf("test: retrying done for the remaining slot\n");
#endif
    if (MallocDebug_Done() != 0) {
        printf("restoration failed\n");
        return 1;
    }

#ifdef TEST_CROSS_SESSION
    printf("\ntest: free previously reported allocation after reinitializing\n");
    if (MallocDebug_Init() != 0) return 1;
    free(carry);
    if (MallocDebug_Done() != 0) return 1;
#endif

#ifdef TEST_REPEATED_CALLS
    printf("\ntest: done again without init\n");
    if (MallocDebug_Done() != 0) return 1;

    printf("\ntest: init twice, allocate, then done twice\n");
    if (MallocDebug_Init() != 0 || MallocDebug_Init() != 0) return 1;
    void *again = malloc(24);
    free(again);
    if (MallocDebug_Done() != 0 || MallocDebug_Done() != 0) return 1;
#endif

#ifdef TEST_STALE_RECORDS
    printf("\ntest: replace stale record at reused address\n");
    void *old_address = (void*)&patch_count;
    void *target_address = (void*)&is_initialized;

    RecordAllocation(target_address, 11);
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == target_address) {
            allocations[i].reported = 1;
        }
    }
    RecordAllocation(target_address, 22);

    int direct_matches = 0;
    int direct_updated = 0;
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == target_address) {
            direct_matches++;
            direct_updated = (allocations[i].size == 22 && !allocations[i].reported);
        }
    }
    if (direct_matches != 1 || !direct_updated) {
        printf("FAIL: stale record was not replaced\n");
        return 1;
    }
    printf("PASS: one record, updated size, reported flag reset\n");

    printf("test: realloc moving to an address with a stale record\n");
    RecordAllocation(old_address, 32);
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == target_address) {
            allocations[i].reported = 1;
        }
    }
    UpdateReallocationRecord(old_address, target_address, 96);

    int target_matches = 0;
    int old_matches = 0;
    int moved_updated = 0;
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == old_address) {
            old_matches++;
        }
        if (allocations[i].active && allocations[i].address == target_address) {
            target_matches++;
            moved_updated = (allocations[i].size == 96 && !allocations[i].reported);
        }
    }
    if (old_matches != 0 || target_matches != 1 || !moved_updated) {
        printf("FAIL: realloc destination has incorrect records\n");
        return 1;
    }
    printf("PASS: realloc removed the old record and replaced the stale destination\n");

    printf("test: realloc keeping the same address\n");
    UpdateReallocationRecord(target_address, target_address, 64);
    int inplace_matches = 0;
    int inplace_updated = 0;
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == target_address) {
            inplace_matches++;
            inplace_updated = (allocations[i].size == 64 && !allocations[i].reported);
        }
    }
    if (inplace_matches != 1 || !inplace_updated) {
        printf("FAIL: in-place realloc record is wrong\n");
        return 1;
    }
    printf("PASS: in-place realloc has exactly one updated record\n");

    // The two addresses above are globals, not real heap allocations.
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == target_address) {
            allocations[i].active = 0;
            allocations[i].address = NULL;
            allocations[i].size = 0;
            allocations[i].reported = 0;
        }
    }

    printf("test: free between Done and Init, then allocate again\n");
    if (MallocDebug_Init() != 0) return 1;
    void *old_block = malloc(80);
    if (old_block == NULL) { MallocDebug_Done(); return 1; }
    if (MallocDebug_Done() != 0) return 1;
    void *saved_address = old_block;
    free(old_block);

    if (MallocDebug_Init() != 0) return 1;
    void *new_block = malloc(80);
    if (new_block == NULL) { MallocDebug_Done(); return 1; }

    int reused = (new_block == saved_address);
    int count_for_new = 0;
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active && allocations[i].address == new_block) {
            count_for_new++;
        }
    }
    free(new_block);
    if (MallocDebug_Done() != 0) return 1;

    int remaining_records = 0;
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active) remaining_records++;
    }

    if (reused) {
        printf("address reused: YES\n");
        if (count_for_new != 1 || remaining_records != 0) {
            printf("FAIL: duplicate or stale records survived\n");
            return 1;
        }
        printf("PASS: one record during allocation, zero after final done\n");
    } else {
        printf("NOPE: heap did not reuse the address\n");
        printf("the direct helper checks are valid\n");
        return 2;
    }
#endif

    printf("finished!\n");
    return 0;
}