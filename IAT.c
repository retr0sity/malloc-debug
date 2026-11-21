
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#define MAX_PATCHES 64

#define MAX_ALLOCATIONS 1024

typedef struct allocation_record {
    void *address;
    size_t size;
    int active;
    int reported; // NEW: prevents repeat reports across Init/Done sessions
} allocation_record;

allocation_record allocations[MAX_ALLOCATIONS];

// NEW: Function declarations must come before the patches array
void *MallocDebug_malloc(size_t size);
void *MallocDebug_calloc(size_t count, size_t size);
void *MallocDebug_realloc(void *ptr, size_t size);
void MallocDebug_free(void *ptr);
int MallocDebug_Done(void); // NEW: Init can call Done to undo partial patching

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
int is_initialized = 0; // NEW: distinguishes a complete Init from partial patching

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

    // NEW: Save calloc's result so we can free it
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

void *MallocDebug_malloc(size_t size) {

    void *(*original)(size_t) =
        (void *(*)(size_t))patches[0].original_address;

    // Call the original malloc
    void *ptr = original(size);

    if (ptr == NULL) {
        return NULL;
    }

    // Find an unused allocation record
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {

        if (allocations[i].active == 0) {
            allocations[i].address = ptr;
            allocations[i].size = size;
            allocations[i].active = 1;
            allocations[i].reported = 0;

            return ptr;
        }
    }

    // Tracking array is full
    printf("Warning: allocation tracking array is full!\n");

    return ptr;
}

void *MallocDebug_calloc(size_t count, size_t size) {

    void *(*original)(size_t, size_t) =
        (void *(*)(size_t, size_t))patches[1].original_address;

    void *ptr = original(count, size);

    if (ptr == NULL) {
        return NULL;
    }

    for (int i = 0; i < MAX_ALLOCATIONS; i++) {

        if (allocations[i].active == 0) {
            allocations[i].address = ptr;
            allocations[i].size = count * size;
            allocations[i].active = 1;
            allocations[i].reported = 0;

            return ptr;
        }
    }

    printf("Warning: allocation tracking array is full!\n");

    return ptr;
}

void *MallocDebug_realloc(void *ptr, size_t size) {

    void *(*original)(void *, size_t) =
        (void *(*)(void *, size_t))patches[2].original_address;

    // realloc(NULL, size) behaves like malloc(size)
    if (ptr == NULL) {
        void *new_ptr = original(NULL, size);

        if (new_ptr != NULL) {
            int recorded = 0;
            for (int i = 0; i < MAX_ALLOCATIONS; i++) {
                if (!allocations[i].active) {
                    allocations[i].address = new_ptr;
                    allocations[i].size = size;
                    allocations[i].active = 1;
                    allocations[i].reported = 0;
                    recorded = 1;
                    break;
                }
            }
            if (!recorded) {
                printf("Warning: allocation tracking array is full!\n");
            }
        }

        return new_ptr;
    }

    // Find the existing allocation record
    int record_index = -1;

    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active &&
            allocations[i].address == ptr) {
            record_index = i;
            break;
        }
    }

    // Handle realloc(ptr, 0) separately
    if (size == 0) {
        void *result = original(ptr, 0);

        // UCRT frees ptr and returns NULL. Other CRTs may return a
        // non-NULL pointer representing a zero-size allocation.
        if (result == NULL) {
            if (record_index != -1) {
                allocations[record_index].active = 0;
                allocations[record_index].address = NULL;
                allocations[record_index].size = 0;
            } else {
                printf("Warning: reallocating untracked pointer %p\n", ptr);
            }
        } else if (record_index != -1) {
            allocations[record_index].address = result;
            allocations[record_index].size = 0;
            allocations[record_index].reported = 0;
        } else {
            printf("Warning: reallocating untracked pointer %p\n", ptr);
            int recorded = 0;
            for (int i = 0; i < MAX_ALLOCATIONS; i++) {
                if (!allocations[i].active) {
                    allocations[i].address = result;
                    allocations[i].size = 0;
                    allocations[i].active = 1;
                    allocations[i].reported = 0;
                    recorded = 1;
                    break;
                }
            }
            if (!recorded) {
                printf("Warning: allocation tracking array is full!\n");
            }
        }
        return result;
    }

    // Call original realloc
    void *new_ptr = original(ptr, size);

    // Failure: original allocation remains valid
    if (new_ptr == NULL) {
        return NULL;
    }

    if (record_index != -1) {
        // Update existing allocation record
        allocations[record_index].address = new_ptr;
        allocations[record_index].size = size;
        allocations[record_index].reported = 0;
    }
    else {
        // The original pointer was not tracked
        printf("Warning: reallocating untracked pointer %p\n", ptr);

        // Track the new allocation if possible
        int recorded = 0;
        for (int i = 0; i < MAX_ALLOCATIONS; i++) {
            if (!allocations[i].active) {
                allocations[i].address = new_ptr;
                allocations[i].size = size;
                allocations[i].active = 1;
                allocations[i].reported = 0;
                recorded = 1;
                break;
            }
        }
        if (!recorded) {
            printf("Warning: allocation tracking array is full!\n");
        }
    }

    return new_ptr;
}

void MallocDebug_free(void *ptr) {

    void (*original)(void *) =
        (void (*)(void *))patches[3].original_address;

    // free(NULL) is valid and does nothing
    if (ptr == NULL) {
        original(ptr);
        return;
    }

    // Search for the allocation record
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {

        if (allocations[i].active &&
            allocations[i].address == ptr) {

            // Mark the allocation as freed
            allocations[i].active = 0;
            allocations[i].address = NULL;
            allocations[i].size = 0;

            // Actually free the memory
            original(ptr);
            return;
        }
    }

    // Pointer was not found in our records
    printf("Warning: freeing untracked pointer %p\n", ptr);

    // Still call the original free to preserve its behavior
    original(ptr);
}

int MallocDebug_Init() {

    // NEW: A complete Init is safe to call again.
    if (is_initialized) {
        return 0;
    }

    // NEW: A previous failed restoration must be retried first.
    if (patch_count > 0) {
        printf("Cannot initialize: patched slots still need restoring\n");
        goto init_failed;
    }

    // MOVED FROM MAIN: Your existing PE parsing
    HMODULE hPEFile = GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER pDosHeader =
        (PIMAGE_DOS_HEADER)hPEFile;

    if (pDosHeader == NULL) {
        printf("Failed to get executable module\n");
        goto init_failed;
    }

    // NEW: Confirm that the executable headers are mapped and readable.
    // This gives us a safe upper limit for e_lfanew before using it.
    MEMORY_BASIC_INFORMATION memoryInfo;
    if (VirtualQuery(hPEFile, &memoryInfo, sizeof(memoryInfo)) == 0 ||
        memoryInfo.State != MEM_COMMIT ||
        memoryInfo.Type != MEM_IMAGE ||
        memoryInfo.AllocationBase != hPEFile ||
        (memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 ||
        memoryInfo.RegionSize < sizeof(IMAGE_DOS_HEADER)) {
        printf("Invalid or unreadable executable headers\n");
        goto init_failed;
    }

    // NEW: Check the DOS signature and the offset to the NT headers.
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        pDosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)) {
        printf("Invalid DOS header\n");
        goto init_failed;
    }

    // NEW: Check that the NT header fields we need fit in the mapped
    // header region BEFORE dereferencing pNTHeaders.
    size_t minOptionalSize =
        offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) +
        (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * sizeof(IMAGE_DATA_DIRECTORY);
    size_t minNTSize =
        offsetof(IMAGE_NT_HEADERS, OptionalHeader) + minOptionalSize;
    size_t ntOffset = (size_t)pDosHeader->e_lfanew;

    if (ntOffset > memoryInfo.RegionSize ||
        minNTSize > memoryInfo.RegionSize - ntOffset) {
        printf("NT headers extend beyond readable header region\n");
        goto init_failed;
    }

    PIMAGE_NT_HEADERS pNTHeaders =
        (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + ntOffset);

    // NEW: Validate header layout before reading the import directory.
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE ||
        pNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
        pNTHeaders->FileHeader.SizeOfOptionalHeader < minOptionalSize ||
        pNTHeaders->OptionalHeader.NumberOfRvaAndSizes <=
            IMAGE_DIRECTORY_ENTRY_IMPORT) {
        printf("Invalid or incompatible NT headers\n");
        goto init_failed;
    }

    DWORD imageSize = pNTHeaders->OptionalHeader.SizeOfImage;
    DWORD headersSize = pNTHeaders->OptionalHeader.SizeOfHeaders;

    // NEW: The NT headers must also fit in the file's declared headers.
    if (headersSize > imageSize || ntOffset > headersSize ||
        minNTSize > headersSize - ntOffset) {
        printf("Invalid PE header sizes\n");
        goto init_failed;
    }

    DWORD importRVA =
        pNTHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT
        ].VirtualAddress;

    DWORD importSize =
        pNTHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT
        ].Size;

    // Check whether the import directory exists
    if (importRVA == 0 || importSize == 0) {
        printf("No import directory found\n");
        goto init_failed;
    }

    // Check whether the directory fits inside the image
    if (importRVA >= imageSize ||
        importSize > imageSize - importRVA) {
        printf("Invalid import directory bounds\n");
        goto init_failed;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR)(
            ((BYTE*)pDosHeader) + importRVA
        );

    int functionCount = 0, dllCount = 0;

    // Only read complete descriptors within the declared directory
    size_t maxDescriptors =
        importSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    // Never read beyond the loaded image
    size_t availableDescriptors =
        (imageSize - importRVA) / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    if (maxDescriptors > availableDescriptors) {
        maxDescriptors = availableDescriptors;
    }

    printf("Import directory size: %lu\n", (unsigned long)importSize);
    printf("Maximum descriptors: %zu\n", maxDescriptors);
    printf("Descriptor size: %zu\n", sizeof(IMAGE_IMPORT_DESCRIPTOR));

    int foundEnd = 0;

    for (size_t d = 0; d < maxDescriptors; d++) {

        PIMAGE_IMPORT_DESCRIPTOR pCurrentDescriptor =
            &pImportDescriptor[d];

        printf("Descriptor %zu: OFT=%08lX, Name=%08lX, FT=%08lX\n",
       d,
       (unsigned long)pCurrentDescriptor->OriginalFirstThunk,
       (unsigned long)pCurrentDescriptor->Name,
       (unsigned long)pCurrentDescriptor->FirstThunk);

        if (pCurrentDescriptor->OriginalFirstThunk == 0 &&
        pCurrentDescriptor->TimeDateStamp == 0 &&
        pCurrentDescriptor->ForwarderChain == 0 &&
        pCurrentDescriptor->Name == 0 &&
        pCurrentDescriptor->FirstThunk == 0) {

        foundEnd = 1;
        break;
        }
    

    

        dllCount++;

        // NEW: Validate the DLL name before printing it
        DWORD dllNameRVA = pCurrentDescriptor->Name;
        if (dllNameRVA >= imageSize ||
            memchr((BYTE*)pDosHeader + dllNameRVA, '\0',
                   imageSize - dllNameRVA) == NULL) {
            printf("Invalid DLL name RVA or missing terminator\n");
            goto init_failed;
        }

        char *pName = (CHAR*)(dllNameRVA + (BYTE*)pDosHeader);

        printf("%s\n", pName);

        // NEW: Detect missing lookup tables
        if (pCurrentDescriptor->OriginalFirstThunk == 0 ||
            pCurrentDescriptor->FirstThunk == 0) {
            printf("Missing import thunk table\n");
            goto init_failed;
        }

        // NEW: Make sure both thunk arrays stay inside the image
        DWORD originalRVA = pCurrentDescriptor->OriginalFirstThunk;
        DWORD firstRVA = pCurrentDescriptor->FirstThunk;

        if (originalRVA >= imageSize || firstRVA >= imageSize) {
            printf("Invalid thunk table RVA\n");
            goto init_failed;
        }

        PIMAGE_THUNK_DATA pOriginalThunk =
            (PIMAGE_THUNK_DATA)(originalRVA + (BYTE*)pDosHeader);
        PIMAGE_THUNK_DATA pFirstThunk =
            (PIMAGE_THUNK_DATA)(firstRVA + (BYTE*)pDosHeader);

        size_t maxOriginalThunks =
            (imageSize - originalRVA) / sizeof(IMAGE_THUNK_DATA);
        size_t maxFirstThunks =
            (imageSize - firstRVA) / sizeof(IMAGE_THUNK_DATA);
        size_t maxThunks = maxOriginalThunks;
        if (maxFirstThunks < maxThunks) {
            maxThunks = maxFirstThunks;
        }

        size_t thunkCount = 0;
        int foundThunkEnd = 0;

        while (thunkCount < maxThunks)
        {
            if (pOriginalThunk->u1.AddressOfData == 0) {
                foundThunkEnd = 1;
                break;
            }

            if (pFirstThunk->u1.Function == 0) {
                printf("Invalid IAT entry: null function address\n");
                goto init_failed;
            }

            if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                printf("Ordinal: %u\n\n",
                    (unsigned)(pOriginalThunk->u1.Ordinal & 0xFFFF));
            }
            else {
                // NEW: Validate the name RVA and its null terminator
                ULONGLONG nameRVA = pOriginalThunk->u1.AddressOfData;
                if (nameRVA >= imageSize ||
                    imageSize - (DWORD)nameRVA <= sizeof(WORD)) {
                    printf("Invalid imported function name RVA\n");
                    goto init_failed;
                }

                PIMAGE_IMPORT_BY_NAME importName =
                    (PIMAGE_IMPORT_BY_NAME)(
                        (BYTE*)pDosHeader + (size_t)nameRVA
                    );

                size_t maxNameLength =
                    imageSize - (size_t)nameRVA - sizeof(WORD);
                if (memchr(importName->Name, '\0', maxNameLength) == NULL) {
                    printf("Unterminated imported function name\n");
                    goto init_failed;
                }

                for (int i = 0; i < 4; i++) {

                    if (strcmp(importName->Name,
                               patches[i].name) == 0) {

                        void **slot =
                            (void**)&pFirstThunk->u1.Function;

                        void *current_address = *slot;

                        // NEW: Avoid patching the same slot twice
                        if (current_address ==
                            patches[i].patched_address) {
                            continue;
                        }

                        // NEW: One shared wrapper has only one original
                        // function pointer. Different implementations with
                        // the same name cannot safely share that wrapper.
                        // Abort and roll back rather than call the wrong CRT.
                        if (patches[i].original_address != NULL &&
                            patches[i].original_address != current_address) {
                            printf("Incompatible duplicate import of %s: "
                                   "original addresses differ\n",
                                   patches[i].name);
                            goto init_failed;
                        }

                        // NEW: Prevent array overflow
                        if (patch_count >= MAX_PATCHES) {
                            printf("Error: patch record array is full!\n");
                            goto init_failed;
                        }

                        // NEW: Unlock this IAT slot for writing
                        DWORD oldProtect;

                        if (!VirtualProtect(
                                slot,
                                sizeof(void*),
                                PAGE_READWRITE,
                                &oldProtect)) {

                            printf("Failed to change memory protection for %s\n",
                                   patches[i].name);
                            goto init_failed;
                        }

                        // NEW: Save the original function address
                        if (patches[i].original_address == NULL) {
                            patches[i].original_address =
                                current_address;
                        }

                        // NEW: Record this particular IAT slot
                        patch_records[patch_count].iat_slot = slot;
                        patch_records[patch_count].original_address =
                            current_address;

                        // NEW: Actually patch the IAT slot
                        *slot = patches[i].patched_address;

                        // NEW: Count it immediately after patching
                        patch_count++;

                        // Restore original memory protection
                        DWORD tempProtect;

                        if (!VirtualProtect(
                                slot,
                                sizeof(void*),
                                oldProtect,
                                &tempProtect)) {

                            printf("Failed to restore memory protection for %s (Error: %lu)\n",
                                patches[i].name, (unsigned long)GetLastError());
                            goto init_failed;
                        }

#ifdef TEST_INIT_ROLLBACK
                        // Test-only: fail only AFTER restoring page protection.
                        if (patch_count == 2) {
                            printf("TEST: forcing Init failure after two patches\n");
                            goto init_failed;
                        }
#endif

                        printf("\nPatched %s:\n"
                               "IAT slot: %p\n"
                               "Original: %p\n"
                               "Wrapper: %p\n\n",
                               patches[i].name,
                               (void*)slot,
                               current_address,
                               patches[i].patched_address);
                    }
                }
            }

            pOriginalThunk++;
            pFirstThunk++;
            functionCount++;
            thunkCount++;
        }

        // NEW: Report a missing terminator instead of reading past the image
        if (!foundThunkEnd) {
            printf("Malformed thunk table: missing terminator\n");
            goto init_failed;
        }
    }

    if (!foundEnd) {
        printf("Malformed import directory: missing terminator\n");
        goto init_failed;
    }

    printf("DOS Header: %p\n", (void*)pDosHeader);
    printf("NT Headers: %p\n", (void*)pNTHeaders);
    printf("DLL Count: %d\n", dllCount);
    printf("Function count: %d\n", functionCount);
    printf("Patch count: %d\n", patch_count);

    is_initialized = 1; // NEW: all imports have been examined successfully
    return 0;

init_failed:
    // NEW: Undo slots patched earlier in this Init call.
    if (patch_count > 0) {
        printf("Init failed; attempting to restore %d patched slots\n", patch_count);
        if (MallocDebug_Done() != 0) {
            printf("Warning: some IAT slots could not be restored\n");
        }
    }
    return 1;
}

// NEW: Restore the original IAT entries
int MallocDebug_Done() {

    if (patch_count == 0) {
        is_initialized = 0;
        return 0;
    }

    int failed = 0;
    int remaining = 0;

    for (int i = 0; i < patch_count; i++) {

        void **slot = patch_records[i].iat_slot;
        void *original_address =
            patch_records[i].original_address;

#ifdef TEST_DONE_RETRY
        // TEST ONLY: simulate one slot that could not be restored.
        // The following Done call must retry the saved record.
        static int skipped_once = 0;
        if (!skipped_once) {
            skipped_once = 1;
            printf("TEST: simulating one failed slot restoration\n");
            patch_records[remaining++] = patch_records[i];
            failed = 1;
            continue;
        }
#endif

        DWORD oldProtect;

        if (!VirtualProtect(
                slot,
                sizeof(void*),
                PAGE_READWRITE,
                &oldProtect)) {

            printf("Failed to unlock IAT slot %p\n", (void*)slot);

            // Keep this patch record, so Done can retry later.
            patch_records[remaining] = patch_records[i];
            remaining++;
            failed = 1;
            continue;
        }

        // Restore the original address.
        *slot = original_address;

        DWORD tempProtect;

        if (!VirtualProtect(
                slot,
                sizeof(void*),
                oldProtect,
                &tempProtect)) {

            printf("Failed to restore memory protection\n");
            failed = 1;
        }

        printf("Restored IAT slot %p\n", (void*)slot);
    }

    patch_count = remaining;

    // NEW: Report leaks and end monitoring only when ALL IAT slots
    // have been restored. A partial failure keeps records for retry.
    if (patch_count == 0) {

        if (is_initialized) {
            printf("\nChecking for memory leaks...\n");

            int leak_count = 0;
            int previously_reported = 0;
            size_t leaked_bytes = 0;

            for (int i = 0; i < MAX_ALLOCATIONS; i++) {
                if (allocations[i].active && allocations[i].reported) {
                    previously_reported++;
                }
                if (allocations[i].active && !allocations[i].reported) {
                    printf("Memory leak: %p (%zu bytes)\n",
                           allocations[i].address,
                           allocations[i].size);

                    leak_count++;
                    leaked_bytes += allocations[i].size;

                    // Keep the live allocation record: it may be freed in
                    // a later monitoring session. Report it only once.
                    allocations[i].reported = 1;
                }
            }

            if (leak_count == 0 && previously_reported == 0) {
                printf("No memory leaks detected.\n");
            } else {
                printf("New leaks: %d blocks, %zu bytes\n",
                       leak_count, leaked_bytes);
                if (previously_reported > 0) {
                    printf("Previously reported blocks still live: %d\n",
                           previously_reported);
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

    // Keep your original imports test
    if (imports() != 0) {
        return 1;
    }

    // NEW: Init now performs searching AND patching
    if (MallocDebug_Init() != 0) {
        printf("Initialization failed\n");
        MallocDebug_Done();
        return 1;
    }

    printf("\nTEST: realloc(NULL, 100)\n");

void *p = realloc(NULL, 100);

if (p != NULL) {
    printf("Allocation succeeded: %p\n", p);
    free(p);
}

printf("\nTEST: realloc(ptr, 0)\n");

void *q = malloc(100);

if (q != NULL) {
    void *result = realloc(q, 0);

    printf("realloc(ptr, 0) returned: %p\n", result);

    // Under the MSVC CRT, q has been freed.
    // Do not free q again.
}

#ifdef TEST_ALLOC_EDGES
    // TEST ONLY: verify failed realloc preserves the old allocation.
    printf("\nTEST: failed realloc preserves original allocation\n");
    void *keep = malloc(64);
    if (keep != NULL) {
        volatile size_t huge = (size_t)-1;
        void *resized = realloc(keep, huge);
        if (resized == NULL) {
            int stillTracked = 0;
            for (int i = 0; i < MAX_ALLOCATIONS; i++) {
                if (allocations[i].active && allocations[i].address == keep &&
                    allocations[i].size == 64) {
                    stillTracked = 1;
                    break;
                }
            }
            printf("Failed realloc kept original record: %s\n",
                   stillTracked ? "YES" : "NO");
            free(keep);
        } else {
            printf("Unexpected: very large realloc succeeded\n");
            free(resized);
        }
    }

    // TEST ONLY: fill the fixed-size record array and exceed capacity once.
    printf("\nTEST: full allocation tracking array\n");
    void *blocks[MAX_ALLOCATIONS + 1] = {0};
    for (int i = 0; i < MAX_ALLOCATIONS + 1; i++) {
        blocks[i] = malloc(1);
    }
    for (int i = 0; i < MAX_ALLOCATIONS + 1; i++) {
        free(blocks[i]);
    }
    printf("Full-array test finished (expected: one full-array warning,\n"
           "and one untracked-free warning).\n");
#endif

#ifdef TEST_CROSS_SESSION
    // TEST ONLY: report this leak once, then free it after reinitializing.
    void *carry = malloc(48);
#endif

    // NEW: Restore original IAT entries
#ifdef TEST_DONE_RETRY
    printf("\nTEST: first Done should fail and keep one patch record\n");
    if (MallocDebug_Done() == 0 || patch_count != 1) {
        printf("TEST FAILED: expected one saved patch record\n");
        return 1;
    }
    printf("TEST: retrying Done for the remaining slot\n");
#endif
    if (MallocDebug_Done() != 0) {
        printf("Restoration failed\n");
        return 1;
    }

#ifdef TEST_CROSS_SESSION
    printf("\nTEST: free previously reported allocation after reinitializing\n");
    if (MallocDebug_Init() != 0) return 1;
    free(carry); // Must NOT be reported as untracked.
    if (MallocDebug_Done() != 0) return 1;
#endif

#ifdef TEST_REPEATED_CALLS
    printf("\nTEST: Done again without Init\n");
    if (MallocDebug_Done() != 0) return 1;

    printf("\nTEST: Init twice, allocate, then Done twice\n");
    if (MallocDebug_Init() != 0 || MallocDebug_Init() != 0) return 1;
    void *again = malloc(24);
    free(again);
    if (MallocDebug_Done() != 0 || MallocDebug_Done() != 0) return 1;
#endif

    printf("Finished successfully\n");

    return 0;
}
