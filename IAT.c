
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATCHES 64

#define MAX_ALLOCATIONS 1024

typedef struct allocation_record {
    void *address;
    size_t size;
    int active;
} allocation_record;

allocation_record allocations[MAX_ALLOCATIONS];
int allocation_count = 0;

// NEW: Function declarations must come before the patches array
void *MallocDebug_malloc(size_t size);
void *MallocDebug_calloc(size_t count, size_t size);
void *MallocDebug_realloc(void *ptr, size_t size);
void MallocDebug_free(void *ptr);

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
            for (int i = 0; i < MAX_ALLOCATIONS; i++) {
                if (!allocations[i].active) {
                    allocations[i].address = new_ptr;
                    allocations[i].size = size;
                    allocations[i].active = 1;
                    break;
                }
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

        // On the MSVC CRT, realloc(ptr, 0) frees ptr.
        if (record_index != -1) {
            allocations[record_index].active = 0;
            allocations[record_index].address = NULL;
            allocations[record_index].size = 0;
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
    }
    else {
        // The original pointer was not tracked
        printf("Warning: reallocating untracked pointer %p\n", ptr);

        // Track the new allocation if possible
        for (int i = 0; i < MAX_ALLOCATIONS; i++) {
            if (!allocations[i].active) {
                allocations[i].address = new_ptr;
                allocations[i].size = size;
                allocations[i].active = 1;
                break;
            }
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

    // NEW: Do nothing if already initialized
    if (patch_count > 0) {
        return 0;
    }

    // MOVED FROM MAIN: Your existing PE parsing
    HMODULE hPEFile = GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER pDosHeader =
        (PIMAGE_DOS_HEADER)hPEFile;

    // NEW: Basic header checks
    if (pDosHeader == NULL ||
        pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        pDosHeader->e_lfanew < 0) {
        printf("Invalid DOS header\n");
        return 1;
    }

    PIMAGE_NT_HEADERS pNTHeaders =
        (PIMAGE_NT_HEADERS)(
            ((BYTE*)pDosHeader) + pDosHeader->e_lfanew
        );

    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT headers\n");
        return 1;
    }

    DWORD importRVA =
    pNTHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT
    ].VirtualAddress;

    DWORD importSize =
        pNTHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT
        ].Size;

    DWORD imageSize = pNTHeaders->OptionalHeader.SizeOfImage;

    // Check whether the import directory exists
    if (importRVA == 0 || importSize == 0) {
        printf("No import directory found\n");
        return 1;
    }

    // Check whether the directory fits inside the image
    if (importRVA >= imageSize ||
        importSize > imageSize - importRVA) {
        printf("Invalid import directory bounds\n");
        return 1;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR)(
            ((BYTE*)pDosHeader) + importRVA
        );

    int functionCount = 0, dllCount = 0;

    // NEW: Maximum number of descriptors within the directory
    // Allow space for a possible terminator after the declared size
    size_t maxDescriptors =
        (importSize / sizeof(IMAGE_IMPORT_DESCRIPTOR)) + 1;

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

        char *pName = (CHAR*)(pCurrentDescriptor->Name + (BYTE*)pDosHeader);

        printf("%s\n", pName);

        // NEW: Detect missing lookup tables
        if (pCurrentDescriptor->OriginalFirstThunk == 0 ||
            pCurrentDescriptor->FirstThunk == 0) {
            printf("Missing import thunk table\n");
            return 1;
        }

        PIMAGE_THUNK_DATA pOriginalThunk =
            (PIMAGE_THUNK_DATA)(
                pCurrentDescriptor->OriginalFirstThunk +
                (BYTE*)pDosHeader
            );

        PIMAGE_THUNK_DATA pFirstThunk =
            (PIMAGE_THUNK_DATA)(
                pCurrentDescriptor->FirstThunk +
                (BYTE*)pDosHeader
            );

        while (pOriginalThunk->u1.AddressOfData != 0)
        {
            if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                printf("Ordinal: %u\n\n",
                    (unsigned)(pOriginalThunk->u1.Ordinal & 0xFFFF));
            }
            else {
                PIMAGE_IMPORT_BY_NAME importName =
                    (PIMAGE_IMPORT_BY_NAME)(
                        pOriginalThunk->u1.AddressOfData +
                        (BYTE*)pDosHeader
                    );

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

                        // NEW: Prevent array overflow
                        if (patch_count >= MAX_PATCHES) {
                            printf("Error: patch record array is full!\n");
                            return 1;
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
                            return 1;
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
                                patches[i].name, GetLastError());
                            return 2;
                        }

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
        }
    }

    if (!foundEnd) {
        printf("Malformed import directory: missing terminator\n");
        return 1;
    }

    printf("DOS Header: %p\n", (void*)pDosHeader);
    printf("NT Headers: %p\n", (void*)pNTHeaders);
    printf("DLL Count: %d\n", dllCount);
    printf("Function count: %d\n", functionCount);
    printf("Patch count: %d\n", patch_count);

    return 0;
}

// NEW: Restore the original IAT entries
int MallocDebug_Done() {

    if (patch_count == 0) {
        return 0;
    }

    int failed = 0;

    printf("\nChecking for memory leaks...\n");

    int leak_count = 0;
    size_t leaked_bytes = 0;

    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocations[i].active) {
            printf("Memory leak: %p (%zu bytes)\n",
                allocations[i].address,
                allocations[i].size);

            leak_count++;
            leaked_bytes += allocations[i].size;

            allocations[i].active = 0;
            allocations[i].address = NULL;
            allocations[i].size = 0;
        }
    }

    if (leak_count == 0) {
        printf("No memory leaks detected.\n");
    } else {
        printf("Total: %d leaked blocks, %zu bytes\n",
            leak_count, leaked_bytes);
    }

    int remaining = 0;

    for (int i = 0; i < patch_count; i++) {

        void **slot = patch_records[i].iat_slot;
        void *original_address =
            patch_records[i].original_address;

        DWORD oldProtect;

        if (!VirtualProtect(
                slot,
                sizeof(void*),
                PAGE_READWRITE,
                &oldProtect)) {

            printf("Failed to unlock IAT slot %p\n", (void*)slot);

            // Keep the record so restoration can be retried
            patch_records[remaining] = patch_records[i];
            remaining++;
            failed = 1;
            continue;
        }

        // Restore the original address
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

    // NEW: Only failed slot writes remain recorded
    patch_count = remaining;

    if (patch_count == 0) {
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

    // NEW: Restore original IAT entries
    if (MallocDebug_Done() != 0) {
        printf("Restoration failed\n");
        return 1;
    }

    printf("Finished successfully\n");

    return 0;
}
