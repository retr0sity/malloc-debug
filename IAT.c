#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct memalloc_patch {
    char *name;
    void *iat_slot;
    void *original_address;
    void *patched_address;
} memalloc_patch;

memalloc_patch patches[4] = {
    {"malloc", NULL, NULL, NULL},
    {"calloc", NULL, NULL, NULL},
    {"realloc", NULL, NULL, NULL},
    {"free", NULL, NULL, NULL}
};

int imports() {
    char *p = malloc(1);
    if (p == NULL) {
        printf("malloc failed\n");
        return 1;
    }
    if (calloc(1, 1) == NULL) {
        printf("calloc failed\n");
        free(p);
        return 2;
    }
    char *q = realloc(p, 2);
    if (q == NULL) {
        printf("realloc failed\n");   // on failure, p is still valid
        free(p);
        return 3;
    }
    free(q);
    return 0;
}

int patch_iat() {
    for (int i = 0; i < 4; i++) {
        if (patches[i].iat_slot != NULL && patches[i].patched_address != NULL) 
        {
            DWORD oldProtect;
            if (VirtualProtect(patches[i].iat_slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) 
            {
                *(void**)patches[i].iat_slot = patches[i].patched_address;
                if (!VirtualProtect(patches[i].iat_slot, sizeof(void*), oldProtect, &oldProtect)) 
                {
                printf("failed to restore memory protection for %s (Error: %lu)\n",
                    patches[i].name, GetLastError());
                return 2;
                }
            } 
            else 
            {
                printf("failed to change memory protection for %s\n", patches[i].name);
                return 1;
            }
        }
    }
    return 0;
}

int main() {
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)( ((BYTE*)pDosHeader) + pDosHeader->e_lfanew );
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImportDescriptor) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size); //not used since we are using the Characteristics field to determine the end of the import descriptors

    int functionCount = 0, dllCount = 0;

    imports(); // call the imports function to ensure the functions are linked and available

    for (;pImportDescriptor->Characteristics!=0;pImportDescriptor++)
    {
        dllCount++;
        char *pName = (CHAR*)(pImportDescriptor->Name + (BYTE*)pDosHeader);
        printf("%s\n", pName);
        
        
        PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA) (pImportDescriptor->OriginalFirstThunk  + (BYTE*)pDosHeader);
        PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA) (pImportDescriptor->FirstThunk  + (BYTE*)pDosHeader);

        while (pOriginalThunk->u1.AddressOfData != 0)
        {
            if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                printf("Ordinal: %u\n\n", (unsigned)(pOriginalThunk->u1.Ordinal & 0xFFFF));
            } else {
                PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(pOriginalThunk->u1.AddressOfData + (BYTE*)pDosHeader);
                for (int i = 0; i < 4; i++) {
                    if (strcmp(importName->Name, patches[i].name) == 0) {
                        patches[i].iat_slot = (void*)&pFirstThunk->u1.Function;
                        patches[i].original_address = (void*)pFirstThunk->u1.Function;
                        printf("\nFound %s: \nIAT slot: %p\nSlot address:%p\nFunction: %p\n\n", patches[i].name, patches[i].iat_slot, (void*)pFirstThunk, (void*)pFirstThunk->u1.Function);
                    }
                }
                //printf("%s\n", importName->Name);
                //printf("%d\n\n", importName->Hint);
                /*if (strcmp(importName->Name, "malloc") == 0) {
                    printf("Found malloc: \nSlot address:%p\n Function: %p\n", (void*)pFirstThunk, (void*)pFirstThunk->u1.Function);
                    printf("malloc's address: %p\n", (void*)malloc);
                    if ((void*)malloc == (void*)pFirstThunk->u1.Function) {
                        printf("address matches!\n");
                    } else {
                        printf("address does not match.\n");
                    }
                }*/
            }
            pOriginalThunk++;
            pFirstThunk++;
            functionCount++;
        }
    }

        printf("DOS Header: %p\n", pDosHeader);
        printf("NT Headers: %p\n", pNTHeaders);
        printf("DLL Count: %d\n", dllCount);
        printf("function count: %d\n", functionCount);
        MessageBoxA(NULL, "wuzuuhhhhhh", "oh hi mark", MB_OK);   // testing with a user32.dll import, oh hi mark reference
        return 0;
}

