#include <windows.h>
#include <winnt.h>

#include <stdio.h>
#include <stdlib.h>

/*
    SPECIAL THANKS TO
        * https://0xrick.github.io/win-internals/pe1/
        * https://wirediver.com/tutorial-writing-a-pe-packer-intro/
*/

// https://github.com/NUL0x4C/AtomPePacker/blob/000982bb625bed6c9c1e135289c8e0f4738b8602/PP64Stub/Structs.h#L37

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;


int main(int argc, char *argv[]) {
    PVOID start_address = NULL;

    if (argc <= 1) {
        printf("Usage :: %s <file>\n", argv[0]);
        return -1;
    }

    // [ File reading (You can replace it) ]

    FILE* fp = fopen(argv[1], "rb");

    if (fp == NULL) {
        return -1;
    }

    fseek(fp, 0L, SEEK_END);
    long int fp_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char* fp_data = (char*)malloc(fp_size + 1);
    if (fp_data == NULL) {
        return -1;
    }

    fread(fp_data, 1, fp_size, fp);
    fclose(fp);

    // [ PE Parsing ]

    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) fp_data;
    IMAGE_NT_HEADERS64* p_NT_HDR = (IMAGE_NT_HEADERS64*) (((PBYTE) p_DOS_HDR) + p_DOS_HDR->e_lfanew);

    IMAGE_DATA_DIRECTORY import_dir = p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY reloc_dir = p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    PBYTE addrp = (PBYTE) VirtualAlloc(NULL, p_NT_HDR->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (addrp == NULL) {
        return -1;
    }

    // [ Mapping PE sections ]

    memcpy(addrp, fp_data, p_NT_HDR->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1);

    for (int i=0; i<p_NT_HDR->FileHeader.NumberOfSections; i++) {
        PBYTE dest = addrp + sections[i].VirtualAddress;

        if (sections[i].SizeOfRawData > 0) {
            memcpy(dest, fp_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        } else {
            memset(dest, 0, sections[i].Misc.VirtualSize);
        }
    }

    // [ Fix imports ]

    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*) (addrp + import_dir.VirtualAddress);

    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; i++) {
        PVOID module_name = addrp + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA((LPCSTR) module_name);

        if (import_module == NULL) {
            return -1;
        }

        IMAGE_THUNK_DATA64* lookup_table = (IMAGE_THUNK_DATA64*) (addrp + import_descriptors[i].OriginalFirstThunk);
        IMAGE_THUNK_DATA64* address_table = (IMAGE_THUNK_DATA64*) (addrp + import_descriptors[i].FirstThunk);

        for (int j = 0; lookup_table[j].u1.AddressOfData != 0; j++) {
            void* function_handle = NULL;

            DWORD64 lookup_addr = lookup_table[j].u1.AddressOfData;

            if ((lookup_addr & IMAGE_ORDINAL_FLAG64) == 0) {
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*) (addrp + lookup_addr);
                char* funct_name = (char*) &(image_import->Name);
                function_handle = (PVOID) GetProcAddress(import_module, funct_name);
            } else {
                function_handle = (PVOID) GetProcAddress(import_module, (LPSTR) lookup_addr);
            }

            if (function_handle == NULL) {
                return -1;
            }

            address_table[j].u1.Function = (DWORD64) function_handle;
        }
    }

    // [ Fix relocations ]
    // https://github.com/NUL0x4C/AtomPePacker/blob/main/PP64Stub/Unpack.c#L179

    PIMAGE_BASE_RELOCATION p_reloc = (PIMAGE_BASE_RELOCATION) (addrp + reloc_dir.VirtualAddress);
    ULONG_PTR delta_VA_reloc = ((ULONG_PTR) addrp) - p_NT_HDR->OptionalHeader.ImageBase;
    PBASE_RELOCATION_ENTRY reloc = NULL;

    while (p_reloc->VirtualAddress != 0) {
        reloc = (PBASE_RELOCATION_ENTRY) (p_reloc + 1);

        while ((PBYTE) reloc != (PBYTE) p_reloc + p_reloc->SizeOfBlock) {
            switch (reloc->Type) {
                case IMAGE_REL_BASED_DIR64:
                    *((ULONG_PTR*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += delta_VA_reloc;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *((DWORD*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += (DWORD) delta_VA_reloc;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *((WORD*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += HIWORD(delta_VA_reloc);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *((WORD*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += LOWORD(delta_VA_reloc);
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    break;
            }
            reloc++;
        }
        p_reloc = (PIMAGE_BASE_RELOCATION) reloc;
    }

    // [ Entrypoint call ]

    start_address = (PVOID) (addrp + p_NT_HDR->OptionalHeader.AddressOfEntryPoint);

    ((void (*)(void)) start_address)();

    return 0;
}

