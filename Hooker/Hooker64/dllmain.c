#include <Windows.h>
#include <libloaderapi.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>

extern void retHooked();

typedef LPVOID(WINAPI* VirtualAllocExType)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef LONG(NTAPI* NtSuspendProcessType)(
    IN HANDLE ProcessHandle
    );

VirtualAllocExType TrueVirtualAllocEx = NULL;
BYTE originalBytes[5];
BYTE originalRetAddr[12];
void* returnAddress;

void PlaceHook(BYTE* pOrigFunc, BYTE* origBytes, SIZE_T pHookedFunc);
void PlaceHookLongJmp(BYTE* pOrigFunc, BYTE* origBytes, void* pHookedFunc);
void RestoreOriginalFunction(BYTE* pOrigFunc, BYTE* origBytes);
void RestoreOriginalFunctionLongJmp(BYTE* returnAddress, BYTE* originalRetAddr);
void handleRetHooked();

SYSTEM_INFO sysInfo;
SIZE_T pageSize;
SIZE_T getPageSize() {
    GetSystemInfo(&sysInfo);
    pageSize = sysInfo.dwPageSize;
    return pageSize;
}

void suspend(HANDLE hCurrentProc) {
    HANDLE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll == NULL) {
        printf("[-] Failed to get handle to ntdll.dll: %d\n", GetLastError());
        return;
    }

    NtSuspendProcessType pNtSuspendProcess = (NtSuspendProcessType)GetProcAddress(
        hNtdll, 
        "NtSuspendProcess"
    );
    pNtSuspendProcess(hCurrentProc);    
}

void handleRetHooked() {
    HANDLE hCurrentProc = GetCurrentProcess();
    HANDLE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll == NULL) {
        printf("[-] Failed to get handle to ntdll.dll: %d\n", GetLastError());
        return;
    }

    NtSuspendProcessType pNtSuspendProcess = (NtSuspendProcessType)GetProcAddress(hNtdll, "NtSuspendProcess");
    if (pNtSuspendProcess == NULL) {
        printf("[-] Failed to get address of NtSuspendProcess: %d\n", GetLastError());
        return;
    }

    RestoreOriginalFunctionLongJmp((BYTE*)returnAddress, (BYTE*)originalRetAddr);
    pNtSuspendProcess(hCurrentProc);
}

LPVOID WINAPI HookedVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) {
    HANDLE hCurrentProc = GetCurrentProcess();
    printf("[+] HANDLE -> 0x%p\n[+] LPVOID -> 0x%p\n[+] dwSize -> %d\n", hProcess, lpAddress, (DWORD)dwSize);
    suspend(hCurrentProc);
    RestoreOriginalFunction((BYTE*)TrueVirtualAllocEx, (BYTE*)originalBytes);

    void* retAddr = _ReturnAddress();
    returnAddress = retAddr;
    PlaceHookLongJmp((BYTE *)retAddr, (BYTE *)originalRetAddr, (void*)retHooked);

    CloseHandle(hCurrentProc);
    LPVOID result = TrueVirtualAllocEx(
        hProcess,
        lpAddress,
        dwSize,
        flAllocationType,
        flProtect
    );
    return result;
}

void RestoreOriginalFunctionLongJmp(BYTE* pOrigFunc, BYTE* origBytes) {
    DWORD oldProtect;
    if (VirtualProtect(pOrigFunc, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pOrigFunc, origBytes, 12);
        VirtualProtect(pOrigFunc, pageSize, oldProtect, &oldProtect);
    }
    else {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
    }
}

void RestoreOriginalFunction(BYTE* pOrigFunc, BYTE* origBytes) {
    DWORD oldProtect;
    if (VirtualProtect(pOrigFunc, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pOrigFunc, origBytes, 5);
        VirtualProtect(pOrigFunc, pageSize, oldProtect, &oldProtect);
    }
    else {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
    }
}

void PlaceHookLongJmp(BYTE* pOrigFunc, BYTE* origBytes, void* pHookedFunc) {
    DWORD oldProtect;
    if (!VirtualProtect(pOrigFunc, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return;
    }

    memcpy(origBytes, pOrigFunc, 12);

    BYTE jump[12];
    jump[0] = 0x48;  // Opcode pour REX.W prefix
    jump[1] = 0xBA;  // Opcode pour MOV RDX, imm64
    *((void**)(jump + 2)) = pHookedFunc;  // Charger l'adresse 64 bits de retHooked dans RDX
    jump[10] = 0xFF;  // Opcode pour JMP RDX
    jump[11] = 0xE2;  // Opcode pour JMP RDX

    memcpy(pOrigFunc, jump, 12);

    if (!VirtualProtect(pOrigFunc, pageSize, oldProtect, &oldProtect)) {
        printf("[-] VirtualProtect failed to restore protection: %d\n", GetLastError());
    }
}

void PlaceHook(BYTE* pOrigFunc, BYTE* origBytes, SIZE_T pHookedFunc) {
    DWORD oldProtect;
    if (!VirtualProtect(pOrigFunc, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed to change protection: %d\n", GetLastError());
        return;
    }

    memcpy(origBytes, pOrigFunc, 5);

    SIZE_T offset = (pHookedFunc - (SIZE_T)pOrigFunc) - 5;
    BYTE jmp[5] = { 0xE9, 0, 0, 0, 0 };
    *(DWORD*)((BYTE*)jmp + 1) = (DWORD)offset;

    memcpy(pOrigFunc, jmp, 5);

    if (!VirtualProtect(pOrigFunc, pageSize, oldProtect, &oldProtect)) {
        printf("[-] VirtualProtect failed to restore protection: %d\n", GetLastError());
    }
}


void InstallMyHook() {
    getPageSize();
    TrueVirtualAllocEx = (VirtualAllocExType)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "VirtualAllocEx");
    if (!TrueVirtualAllocEx) {
        printf("[-] Failed to get address of VirtualAllocEx\n");
        return;
    }
    PlaceHook((BYTE*)TrueVirtualAllocEx, (BYTE*)originalBytes, (SIZE_T)HookedVirtualAllocEx);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "[+] Hooked 64bits !", "API Hooking By Kl43s !", 0);
            InstallMyHook();
            break;

        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
