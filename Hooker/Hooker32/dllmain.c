#include <Windows.h>
#include <libloaderapi.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

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
BYTE originalRetAddr[5];
void* returnAddress;

void PlaceHook(BYTE* pOrigFunc, BYTE* origBytes, DWORD_PTR pHookedFunc);
void RestoreOriginalFunction(BYTE* pOrigFuncRestore, BYTE* origBytesRestore);
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
void __declspec(naked) retHooked() {
    __asm {
        pushad
        pushfd
        call handleRetHooked
        popfd
        popad
        jmp returnAddress
    }
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

    RestoreOriginalFunction((BYTE*)returnAddress, (BYTE*)originalRetAddr);
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
    PlaceHook((BYTE*)retAddr, (BYTE*)originalRetAddr, (DWORD_PTR)retHooked);

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

void PlaceHook(BYTE* pOrigFunc, BYTE* origBytes, DWORD_PTR pHookedFunc) {
    DWORD oldProtect;
    if (!VirtualProtect(pOrigFunc, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed to change protection: %d\n", GetLastError());
        return;
    }

    memcpy(origBytes, pOrigFunc, 5);

    DWORD offset = (pHookedFunc - (DWORD_PTR)pOrigFunc) - 5;
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
    PlaceHook((BYTE*)TrueVirtualAllocEx, (BYTE*)originalBytes, (DWORD_PTR)HookedVirtualAllocEx);
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
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
