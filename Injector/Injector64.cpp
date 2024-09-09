#include <Windows.h>
#include <psapi.h>
#include <stdio.h>
#define IOCTL_GET_DATA_64 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct MyProcessInfo {
    HANDLE PID;
    WCHAR processName[256];
};
const char* MyDLL64 = "Hook64.dll";


int WhatTheHook64(HANDLE hCurrentProc) {
    LPVOID pRemoteAddr = VirtualAllocEx(
        hCurrentProc,
        NULL,
        strlen(MyDLL64) + 1,
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_READWRITE
    );

    if (pRemoteAddr == NULL) {
        printf("[-] Error during VirtualAllocEx\n");
        return 1;
    }
    printf("[*] Success VirtualAllocEx in remote process, addr of new virtual memory : 0x%p.\n", pRemoteAddr);


    WriteProcessMemory(
        hCurrentProc,
        pRemoteAddr,
        (LPCVOID)MyDLL64,
        strlen(MyDLL64) + 1,
        NULL
    );

    HANDLE hRemoteThread = CreateRemoteThread(
        hCurrentProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        pRemoteAddr,
        0,
        NULL
    );

    if (hRemoteThread == NULL) {
        printf("[-] Error during CreateRemoteThread\n");
        return 1;
    }
    printf("[*] Success CreateRemoteThread, handle of new thread : 0x%p.\n", hRemoteThread);


    WaitForSingleObject(hRemoteThread, INFINITE);
    VirtualFreeEx(
        hCurrentProc,
        pRemoteAddr,
        0,
        MEM_RELEASE
    );

    CloseHandle(hRemoteThread);
    return 0;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES TknPrv;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    TknPrv.PrivilegeCount = 1;
    TknPrv.Privileges[0].Luid = luid;
    TknPrv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &TknPrv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] The token doesn't have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}
BOOL EnableDebugPrivilege() {
    HANDLE hTkn;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hTkn)) {
        printf("[-] OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if (!SetPrivilege(hTkn, SE_DEBUG_NAME, TRUE)) {
        printf("[-] Failed to enable SeDebugPrivilege\n");
        CloseHandle(hTkn);
        return FALSE;
    }

    CloseHandle(hTkn);
    return TRUE;
}
BOOL isProcess32(HANDLE handle, BOOL* isWow64) {
    if (IsWow64Process(handle, isWow64)) {
        if (*isWow64) {
            return TRUE;
        }
        else {
            return FALSE;
        }
    }
    else {
        printf("[-] Error during architecture finding.\n");
        exit(-1);
    }
}
BOOL ignoreProcess(const WCHAR* processPath) {
    WCHAR lowerPath[MAX_PATH];
    wcscpy_s(lowerPath, processPath);
    _wcslwr_s(lowerPath, wcslen(lowerPath) + 1);

    if (wcsstr(lowerPath, L"windowsapps") != NULL ||
        wcsstr(lowerPath, L"microsoft.net") != NULL ||
        wcsstr(lowerPath, L"runtimebroker.exe") != NULL ||
        wcsstr(lowerPath, L"injector64.exe") != NULL ||
        wcsstr(lowerPath, L"svchost.exe") != NULL ||
        wcsstr(lowerPath, L"search") != NULL ||
        wcsstr(lowerPath, L"edge") != NULL ||
        wcsstr(lowerPath, L"update") != NULL ||
        wcsstr(lowerPath, L"labs") != NULL) {

        return FALSE;
    }

    return TRUE;
}

int comWithMyDriver() {
    HANDLE hDevice = CreateFile(L"\\\\.\\AgentDriverLnk", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device. Error %d\n", GetLastError());
        return 1;
    }

    DWORD bytesReturned;
    struct MyProcessInfo processInfo;
    ZeroMemory(&processInfo, sizeof(processInfo));
    BOOL isWow64;

    while (true) {
        ZeroMemory(&processInfo, sizeof(processInfo));
        if (!DeviceIoControl(hDevice, IOCTL_GET_DATA_64, NULL, 0, &processInfo, sizeof(processInfo), &bytesReturned, NULL)) {
            printf("[-] DeviceIoControl failed. Error %d\n", GetLastError());
            CloseHandle(hDevice);
            return 1;
        }

        if (processInfo.PID != 0 && ignoreProcess(processInfo.processName)) {
            wprintf(L"[*] Received data from driver:\nName -> %ws\nPID -> %d\n",
                processInfo.processName,
                (DWORD)processInfo.PID
            );

            HANDLE hCurrentProc = OpenProcess(
                PROCESS_ALL_ACCESS,
                TRUE,
                (DWORD)processInfo.PID
            );

            if (!isProcess32(hCurrentProc, &isWow64)) {
                printf("WhatTheHook64\n\n");
                WhatTheHook64(hCurrentProc);
            }
            CloseHandle(hCurrentProc);
        }
        Sleep(100);
    }
    CloseHandle(hDevice);
    return 0;
}

int main() {
    if (!EnableDebugPrivilege()) {
        printf("[-] Failed to enable debug privilege\n");
        return 1;
    }

    comWithMyDriver();
    return 0;
}
