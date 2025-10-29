#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "MrtTInfo.h"

// --- Mirrored Windows 6.x structures ---

typedef enum MRT_SYSTEM_INFORMATION_CLASS {
    MrtSystemProcessInformation = 5
} MRT_SYSTEM_INFORMATION_CLASS;

typedef struct MRT_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MRT_CLIENT_ID;

typedef struct MRT_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    MRT_CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} MRT_SYSTEM_THREAD_INFORMATION;

typedef struct MRT_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PeakVirtualSize;
    ULONG_PTR VirtualSize;
    SIZE_T PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
    MRT_SYSTEM_THREAD_INFORMATION Threads[1];
} MRT_SYSTEM_PROCESS_INFORMATION;

// --- Function pointer to NtQuerySystemInformation ---
typedef NTSTATUS (NTAPI *PFN_NTQUERYSYSTEMINFORMATION)(
    MRT_SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// --- Helper union for strict aliasing ---
typedef union {
    LARGE_INTEGER li;
    FILETIME ft;
} LARGE_INTEGER_TO_FILETIME;

// --- Main API ---

NTSTATUS MrtTInfo_GetAllProcesses(MRT_PROCESS_INFO** Processes, ULONG* Count) {
    if (!Processes || !Count) return STATUS_INVALID_PARAMETER;
    *Processes = NULL;
    *Count = 0;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return STATUS_DLL_NOT_FOUND;

    PFN_NTQUERYSYSTEMINFORMATION NtQuerySystemInformation =
        (PFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return STATUS_PROCEDURE_NOT_FOUND;

    ULONG bufferSize = 0x10000;
    MRT_SYSTEM_PROCESS_INFORMATION* buffer = NULL;
    NTSTATUS status;

    do {
        buffer = (MRT_SYSTEM_PROCESS_INFORMATION*)malloc(bufferSize);
        if (!buffer) return STATUS_NO_MEMORY;

        status = NtQuerySystemInformation(
            MrtSystemProcessInformation,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            buffer = NULL;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) return status;

    // Count processes
    ULONG processCount = 0;
    MRT_SYSTEM_PROCESS_INFORMATION* p = buffer;
    while (1) {
        processCount++;
        if (!p->NextEntryOffset) break;
        p = (MRT_SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
    }

    MRT_PROCESS_INFO* procArray = (MRT_PROCESS_INFO*)calloc(processCount, sizeof(MRT_PROCESS_INFO));
    if (!procArray) {
        free(buffer);
        return STATUS_NO_MEMORY;
    }

    // Fill process info
    p = buffer;
    for (ULONG i = 0; i < processCount; i++) {
        MRT_PROCESS_INFO* mp = &procArray[i];

        mp->PID = (DWORD)(ULONG_PTR)p->UniqueProcessId;
        mp->ParentPID = (DWORD)(ULONG_PTR)p->InheritedFromUniqueProcessId;
        mp->ImageName = p->ImageName;
        LARGE_INTEGER_TO_FILETIME u;
        u.li = p->CreateTime;
        mp->CreateTime = u.ft;
        mp->UserTime = p->UserTime;
        mp->KernelTime = p->KernelTime;
        mp->WorkingSetSize = p->WorkingSetSize;
        mp->VirtualSize = p->VirtualSize;
        mp->PeakWorkingSetSize = p->PeakWorkingSetSize;
        mp->PrivatePageCount = p->PrivatePageCount;
        mp->HandleCount = p->HandleCount;
        mp->BasePriority = p->BasePriority;
        mp->IoCounters = p->IoCounters;

        // Additional fields for convenience
        mp->SessionId = p->SessionId;
        mp->CycleTime = p->CycleTime;
        mp->HardFaultCount = p->HardFaultCount;
        mp->PeakVirtualSize = p->PeakVirtualSize;
        mp->PageFaultCount = p->PageFaultCount;

        mp->ThreadCount = p->NumberOfThreads;
        if (mp->ThreadCount) {
            mp->Threads = (MRT_THREAD_INFO*)calloc(mp->ThreadCount, sizeof(MRT_THREAD_INFO));
            for (ULONG t = 0; t < mp->ThreadCount; t++) {
                MRT_SYSTEM_THREAD_INFORMATION* st = &p->Threads[t];
                MRT_THREAD_INFO* mt = &mp->Threads[t];

                mt->TID = (DWORD)(ULONG_PTR)st->ClientId.UniqueThread;
                mt->ParentPID = (DWORD)(ULONG_PTR)st->ClientId.UniqueProcess;

                u.li = st->CreateTime;
                mt->CreateTime = u.ft;

                mt->KernelTime = st->KernelTime;
                mt->UserTime = st->UserTime;
                mt->BasePriority = st->BasePriority;
                mt->Priority = st->Priority;
                mt->ContextSwitches = st->ContextSwitches;
                mt->ThreadState = st->ThreadState;
                mt->WaitReason = st->WaitReason;
                mt->StartAddress = st->StartAddress;
            }
        }

        if (!p->NextEntryOffset) break;
        p = (MRT_SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
    }

    *Processes = procArray;
    *Count = processCount;

    free(buffer);
    return STATUS_SUCCESS;
}

void MrtTInfo_FreeProcesses(MRT_PROCESS_INFO* Processes, ULONG Count) {
    if (!Processes) return;
    for (ULONG i = 0; i < Count; i++) free(Processes[i].Threads);
    free(Processes);
}

wchar_t* MrtTInfo_UnicodeStringToWString(UNICODE_STRING* ustr) {
    if (!ustr || !ustr->Buffer || ustr->Length == 0) return NULL;
    size_t len = ustr->Length / sizeof(WCHAR);
    wchar_t* str = (wchar_t*)malloc((len + 1) * sizeof(WCHAR));
    if (!str) return NULL;
    wcsncpy(str, ustr->Buffer, len);
    str[len] = L'\0';
    return str;
}
