#pragma once
#include <windows.h>
#include <stdlib.h>

// -----------------------------
// Basic NTSTATUS and macros
// -----------------------------
typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_PROCEDURE_NOT_FOUND  ((NTSTATUS)0xC000007FL)
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000DL)
#define STATUS_DLL_NOT_FOUND         ((NTSTATUS)0xC0000135L)

#define Running    2
#define Executive  0

// -----------------------------
// Minimal structures and enums
// -----------------------------
typedef enum _MRT_SYSTEM_INFORMATION_CLASS {
    MrtSystemProcessInformation = 5
} MRT_SYSTEM_INFORMATION_CLASS;

#define ThreadBasicInformation 0

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

// -----------------------------
// Thread & process info structs
// -----------------------------
typedef struct _MRT_THREAD_INFO {
    DWORD TID;
    DWORD ParentPID;
    FILETIME CreateTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LONG BasePriority;
    LONG Priority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
    PVOID StartAddress;
    PVOID TebAddress;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID TlsPointer;
    PVOID PebAddress;
    ULONG LastErrorValue;
} MRT_THREAD_INFO;

typedef struct _MRT_PROCESS_INFO {
    DWORD PID;
    DWORD ParentPID;
    UNICODE_STRING ImageName;
    FILETIME CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;

    SIZE_T WorkingSetSize;
    SIZE_T VirtualSize;
    SIZE_T PeakWorkingSetSize;
    SIZE_T PrivatePageCount;
    SIZE_T PageFaultCount;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG HardFaultCount;
    ULONG_PTR PeakVirtualSize;
    ULONGLONG CycleTime;
    LONG BasePriority;
    IO_COUNTERS IoCounters;

    ULONG ThreadCount;
    MRT_THREAD_INFO* Threads;
} MRT_PROCESS_INFO;

typedef struct MRT_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MRT_CLIENT_ID;

typedef struct _TEB_PARTIAL {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    MRT_CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PVOID ProcessEnvironmentBlock;
    ULONG LastErrorValue;
} TEB_PARTIAL;

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

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    MRT_CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;

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

typedef union {
    LARGE_INTEGER li;
    FILETIME ft;
} LARGE_INTEGER_TO_FILETIME;

// -----------------------------
// Function pointer typedefs
// -----------------------------
typedef NTSTATUS (NTAPI *PFN_NTQUERYSYSTEMINFORMATION)(
    MRT_SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    int ThreadInformationClass, // THREADINFOCLASS
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------
// API declarations
// -----------------------------
NTSTATUS MrtTInfo_GetAllProcesses(MRT_PROCESS_INFO** Processes, ULONG* Count);
void MrtTInfo_FreeProcesses(MRT_PROCESS_INFO* Processes, ULONG Count);
wchar_t* MrtTInfo_UnicodeStringToWString(UNICODE_STRING* ustr);
const char* WaitReasonToString(ULONG reason);
const char* ThreadStateToString(ULONG state);
MRT_PROCESS_INFO* MrtTInfo_FindProcessByPID(MRT_PROCESS_INFO* processes, ULONG count, DWORD pid);
MRT_THREAD_INFO* MrtTInfo_FindThreadByTID(MRT_PROCESS_INFO* processes, ULONG count, DWORD tid);

#ifdef __cplusplus
}
#endif
