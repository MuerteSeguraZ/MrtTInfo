#pragma once
#include <windows.h>
#include <stdlib.h>
#include "MrtTInfo.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_PROCEDURE_NOT_FOUND
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007FL)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

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

// Allocates and fills MRT_PROCESS_INFO array
// *Processes: output pointer, needs free() by caller
// *Count: number of processes returned
NTSTATUS MrtTInfo_GetAllProcesses(MRT_PROCESS_INFO** Processes, ULONG* Count);

void MrtTInfo_FreeProcesses(MRT_PROCESS_INFO* Processes, ULONG Count);

// Converts UNICODE_STRING to null-terminated wchar_t*.
// Returns a malloc'd string, must be free() by caller.
wchar_t* MrtTInfo_UnicodeStringToWString(UNICODE_STRING* ustr);

const char* WaitReasonToString(ULONG reason);
const char* ThreadStateToString(ULONG state);

#ifdef __cplusplus
}
#endif
