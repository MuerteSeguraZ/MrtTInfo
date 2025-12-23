#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

// -----------------------------
// basic NTSTATUS and macross
// -----------------------------
typedef LONG NTSTATUS;
typedef ULONG_PTR KAFFINITY;
typedef ULONG MRT_THREAD_STATE;
typedef ULONG MRT_WAIT_REASON;

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
#define STATUS_PROCEDURE_NOT_FOUND  ((NTSTATUS)0xC000007FL)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_DLL_NOT_FOUND
#define STATUS_DLL_NOT_FOUND         ((NTSTATUS)0xC0000135L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#endif
#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS        ((NTSTATUS)0xC0000003L)
#endif
#ifndef STATUS_ACCESS_VIOLATION
#define STATUS_ACCESS_VIOLATION          ((NTSTATUS)0xC0000005L)
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE            ((NTSTATUS)0xC0000008L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_OBJECT_PATH_NOT_FOUND
#define STATUS_OBJECT_PATH_NOT_FOUND     ((NTSTATUS)0xC000003AL)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION     ((NTSTATUS)0xC0000035L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH      ((NTSTATUS)0xC0000024L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_PROCESS_IS_TERMINATING
#define STATUS_PROCESS_IS_TERMINATING    ((NTSTATUS)0xC000010AL)
#endif
#ifndef STATUS_THREAD_IS_TERMINATING
#define STATUS_THREAD_IS_TERMINATING     ((NTSTATUS)0xC000004BL)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY                 ((NTSTATUS)0xC0000017L)
#endif
#ifndef STATUS_INVALID_PARAMETER_1
#define STATUS_INVALID_PARAMETER_1       ((NTSTATUS)0xC00000EFL)
#endif
#ifndef STATUS_INVALID_PARAMETER_2
#define STATUS_INVALID_PARAMETER_2       ((NTSTATUS)0xC00000F0L)
#endif
#ifndef STATUS_INVALID_PARAMETER_3
#define STATUS_INVALID_PARAMETER_3       ((NTSTATUS)0xC00000F1L)
#endif
#ifndef STATUS_INVALID_PARAMETER_4
#define STATUS_INVALID_PARAMETER_4       ((NTSTATUS)0xC00000F2L)
#endif
#ifndef STATUS_INVALID_PARAMETER_5
#define STATUS_INVALID_PARAMETER_5       ((NTSTATUS)0xC00000F3L)
#endif
#ifndef STATUS_INVALID_PARAMETER_6
#define STATUS_INVALID_PARAMETER_6       ((NTSTATUS)0xC00000F4L)
#endif
#ifndef STATUS_INVALID_PARAMETER_7
#define STATUS_INVALID_PARAMETER_7       ((NTSTATUS)0xC00000F5L)
#endif
#ifndef STATUS_INVALID_PARAMETER_8
#define STATUS_INVALID_PARAMETER_8       ((NTSTATUS)0xC00000F6L)
#endif
#ifdef _WIN64
typedef PVOID SUBSYSTEM_TIB;
#else
typedef DWORD SUBSYSTEM_TIB;
#endif

#define Running    2
#define Executive  0
#define ThreadBasicInformation 0

// -----------------------------
// Minimal structures and enums
// -----------------------------
typedef enum _MRT_SYSTEM_INFORMATION_CLASS {
    MrtSystemProcessInformation = 5
} MRT_SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD* Next;
    PVOID Handler; // pointer to exception handler
} EXCEPTION_REGISTRATION_RECORD;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS;

// -----------------------------
// Thread & process info structs
// -----------------------------
typedef struct _PEB_PARTIAL {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG SessionId;
} PEB_PARTIAL;

typedef struct _MRT_THREAD_INFO {
    DWORD TID;
    DWORD ParentPID;
    FILETIME CreateTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LONG BasePriority;
    LONG Priority;
    ULONG ContextSwitches;
    MRT_THREAD_STATE ThreadState;
    MRT_WAIT_REASON WaitReason;
    PVOID StartAddress;
    PVOID TebAddress;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID TlsPointer;
    BYTE  PebBeingDebugged;
    ULONG PebSessionId;
    wchar_t* PebCommandLine;
    wchar_t* PebImagePath;
    PVOID PebAddress;
    ULONG LastErrorValue;
    PVOID ArbitraryUserPointer;          
    ULONG CountOfOwnedCriticalSections; 
    PVOID Win32ThreadInfo;             
    ULONG TLSSlotCount;        
    KAFFINITY AffinityMask;
    ULONG IdealProcessor;
    ULONG CurrentProcessor;  
    PVOID ExceptionList; 
    SUBSYSTEM_TIB SubSystemTib;
    PVOID Self;
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
    PVOID Win32ThreadInfo;            
    ULONG CountOfOwnedCriticalSections;
    PVOID ExceptionList; 
    SUBSYSTEM_TIB SubSystemTib;
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
    MRT_THREAD_STATE ThreadState;
    MRT_WAIT_REASON WaitReason;
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

typedef DWORD (WINAPI *PFN_GetCurrentProcessorNumber)(
    void
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
const char* MrtHelper_WaitReasonToString(MRT_WAIT_REASON reason);
const char* MrtHelper_ThreadStateToString(MRT_THREAD_STATE state);
void MrtHelper_PrintSEHChain(PVOID exceptionList);
MRT_PROCESS_INFO* MrtTInfo_FindProcessByPID(MRT_PROCESS_INFO* processes, ULONG count, DWORD pid);
MRT_THREAD_INFO* MrtTInfo_FindThreadByTID(MRT_PROCESS_INFO* processes, ULONG count, DWORD tid);

#ifdef __cplusplus
}
#endif
