#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include "MrtTInfo.h"

// --- Main API ---
const char* ThreadStateToString(ULONG state) {
    switch (state) {
        case 0: return "Initialized";
        case 1: return "Ready";
        case 2: return "Running";
        case 3: return "Standby";
        case 4: return "Terminated";
        case 5: return "Waiting";
        case 6: return "Transition";
        case 7: return "Unknown"; // Rare, reserved
        case 8: return "Waiting (Suspended)";
        case 9: return "UserRequest";
        case 10: return "Unknown";
        case 11: return "DeferredReady";
        case 12: return "WaitingForCompletion";
        case 13: return "WaitingForDispatch";
        case 14: return "WaitingForExecution";
        case 15: return "WaitingForResource";
        case 16: return "WaitingForTimer";
        case 23: return "Suspended";
        case 27: return "WaitingForEvent";
        default: return "Unknown";
    }
}

const char* WaitReasonToString(ULONG reason) {
    switch (reason) {
        case 0: return "Executive";
        case 1: return "FreePage";
        case 2: return "PageIn";
        case 3: return "PoolAllocation";
        case 4: return "ExecutionDelay";
        case 5: return "Suspended";
        case 6: return "UserRequest";
        case 7: return "EventPairHigh";
        case 8: return "EventPairLow";
        case 9: return "LpcReceive";
        case 10: return "LpcReply";
        case 11: return "VirtualMemory";
        case 12: return "PageOut";
        case 13: return "Unknown";
        case 14: return "SuspendedExecution";
        case 15: return "DelayExecution";
        case 16: return "QueueWait";
        case 17: return "Unknown";
        case 18: return "LpcReplyMessage";
        case 31: return "Unknown";
        case 42: return "Timer";
        case 91: return "WaitForLoaderLock";
        default: return "Other";
    }
}

// Walk TLS slots and count how many are actually used
ULONG CountTLSSlots(PVOID tlsPointer)
{
    if (!tlsPointer)
        return 0;

    ULONG count = 0;
    PVOID* tlsArray = (PVOID*)tlsPointer;

    // Windows 7 has 108 TLS slots
    for (ULONG i = 0; i < 108; i++) {
        // Count a slot as "used" if it's non-NULL or reserved (optional)
        if (tlsArray[i] != NULL)
            count++;
    }
    return count;
}


NTSTATUS MrtTInfo_GetAllProcesses(MRT_PROCESS_INFO** Processes, ULONG* Count)
{
    if (!Processes || !Count)
        return STATUS_INVALID_PARAMETER;

    *Processes = NULL;
    *Count = 0;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return STATUS_DLL_NOT_FOUND;

    PFN_NTQUERYSYSTEMINFORMATION NtQuerySystemInformation =
        (PFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(
            ntdll, "NtQuerySystemInformation");

    PFN_NtQueryInformationThread NtQueryInformationThread =
        (PFN_NtQueryInformationThread)GetProcAddress(
            ntdll, "NtQueryInformationThread");

    if (!NtQuerySystemInformation || !NtQueryInformationThread)
        return STATUS_PROCEDURE_NOT_FOUND;

    ULONG bufferSize = 0x10000;
    MRT_SYSTEM_PROCESS_INFORMATION* buffer = NULL;
    NTSTATUS status;

    do {
        buffer = (MRT_SYSTEM_PROCESS_INFORMATION*)malloc(bufferSize);
        if (!buffer)
            return STATUS_NO_MEMORY;

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

    if (!NT_SUCCESS(status))
        return status;

    // Count processes
    ULONG processCount = 0;
    MRT_SYSTEM_PROCESS_INFORMATION* p = buffer;
    while (1) {
        processCount++;
        if (!p->NextEntryOffset)
            break;
        p = (MRT_SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
    }

    MRT_PROCESS_INFO* procArray =
        (MRT_PROCESS_INFO*)calloc(processCount, sizeof(MRT_PROCESS_INFO));
    if (!procArray) {
        free(buffer);
        return STATUS_NO_MEMORY;
    }

    // Fill process info
    p = buffer;
    for (ULONG i = 0; i < processCount; i++) {
        MRT_PROCESS_INFO* mp = &procArray[i];

        mp->PID       = (DWORD)(ULONG_PTR)p->UniqueProcessId;
        mp->ParentPID = (DWORD)(ULONG_PTR)p->InheritedFromUniqueProcessId;
        mp->ImageName = p->ImageName;

        LARGE_INTEGER_TO_FILETIME u;
        u.li = p->CreateTime;
        mp->CreateTime = u.ft;

        mp->UserTime          = p->UserTime;
        mp->KernelTime        = p->KernelTime;
        mp->WorkingSetSize    = p->WorkingSetSize;
        mp->VirtualSize       = p->VirtualSize;
        mp->PeakWorkingSetSize= p->PeakWorkingSetSize;
        mp->PrivatePageCount  = p->PrivatePageCount;
        mp->HandleCount       = p->HandleCount;
        mp->BasePriority      = p->BasePriority;
        mp->IoCounters        = p->IoCounters;

        mp->SessionId         = p->SessionId;
        mp->CycleTime         = p->CycleTime;
        mp->HardFaultCount    = p->HardFaultCount;
        mp->PeakVirtualSize   = p->PeakVirtualSize;
        mp->PageFaultCount    = p->PageFaultCount;
        mp->ThreadCount = p->NumberOfThreads;
        if (mp->ThreadCount) {
            mp->Threads = (MRT_THREAD_INFO*)
                calloc(mp->ThreadCount, sizeof(MRT_THREAD_INFO));

            for (ULONG t = 0; t < mp->ThreadCount; t++) {
                MRT_SYSTEM_THREAD_INFORMATION* st = &p->Threads[t];
                MRT_THREAD_INFO* mt = &mp->Threads[t];

                mt->TID       = (DWORD)(ULONG_PTR)st->ClientId.UniqueThread;
                mt->ParentPID = (DWORD)(ULONG_PTR)st->ClientId.UniqueProcess;

                u.li = st->CreateTime;
                mt->CreateTime = u.ft;

                mt->KernelTime      = st->KernelTime;
                mt->UserTime        = st->UserTime;
                mt->BasePriority    = st->BasePriority;
                mt->Priority        = st->Priority;
                mt->ContextSwitches = st->ContextSwitches;
                mt->ThreadState     = st->ThreadState;
                mt->WaitReason      = st->WaitReason;
                mt->StartAddress = st->StartAddress;
                mt->TebAddress = NULL;

                // --- TEB extraction ---
                HANDLE hThread =
                    OpenThread(THREAD_QUERY_INFORMATION, FALSE, mt->TID);

                if (hThread) {
                    THREAD_BASIC_INFORMATION tbi;
                    if (NT_SUCCESS(
                        NtQueryInformationThread(
                            hThread,
                            ThreadBasicInformation,
                            &tbi,
                            sizeof(tbi),
                            NULL)))
                    {
                        mt->TebAddress = tbi.TebBaseAddress;

                        if (mt->TebAddress &&
                            mt->ParentPID == GetCurrentProcessId())
                        {
                            TEB_PARTIAL* teb =
                                (TEB_PARTIAL*)mt->TebAddress;

                            mt->StackBase      = teb->NtTib.StackBase;
                            mt->StackLimit     = teb->NtTib.StackLimit;
                            mt->TlsPointer     = teb->ThreadLocalStoragePointer;
                            mt->PebAddress     = teb->ProcessEnvironmentBlock;
                            mt->LastErrorValue = teb->LastErrorValue;
                            mt->ArbitraryUserPointer          = teb->NtTib.ArbitraryUserPointer;
                            mt->CountOfOwnedCriticalSections  = teb->CountOfOwnedCriticalSections;
                            mt->Win32ThreadInfo               = teb->Win32ThreadInfo;
                            mt->TLSSlotCount = CountTLSSlots(mt->TlsPointer);
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        }

        if (!p->NextEntryOffset)
            break;

        p = (MRT_SYSTEM_PROCESS_INFORMATION*)
            ((BYTE*)p + p->NextEntryOffset);
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

static BOOL MrtTInfo_QueryCurrentThreadLive(MRT_THREAD_INFO* out)
{
    if (!out)
        return FALSE;

    PFN_NtQueryInformationThread NtQueryInformationThread =
        (PFN_NtQueryInformationThread)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "NtQueryInformationThread"
        );
    if (!NtQueryInformationThread)
        return FALSE;

    THREAD_BASIC_INFORMATION tbi;
    ZeroMemory(&tbi, sizeof(tbi));

    NTSTATUS status = NtQueryInformationThread(
        GetCurrentThread(),
        ThreadBasicInformation,
        &tbi,
        sizeof(tbi),
        NULL
    );

    if (!NT_SUCCESS(status))
        return FALSE;

    out->TID = GetCurrentThreadId();
    out->BasePriority = (LONG)tbi.BasePriority;
    out->Priority = (LONG)tbi.Priority;
    out->TebAddress = tbi.TebBaseAddress;

    // --- Read extra TEB fields safely ---
    if (out->TebAddress) {
        TEB_PARTIAL* teb = (TEB_PARTIAL*)out->TebAddress;
        out->StackBase = teb->NtTib.StackBase;
        out->StackLimit = teb->NtTib.StackLimit;
        out->TlsPointer = teb->ThreadLocalStoragePointer;
        out->PebAddress = teb->ProcessEnvironmentBlock;
        out->LastErrorValue = teb->LastErrorValue;
    }

    // Live thread → always running
    out->ThreadState = Running;
    out->WaitReason  = Executive;

    out->KernelTime.QuadPart = 0;
    out->UserTime.QuadPart = 0;
    out->ContextSwitches = 0;
    out->StartAddress = NULL;

    return TRUE;
}

// ---------------------------------------------------------------------------
// Find a process by its PID within the array returned by MrtTInfo_GetAllProcesses.
// Returns a pointer to the process structure, or NULL if not found.
// ---------------------------------------------------------------------------
MRT_PROCESS_INFO* MrtTInfo_FindProcessByPID(
    MRT_PROCESS_INFO* processes,
    ULONG count,
    DWORD pid
)
{
    if (!processes || count == 0)
        return NULL;

    for (ULONG i = 0; i < count; i++) {
        if (processes[i].PID == pid)
            return &processes[i];
    }

    return NULL;
}

// ---------------------------------------------------------------------------
// Find a thread by its TID across all processes in the array returned by
// MrtTInfo_GetAllProcesses. Returns a pointer to the thread structure,
// or NULL if not found.
// ---------------------------------------------------------------------------
MRT_THREAD_INFO* MrtTInfo_FindThreadByTID(
    MRT_PROCESS_INFO* processes,
    ULONG count,
    DWORD tid
)
{
    if (!processes || count == 0)
        return NULL;

    // 1) Try snapshot first (fast path)
    for (ULONG i = 0; i < count; i++) {
        MRT_PROCESS_INFO* proc = &processes[i];
        if (!proc->Threads || proc->ThreadCount == 0)
            continue;

        for (ULONG t = 0; t < proc->ThreadCount; t++) {
            if (proc->Threads[t].TID == tid)
                return &proc->Threads[t];
        }
    }

    // 2) If it's the current thread, query live
    if (tid == GetCurrentThreadId()) {
        static MRT_THREAD_INFO liveThread;
        ZeroMemory(&liveThread, sizeof(liveThread));

        if (MrtTInfo_QueryCurrentThreadLive(&liveThread))
            return &liveThread;
    }

    return NULL;
}
