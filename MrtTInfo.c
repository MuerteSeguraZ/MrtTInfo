#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include "MrtTInfo.h"

static ULONG CountTLSSlots(PVOID tlsPointer);

// --- Main API ---

/**
 * @brief Returns the processor number the current thread is running on.
 *
 * Resolves GetCurrentProcessorNumber from kernel32.dll at runtime to avoid
 * hard dependencies on newer Windows versions. The function pointer is
 * cached after the first lookup.
 *
 * @return Zero-based processor number, or 0 if the API is unavailable.
 */
static DWORD WrapGetCurrentProcessorNumber() {
    static PFN_GetCurrentProcessorNumber pFunc = NULL;
    if (!pFunc) {
        HMODULE hKernel = GetModuleHandleA("kernel32.dll");
        if (hKernel)
            pFunc = (PFN_GetCurrentProcessorNumber)GetProcAddress(hKernel, "GetCurrentProcessorNumber");
        if (!pFunc) return 0; // fallback if not available
    }
    return pFunc();
}

/**
 * @brief Dumps the structured exception handling (SEH) chain.
 *
 * Walks the SEH linked list starting at the given exception list pointer
 * and prints each handler entry. The walk is bounded and includes basic
 * sanity checks to avoid infinite loops or corrupted chains.
 *
 * @param exceptionList Pointer to the head of the SEH chain.
 */
void MrtHelper_PrintSEHChain(PVOID exceptionList)
{
    if (!exceptionList) {
        wprintf(L"        ExceptionList: <empty>\n");
        return;
    }

    EXCEPTION_REGISTRATION_RECORD* record =
        (EXCEPTION_REGISTRATION_RECORD*)exceptionList;

    wprintf(L"        SEH chain:\n");

    int index = 0;
    while (record && index < 32) {
        wprintf(L"          [%d] Handler: %p  Next: %p\n",
                index, record->Handler, record->Next);

        if (record->Next <= record) {
            wprintf(L"            (terminating walk due to invalid Next)\n");
            break;
        }

        record = record->Next;
        index++;
    }
}

/**
 * @brief Prints loaded modules from the PEB loader data.
 *
 * Walks the InLoadOrderModuleList and prints basic information
 * about each loaded module, including base name, base address,
 * and image size.
 *
 * @param ldr Pointer to the process loader data (PEB_LDR_DATA).
 */
void MrtHelper_PrintModules(PEB_LDR_DATA* ldr)
{
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY* mod =
            CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        wchar_t* baseName = mod->BaseDllName.Buffer;
        wprintf(L"        Module: %ls  Base: %p  Size: %lu\n",
                baseName, mod->DllBase, mod->SizeOfImage);

        entry = entry->Flink;
    }
}

/**
 * @brief Queries information about the current thread and fills a MRT_THREAD_INFO structure.
 *
 * Uses NtQueryInformationThread to gather basic thread information, then
 * reads selected TEB and PEB fields to populate the provided output structure.
 * Also prints loaded modules if the PEB loader data is available.
 *
 * @param out Pointer to an MRT_THREAD_INFO structure to receive thread info.
 *
 * @return TRUE if the thread info was successfully retrieved, FALSE otherwise.
 *
 * @note Some fields are read directly from the TEB/PEB and may not be
 *       valid if the structure layout differs from expected.
 */
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
        PEB_PARTIAL peb = {0};
        out->PebAddress = teb->ProcessEnvironmentBlock;
        out->StackBase = teb->NtTib.StackBase;
        out->StackLimit = teb->NtTib.StackLimit;
        out->TlsPointer = teb->ThreadLocalStoragePointer;
        out->PebAddress = teb->ProcessEnvironmentBlock;
        out->LastErrorValue = teb->LastErrorValue;
        out->ArbitraryUserPointer = teb->NtTib.ArbitraryUserPointer;
        out->CountOfOwnedCriticalSections = teb->CountOfOwnedCriticalSections;
        out->Win32ThreadInfo = teb->Win32ThreadInfo;
        out->TLSSlotCount = CountTLSSlots(out->TlsPointer);
        out->ExceptionList = teb->NtTib.ExceptionList;
        out->SubSystemTib  = teb->SubSystemTib;
        out->Self = out->TebAddress;
    
    if (out->PebAddress) {
        memcpy(&peb, out->PebAddress, sizeof(PEB_PARTIAL));

        if (peb.Ldr) {
            PEB_LDR_DATA* ldr = (PEB_LDR_DATA*)peb.Ldr;
            MrtHelper_PrintModules(ldr);
        }

        out->PebBeingDebugged = peb.BeingDebugged;
        out->PebSessionId    = peb.SessionId;
        out->PebLdr = peb.Ldr;

        if (peb.ProcessParameters) {
            RTL_USER_PROCESS_PARAMETERS* params =
                (RTL_USER_PROCESS_PARAMETERS*)peb.ProcessParameters;

            out->PebCommandLine =
                MrtTHelper_UnicodeStringToWString(&params->CommandLine);
            out->PebImagePath =
                MrtTHelper_UnicodeStringToWString(&params->ImagePathName);
        }
    }
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

/**
 * @brief Reads and prints basic information from a process's PEB.
 *
 * Uses the PEB pointer from the first thread of the process to access
 * process-wide information such as command line, image path, debug flag,
 * and session ID.
 *
 * @param proc Pointer to an MRT_PROCESS_INFO structure containing thread info.
 *
 * @return TRUE if the PEB information was successfully read, FALSE otherwise.
 *
 * @note Assumes all threads share the same PEB. Prints info to standard output.
 */
BOOL MrtTInfo_QueryProcessPEB(MRT_PROCESS_INFO* proc)
{
    if (!proc || !proc->Threads || proc->ThreadCount == 0)
        return FALSE;

    // Pick first thread to read PEB (every thread has TEB, and TEB->PEB is the same for all)
    MRT_THREAD_INFO* t = &proc->Threads[0];
    if (!t->TebAddress || !t->PebAddress)
        return FALSE;

    PEB_PARTIAL* peb = (PEB_PARTIAL*)t->PebAddress;
    if (!peb)
        return FALSE;

    // Example: read ProcessParameters
    RTL_USER_PROCESS_PARAMETERS* params =
        (RTL_USER_PROCESS_PARAMETERS*)peb->ProcessParameters;
    if (params && params->CommandLine.Buffer) {
        wchar_t* cmd = MrtTHelper_UnicodeStringToWString(&params->CommandLine);
        if (cmd) {
            wprintf(L"        CommandLine: %s\n", cmd);
            free(cmd);
        }
    }

    if (params && params->ImagePathName.Buffer) {
        wchar_t* imagePath = MrtTHelper_UnicodeStringToWString(&params->ImagePathName);
        if (imagePath) {
            wprintf(L"        ImagePath: %s\n", imagePath);
            free(imagePath);
        }
    }

    // Optional: read BeingDebugged, SessionId
    wprintf(L"        BeingDebugged: %d\n", peb->BeingDebugged);
    wprintf(L"        SessionId: %lu\n", peb->SessionId);

    return TRUE;
}

/**
 * @brief Converts a thread state code to a readable string.
 *
 * Maps NT thread state values to descriptive names for easier logging
 * or debugging.
 *
 * @param state Numeric thread state value.
 * @return A string representing the thread state. Returns "Unknown" for
 *         unrecognized codes.
 */
const char* MrtHelper_ThreadStateToString(ULONG state) {
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

/**
 * @brief Converts a thread wait reason code to a readable string.
 *
 * Maps NT wait reason values to descriptive names for easier logging
 * or debugging.
 *
 * @param reason Numeric wait reason code.
 * @return A string representing the wait reason. Returns "Other" for
 *         unrecognized codes.
 */
const char* MrtHelper_WaitReasonToString(ULONG reason) {
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

/**
 * @brief Counts the number of used TLS (Thread Local Storage) slots.
 *
 * Iterates over the TLS array for a thread and counts how many slots
 * contain non-NULL values, indicating they are in use.
 *
 * @param tlsPointer Pointer to the thread's TLS array.
 * @return Number of TLS slots that are currently used.
 */
static ULONG CountTLSSlots(PVOID tlsPointer)
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

/**
 * @brief Retrieves information about all running processes and their threads.
 *
 * Queries the system using NtQuerySystemInformation to enumerate processes,
 * then gathers detailed information for each process and its threads, including:
 * - Basic process info (PID, parent PID, image name, creation time)
 * - Memory and handle statistics
 * - Thread info (TID, priorities, times, state, wait reason, start address)
 * - TEB and PEB data for threads in the current process
 * - TLS slots count, loader data, process parameters, shutdown info
 * - CPU affinity, ideal processor, and current processor for threads
 *
 * @param Processes Pointer to receive an array of MRT_PROCESS_INFO structures.
 *                  Memory is allocated by the function and must be freed by the caller.
 * @param Count Pointer to receive the number of processes returned.
 *
 * @return NTSTATUS code indicating success or failure.
 *         Common return values include:
 *         - STATUS_SUCCESS
 *         - STATUS_INVALID_PARAMETER
 *         - STATUS_DLL_NOT_FOUND
 *         - STATUS_PROCEDURE_NOT_FOUND
 *         - STATUS_NO_MEMORY
 *
 * @note For threads in other processes, TEB/PEB and CPU info may be incomplete or unavailable.
 */
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

    PFN_NtQueryInformationProcess NtQueryInformationProcess =
            (PFN_NtQueryInformationProcess)GetProcAddress(
                ntdll, "NtQueryInformationProcess");

    if (!NtQuerySystemInformation || !NtQueryInformationThread || !NtQueryInformationProcess)
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
        ULONG memPriority = 0;

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

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, mp->PID);
        if (hProcess) {
            NTSTATUS status = NtQueryInformationProcess(
                hProcess, 
                ProcessMemoryPriority, 
                &memPriority, 
                sizeof(memPriority), 
                NULL
            );
            mp->MemoryPriority = (status >= 0) ? memPriority : 0;
            CloseHandle(hProcess);
        } else {
            mp->MemoryPriority = 0; // fallback
        }

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

                        if (mt->TebAddress && mp->PID == GetCurrentProcessId())
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
                            mt->ExceptionList = teb->NtTib.ExceptionList;
                            mt->SubSystemTib  = teb->SubSystemTib;
                            mt->Self = mt->TebAddress;
                        }

                            if (mt->PebAddress) {
                                PEB_PARTIAL* peb = (PEB_PARTIAL*)mt->PebAddress;

                                mt->PebBeingDebugged = peb->BeingDebugged;
                                mt->PebSessionId     = peb->SessionId;

                                // --- Loader info ---
                                if (peb->Ldr) {
                                    mt->PebLdr = peb->Ldr;
                                    PEB_LDR_DATA* ldr = (PEB_LDR_DATA*)peb->Ldr;
                                    mt->PebLdr_EntryInProgress = ldr->EntryInProgress;
                                }

                                // --- Shutdown info ---
                                mt->ShutdownInProgress = peb->ShutdownInProgress;
                                mt->ShutdownThreadId   = peb->ShutdownThreadId;

                                // --- Process parameters ---
                                if (peb->ProcessParameters) {
                                    RTL_USER_PROCESS_PARAMETERS* params =
                                        (RTL_USER_PROCESS_PARAMETERS*)peb->ProcessParameters;

                                    mt->PebCommandLine =
                                        MrtTHelper_UnicodeStringToWString(&params->CommandLine);
                                    mt->PebImagePath =
                                        MrtTHelper_UnicodeStringToWString(&params->ImagePathName);
                                }
                            }

                        // ---------------- CPU / Affinity info ----------------
                        if (mt->ParentPID == GetCurrentProcessId()) {
                            // open thread with proper access
                            HANDLE hQueryThread = OpenThread(
                                THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION,
                                FALSE,
                                mt->TID
                            );

                            if (hQueryThread) {
                                // ----- Affinity -----
                                DWORD_PTR oldAffinity = SetThreadAffinityMask(hQueryThread, (DWORD_PTR)-1);
                                if (oldAffinity != 0) {
                                    mt->AffinityMask = oldAffinity;
                                    // restore original affinity
                                    SetThreadAffinityMask(hQueryThread, oldAffinity);
                                } else {
                                    mt->AffinityMask = 0;
                                }

                                // ----- Ideal Processor -----
                                DWORD oldIdeal = SetThreadIdealProcessor(hQueryThread, MAXIMUM_PROCESSORS);
                                if (oldIdeal != (DWORD)-1) {
                                    mt->IdealProcessor = oldIdeal;
                                    SetThreadIdealProcessor(hQueryThread, oldIdeal);
                                } else {
                                    mt->IdealProcessor = 0;
                                }
                        
                                // ----- Current CPU -----
                                // Only safe for the calling thread; for others, leave as -1
                                if (GetCurrentThreadId() == mt->TID) {
                                    mt->CurrentProcessor = WrapGetCurrentProcessorNumber();
                                } else {
                                    mt->CurrentProcessor = (ULONG)-1;
                                }

                                CloseHandle(hQueryThread);
                            } else {
                                // fallback if OpenThread failed
                                mt->AffinityMask = 0;
                                mt->IdealProcessor = 0;
                                mt->CurrentProcessor = (ULONG)-1;
                            }
                        } else {
                            // threads from other processes
                            mt->AffinityMask = 0;
                            mt->IdealProcessor = (ULONG)-1;
                            mt->CurrentProcessor = (ULONG)-1;
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

/**
 * @brief Frees memory allocated for an array of MRT_PROCESS_INFO structures.
 *
 * Releases all dynamically allocated memory for each process and its threads,
 * including TEB/PEB strings and the threads array, then frees the main array.
 *
 * @param Processes Pointer to the array of MRT_PROCESS_INFO structures.
 * @param Count Number of processes in the array.
 */
void MrtTInfo_FreeProcesses(MRT_PROCESS_INFO* Processes, ULONG Count) {
    if (!Processes) return;
    for (ULONG i = 0; i < Count; i++) {
        for (ULONG t = 0; t < Processes[i].ThreadCount; t++) {
            free(Processes[i].Threads[t].PebCommandLine);
            free(Processes[i].Threads[t].PebImagePath);
        }
        free(Processes[i].Threads);
    }
    free(Processes);
}

/**
 * @brief Converts a UNICODE_STRING to a null-terminated wide string (wchar_t*).
 *
 * Allocates memory for the new string, which must be freed by the caller.
 *
 * @param ustr Pointer to the UNICODE_STRING to convert.
 * @return Newly allocated null-terminated wide string, or NULL if input is invalid
 *         or memory allocation fails.
 */
wchar_t* MrtTHelper_UnicodeStringToWString(UNICODE_STRING* ustr) {
    if (!ustr || !ustr->Buffer || ustr->Length == 0) return NULL;
    size_t len = ustr->Length / sizeof(WCHAR);
    wchar_t* str = (wchar_t*)malloc((len + 1) * sizeof(WCHAR));
    if (!str) return NULL;
    wcsncpy(str, ustr->Buffer, len);
    str[len] = L'\0';
    return str;
}

/**
 * @brief Finds a process in an array by its PID.
 *
 * Searches through an array of MRT_PROCESS_INFO structures and returns
 * a pointer to the process with the specified PID.
 *
 * @param processes Pointer to the array of MRT_PROCESS_INFO structures.
 * @param count Number of processes in the array.
 * @param pid The process ID to search for.
 * @return Pointer to the matching MRT_PROCESS_INFO, or NULL if not found.
 */
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

/**
 * @brief Finds a thread in an array of processes by its TID.
 *
 * Searches through all processes and their threads to locate a thread
 * with the specified TID. If the thread is the current thread and not
 * found in the snapshot, it queries live thread information.
 *
 * @param processes Pointer to the array of MRT_PROCESS_INFO structures.
 * @param count Number of processes in the array.
 * @param tid The thread ID to search for.
 * @return Pointer to the matching MRT_THREAD_INFO, or NULL if not found.
 */
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
