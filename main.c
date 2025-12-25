#include <windows.h>
#include <stdio.h>
#include "MrtTInfo.h"

int main(void)
{
    MRT_PROCESS_INFO* processes = NULL;
    ULONG processCount = 0;
    NTSTATUS status;

    wprintf(L"[MrtTInfo Test]\n\n");

    Sleep(500); // give scheduler time to record thread info
    status = MrtTInfo_GetAllProcesses(&processes, &processCount);
    if (!NT_SUCCESS(status)) {
        wprintf(L"Failed to get process info (NTSTATUS 0x%08X)\n", status);
        return 1;
    }

    wprintf(L"Total processes: %lu\n\n", processCount);

    // Print a few basic details
    for (ULONG i = 0; i < processCount; i++) {
        MRT_PROCESS_INFO* p = &processes[i];
        wchar_t* imageName = MrtTHelper_UnicodeStringToWString(&p->ImageName);

        wprintf(L"PID: %-5lu  PPID: %-5lu  Name: %s\n",
                p->PID,
                p->ParentPID,
                imageName ? imageName : L"<unnamed>");

        wprintf(L"    Threads: %lu  Handles: %lu  WS: %zu KB  MemPrio: %lu\n",
                p->ThreadCount,
                p->HandleCount,
                p->WorkingSetSize / 1024,
                p->MemoryPriority);

        // Print first few threads
        for (ULONG t = 0; t < p->ThreadCount && t < 3; t++) {
            MRT_THREAD_INFO* th = &p->Threads[t];

            // ---- Header line (UNCHANGED) ----
            wprintf(
                L"      TID: %-6lu  BasePrio: %-2ld  State: %-15hs  Wait: %-15hs  ",
                th->TID,
                th->BasePriority,
                MrtHelper_ThreadStateToString(th->ThreadState),
                MrtHelper_WaitReasonToString(th->WaitReason)
            );

            wprintf(L"\n");

            // Print EntryInProgress from loader if available
            if (th->PebLdr) {
                PEB_LDR_DATA* ldr = (PEB_LDR_DATA*)th->PebLdr;
                wprintf(L"EntryInProgress: %p  ", ldr->EntryInProgress);

                // Print Shutdown info
                wprintf(L"ShutdownInProgress: %s  ShutdownThreadId: %p\n",
                        th->ShutdownInProgress ? L"YES" : L"NO",
                        th->ShutdownThreadId);

                // ---- Module list ----
                MrtHelper_PrintModules(ldr);

            }
        }
    }

    // Demonstrate lookup helpers
    DWORD testPID = GetCurrentProcessId();
    MRT_PROCESS_INFO* selfProc = MrtTInfo_FindProcessByPID(processes, processCount, testPID);
    if (selfProc) {
        wchar_t* name = MrtTHelper_UnicodeStringToWString(&selfProc->ImageName);
        wprintf(L"[Lookup] Found current process by PID %lu (%s)\n",
                testPID,
                name ? name : L"<unnamed>");
        free(name);
    } else {
        wprintf(L"[Lookup] Current process not found by PID!\n");
    }

    DWORD tid = GetCurrentThreadId();
    MRT_THREAD_INFO* selfThread = MrtTInfo_FindThreadByTID(processes, processCount, tid);
    if (selfThread) {
        wprintf(L"[Lookup] Found current thread by TID %lu, base priority %ld, TEB: %p\n",
                tid, selfThread->BasePriority, selfThread->TebAddress);
    } else {
        wprintf(L"[Lookup] Current thread not found by TID!\n");
    }

    // Cleanup
    MrtTInfo_FreeProcesses(processes, processCount);
    wprintf(L"\nDone.\n");
    return 0;
}
