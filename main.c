#include <windows.h>
#include <stdio.h>
#include "MrtTInfo.h"

int main(void)
{
    MRT_PROCESS_INFO* processes = NULL;
    ULONG processCount = 0;
    NTSTATUS status;

    wprintf(L"[MrtTInfo Test]\n\n");

    Sleep(200); // give scheduler time to record thread info
    status = MrtTInfo_GetAllProcesses(&processes, &processCount);
    if (!NT_SUCCESS(status)) {
        wprintf(L"Failed to get process info (NTSTATUS 0x%08X)\n", status);
        return 1;
    }

    wprintf(L"Total processes: %lu\n\n", processCount);

    // Print a few basic details
    for (ULONG i = 0; i < processCount; i++) {
        MRT_PROCESS_INFO* p = &processes[i];
        wchar_t* imageName = MrtTInfo_UnicodeStringToWString(&p->ImageName);

        wprintf(L"PID: %-5lu  PPID: %-5lu  Name: %s\n",
                p->PID,
                p->ParentPID,
                imageName ? imageName : L"<unnamed>");

        wprintf(L"    Threads: %lu  Handles: %lu  WS: %zu KB\n",
                p->ThreadCount,
                p->HandleCount,
                p->WorkingSetSize / 1024);

        // Print first few threads
        BOOL isX86 = (sizeof(void*) == 4);

        for (ULONG t = 0; t < p->ThreadCount && t < 3; t++) {
            MRT_THREAD_INFO* th = &p->Threads[t];

            wprintf(L"      TID: %-6lu  BasePrio: %-2ld  State: %-15hs  Wait: %-15hs  "
                    L"ExceptionList: %p  SubSystemTib: %p  Self: %p\n",
                    th->TID,
                    th->BasePriority,
                    MrtHelper_ThreadStateToString(th->ThreadState),
                    MrtHelper_WaitReasonToString(th->WaitReason),
                    th->ExceptionList,
                    (PVOID)(ULONG_PTR)th->SubSystemTib,
                    th->Self);

            if (!isX86) {
                wprintf(L"  (warning: SubSystemTib only valid on x86)");
            }

            wprintf(L"\n");

            // Print SEH chain for threads of the current process
            if (th->ParentPID == GetCurrentProcessId() && th->ExceptionList)
                MrtHelper_PrintSEHChain(th->ExceptionList);
        }
    }


    // Demonstrate lookup helpers
    DWORD testPID = GetCurrentProcessId();
    MRT_PROCESS_INFO* selfProc = MrtTInfo_FindProcessByPID(processes, processCount, testPID);
    if (selfProc) {
        wchar_t* name = MrtTInfo_UnicodeStringToWString(&selfProc->ImageName);
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
