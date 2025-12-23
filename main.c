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

    // print a few basic details
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

        // print first few threads
        for (ULONG t = 0; t < p->ThreadCount && t < 3; t++) {
            MRT_THREAD_INFO* th = &p->Threads[t];
            wprintf(L"      TID: %-6lu  BasePrio: %-2ld  State: %-15hs  Wait: %-15hs  "
                    L"ExceptionList: %p\n",
                    th->TID,
                    th->BasePriority,
                    MrtHelper_ThreadStateToString(th->ThreadState),
                    MrtHelper_WaitReasonToString(th->WaitReason),
                    th->ExceptionList);

            if (th->ParentPID == GetCurrentProcessId() && th->ExceptionList)
                MrtHelper_PrintSEHChain(th->ExceptionList);
        }

        wprintf(L"\n");
        free(imageName);

    }

    // demonstrate lookup helpers
    DWORD testPID = GetCurrentProcessId();
    MRT_PROCESS_INFO* selfProc = MrtTInfo_FindProcessByPID(processes, processCount, testPID);
    if (selfProc) {
        wprintf(L"[Lookup] Found current process by PID %lu (%.*s)\n",
                testPID,
                selfProc->ImageName.Length / 2,
                selfProc->ImageName.Buffer);
    } else {
        wprintf(L"[Lookup] Current process not found by PID!\n");
    }

    // try finding one thread by TID (the current one)
    DWORD tid = GetCurrentThreadId();
    MRT_THREAD_INFO* selfThread = MrtTInfo_FindThreadByTID(processes, processCount, tid);
    if (selfThread) {
        wprintf(L"[Lookup] Found current thread by TID %lu, base priority %ld, TEB: %p\n",
                tid, selfThread->BasePriority, selfThread->TebAddress);
    } else {
        wprintf(L"[Lookup] Current thread not found by TID!\n");
    }

    // cleanup
    MrtTInfo_FreeProcesses(processes, processCount);
    wprintf(L"\nDone.\n");
    return 0;
}
