#include <windows.h>
#include <stdio.h>
#include "MrtTInfo.h"

int main(void)
{
    MRT_PROCESS_INFO* processes = NULL;
    ULONG processCount = 0;
    NTSTATUS status;

    wprintf(L"[MrtTInfo Test]\n\n");

    Sleep(500);
    status = MrtTInfo_GetAllProcesses(&processes, &processCount);
    if (!NT_SUCCESS(status)) {
        wprintf(L"Failed to get process info (NTSTATUS 0x%08X)\n", status);
        return 1;
    }

    wprintf(L"Total processes: %lu\n\n", processCount);

    for (ULONG i = 0; i < processCount; i++) {
        MRT_PROCESS_INFO* p = &processes[i];

        if (p->PID == 0)
            continue;

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

        free(imageName);

        for (ULONG t = 0; t < p->ThreadCount && t < 3; t++) {
            MRT_THREAD_INFO* th = &p->Threads[t];

            wprintf(L"      TID: %-6lu  BasePrio: %-2ld  State: %-20hs  Wait: %hs\n",
                    th->TID,
                    th->BasePriority,
                    MrtHelper_ThreadStateToString(th->ThreadState),
                    MrtHelper_WaitReasonToString(th->WaitReason));

            if (th->StartAddress && th->EndAddress) {
                wprintf(L"        StartAddress: %p  EndAddress: %p  Size: 0x%Ix bytes\n",
                        th->StartAddress, th->EndAddress,
                        (SIZE_T)((PBYTE)th->EndAddress - (PBYTE)th->StartAddress));
            } else if (th->StartAddress) {
                wprintf(L"        StartAddress: %p  EndAddress: <n/a>\n", th->StartAddress);
            } else {
                wprintf(L"        StartAddress: <n/a>  EndAddress: <n/a>\n");
            }

            if (th->TebAddress) {
                wprintf(L"        TEB: %p  Stack: %p - %p  TLS used: %lu/108\n",
                        th->TebAddress, th->StackLimit, th->StackBase, th->TLSSlotCount);
            }

            if (th->PebLdr) {
                PEB_LDR_DATA* ldr = (PEB_LDR_DATA*)th->PebLdr;
                wprintf(L"        Ldr: %p  EntryInProgress: %p  Shutdown: %s\n",
                        th->PebLdr,
                        th->PebLdr_EntryInProgress,
                        th->ShutdownInProgress ? L"YES" : L"NO");
                if (p->PID == GetCurrentProcessId())
                    MrtHelper_PrintModules(ldr);
            }

            if (th->PebCommandLine)
                wprintf(L"        CmdLine: %s\n", th->PebCommandLine);
        }

        wprintf(L"\n");
    }

    // Lookup helpers
    DWORD testPID = GetCurrentProcessId();
    MRT_PROCESS_INFO* selfProc = MrtTInfo_FindProcessByPID(processes, processCount, testPID);
    if (selfProc) {
        wchar_t* name = MrtTHelper_UnicodeStringToWString(&selfProc->ImageName);
        wprintf(L"[Lookup] Found self: PID %lu (%s)\n",
                testPID, name ? name : L"<unnamed>");
        free(name);
    } else {
        wprintf(L"[Lookup] Current process not found!\n");
    }

    DWORD tid = GetCurrentThreadId();
    MRT_THREAD_INFO* selfThread = MrtTInfo_FindThreadByTID(processes, processCount, tid);
    if (selfThread) {
        wprintf(L"[Lookup] Found self thread: TID %lu  BasePrio: %ld  TEB: %p\n",
                tid, selfThread->BasePriority, selfThread->TebAddress);
        if (selfThread->PebCommandLine)
            wprintf(L"         CmdLine: %s\n", selfThread->PebCommandLine);
    } else {
        wprintf(L"[Lookup] Current thread not found!\n");
    }

    MrtTInfo_FreeProcesses(processes, processCount);
    wprintf(L"\nDone.\n");
    return 0;
}