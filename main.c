#include <windows.h>
#include <stdio.h>
#include "MrtTInfo.h"

int wmain(void) {
    MRT_PROCESS_INFO* processes = NULL;
    ULONG count = 0;

    NTSTATUS status = MrtTInfo_GetAllProcesses(&processes, &count);
    if (!NT_SUCCESS(status)) {
        wprintf(L"Failed to get processes: 0x%08X\n", status);
        return 1;
    }

    wprintf(L"Found %lu processes\n\n", count);

    for (ULONG i = 0; i < count; i++) {
        MRT_PROCESS_INFO* p = &processes[i];
        wchar_t* pname = MrtTInfo_UnicodeStringToWString(&p->ImageName);
        if (!pname) pname = L"(unknown)";

        wprintf(L"Process: %s (PID: %lu, Parent: %lu)\n", pname, p->PID, p->ParentPID);
        wprintf(L"  Threads: %lu\n", p->ThreadCount);
        for (ULONG t = 0; t < p->ThreadCount; t++) {
            MRT_THREAD_INFO* th = &p->Threads[t];
            wprintf(L"    Thread TID: %lu, Priority: %ld, State: %lu, WaitReason: %lu\n",
                    th->TID, th->Priority, th->ThreadState, th->WaitReason);
        }

        if (pname != L"(unknown)") free(pname);
        wprintf(L"\n");
    }

    MrtTInfo_FreeProcesses(processes, count);
    return 0;
}
