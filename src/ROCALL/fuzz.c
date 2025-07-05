/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       FUZZ.C
*
*  VERSION:     2.00
*
*  DATE:        05 Jul 2025
*
*  Fuzzing take place here.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#pragma warning(push)
#pragma warning(disable:4100)

DWORD g_privs[] = {
    SE_CREATE_TOKEN_PRIVILEGE,
    SE_ASSIGNPRIMARYTOKEN_PRIVILEGE,
    SE_LOCK_MEMORY_PRIVILEGE,
    SE_INCREASE_QUOTA_PRIVILEGE,
    SE_MACHINE_ACCOUNT_PRIVILEGE,
    SE_TCB_PRIVILEGE,
    SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
    SE_LOAD_DRIVER_PRIVILEGE,
    SE_SYSTEM_PROFILE_PRIVILEGE,
    SE_SYSTEMTIME_PRIVILEGE,
    SE_PROF_SINGLE_PROCESS_PRIVILEGE,
    SE_INC_BASE_PRIORITY_PRIVILEGE,
    SE_CREATE_PAGEFILE_PRIVILEGE,
    SE_CREATE_PERMANENT_PRIVILEGE,
    SE_BACKUP_PRIVILEGE,
    SE_RESTORE_PRIVILEGE,
    SE_SHUTDOWN_PRIVILEGE,
    SE_DEBUG_PRIVILEGE,
    SE_AUDIT_PRIVILEGE,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE,
    SE_CHANGE_NOTIFY_PRIVILEGE,
    SE_REMOTE_SHUTDOWN_PRIVILEGE,
    SE_UNDOCK_PRIVILEGE,
    SE_SYNC_AGENT_PRIVILEGE,
    SE_ENABLE_DELEGATION_PRIVILEGE,
    SE_MANAGE_VOLUME_PRIVILEGE,
    SE_IMPERSONATE_PRIVILEGE,
    SE_CREATE_GLOBAL_PRIVILEGE,
};

/*
* ntSyscallGateX86
*
* Purpose:
*
* Direct system call.
*
*/
__declspec(naked)
ULONG
NTAPI
ntSyscallGateX86(
    ULONG ServiceID,
    ULONG ArgsCount,
    PULONG Args)
{
    __asm {
        push ebx
        push edi
        push esi

        mov esi, dword ptr[esp + 0x18] // Args
        mov ebx, dword ptr[esp + 0x14] // ArgsCount
        mov eax, dword ptr[esp + 0x10] // ServiceID

        // load stack with args
        mov ecx, ebx
        lea ebx, dword ptr[ebx * 4]
        sub esp, ebx
        mov edi, esp
        repne movsd
        call syscall_stub

        add esp, ebx

        pop esi
        pop edi
        pop ebx
        retn 0xc
        int 3
        int 3

        syscall_stub:
        mov edx, 0x07FFE0300 //UserSharedData->SystemCall
            call dword ptr[edx]
            retn
    }
}
#pragma warning(pop)

/*
* DoSystemCall
*
* Purpose:
*
* Run syscall with random parameters.
*
*/
VOID DoSystemCall(
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ PVOID LogParams,
    _In_ LPCSTR ServiceName,
    _In_ BOOL EnableParamsHeuristic,
    _In_ BOOL LogEnabled
)
{
    ULONG c;
    BOOL isWin32kSyscall = (ServiceId >= W32SYSCALLSTART);
    NTSTATUS status;
    ULONG args[MAX_PARAMETERS];
    PARAM_TYPE_HINT typeHints[MAX_PARAMETERS];

    // Local thread buffer for parameters generation
    BYTE fuzzStructBuffer[MAX_STRUCT_BUFFER_SIZE] = { 0 };

    g_MemoryTracker.Count = 0;
    g_MemoryTracker.InUse = TRUE;

    RtlZeroMemory(&args, sizeof(args));
    RtlZeroMemory(&typeHints, sizeof(typeHints));

    if (EnableParamsHeuristic) {
        FuzzDetectParameterTypes(ServiceName, NumberOfArguments, isWin32kSyscall, typeHints);
    }

    for (c = 0; c < NumberOfArguments; c++) {
        args[c] = FuzzGenerateParameter(c, typeHints[c], isWin32kSyscall,
            EnableParamsHeuristic, fuzzStructBuffer);
    }

    if (LogEnabled && LogParams) {
        FuzzLogCallBinary((PLOG_PARAMS)LogParams,
            ServiceId,
            NumberOfArguments,
            args);
    }

    status = ntSyscallGateX86(
        ServiceId,
        NumberOfArguments,
        (PULONG)&args);

    InterlockedIncrement((PLONG)&g_FuzzStats.TotalCalls);

    if (NT_SUCCESS(status)) {
        InterlockedIncrement((PLONG)&g_FuzzStats.SuccessCalls);
    }
    else {
        InterlockedIncrement((PLONG)&g_FuzzStats.ErrorCalls);
    }
}

/*
* FuzzThreadProc
*
* Purpose:
*
* Call service thread.
*
*/
DWORD WINAPI FuzzThreadProc(
    _In_ LPVOID lpThreadParameter
)
{
    ULONG i, passCount;
    CALL_PARAM* context = (CALL_PARAM*)lpThreadParameter;

    passCount = context->NumberOfPassesForCall;

    __try {
        for (i = 0; i < passCount; i++) {
            DoSystemCall(context->Syscall,
                context->NumberOfArguments,
                context->LogParams,
                context->ServiceName,
                context->EnableParamsHeuristic,
                context->LogEnabled);

            FuzzCleanupAllocations();
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FuzzCleanupAllocations();
        InterlockedIncrement((PLONG)&g_FuzzStats.CrashedCalls);
    }

    return 0;
}

/*
* FuzzPrintServiceInformation
*
* Purpose:
*
* Display service information.
*
*/
void FuzzPrintServiceInformation(
    _In_ ULONG ServicesCount,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG ServiceId,
    _In_opt_ LPCSTR ServiceName,
    _In_ BOOL BlackListed)
{
    CHAR szConsoleText[4096];
    WORD wColor = (BlackListed) ? FOREGROUND_GREEN | FOREGROUND_INTENSITY : 0;

    if (BlackListed) {
        StringCchPrintfA(szConsoleText, sizeof(szConsoleText),
            "\r[%04lu/%04lu] Service: %s, args: %lu - found in blacklist, skipped",
            ServiceId,
            ServicesCount,
            ServiceName,
            NumberOfArguments);

        ConsoleShowMessage(szConsoleText, wColor);
    }
    else {

        StringCchPrintfA(szConsoleText, sizeof(szConsoleText),
            "\r[%04lu/%04lu] Service: %s, args: %lu",
            ServiceId,
            ServicesCount,
            ServiceName,
            NumberOfArguments);

        ConsoleShowMessage2(szConsoleText, wColor);
    }
}

/*
* FuzzCriticalStructures
*
* Purpose:
*
* Perform destructive tests on critical Windows structures after syscall fuzzing.
* This is highly likely to crash the process but may reveal kernel vulnerabilities.
*
*/
VOID FuzzCriticalStructures(
    VOID
)
{
    CHAR szOut[MAX_PATH * 2];
    HANDLE hThread = NULL;
    PVOID pTeb = NULL, pPeb = NULL;
    PVOID pSectionBase = NULL;
    DWORD dwThreadId = 0;
    PVOID baseAddress;
    SIZE_T regionSize;
    BOOL loggedMessage = FALSE;
    MEMORY_BASIC_INFORMATION memInfo;

    ConsoleShowMessage("[!] Starting critical structure tests - system instability expected", TEXT_COLOR_RED);

    // Get PEB and TEB addresses
    pTeb = NtCurrentTeb();

    if (pTeb) {
        pPeb = *(PVOID*)((PBYTE)pTeb + 0x30); // PEB pointer offset in TEB

        StringCchPrintfA(szOut, sizeof(szOut), "[+] TEB found at 0x%p, PEB at 0x%p", pTeb, pPeb);
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
    }
    else {
        ConsoleShowMessage("[-] Failed to locate TEB/PEB", TEXT_COLOR_RED);
        return;
    }

    // Create a thread to have more targets
    hThread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)Sleep,
        (LPVOID)INFINITE,
        CREATE_SUSPENDED,
        &dwThreadId);

    if (hThread) {
        StringCchPrintfA(szOut, sizeof(szOut), "[+] Created test thread %lu", dwThreadId);
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
    }

    ConsoleShowMessage("[!] Beginning destructive tests - crashes are expected", TEXT_COLOR_RED);

    if (pPeb) {

        //
        // =========================
        // TEST 1: TEB Corruption
        // =========================
        //

        __try {
            FuzzLogLastService("TEB Corruption (TEB.LastErrorValue)");

            // Corrupt TEB.LastErrorValue
            PULONG pLastError = (PULONG)((PBYTE)pTeb + 0x34);
            *pLastError = 0xDEADCAFE;

            StringCchPrintfA(szOut, sizeof(szOut), "[+] Corrupted TEB.LastErrorValue -> 0xDEADCAFE");
            ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);

            FuzzLogLastService("TEB Corruption (TEB.CountOfOwnedCriticalSections)");

            // Corrupt TEB.CountOfOwnedCriticalSections
            PULONG pCountCS = (PULONG)((PBYTE)pTeb + 0x6A0);
            *pCountCS = 0xFFFFFFFF;

            StringCchPrintfA(szOut, sizeof(szOut), "[+] Corrupted TEB.CountOfOwnedCriticalSections -> 0xFFFFFFFF");
            ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);

            loggedMessage = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ConsoleShowMessage("[-] Exception during TEB corruption test", TEXT_COLOR_RED);
        }

        //
        // ===============================
        // TEST 2: Change TEB/PEB Permissions
        // ===============================
        //
        __try {
            DWORD oldProtect;

            FuzzLogLastService("TEB Corruption (Protection PAGE_READONLY)");

            if (VirtualProtect(pTeb, 0x1000, PAGE_READONLY, &oldProtect)) {
                StringCchPrintfA(szOut, sizeof(szOut), "[+] Changed TEB protection  PAGE_READONLY");
                ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
                loggedMessage = TRUE;
            }

            FuzzLogLastService("PEB Corruption (Protection PAGE_READONLY)");

            if (VirtualProtect(pPeb, 0x1000, PAGE_READONLY, &oldProtect)) {
                StringCchPrintfA(szOut, sizeof(szOut), "[+] Changed PEB protection PAGE_READONLY");
                ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
                loggedMessage = TRUE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ConsoleShowMessage("[-] Exception changing TEB/PEB permissions", TEXT_COLOR_RED);
        }

        //
        // ===============================
        // TEST 3: Unmap Critical DLLs
        // ===============================
        //

        __try {
            FuzzLogLastService("PEB->LDR Unmap critical DLLs");

            PPEB_LDR_DATA pLdr = *(PPEB_LDR_DATA*)((PBYTE)pPeb + 0x0C);
            if (pLdr) {
                PLIST_ENTRY pListEntry = pLdr->InLoadOrderModuleList.Flink;
                PLDR_DATA_TABLE_ENTRY pEntry;

                while (pListEntry != &pLdr->InLoadOrderModuleList) {
                    pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                    if (pEntry->BaseDllName.Buffer &&
                        _strcmpi_w(pEntry->BaseDllName.Buffer, L"ntdll.dll") == 0) {

                        pSectionBase = pEntry->DllBase;

                        StringCchPrintfA(szOut, sizeof(szOut), "[+] Found ntdll.dll");
                        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);

                        baseAddress = (PVOID)((ULONG_PTR)pSectionBase + 0x1000);
                        regionSize = 0x1000;

                        NtUnmapViewOfSection(GetCurrentProcess(), baseAddress);

                        if (NT_SUCCESS(NtQueryVirtualMemory(GetCurrentProcess(),
                            pSectionBase,
                            MemoryBasicInformation,
                            &memInfo,
                            sizeof(memInfo),
                            NULL)))
                        {
                            PVOID iatAddress = (PVOID)((ULONG_PTR)pSectionBase + 0x2000);
                            DWORD oldProtect;

                            if (VirtualProtect(iatAddress, 0x100, PAGE_READWRITE, &oldProtect)) {
                                *(PDWORD)iatAddress = 0xDEADC0DE;
                                *((PDWORD)iatAddress + 1) = 0xCAFEBABE;
                                *((PDWORD)iatAddress + 2) = 0xBAADF00D;

                                StringCchPrintfA(szOut, sizeof(szOut),
                                    "[+] Corrupted potential IAT");
                                ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);

                                VirtualProtect(iatAddress, 0x100, oldProtect, &oldProtect);
                            }
                        }

                        loggedMessage = TRUE;
                        break;
                    }

                    pListEntry = pListEntry->Flink;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ConsoleShowMessage("[-] Exception during DLL unmapping test", TEXT_COLOR_RED);
        }
    }

    //
    // ===============================
    // TEST 4: Execute Invalid Code
    // ===============================
    //
    __try {
        FuzzLogLastService("Execute Invalid Code");

        PVOID execMem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (execMem) {
            memset(execMem, 0xF4, 0x1000); // 0xF4 = HLT instruction

            StringCchPrintfA(szOut, sizeof(szOut), "[!] Attempting to execute invalid code");
            ConsoleShowMessage(szOut, TEXT_COLOR_RED);

            ((void(*)())execMem)();

            ConsoleShowMessage("[!] Executed invalid code without exception!", TEXT_COLOR_RED);
            VirtualFree(execMem, 0, MEM_RELEASE);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ConsoleShowMessage("[+] Expected exception from invalid code execution", TEXT_COLOR_CYAN);
        loggedMessage = TRUE;
    }

    //
    // Clean up
    //
    if (hThread) {
        ResumeThread(hThread);
        CloseHandle(hThread);
    }

    if (!loggedMessage) {
        ConsoleShowMessage("[-] No critical structure tests succeeded", TEXT_COLOR_RED);
    }

    ConsoleShowMessage("[+] Critical structure tests completed", TEXT_COLOR_CYAN);
}

/*
* FuzzRun
*
* Purpose:
*
* Perform reactos syscall table fuzzing.
*
*/
UINT FuzzRun(
    _In_ BLACKLIST* BlackList,
    _In_ PFUZZ_PARAMS Context
)
{
    UINT result = 0;
    BOOLEAN bWasEnabled;
    BOOL probeWin32k = Context->ProbeWin32k, bSkip = FALSE;
    ULONG i, syscallIndex, syscallMax, sid;
    ULONG numberOfArguments;
    DWORD dwThreadId, enabled;
    CHAR* serviceName;
    CONST SYSCALL_ENTRY* serviceTable;
    HANDLE hThread = NULL;
    CALL_PARAM callParams;
    CHAR szOut[MAX_PATH * 2];

    ConsoleShowMessage("[+] Entering FuzzRun()", TEXT_COLOR_CYAN);

    // Assign as much privileges as we can.
    enabled = 0;
    for (i = 0; i < _countof(g_privs); i++) {
        if (NT_SUCCESS(RtlAdjustPrivilege(g_privs[i], TRUE, FALSE, &bWasEnabled)))
            enabled++;
    }
    // Warn if less than half of requested privileges could be enabled.
    // This is not usually critical for normal user runs, but may indicate
    // unusual restrictions or a non-admin context.
    if (enabled < (_countof(g_privs) / 2)) {
        StringCchPrintfA(szOut, sizeof(szOut),
            "[~] Warning: Only a minority of privileges were enabled (%lu/%lu)",
            enabled, _countof(g_privs));
        ConsoleShowMessage(szOut, TEXT_COLOR_YELLOW);
    }
    else {
        StringCchPrintfA(szOut, sizeof(szOut),
            "[+] Majority of privileges were enabled (%lu/%lu)",
            enabled, _countof(g_privs));
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
    }

    if (probeWin32k) {
        serviceTable = W32pServiceTable;
        syscallMax = W32pServiceLimit;
    }
    else {
        serviceTable = KiServiceTable;
        syscallMax = KiServiceLimit;
    }

    syscallIndex = 0;
    if (Context->ProbeFromSyscallId) {
        syscallIndex = Context->SyscallStartFrom;
        if (probeWin32k)
            syscallIndex -= W32SYSCALLSTART;
    }

    // Iterate through services and call them with predefined bad arguments
    for (; syscallIndex < syscallMax; syscallIndex++)
    {
        StringCchPrintfA(szOut, sizeof(szOut), "%lu", syscallIndex);
        SetConsoleTitleA(szOut);

        serviceName = (CHAR*)serviceTable[syscallIndex].Name;
        numberOfArguments = serviceTable[syscallIndex].NumberOfArguments;

        if (probeWin32k) {
            sid = W32SYSCALLSTART + syscallIndex;
        }
        else {
            sid = syscallIndex;
        }

        bSkip = BlackListEntryPresent(BlackList, (LPCSTR)serviceName);

        // Print service info
        FuzzPrintServiceInformation(
            syscallMax,
            numberOfArguments,
            (probeWin32k) ? sid - W32SYSCALLSTART : sid,
            serviceName,
            bSkip);

        if (bSkip) {
            bSkip = FALSE;
            continue;
        }

        // Always log last service name
        FuzzLogLastService(serviceName);
        Sleep(50);

        // Create caller thread and do syscall in it
        callParams.NumberOfArguments = numberOfArguments;
        callParams.Syscall = sid;
        callParams.NumberOfPassesForCall = Context->PassCount;
        callParams.ServiceName = serviceName;
        callParams.ThreadTimeout = Context->WaitTimeout;
        callParams.EnableParamsHeuristic = Context->EnableParamsHeuristic;
        callParams.LogParams = &g_Log;
        callParams.LogEnabled = Context->LogEnabled;

        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FuzzThreadProc,
            (LPVOID)&callParams, 0, &dwThreadId);

        if (hThread) {
            if (WaitForSingleObject(hThread, Context->WaitTimeout * 1000) == WAIT_TIMEOUT) {
                InterlockedIncrement((PLONG)&g_FuzzStats.TimeoutCalls);
                TerminateThread(hThread, (DWORD)-1);
                StringCchPrintfA(szOut, sizeof(szOut),
                    "\r\n[~]Timeout reached for callproc of service: %s, callproc terminated",
                    serviceName);
                ConsoleShowMessage(szOut, 0);
            }
            CloseHandle(hThread);
        }
    }

    StringCchPrintfA(szOut, sizeof(szOut), "\r----FuzzRun statistics----\r\n"\
        "Succeeded calls: %lu\r\n"\
        "Error calls: %lu\r\n"\
        "Crashed calls: %lu\r\n"\
        "Timed out calls: %lu\r\n"\
        "Total calls: %lu\r\n----FuzzRun statistics----\r\n",
        g_FuzzStats.SuccessCalls,
        g_FuzzStats.ErrorCalls,
        g_FuzzStats.CrashedCalls,
        g_FuzzStats.TimeoutCalls,
        g_FuzzStats.TotalCalls);

    ConsoleShowMessage2(szOut, 0);
    ConsoleShowMessage("[-] Leaving FuzzRun()", TEXT_COLOR_CYAN);

    return result;
}