/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        05 Dec 2018
*
*  Program entry point.
*
*  Codename: Aquila KC
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#include "global.h"

//
// Copy-paste begin.
//

//
// Invoke bullshit mantra lvl 80
//
//
//  "There is no ReactOS code in RoCall. There never was. 
//   There was never such an accusation in the first place."
//

#define ServiceMacro(name, argcount) (CHAR*)"Nt"##name,
CHAR *KiServiceTableNames[] = {
#include "KiServiceTable.h"
};
#undef ServiceMacro

#define ServiceMacro(name, argcount) argcount * sizeof(void *), 
UCHAR KiServiceArgumentTable[] = {
#include "KiServiceTable.h"
};
#undef ServiceMacro

#define ServiceMacro(name, argcount) (CHAR*)"Nt"##name,
CHAR *W32pServiceTableNames[] = {
#include "W32pServiceTable.h"
};
#undef ServiceMacro

#define ServiceMacro(name, argcount) argcount * sizeof(void *), 
UCHAR W32pServiceArgumentTable[] = {
#include "W32pServiceTable.h"
};
#undef ServiceMacro

#define NTOS_MIN_SYSCALL_NUMBER    0
#define NTOS_NUMBER_OF_SYSCALLS    (sizeof(KiServiceArgumentTable) / sizeof(KiServiceArgumentTable[0]))
#define NTOS_MAX_SYSCALL_NUMBER    (NTOS_NUMBER_OF_SYSCALLS - 1)

#define W32K_MIN_SYSCALL_NUMBER    0x1000
#define W32K_NUMBER_OF_SYSCALLS    (sizeof(W32pServiceArgumentTable) / sizeof(W32pServiceArgumentTable[0]))
#define W32K_MAX_SYSCALL_NUMBER    W32K_MIN_SYSCALL_NUMBER + (W32K_NUMBER_OF_SYSCALLS - 1)

//
// Copy-paste end.
//

//
// COM1 Log handle
//
HANDLE g_hLoggingPort = INVALID_HANDLE_VALUE;

// 
// Number of fuzzing passes
//
ULONG g_pcValue = FUZZ_PASS_COUNT;

//
// Verbose logging
//
BOOL g_bLogVerbose = FALSE;

//
// Reactos real version global
//
REACTOS_VERSION g_rosVer;

/*
* FuzzLogCallName
*
* Purpose:
*
* Send syscall name to the log before it is not too late.
*
*/
VOID FuzzLogCallName(
    _In_ LPCSTR ServiceName
)
{
    ULONG bytesIO;
    CHAR szLog[128];

    if (g_hLoggingPort) {
        WriteFile(g_hLoggingPort, (LPCVOID)ServiceName,
            (DWORD)_strlen_a(ServiceName), &bytesIO, NULL);

        _strcpy_a(szLog, "\r\n");
        WriteFile(g_hLoggingPort, (LPCVOID)&szLog,
            (DWORD)_strlen_a(szLog), &bytesIO, NULL);
    }
}

/*
* FuzzLogCallParameters
*
* Purpose:
*
* Send syscall parameters to the log before it is not too late.
*
*/
VOID FuzzLogCallParameters(
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG *Arguments
)
{
    ULONG i;
    DWORD bytesIO;
    CHAR szLog[2048];

    if (g_hLoggingPort == INVALID_HANDLE_VALUE)
        return;

    ultostr_a(ServiceId, _strcpy_a(szLog, "[RoCall] ServiceId = "));
    ultostr_a(NumberOfArguments, _strcat_a(szLog, " NumberOfArgs = "));
    _strcat_a(szLog, " Arguments:");

    for (i = 0; i < NumberOfArguments; i++) {
        ultohex_a(Arguments[i], _strcat_a(szLog, " "));
    }
    _strcat_a(szLog, "\r\n");
    WriteFile(g_hLoggingPort, (LPCVOID)&szLog,
        (DWORD)_strlen_a(szLog), &bytesIO, NULL);
}

/*
* VehHandler
*
* Purpose:
*
* Vectored exception handler.
*
*/
LONG CALLBACK VehHandler(
    EXCEPTION_POINTERS *ExceptionInfo
)
{
    HMODULE hModule = GetModuleHandle(TEXT("kernel32.dll"));
    if (hModule) {
        ExceptionInfo->ContextRecord->Eip = (DWORD)GetProcAddress(hModule, "ExitThread");
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

BLACKLIST g_NtOsBlackList;
BLACKLIST g_W32kBlackList;

#define DECLSPEC_NAKED __declspec(naked)

#pragma warning(push)
#pragma warning(disable:4100)

/*
* system_call_x86
*
* Purpose:
*
* Direct system call.
*
*/
DECLSPEC_NAKED
ULONG
NTAPI
system_call_x86(
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


#include <intrin.h>

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
    _In_ ULONG NumberOfArguments
)
{
    ULONG i;
    ULONG64 u_rand;
    ULONG Arguments[ARGUMENT_COUNT];

    __try {

        RtlSecureZeroMemory(Arguments, ARGUMENT_COUNT * sizeof(ULONG));

        for (i = 0; i < NumberOfArguments; i++) {
            u_rand = __rdtsc();
            Arguments[i] = fuzzdata[u_rand % SIZEOF_FUZZDATA];
        }

        if (g_bLogVerbose)
            FuzzLogCallParameters(ServiceId, NumberOfArguments, Arguments);

        system_call_x86(
            ServiceId,
            NumberOfArguments,
            (PULONG)&Arguments);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ;
    }
}

/*
* CallThread
*
* Purpose:
*
* Call service thread.
*
*/
DWORD WINAPI CallThread(
    _In_ LPVOID lpThreadParameter
)
{
    ULONG currentPass;
    ULONG ServiceId;
    ULONG NumberOfArguments;

    CALL_PARAM *CallParam = (CALL_PARAM*)lpThreadParameter;

    NumberOfArguments = CallParam->NumberOfArguments;
    ServiceId = CallParam->ServiceId;

    currentPass = 0;

    do {

        DoSystemCall(ServiceId, NumberOfArguments);

        currentPass++;

    } while (currentPass < g_pcValue);

    ExitThread(0);
}

/*
* PrintServiceInformation
*
* Purpose:
*
* Display service information.
*
*/
void PrintServiceInformation(
    _In_ ULONG NumberOfArguments,
    _In_ ULONG ServiceId,
    _In_ LPCSTR ServiceName)
{
    CHAR *pLog;
    CHAR szConsoleText[4096];

    _strcpy_a(szConsoleText, "\tArgs: 0x");
    ultohex_a(NumberOfArguments, _strend_a(szConsoleText));

    _strcat_a(szConsoleText, " Id 0x");
    ultohex_a(ServiceId, _strend_a(szConsoleText));
    pLog = _strcat_a(szConsoleText, "\tName:");
    _strncpy_a(pLog, MAX_PATH, ServiceName, MAX_PATH);
    _strcat_a(szConsoleText, "\r\n");

    OutputConsoleMessage(szConsoleText);
}

/*
* FuzzRun
*
* Purpose:
*
* Perform reactos syscall table fuzzing.
*
*/
void FuzzRun(
    _In_ UCHAR *ArgumentsTable,
    _In_ CHAR **ServiceNames,
    _In_ BLACKLIST *BlackList,
    _In_ ULONG MinSyscallNumber,
    _In_ ULONG MaxSyscallNumber,
    _In_ BOOL IsWin32k
)
{
    CHAR* ServiceName;
    ULONG ServiceIndex;
    ULONG NumberOfArguments;

    DWORD dwThreadId;

    HANDLE hThread = NULL;

    CALL_PARAM CalleParam;

    CHAR szConsoleText[200];

    OutputConsoleMessage("[+] Entering FuzzRun()\r\n\n");


    //
    // Assign much possible privileges if can.
    //
    ForcePrivilegeEnabled();

    //
    // Iterate through services and call them with predefined bad arguments.
    //
    for (ServiceIndex = MinSyscallNumber;
        ServiceIndex < MaxSyscallNumber; ServiceIndex++)
    {
        szConsoleText[0] = 0;
        ultostr_a(ServiceIndex, szConsoleText);
        SetConsoleTitleA(szConsoleText);


        //
        // Show generic syscall info.
        //
        ServiceName = (CHAR*)ServiceNames[ServiceIndex];

        //
        // Log name.
        //
        FuzzLogCallName(ServiceName);

        NumberOfArguments = ArgumentsTable[ServiceIndex] / sizeof(void*);

        PrintServiceInformation(NumberOfArguments,
            ServiceIndex,
            ServiceName);

        //
        // Check if syscall blacklisted and skip if it is.
        //
        if (BlackListEntryPresent(BlackList, (LPCSTR)ServiceName)) {
            OutputConsoleMessage("\t\t\t^^^^^ Service found in blacklist, skip\n\r");
            continue;
        }

        //
        // Create caller thread and do syscall in it.
        //
        CalleParam.NumberOfArguments = NumberOfArguments;
        CalleParam.ServiceId = ServiceIndex;

        if (IsWin32k) {
            CalleParam.ServiceId += W32K_MIN_SYSCALL_NUMBER;
        }

        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CallThread,
            (LPVOID)&CalleParam, 0, &dwThreadId);

        if (hThread) {
            if (WaitForSingleObject(hThread, 30 * 1000) == WAIT_TIMEOUT) {
                _strcpy_a(szConsoleText, "Timeout reached for callproc of Service: ");
                ultostr_a(CalleParam.ServiceId, _strend_a(szConsoleText));
                _strcat_a(szConsoleText, "\r\n");
                OutputConsoleMessage(szConsoleText);
                TerminateThread(hThread, (DWORD)-1);
            }
            CloseHandle(hThread);
        }
    }

    OutputConsoleMessage("\r\n[!] Service table probing complete.\n\r");
    OutputConsoleMessage("[-] Leaving FuzzRun()\r\n");
}

/*
* FuzzOpenLog
*
* Purpose:
*
* Open COM1 port for logging.
*
*/
BOOL FuzzOpenLog(
    VOID
)
{
    HANDLE	hFile;
    CHAR	szWelcome[128];
    DWORD	bytesIO;

    hFile = CreateFile(TEXT("COM1"),
        GENERIC_ALL | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_WRITE_THROUGH,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {

        _strcpy_a(szWelcome, "\r\n[RoCall] Logging start.\r\n");
        WriteFile(hFile, (LPCVOID)&szWelcome,
            (DWORD)_strlen_a(szWelcome), &bytesIO, NULL);

        g_hLoggingPort = hFile;
        return TRUE;
    }

    return FALSE;
}

/*
* FuzzCloseLog
*
* Purpose:
*
* Close COM1 port.
*
*/
VOID FuzzCloseLog(
    VOID
)
{
    CHAR	szBye[128];
    DWORD	bytesIO;

    if (g_hLoggingPort == INVALID_HANDLE_VALUE)
        return;

    _strcpy_a(szBye, "\r\n[RoCall] Log stop.\r\n");
    WriteFile(g_hLoggingPort,
        (LPCVOID)&szBye, (DWORD)_strlen_a(szBye), &bytesIO, NULL);

    CloseHandle(g_hLoggingPort);
    g_hLoggingPort = INVALID_HANDLE_VALUE;
}

/*
* FuzzRun
*
* Purpose:
*
* Prepare and start probing.
*
*/
VOID FuzzInit(
    _In_ BOOL probeWin32k,
    _In_ BOOL enableLog,
    _In_ BOOL verboseLog,
    _In_ ULONG pcValue,
    _In_ ULONG syscallStartFrom
)
{
    BOOL LogEnabled = FALSE;
    UCHAR *ArgumentsTable;
    CHAR **ServiceNames;
    BLACKLIST *BlackList;

    HMODULE hUser32 = NULL;

    ULONG MinSyscallNumber, MaxSyscallNumber;

    CHAR szOut[200];

    OutputConsoleMessage("[+] Entering FuzzInit()\r\n");

    RtlSecureZeroMemory(&g_rosVer, sizeof(REACTOS_VERSION));

    //
    // Show version logo if possible.
    //
    if (GetReactOSVersion(&g_rosVer.Major,
        &g_rosVer.Minor,
        &g_rosVer.Build,
        &g_rosVer.Revision))
    {
        _strcpy_a(szOut, "[~] ReactOS version: ");
        ultostr_a(g_rosVer.Major, _strend_a(szOut));
        ultostr_a(g_rosVer.Minor, _strcat_a(szOut, "."));
        ultostr_a(g_rosVer.Build, _strcat_a(szOut, "."));
        ultostr_a(g_rosVer.Revision, _strcat_a(szOut, "."));
        _strcat_a(szOut, "\r\n");
        OutputConsoleMessage(szOut);
    }

    if (pcValue) {
        g_pcValue = pcValue;
    }

    g_bLogVerbose = verboseLog;

    _strcpy_a(szOut, "[+] Number of passes for each syscall = ");
    ultostr_a(g_pcValue, _strend_a(szOut));
    _strcat_a(szOut, "\r\n");
    OutputConsoleMessage(szOut);

    if (enableLog) {

        _strcpy_a(szOut, "[+] Logging type ");
        if (g_bLogVerbose)
            _strcat_a(szOut, "verbose, include parameters\r\n");
        else
            _strcat_a(szOut, " default, only syscall names\r\n");

        OutputConsoleMessage(szOut);

        LogEnabled = FuzzOpenLog();
        if (!LogEnabled) {
            OutputConsoleMessage("[!] Cannot open COM port for logging, logging disabled\r\n");
            g_bLogVerbose = FALSE;
        }
        else
            OutputConsoleMessage("[+] Logging enabled\r\n");
    }

    if (probeWin32k) {
        OutputConsoleMessage("[*] Probing win32k table.\r\n");
        Sleep(1000);

        //
        // Reference user32.
        //
        hUser32 = LoadLibrary(TEXT("user32.dll"));

        RtlSecureZeroMemory(&g_W32kBlackList, sizeof(g_W32kBlackList));
        BlackListCreateFromFile(&g_W32kBlackList, (LPCSTR)CFG_FILE, (LPCSTR)"win32k");

        ArgumentsTable = W32pServiceArgumentTable;
        ServiceNames = (CHAR**)W32pServiceTableNames;

        MaxSyscallNumber = W32K_NUMBER_OF_SYSCALLS - 1;

        BlackList = &g_W32kBlackList;
    }
    else {
        OutputConsoleMessage("[*] Probing ntoskrnl table.\r\n");
        Sleep(1000);

        RtlSecureZeroMemory(&g_NtOsBlackList, sizeof(g_NtOsBlackList));
        BlackListCreateFromFile(&g_NtOsBlackList, (LPCSTR)CFG_FILE, (LPCSTR)"ntos");

        ArgumentsTable = KiServiceArgumentTable;
        ServiceNames = (CHAR**)KiServiceTableNames;

        MaxSyscallNumber = NTOS_MAX_SYSCALL_NUMBER;

        BlackList = &g_NtOsBlackList;
    }

    //
    // Set starting syscall index.
    //
    szOut[0] = 0;

    if (syscallStartFrom >= MaxSyscallNumber) {
        MinSyscallNumber = 0;
        _strcpy_a(szOut, "[!] Invalid syscall start index specified, defaulted to 0\r\n");
    }
    else {
        MinSyscallNumber = syscallStartFrom;
        _strcpy_a(szOut, "[+] Syscall start index = ");
        ultostr_a(MinSyscallNumber, _strend_a(szOut));
        _strcat_a(szOut, "\r\n");
    }
    OutputConsoleMessage(szOut);

    FuzzRun(ArgumentsTable,
        ServiceNames,
        BlackList,
        MinSyscallNumber,
        MaxSyscallNumber,
        probeWin32k);

    BlackListDestroy(BlackList);

    if (enableLog) {
        if (LogEnabled) {
            OutputConsoleMessage("[+] Logging stop\r\n");
            FuzzCloseLog();
        }
    }

    if (hUser32)
        FreeLibrary(hUser32);

    OutputConsoleMessage("[-] Leaving FuzzInit()\r\n");
}

/*
* GetCommandLineOption
*
* Purpose:
*
* Parse command line options.
*
*/
BOOL GetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Out_writes_opt_z_(ValueSize) LPTSTR OptionValue,
    _In_ ULONG ValueSize
)
{
    LPTSTR	cmdline = GetCommandLine();
    TCHAR   Param[64];
    ULONG   rlen;
    int		i = 0;

    while (GetCommandLineParam(cmdline, i, Param, sizeof(Param), &rlen))
    {
        if (rlen == 0)
            break;

        if (_strcmp(Param, OptionName) == 0)
        {
            if (IsParametric)
                return GetCommandLineParam(cmdline, i + 1, OptionValue, ValueSize, &rlen);

            return TRUE;
        }
        ++i;
    }

    return 0;
}

#define T_USAGE "ROCALL - ReactOS syscall fuzzer\r\nUsage:  [-win32k] [-logn | -logv] [-pc Value] [-sc Value]\r\n\
\r\n-logn - enable logging via COM1 port, service name will be logged, default disabled;\r\n\
-logv - enable logging via COM1 port, service name and call parameters will be logged(slow), default disabled;\r\n\
-win32k - launch win32k service table fuzzing, default ntoskrnl service table fuzzing;\r\n\
-pc Value - number of passes for each service(default value 1024);\r\n\
-sc Value - start fuzzing from service entry number(index from 0), default 0.\r\n"

/*
* main
*
* Purpose:
*
* Program main, process command line options.
*
*/
void main()
{
    BOOL    probeWin32k, enableLog, verboseLog;
    ULONG   PassCount = 0, SyscallStartFrom = 0;
    PVOID   ExceptionHandler;
    TCHAR   text[64];

    ExceptionHandler = AddVectoredExceptionHandler(1, &VehHandler);
    if (ExceptionHandler) {

        if (IsReactOS()) {
            OutputConsoleMessage("[*] Hello ReactOS world!\r\n");
        }
        else {
            OutputConsoleMessage("This program requires ReactOS.\r\n");
#ifndef _DEBUG
            ExitProcess(0);
#endif
        }

        //
        // Parse command line.
        //
        // Possible switches:
        //  
        //    ROCALL [-win32k] [-logn | -logv] [-pc Value] [-sc Value]
        //
        if (GetCommandLineOption(TEXT("-help"), FALSE, NULL, 0)) {
            OutputConsoleMessage(T_USAGE);
            ExitProcess(0);
        }

        probeWin32k = GetCommandLineOption(TEXT("-win32k"), FALSE, NULL, 0);
        enableLog = GetCommandLineOption(TEXT("-logn"), FALSE, NULL, 0);
        verboseLog = GetCommandLineOption(TEXT("-logv"), FALSE, NULL, 0);
        if (verboseLog) {
            enableLog = TRUE;
        }

        RtlSecureZeroMemory(text, sizeof(text));
        if (GetCommandLineOption(TEXT("-pc"), TRUE, text, sizeof(text) / sizeof(TCHAR)))
        {
            PassCount = strtoul(text);
        }

        RtlSecureZeroMemory(text, sizeof(text));
        if (GetCommandLineOption(TEXT("-sc"), TRUE, text, sizeof(text) / sizeof(TCHAR)))
        {
            SyscallStartFrom = strtoul(text);
        }

        if (PassCount == 0)
            PassCount = FUZZ_PASS_COUNT;

        FuzzInit(probeWin32k, enableLog, verboseLog, PassCount, SyscallStartFrom);

        RemoveVectoredExceptionHandler(ExceptionHandler);
    }

    ExitProcess(0);
}
