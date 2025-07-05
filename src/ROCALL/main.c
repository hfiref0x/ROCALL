/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.00
*
*  DATE:        07 Jul 2025
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

#include "global.h"

#define PARAM_HELP          TEXT("-help")
#define PARAM_LOG           TEXT("-log")
#define PARAM_OUTPUT        TEXT("-o")
#define PARAM_WIN32K        TEXT("-win32k")
#define PARAM_PASSCOUNT     TEXT("-pc")
#define PARAM_WAITTIMEOUT   TEXT("-wt")
#define PARAM_SYSCALL_START TEXT("-sc")
#define PARAM_HEUR          TEXT("-h")

#define DEFAULT_LOG_FILE    TEXT("rocall64.log")

#define WELCOME_BANNER      "ReactOS x86 syscall fuzzer"
#define VERSION_BANNER      "Version 2.0.0 from "__DATE__"\r\n"
#define PSEUDO_GRAPHICS_BANNER \
"  ____   ___   ____    _    _     _     \n"\
" |  _ \\ / _ \\ / ___|  / \\  | |   | |    \n"\
" | |_) | | | | |     / _ \\ | |   | |    \n"\
" |  _ <| |_| | |___ / ___ \\| |___| |___ \n"\
" |_| \\_\\\\___/ \\____/_/   \\_\\_____|_____|\n"\
"     Y o u  s h a l l  n o t  p a s s         \n"

#define T_HELP "Usage:  [-win32k] [-log] [-pc Value] [-wt Value] [-sc Value] [-s] [-h] [-cr]\r\n\
-log      - Enable logging to file last call parameters (warning: this will drop performance)\r\n\
-o Value  - Output log destination (port name like COM1, COM2... or file name), default rocall64.log (-log required)\r\n\
-win32k   - launch win32k service table fuzzing, default ntoskrnl service table fuzzing\r\n\
-pc Value - number of passes for each service, default value 65536\r\n\
-wt Value - wait timeout in seconds, default value 30\r\n\
-sc Value - start fuzzing from service entry number(index from 0), default 0\r\n\
-s        - restart program under LocalSystem account\r\n\
-h        - enable heuristic parameter building for more targeted fuzzing\r\n"

// Global flag indicating we are running under LocalSystem account
BOOL g_IsLocalSystem = FALSE;

// Reactos real version global
REACTOS_VERSION g_OsVersion;

// Global variable used to track memory allocations for fuzzed data
FUZZ_MEMORY_TRACKER g_MemoryTracker;

// Global fuzzing statistics
FUZZ_STATS g_FuzzStats = { 0 };

// Global log support
LOG_PARAMS g_Log;

// Global blacklist
BLACKLIST g_BlackList;

/*
* VehHandler
*
* Purpose:
*
* Vectored exception handler.
*
*/
LONG CALLBACK VehHandler(
    EXCEPTION_POINTERS* ExceptionInfo
)
{
    HMODULE hModule = GetModuleHandle(TEXT("kernel32.dll"));
    if (hModule) {
        ExceptionInfo->ContextRecord->Eip = (DWORD)GetProcAddress(hModule, "ExitThread");
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

/*
* FuzzRun
*
* Purpose:
*
* Prepare and start probing.
*
*/
UINT FuzzInit(
    _In_ PFUZZ_PARAMS FuzzParams
)
{
    UINT result = 0;
    BOOL LogEnabled = FALSE, CheckedBuild = FALSE;
    LPSTR cmdLine;
    HMODULE hUser32 = NULL;
    CHAR szOut[MAX_PATH];
    CHAR szCurrentDir[MAX_PATH + 1];

    ConsoleShowMessage("[+] Entering FuzzInit()", TEXT_COLOR_CYAN);

    if (g_IsLocalSystem)
        ConsoleShowMessage("[+] LocalSystem account", TEXT_COLOR_CYAN);

    CheckedBuild = supIsCheckedBuild();
    if (CheckedBuild) {
#ifndef _USE_CHECKED_TABLE
        if (FuzzParams->ProbeWin32k) {
            ConsoleShowMessage("[!] ReactOS build type is Checked and win32k table probe selected!", TEXT_COLOR_YELLOW);
            ConsoleShowMessage("[!] Use ROCALL for Checked builds, aborting", TEXT_COLOR_YELLOW);
            return (UINT)-3;
        }
#endif
    }

    // Show version logo if possible.
    if (supGetReactOSVersion(&g_OsVersion)) {
        StringCchPrintfA(szOut, sizeof(szOut), "[+] Reactos version: %lu.%lu.%lu",
            g_OsVersion.Major,
            g_OsVersion.Minor,
            g_OsVersion.Build);
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
    }

    cmdLine = GetCommandLineA();
    GetCurrentDirectoryA(MAX_PATH, szCurrentDir);
    StringCchPrintfA(szOut, sizeof(szOut), "[~] Base configuration\nCurrent directory: %s\nCommand line: %s\n"\
        "Pass count: %lu per each syscall\n"\
        "Thread timeout: %lu sec\nParam heuristics: %s",
        szCurrentDir,
        cmdLine,
        FuzzParams->PassCount,
        FuzzParams->WaitTimeout,
        FuzzParams->EnableParamsHeuristic ? "Enabled" : "Disabled");

    ConsoleShowMessage(szOut, 0);

    if (FuzzParams->LogEnabled) {

        g_Log.LogHandle = INVALID_HANDLE_VALUE;
        g_Log.LogToFile = FuzzParams->LogToFile;

        LogEnabled = FuzzOpenLog(FuzzParams->szLogDeviceOrFile, &g_Log);
        if (!LogEnabled) {
            StringCchPrintfA(szOut, sizeof(szOut), "[!] Log open error, GetLastError() = %lu, log will be disabled", GetLastError());
            ConsoleShowMessage(szOut, TEXT_COLOR_RED);
        }
        else {
            _strcpy_a(szOut, "[+] Logging is enabled, output will be written to ");
            WideCharToMultiByte(CP_ACP, 0, FuzzParams->szLogDeviceOrFile, -1,
                _strend_a(szOut), MAX_PATH, NULL, NULL);
            ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
        }
    }

    ConsoleShowMessage(FuzzParams->ProbeWin32k ? "[*] Win32k table probe mode" : "[*] Ntoskrnl table probe mode", TEXT_COLOR_CYAN);

    if (BlackListCreateFromFile(&g_BlackList, CFG_FILE, FuzzParams->ProbeWin32k ? (LPCSTR)"win32k" : (LPCSTR)"ntos")) {
        StringCchPrintfA(szOut, sizeof(szOut), "[+] Blacklist created with %lu entries", g_BlackList.NumberOfEntries);
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
    }

    if (FuzzParams->ProbeWin32k) {
#ifdef _USE_CHECKED_TABLE
        ConsoleShowMessage("[+] Checked build tables will be used", TEXT_COLOR_CYAN);
#else
        ConsoleShowMessage("[+] Release build tables will be used", TEXT_COLOR_CYAN);
#endif
        // Reference user32.
        hUser32 = LoadLibrary(TEXT("user32.dll"));
    }

    ConsoleShowMessage("[+] Waiting 5 sec to go", TEXT_COLOR_CYAN);
#ifndef _DEBUG
    for (ULONG countdown = 5; countdown > 0; countdown--) {
        StringCchPrintfA(szOut, sizeof(szOut), "[+] Starting in %lu...", countdown);
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
        Sleep(1000);
    }
#endif
    result = FuzzRun(&g_BlackList, FuzzParams);

    BlackListDestroy(&g_BlackList);

    if (LogEnabled) {
        ConsoleShowMessage("[-] Logging stop", TEXT_COLOR_CYAN);
        FuzzCloseLog(&g_Log);
    }

    if (hUser32)
        FreeLibrary(hUser32);

    supSessionParamsRemove();

    ConsoleShowMessage("[-] Leaving FuzzInit()", TEXT_COLOR_CYAN);
    return result;
}

/*
* RocallMain
*
* Purpose:
*
* Program main, process command line options.
*
*/
UINT RocallMain()
{
    UINT result = 0;
    ULONG rLen;
    PVOID exceptionHandler;

    FUZZ_PARAMS fuzzParams;
    LPWSTR commandLine = GetCommandLine();

    WCHAR szTextBuf[MAX_PATH + 1];

    if (!ConsoleInit())
        return (UINT)-1;

    ConsoleShowMessage(PSEUDO_GRAPHICS_BANNER, TEXT_COLOR_CYAN);
    ConsoleShowMessage(WELCOME_BANNER, TEXT_COLOR_CYAN);
    ConsoleShowMessage(VERSION_BANNER, TEXT_COLOR_CYAN);

    if (!supIsReactOS()) {
        ConsoleShowMessage("This program requires ReactOS", TEXT_COLOR_YELLOW);
#ifndef _DEBUG
        ExitProcess((UINT)-2);
#endif
    }

    // Default ROCALL params
    RtlSecureZeroMemory(&fuzzParams, sizeof(fuzzParams));
    fuzzParams.PassCount = FUZZ_PASS_COUNT;
    fuzzParams.WaitTimeout = FUZZ_THREAD_TIMEOUT_SEC;

    g_IsLocalSystem = supIsLocalSystem();
    if (g_IsLocalSystem) {
        supSessionParamsManage(FALSE, &fuzzParams);
    }
    else {

        if (supGetParamOption(commandLine, PARAM_HELP, FALSE, NULL, 0, NULL)) {
            ConsoleShowMessage(T_HELP, 0);
            ExitProcess(0);
        }

        // win32k switch state.
        fuzzParams.ProbeWin32k = supGetParamOption(commandLine, PARAM_WIN32K, FALSE, NULL, 0, NULL);

        // log switch state.
        fuzzParams.LogEnabled = supGetParamOption(commandLine, PARAM_LOG, FALSE, NULL, 0, NULL);
        if (fuzzParams.LogEnabled) {
            rLen = 0;
            RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
            if (supGetParamOption(commandLine,
                PARAM_OUTPUT,
                TRUE,
                szTextBuf,
                RTL_NUMBER_OF(szTextBuf),
                &rLen) && rLen)
            {
                _strcpy(fuzzParams.szLogDeviceOrFile, szTextBuf);
            }
            else {
                _strcpy(fuzzParams.szLogDeviceOrFile, DEFAULT_LOG_FILE);
            }

            if (supIsComPort(fuzzParams.szLogDeviceOrFile)) {
                fuzzParams.LogToFile = FALSE;
            }
            else {
                fuzzParams.LogToFile = TRUE;
            }
        }

        // -pc (PassCount) param.
        rLen = 0;
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetParamOption(commandLine,
            PARAM_PASSCOUNT,
            TRUE,
            szTextBuf,
            RTL_NUMBER_OF(szTextBuf),
            &rLen) && rLen)
        {
            fuzzParams.PassCount = _strtoul(szTextBuf);
        }

        if (fuzzParams.PassCount == 0)
            fuzzParams.PassCount = FUZZ_PASS_COUNT;

        // -sc (Start from)
        rLen = 0;
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetParamOption(commandLine,
            PARAM_SYSCALL_START,
            TRUE,
            szTextBuf,
            RTL_NUMBER_OF(szTextBuf),
            &rLen) && rLen)
        {
            fuzzParams.SyscallStartFrom = _strtoul(szTextBuf);
            fuzzParams.ProbeFromSyscallId = TRUE;
            if (fuzzParams.SyscallStartFrom >= W32SYSCALLSTART)
                fuzzParams.ProbeWin32k = TRUE; // Force flag
        }

        // -wt (WaitTimeout) param.
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetParamOption(commandLine,
            PARAM_WAITTIMEOUT,
            TRUE,
            szTextBuf,
            RTL_NUMBER_OF(szTextBuf),
            &rLen) && rLen)
        {
            fuzzParams.WaitTimeout = _strtoul(szTextBuf);
        }

        if (fuzzParams.WaitTimeout == 0)
            fuzzParams.WaitTimeout = FUZZ_THREAD_TIMEOUT_SEC;

        // -h (Heuristics) param.
        if (supGetParamOption(commandLine, PARAM_HEUR, FALSE, NULL, 0, NULL)) {
            fuzzParams.EnableParamsHeuristic = TRUE;
        }
    }

    supTryRunAsService(g_IsLocalSystem, &fuzzParams);

    exceptionHandler = AddVectoredExceptionHandler(1, &VehHandler);
    if (exceptionHandler) {
        result = FuzzInit(&fuzzParams);
        RemoveVectoredExceptionHandler(exceptionHandler);
    }

    ExitProcess(result);
}


void main()
{
    //SyscallDBGen();
    //OutputSortedWin32kSyscalls();
    ExitProcess(RocallMain());
}