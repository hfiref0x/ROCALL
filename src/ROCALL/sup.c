/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       SUP.C
*
*  VERSION:     2.00
*
*  DATE:        05 Jul 2025
*
*  Program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

//
// Events.
//
#define ROCALL_EVENT_123 TEXT("Global\\ROCEvent123")
#define ROCALL_EVENT_456 TEXT("Global\\ROCEvent456")
#define ROCALL_EVENT_789 TEXT("Global\\ROCEvent789")

//
// Service mode service name.
//
#define ROCALL_SERVICE   TEXT("ROCSVC")

//
// Shared session configuration.
//
#define ROCALL_CFG_KEY   TEXT("Software\\ROCALL")
#define ROCALL_CFG_VALUE TEXT("Params")

SERVICE_STATUS g_ServiceStatus;
SERVICE_STATUS_HANDLE g_ServiceStatusHandle;

BOOL ConsoleInit(
    VOID)
{
    COORD coordScreen = { 0, 0 };
    DWORD cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD dwConSize;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (hConsole == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return FALSE;

    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);

    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

    if (!FillConsoleOutputCharacter(hConsole, (TCHAR)' ',
        dwConSize, coordScreen, &cCharsWritten))
        return FALSE;

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return FALSE;

    if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes,
        dwConSize, coordScreen, &cCharsWritten))
        return FALSE;

    SetConsoleCursorPosition(hConsole, coordScreen);

    return TRUE;
}

/*
* ConsoleShowMessage2
*
* Purpose:
*
* Output text to screen on the same line.
*
*/
VOID ConsoleShowMessage2(
    _In_ LPCSTR lpMessage,
    _In_ WORD wColor
)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    ULONG r, sz;
    WORD SavedAttributes = 0;
    HANDLE hStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    BOOL isCarriageReturn = FALSE;
    LPSTR lpClearBuffer = NULL;
    DWORD clearBufferSize;

    sz = (DWORD)_strlen_a(lpMessage);
    if (sz == 0)
        return;

    if (lpMessage[0] == '\r') {
        isCarriageReturn = TRUE;
        lpMessage++;
        sz--;
    }

    RtlSecureZeroMemory(&csbi, sizeof(csbi));
    GetConsoleScreenBufferInfo(hStdHandle, &csbi);

    if (wColor) {
        SavedAttributes = csbi.wAttributes;
        SetConsoleTextAttribute(hStdHandle, wColor);
    }

    if (isCarriageReturn) {
        COORD beginPos = { 0, csbi.dwCursorPosition.Y };
        SetConsoleCursorPosition(hStdHandle, beginPos);

        clearBufferSize = csbi.dwSize.X;
        lpClearBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, clearBufferSize + 1);

        if (lpClearBuffer) {
            memset(lpClearBuffer, ' ', clearBufferSize);
            WriteFile(hStdHandle, lpClearBuffer, clearBufferSize, &r, NULL);
            SetConsoleCursorPosition(hStdHandle, beginPos);
            HeapFree(GetProcessHeap(), 0, lpClearBuffer);
        }
    }

    WriteFile(hStdHandle, lpMessage, sz, &r, NULL);

    if (wColor) {
        SetConsoleTextAttribute(hStdHandle, SavedAttributes);
    }
}

/*
* ConsoleShowMessage
*
* Purpose:
*
* Output text to screen.
*
*/
VOID ConsoleShowMessage(
    _In_ LPCSTR lpMessage,
    _In_ WORD wColor
)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    ULONG r, sz;
    WORD SavedAttributes = 0;
    HANDLE hStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    LPCSTR szNewLine = "\r\n";

    sz = (DWORD)_strlen_a(lpMessage);
    if (sz == 0)
        return;

    if (wColor) {
        RtlSecureZeroMemory(&csbi, sizeof(csbi));
        GetConsoleScreenBufferInfo(hStdHandle, &csbi);
        SavedAttributes = csbi.wAttributes;
        SetConsoleTextAttribute(hStdHandle, wColor);
    }

    WriteFile(hStdHandle, lpMessage, sz, &r, NULL);
    WriteFile(hStdHandle, szNewLine, 2, &r, NULL);

    if (wColor) {
        SetConsoleTextAttribute(hStdHandle, SavedAttributes);
    }
}

/*
* supRunAsLocalSystem
*
* Purpose:
*
* Execute current application as LocalSystem.
*
*/
BOOL supRunAsLocalSystem()
{
    BOOL bResult = FALSE;
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInfo;
    HANDLE hEvent123 = NULL, hEvent456 = NULL, hEvent789 = NULL;
    WCHAR szFileName[MAX_PATH + 1];
    CHAR szDebugMsg[100];
    DWORD dwExitCode = 0;

    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(STARTUPINFO);
    startupInfo.lpDesktop = TEXT("WinSta0\\Default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOW;

    hEvent456 = OpenEvent(EVENT_MODIFY_STATE, FALSE, ROCALL_EVENT_456);
    hEvent789 = OpenEvent(EVENT_MODIFY_STATE, FALSE, ROCALL_EVENT_789);

    if (hEvent456 && hEvent789) {

        hEvent123 = CreateEvent(NULL, TRUE, TRUE, ROCALL_EVENT_123);
        if (hEvent123) {
            RtlSecureZeroMemory(szFileName, sizeof(szFileName));
            if (GetModuleFileName(NULL, szFileName, MAX_PATH) == 0) {
                StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
                    "GetModuleFileName failed: %lu", GetLastError());
                OutputDebugStringA(szDebugMsg);
                SetEvent(hEvent456);
            }
            else {
                if (CreateProcess(NULL, szFileName, NULL, NULL,
                    FALSE, CREATE_NEW_CONSOLE, NULL, NULL,
                    &startupInfo, &processInfo))
                {
                    WaitForInputIdle(processInfo.hProcess, 3000);

                    if (GetExitCodeProcess(processInfo.hProcess, &dwExitCode) &&
                        dwExitCode == STILL_ACTIVE)
                    {
                        SetEvent(hEvent789);
                        bResult = TRUE;
                    }
                    else {
                        SetEvent(hEvent456);
                    }

                    CloseHandle(processInfo.hThread);
                    CloseHandle(processInfo.hProcess);
                }
                else {
                    StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
                        "CreateProcess failed: %lu", GetLastError());
                    OutputDebugStringA(szDebugMsg);
                    SetEvent(hEvent456);
                }
            }
            CloseHandle(hEvent123);
        }
        CloseHandle(hEvent789);
        CloseHandle(hEvent456);
    }

    return bResult;
}

/*
* supInstallAndRunService
*
* Purpose:
*
* Install program as interactive service.
*
*/
BOOL supInstallAndRunService(LPWSTR lpServiceName)
{
    BOOL bResult = FALSE;
    SC_HANDLE hManager = NULL, hService = NULL;
    DWORD retryCount = 0;
    WCHAR szFileName[MAX_PATH + 1];
    CHAR szDebugMsg[100];
    SERVICE_STATUS serviceStatus;

    if (GetModuleFileName(NULL, szFileName, MAX_PATH) == 0) {
        StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
            "[!] GetModuleFileName failed: %lu", GetLastError());
        ConsoleShowMessage(szDebugMsg, TEXT_COLOR_RED);
        return FALSE;
    }

    hManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);
    if (hManager == NULL) {
        StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
            "[!] OpenSCManager failed: %lu", GetLastError());
        ConsoleShowMessage(szDebugMsg, TEXT_COLOR_RED);
        return FALSE;
    }

    for (retryCount = 0; retryCount < 2; retryCount++) {
        hService = CreateService(hManager,
            lpServiceName,
            lpServiceName,
            SERVICE_ALL_ACCESS,
            SERVICE_INTERACTIVE_PROCESS | SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            szFileName,
            NULL, NULL, NULL, NULL, NULL);

        if (hService) break;

        if (GetLastError() != ERROR_SERVICE_EXISTS) {
            break;
        }

        hService = OpenService(hManager, lpServiceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (hService) {
            if (QueryServiceStatus(hService, &serviceStatus)) {
                if (serviceStatus.dwCurrentState != SERVICE_STOPPED) {
                    ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);

                    DWORD dwStartTime = GetTickCount();
                    while (QueryServiceStatus(hService, &serviceStatus)) {
                        if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
                            break;

                        if (GetTickCount() - dwStartTime > 3000)
                            break;

                        Sleep(250);
                    }
                }
            }

            DeleteService(hService);
            CloseServiceHandle(hService);
            hService = NULL;
            Sleep(1000);
        }
    }

    if (hService) {
        if (StartService(hService, 0, NULL)) {
            bResult = TRUE;
        }
        else {
            StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
                "[!] StartService failed: %lu", GetLastError());
            ConsoleShowMessage(szDebugMsg, TEXT_COLOR_RED);
        }

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hManager);
    return bResult;
}

/*
* RoCallSvcHandler
*
* Purpose:
*
* Service control handler.
*
*/
VOID RoCallSvcHandler(
    _In_ DWORD dwControl
)
{
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWaitHint = 3000;
        break;
    }

    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

/*
* RoCallSvcMain
*
* Purpose:
*
* Service main, run program under LocalSystem account.
*
*/
VOID WINAPI RoCallSvcMain(
    DWORD dwNumServicesArgs,
    LPTSTR* lpServiceArgVectors
)
{
    CHAR szDebugMsg[100];

    UNREFERENCED_PARAMETER(dwNumServicesArgs);
    UNREFERENCED_PARAMETER(lpServiceArgVectors);

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 2000;

    g_ServiceStatusHandle = RegisterServiceCtrlHandler(ROCALL_SERVICE,
        (LPHANDLER_FUNCTION)RoCallSvcHandler);
    if (!g_ServiceStatusHandle) {
        StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
            "RegisterServiceCtrlHandler failed: %lu", GetLastError());
        OutputDebugStringA(szDebugMsg);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    BOOL bRunResult = supRunAsLocalSystem();

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = bRunResult ? 0 : ERROR_SERVICE_SPECIFIC_ERROR;
    g_ServiceStatus.dwServiceSpecificExitCode = bRunResult ? 0 : 1;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

/*
* supEnableInteractiveService
*
* Purpose:
*
* Enable or disable interactive services.
*
*/
INT supEnableInteractiveService(
    _In_ BOOL fEnable
)
{
    HKEY hKey = NULL;
    INT iResult = -1;
    DWORD dwType;
    DWORD dwData = 0;
    DWORD cbData = sizeof(DWORD);

    do {

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            TEXT("SYSTEM\\CurrentControlSet\\Control\\Windows"),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &hKey) != ERROR_SUCCESS)
        {
            break;
        }

        if (RegQueryValueEx(hKey,
            TEXT("NoInteractiveServices"),
            NULL,
            &dwType,
            (LPBYTE)&dwData,
            &cbData) != ERROR_SUCCESS)
        {
            break;
        }

        if (fEnable) {

            if (dwData != 0) {
                iResult = 1;
                break;
            }

            dwData = 1;
        }
        else {

            if (dwData == 0) {
                iResult = 0;
                break;
            }

            dwData = 0;
        }

        if (ERROR_SUCCESS != RegSetValueEx(hKey,
            TEXT("NoInteractiveServices"),
            0,
            dwType,
            (LPBYTE)&dwData,
            cbData))
        {
            break;
        }

        iResult = (INT)dwData;

    } while (FALSE);

    if (hKey) RegCloseKey(hKey);

    return iResult;
}

/*
* supElevateViaLegacyService
*
* Purpose:
*
* Legacy method to run as LocalSystem via service creation.
*
*/
BOOL supElevateViaLegacyService(
    VOID
)
{
    BOOL bSuccess = FALSE;
    HANDLE hEventWait = NULL;
    HANDLE hEventSuccess = NULL;
    DWORD waitResult;
    INT interactiveServiceState;

    hEventWait = CreateEvent(NULL, TRUE, FALSE, TEXT("Global\\ROCALL_ElevationPending"));
    hEventSuccess = CreateEvent(NULL, TRUE, FALSE, TEXT("Global\\ROCALL_ElevationComplete"));

    if (!hEventWait || !hEventSuccess) {
        ConsoleShowMessage("[!] Failed to create synchronization events", TEXT_COLOR_RED);
        if (hEventWait) CloseHandle(hEventWait);
        if (hEventSuccess) CloseHandle(hEventSuccess);
        return FALSE;
    }

    interactiveServiceState = supEnableInteractiveService(TRUE);
    if (interactiveServiceState == -1) {
        ConsoleShowMessage("[!] Failed to configure interactive services", TEXT_COLOR_RED);
        CloseHandle(hEventWait);
        CloseHandle(hEventSuccess);
        return FALSE;
    }

    if (supInstallAndRunService(ROCALL_SERVICE)) {
        waitResult = WaitForSingleObject(hEventSuccess, 5000);
        if (waitResult == WAIT_OBJECT_0) {
            ConsoleShowMessage("[+] Successfully elevated via service", TEXT_COLOR_CYAN);
            bSuccess = TRUE;
        }
        else {
            ConsoleShowMessage("[!] Service elevation timeout or failure", TEXT_COLOR_RED);
        }
    }
    else {
        ConsoleShowMessage("[!] Failed to install or start service", TEXT_COLOR_RED);
    }

    if (interactiveServiceState == 1) {
        supEnableInteractiveService(FALSE);
    }

    CloseHandle(hEventWait);
    CloseHandle(hEventSuccess);

    return bSuccess;
}

/*
* supIsReactOS
*
* Purpose:
*
* Return TRUE if the given system is identified as ReactOS.
*
*/
BOOL supIsReactOS()
{
    BOOL bResult = FALSE;
    HKEY hKey;
    DWORD dwType, dwSize;
    LPTSTR lpBuffer;
    HANDLE hSection = NULL;
    const TCHAR szRegKey[] = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    STATIC_UNICODE_STRING(usSectionName, L"\\KnownDlls\\kernel32_vista.dll");
    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES(&usSectionName, OBJ_CASE_INSENSITIVE);

    if (NT_SUCCESS(NtOpenSection(&hSection, SECTION_QUERY, &obja))) {
        CloseHandle(hSection);
        bResult = TRUE;
    }

    if (bResult == FALSE) {

        if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            szRegKey, 0, KEY_QUERY_VALUE, &hKey))
        {
            if (ERROR_SUCCESS == RegQueryValueEx(hKey,
                TEXT("ProductName"), NULL, &dwType, NULL, &dwSize))
            {
                if (dwType == REG_SZ) {
                    lpBuffer = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
                    if (lpBuffer) {

                        if (ERROR_SUCCESS == RegQueryValueEx(hKey,
                            TEXT("ProductName"), NULL, &dwType, (LPBYTE)lpBuffer, &dwSize))
                        {
                            bResult = (_strcmpi(lpBuffer, TEXT("ReactOS")) == 0);
                        }
                        HeapFree(GetProcessHeap(), 0, lpBuffer);
                    }
                }
            }

            RegCloseKey(hKey);
        }
    }

    return bResult;
}

/*
* InternalGetImageVersionInfo
*
* Purpose:
*
* Return version numbers from version info.
*
*/
_Success_(return != FALSE)
BOOL InternalGetImageVersionInfo(
    _In_ LPWSTR lpFileName,
    _Out_opt_ ULONG * MajorVersion,
    _Out_opt_ ULONG * MinorVersion,
    _Out_opt_ ULONG * Build,
    _Out_opt_ ULONG * Revision
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO* pFileInfo;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID*)&pFileInfo, (PUINT)&Length);
                if (bResult) {
                    if (MajorVersion)
                        *MajorVersion = HIWORD(pFileInfo->dwFileVersionMS);
                    if (MinorVersion)
                        *MinorVersion = LOWORD(pFileInfo->dwFileVersionMS);
                    if (Build)
                        *Build = HIWORD(pFileInfo->dwFileVersionLS);
                    if (Revision)
                        *Revision = LOWORD(pFileInfo->dwFileVersionLS);
                }
            }
            HeapFree(GetProcessHeap(), 0, vinfo);
        }
    }
    return bResult;
}

/*
* supGetReactOSVersion
*
* Purpose:
*
* Return ReactOS version based on AFD.SYS version info.
*
*/
BOOL supGetReactOSVersion(
    _Inout_ REACTOS_VERSION * OsVersion
)
{
    BOOL bResult = FALSE;
    DWORD cch;
    WCHAR szFilePath[MAX_PATH * 2];

    //
    // Assume failure.
    //
    RtlZeroMemory(OsVersion, sizeof(REACTOS_VERSION));

    RtlSecureZeroMemory(szFilePath, sizeof(szFilePath));
    cch = GetSystemDirectory(szFilePath, MAX_PATH);
    if ((cch == 0) || (cch > MAX_PATH))
        return FALSE;

    _strcat_w(szFilePath, L"\\drivers\\afd.sys");

    bResult = InternalGetImageVersionInfo(szFilePath,
        &OsVersion->Major,
        &OsVersion->Minor,
        &OsVersion->Build,
        &OsVersion->Revision);

    return bResult;
}

/*
* supIsUserInAdminGroup
*
* Purpose:
*
* Returns TRUE if current user is in admin group.
*
*/
BOOL supIsUserInAdminGroup()
{
    BOOL bResult = FALSE;
    HANDLE hToken;

    ULONG returnLength, i;

    PSID pSid = NULL;

    PTOKEN_GROUPS ptg = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {

        GetTokenInformation(hToken, TokenGroups, NULL, 0, &returnLength);

        ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)returnLength);
        if (ptg) {

            if (GetTokenInformation(hToken,
                TokenGroups,
                ptg,
                returnLength,
                &returnLength))
            {
                if (AllocateAndInitializeSid(&NtAuthority,
                    2,
                    SECURITY_BUILTIN_DOMAIN_RID,
                    DOMAIN_ALIAS_RID_ADMINS,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    &pSid))
                {
                    for (i = 0; i < ptg->GroupCount; i++) {
                        if (EqualSid(pSid, ptg->Groups[i].Sid)) {
                            bResult = TRUE;
                            break;
                        }
                    }

                    FreeSid(pSid);
                }
            }

            HeapFree(GetProcessHeap(), 0, ptg);
        }
        CloseHandle(hToken);
    }
    return bResult;
}

/*
* supIsLocalSystem
*
* Purpose:
*
* Returns TRUE if current user is LocalSystem.
*
*/
BOOL supIsLocalSystem()
{
    BOOL bResult = FALSE;
    ULONG returnLength;
    HANDLE hToken;
    TOKEN_USER* ptu;

    PSID pSid;

    BYTE TokenInformation[256];

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenUser, &TokenInformation,
            sizeof(TokenInformation), &returnLength))
        {

            if (AllocateAndInitializeSid(&NtAuthority,
                1,
                SECURITY_LOCAL_SYSTEM_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &pSid))
            {
                ptu = (PTOKEN_USER)&TokenInformation;

                bResult = (EqualSid(pSid, ptu->User.Sid) != 0);

                FreeSid(pSid);
            }

        }

        CloseHandle(hToken);
    }

    return bResult;
}

/*
* supGetParamOption
*
* Purpose:
*
* Query parameters options by name and type.
*
*/
_Success_(return)
BOOL supGetParamOption(
    _In_ LPCWSTR params,
    _In_ LPCWSTR optionName,
    _In_ BOOL isParametric,
    _Out_opt_ LPWSTR value,
    _In_ ULONG valueLength, //in chars
    _Out_opt_ PULONG paramLength
)
{
    BOOL result;
    WCHAR paramBuffer[MAX_PATH + 1];
    ULONG rlen;
    INT i = 0;

    if (paramLength)
        *paramLength = 0;

    if (isParametric) {
        if (value == NULL || valueLength == 0)
        {
            return FALSE;
        }
    }

    if (value)
        *value = L'\0';

    RtlSecureZeroMemory(paramBuffer, sizeof(paramBuffer));

    while (GetCommandLineParam(
        params,
        i,
        paramBuffer,
        MAX_PATH,
        &rlen))
    {
        if (rlen == 0)
            break;

        if (_strcmp(paramBuffer, optionName) == 0) {
            if (isParametric) {
                result = GetCommandLineParam(params, i + 1, value, valueLength, &rlen);
                if (paramLength)
                    *paramLength = rlen;
                return result;
            }

            return TRUE;
        }
        ++i;
    }

    return FALSE;
}

/*
* supSessionParamsRemove
*
* Purpose:
*
* Remove session params from registry.
*
*/
VOID supSessionParamsRemove()
{
    RegDeleteKey(HKEY_LOCAL_MACHINE, ROCALL_CFG_KEY);
}

/*
* supSessionParamsManage
*
* Purpose:
*
* Save/Read session params from registry.
*
*/
BOOL supSessionParamsManage(
    _In_ BOOLEAN fSet,
    _Inout_ PFUZZ_PARAMS FuzzParams)
{
    BOOL bSuccess = TRUE;
    HKEY hKey = NULL;
    DWORD dwType = REG_BINARY;
    DWORD cbData;

    FUZZ_PARAMS localSessionParams;

    if (RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        ROCALL_CFG_KEY,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        (fSet) ? KEY_WRITE : KEY_READ,
        NULL,
        &hKey,
        NULL) == ERROR_SUCCESS)
    {
        if (fSet) {
            bSuccess = (RegSetValueEx(hKey,
                ROCALL_CFG_VALUE,
                0,
                REG_BINARY,
                (BYTE*)FuzzParams,
                sizeof(FUZZ_PARAMS)) == ERROR_SUCCESS);
        }
        else {

            dwType = REG_NONE;
            cbData = sizeof(FUZZ_PARAMS);
            RtlSecureZeroMemory(&localSessionParams, sizeof(FUZZ_PARAMS));
            bSuccess = RegQueryValueEx(hKey,
                TEXT("Params"),
                0,
                &dwType,
                (BYTE*)&localSessionParams,
                &cbData) == ERROR_SUCCESS;
            if (bSuccess) {
                if (dwType == REG_BINARY) {
                    if (localSessionParams.PassCount == 0)
                        localSessionParams.PassCount = FUZZ_PASS_COUNT;
                    if (localSessionParams.WaitTimeout == 0)
                        localSessionParams.WaitTimeout = FUZZ_THREAD_TIMEOUT_SEC;

                    RtlCopyMemory(FuzzParams, &localSessionParams, sizeof(FUZZ_PARAMS));
                }
                else {
                    bSuccess = FALSE;
                }
            }
        }
        RegCloseKey(hKey);

    }

    if (bSuccess == FALSE)
        OutputDebugStringA("Error managing session params");

    return bSuccess;
}

/*
* supIsCheckedBuild
*
* Purpose:
*
* Return TRUE if this is checked build, false otherwise.
*
*/
BOOL supIsCheckedBuild()
{
    BOOLEAN bResult = FALSE;
    HKEY hKey;
    DWORD dwType, dwSize;
    LPTSTR lpBuffer;
    const TCHAR szRegKey[] = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");

    if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        szRegKey, 0, KEY_QUERY_VALUE, &hKey))
    {
        if (ERROR_SUCCESS == RegQueryValueEx(hKey,
            TEXT("CurrentType"), NULL, &dwType, NULL, &dwSize))
        {
            if (dwType == REG_SZ) {
                lpBuffer = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
                if (lpBuffer) {

                    if (ERROR_SUCCESS == RegQueryValueEx(hKey,
                        TEXT("CurrentType"), NULL, &dwType, (LPBYTE)lpBuffer, &dwSize))
                    {
                        bResult = (_strstri(lpBuffer, TEXT("Checked")) != NULL);
                    }
                    HeapFree(GetProcessHeap(), 0, lpBuffer);
                }
            }
        }

        RegCloseKey(hKey);
    }

    return bResult;
}

/*
* supIsComPort
*
* Purpose:
*
* Return TRUE if wsz is a valid COM port string (COM1..COM255, case-insensitive, no extra chars).
*
*/
BOOL supIsComPort(
    _In_ LPCWSTR wsz
)
{
    if (!wsz)
        return FALSE;

    if ((wsz[0] == L'C' || wsz[0] == L'c') &&
        (wsz[1] == L'O' || wsz[1] == L'o') &&
        (wsz[2] == L'M' || wsz[2] == L'm'))
    {
        int i = 3;
        int portNum = 0;

        if (wsz[i] == L'\0')
            return FALSE;

        while (wsz[i] && (i - 3) < 3) {
            if (wsz[i] < L'0' || wsz[i] > L'9')
                return FALSE;
            portNum = portNum * 10 + (wsz[i] - L'0');
            i++;
        }

        if (wsz[i] != L'\0')
            return FALSE;

        if (portNum >= 1 && portNum <= 255)
            return TRUE;
    }
    return FALSE;
}

/*
* supTryRunAsService
*
* Purpose:
*
* Restart program as LocalSystem via interactive service.
*
*/
VOID supTryRunAsService(
    _In_ BOOL IsRunAsLocalSystem,
    _In_ PFUZZ_PARAMS FuzzParams
)
{
    BOOL bSuccess = FALSE;
    BOOL bServiceRun = FALSE;
    HANDLE hEvent123 = NULL;
    HANDLE hEvents[2] = { NULL, NULL };
    INT iResult = -1;
    DWORD WaitResult;
    LPWSTR cmdLine = GetCommandLine();
    SERVICE_TABLE_ENTRY ServiceStartTable;
    CHAR szDebugMsg[256];

    if (supGetParamOption(cmdLine, TEXT("-s"), FALSE, NULL, 0, NULL)) {
        ConsoleShowMessage("[~] Attempting to restart as LocalSystem via ReactOS service", TEXT_COLOR_CYAN);
        bServiceRun = TRUE;
    }

    hEvent123 = OpenEvent(EVENT_ALL_ACCESS, FALSE, ROCALL_EVENT_123);
    if (!hEvent123) {
        if (IsRunAsLocalSystem) {
            ConsoleShowMessage("[+] Running as service, initializing service dispatcher", TEXT_COLOR_CYAN);

            ServiceStartTable.lpServiceName = ROCALL_SERVICE;
            ServiceStartTable.lpServiceProc = (LPSERVICE_MAIN_FUNCTION)RoCallSvcMain;

            StartServiceCtrlDispatcher(&ServiceStartTable);
            ExitProcess(0);
            return;
        }

        if (bServiceRun) {
            if (!supIsUserInAdminGroup()) {
                ConsoleShowMessage("[!] Administrative privileges required to run as LocalSystem account", TEXT_COLOR_RED);
                ExitProcess(0);
                return;
            }

            iResult = supEnableInteractiveService(TRUE);
            if (iResult == -1) {
                ConsoleShowMessage("[!] Failed to configure interactive services", TEXT_COLOR_RED);
            }
            else {

                ConsoleShowMessage("[+] Interactive services configured", TEXT_COLOR_CYAN);

                // Create events for synchronization
                hEvents[0] = CreateEvent(NULL, TRUE, FALSE, ROCALL_EVENT_456);
                hEvents[1] = CreateEvent(NULL, TRUE, FALSE, ROCALL_EVENT_789);

                if (hEvents[0] && hEvents[1]) {
                    ConsoleShowMessage("[+] Synchronization events created successfully", TEXT_COLOR_CYAN);

                    // Save parameters for the elevated process
                    if (supSessionParamsManage(TRUE, FuzzParams)) {
                        ConsoleShowMessage("[+] Session parameters saved successfully", TEXT_COLOR_CYAN);
                    }
                    else {
                        ConsoleShowMessage("[!] Failed to save session parameters", TEXT_COLOR_YELLOW);
                    }

                    ConsoleShowMessage("[~] Installing and starting service...", TEXT_COLOR_CYAN);
                    if (supInstallAndRunService(ROCALL_SERVICE)) {
                        ConsoleShowMessage("[+] Service installed and started", TEXT_COLOR_CYAN);

                        ConsoleShowMessage("[~] Waiting for service process initialization...", TEXT_COLOR_CYAN);
                        WaitResult = WaitForMultipleObjects(2, hEvents, FALSE, 5000); // 5 second timeout

                        switch (WaitResult) {
                        case WAIT_OBJECT_0:
                            ConsoleShowMessage("[!] Service reported initialization failure", TEXT_COLOR_RED);
                            break;

                        case WAIT_OBJECT_0 + 1:
                            ConsoleShowMessage("[+] Service successfully started child process", TEXT_COLOR_CYAN);
                            bSuccess = TRUE;
                            break;

                        case WAIT_TIMEOUT:
                            ConsoleShowMessage("[!] Timeout waiting for service response", TEXT_COLOR_RED);
                            break;

                        default:
                            StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
                                "[!] Wait failed with error code: %lu", GetLastError());
                            ConsoleShowMessage(szDebugMsg, TEXT_COLOR_RED);
                        }
                    }
                    else {
                        StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
                            "[!] Failed to install/start service, error: %lu", GetLastError());
                        ConsoleShowMessage(szDebugMsg, TEXT_COLOR_RED);
                    }

                    CloseHandle(hEvents[0]);
                    CloseHandle(hEvents[1]);
                }
                else {
                    StringCchPrintfA(szDebugMsg, _countof(szDebugMsg),
                        "[!] Failed to create synchronization events, error: %lu", GetLastError());
                    ConsoleShowMessage(szDebugMsg, TEXT_COLOR_RED);

                    if (hEvents[0]) CloseHandle(hEvents[0]);
                    if (hEvents[1]) CloseHandle(hEvents[1]);
                }

                if (iResult == 1) {
                    ConsoleShowMessage("[~] Restoring interactive services setting", TEXT_COLOR_CYAN);
                    supEnableInteractiveService(FALSE);
                }
            }

            if (bSuccess) {
                ConsoleShowMessage("[+] Elevation successful, exiting current process", TEXT_COLOR_CYAN);
                ExitProcess(0);
                return;
            }
        } //bServiceRun
    }
    else {
        CloseHandle(hEvent123);
    }

    if (!bServiceRun)
        ConsoleShowMessage("[~] Normal initialization started", TEXT_COLOR_CYAN);
}
