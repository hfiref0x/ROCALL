/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       UTIL.C
*
*  VERSION:     1.02
*
*  DATE:        30 Nov 2019
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
#pragma comment(lib, "version.lib")

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

VOID ShowDebugRoutine(LPWSTR Message);

#ifndef _DEBUG
#define ShowDebug
#else
#define ShowDebug ShowDebugRoutine
#endif

/*
* ShowDebugRoutine
*
* Purpose:
*
* Debug output.
*
*/
VOID ShowDebugRoutine(LPWSTR Message)
{
    WCHAR szDebug[100];

    szDebug[0] = 0;
    ultohex(GetCurrentProcessId(), szDebug);
    MessageBox(0, Message, szDebug, 0);
}

/*
* RunAsLocalSystem
*
* Purpose:
*
* Execute current application as LocalSystem.
*
*/
BOOL RunAsLocalSystem()
{
    BOOL bResult = FALSE;
    STARTUPINFO StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    HANDLE hEvent123, hEvent456, hEvent789;

    WCHAR szFileName[MAX_PATH + 1];

    RtlSecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(STARTUPINFO);

    hEvent456 = OpenEvent(EVENT_MODIFY_STATE, FALSE, ROCALL_EVENT_456);
    hEvent789 = OpenEvent(EVENT_MODIFY_STATE, FALSE, ROCALL_EVENT_789);

    if (hEvent456 && hEvent789) {

        ShowDebug(TEXT("RunAsLocalService wait events 2 & 3 opened"));

        hEvent123 = CreateEvent(NULL, TRUE, TRUE, ROCALL_EVENT_123);
        if (hEvent123) {

            ShowDebug(TEXT("RunAsLocalService wait event 1 created"));

            RtlSecureZeroMemory(szFileName, sizeof(szFileName));
            GetModuleFileName(NULL, (LPWSTR)&szFileName, MAX_PATH);

            if (CreateProcess(NULL,
                (LPWSTR)szFileName,
                NULL, NULL, FALSE, 0, NULL, NULL,
                &StartupInfo, &ProcessInformation))
            {
                ShowDebug(TEXT("RunAsLocalService CreateProcess success"));

                WaitForInputIdle(ProcessInformation.hProcess, 3000);
                Sleep(100);
                CloseHandle(ProcessInformation.hThread);
                CloseHandle(ProcessInformation.hProcess);
                SetEvent(hEvent789);
            }
            else {
                SetEvent(hEvent456);
                ShowDebug(TEXT("RunAsLocalService CreateProcess failed"));
            }
            CloseHandle(hEvent123);
        }

        CloseHandle(hEvent789);
        bResult = CloseHandle(hEvent456);
    }

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
    DWORD dwControl
)
{
    UNREFERENCED_PARAMETER(dwControl);
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
    LPTSTR *lpServiceArgVectors
)
{
    UNREFERENCED_PARAMETER(dwNumServicesArgs);
    UNREFERENCED_PARAMETER(lpServiceArgVectors);

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;

    g_ServiceStatusHandle = RegisterServiceCtrlHandler(ROCALL_SERVICE, (LPHANDLER_FUNCTION)RoCallSvcHandler);
    if (g_ServiceStatusHandle) {
        if (SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus)) {
            ShowDebug(TEXT("RunAsLocalSystem"));
            RunAsLocalSystem();
        }

        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
    }
}

/*
* EnableInteractiveService
*
* Purpose:
*
* Enable or disable interactive services.
*
*/
INT EnableInteractiveService(
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
            iResult = -1;
            break;
        }

        iResult = (INT)dwData;

    } while (FALSE);

    if (hKey) RegCloseKey(hKey);

    return iResult;
}

/*
* InstallAndRunService
*
* Purpose:
*
* Install program as interactive service.
*
*/
BOOL InstallAndRunService(LPWSTR lpServiceName)
{
    BOOL bResult = FALSE;

    DWORD retryCount;

    SC_HANDLE hManager, hService = NULL;

    WCHAR szFileName[MAX_PATH + 1];

    GetModuleFileName(NULL, (LPWSTR)&szFileName, MAX_PATH);

    hManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);
    if (hManager) {

        retryCount = 0;

        while (1) {

            hService = CreateService(hManager,
                lpServiceName,
                lpServiceName,
                SERVICE_ALL_ACCESS,
                SERVICE_INTERACTIVE_PROCESS | SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                (LPCWSTR)&szFileName,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);

            if (hService) {
                break;
            }
            else {
                ShowDebug(TEXT("CreateService failed"));
            }

            if (GetLastError() == ERROR_SERVICE_EXISTS) {
                ShowDebug(TEXT("Service already exist"));

                hService = OpenService(hManager, lpServiceName, DELETE);
                if (hService) {
                    ShowDebug(TEXT("Service opened successfully"));

                    DeleteService(hService);
                    CloseServiceHandle(hService);
                    hService = 0;
                    Sleep(5000);
                }

                if (++retryCount < 2)
                    continue;

            }

            if (hService == NULL) {
                ultohex(GetLastError(), szFileName);
                ShowDebug(szFileName);
                break;
            }

            break;
        }

        if (hService) {
            ShowDebug(TEXT("Starting service"));
            bResult = StartService(hService, 0, NULL);
            DeleteService(hService);
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hManager);
    }
    else {
        ShowDebug(TEXT("Cannot open SCM database"));
    }
    return bResult;
}

/*
* TryRunAsService
*
* Purpose:
*
* Restart program as LocalSystem via interactive service.
*
*/
VOID TryRunAsService(
    _In_ BOOLEAN IsRunAsLocalSystem,
    _In_ ROCALL_PARAMS *SessionParams
)
{
    BOOL bSuccess = FALSE, bServiceRun = FALSE;
    HANDLE hEvent123;

    HANDLE hEvents[2];

    INT iResult;

    DWORD WaitResult;

    SERVICE_TABLE_ENTRY ServiceStartTable;

    if (GetCommandLineOption(TEXT("-s"), FALSE, NULL, 0)) {
        OutputConsoleMessage("[~] Trying to restart as LocalSystem\r\n");
        bServiceRun = TRUE;
    }

    hEvent123 = OpenEvent(EVENT_ALL_ACCESS, FALSE, ROCALL_EVENT_123);
    if (!hEvent123) {

        ShowDebug(TEXT("!hEvent123"));

        if (IsUserInAdminGroup()) {
            if (IsRunAsLocalSystem) {
                ShowDebug(TEXT("IsLocalSystem"));

                ServiceStartTable.lpServiceName = ROCALL_SERVICE;
                ServiceStartTable.lpServiceProc = (LPSERVICE_MAIN_FUNCTION)RoCallSvcMain;
                hEvents[0] = NULL;
                hEvents[1] = NULL;

                StartServiceCtrlDispatcher(&ServiceStartTable);
                ExitProcess(0);
                return;
            }

            if (bServiceRun) {

                ShowDebug(TEXT("bServiceRun"));

                iResult = EnableInteractiveService(TRUE);
                if (iResult == -1) {
                    MessageBox(0, TEXT("Unable to run as LocalSystem account"), NULL, 0);
                }
                else {

                    ShowDebug(TEXT("EnableInteractiveService success"));

                    hEvents[0] = CreateEvent(NULL, TRUE, FALSE, ROCALL_EVENT_456);
                    hEvents[1] = CreateEvent(NULL, TRUE, FALSE, ROCALL_EVENT_789);

                    if (hEvents[0] && hEvents[1]) {

                        SessionParamsManage(TRUE, SessionParams);

                        if (InstallAndRunService(ROCALL_SERVICE)) {

                            ShowDebug(TEXT("InstallAndRunService success"));

                            WaitResult = WaitForMultipleObjects(2, hEvents, FALSE, 5000);
                            if (WaitResult && WaitResult != WAIT_TIMEOUT) {
                                bSuccess = TRUE;
                                ShowDebug(TEXT("WaitForMultipleObjects success"));
                            }
                            else {
                                MessageBox(0, TEXT("Unable to run as LocalSystem account."), NULL, 0);
                            }
                        }

                        if (hEvents[0])
                            CloseHandle(hEvents[0]);
                        if (hEvents[1])
                            CloseHandle(hEvents[1]);
                    }

                    if (iResult == 1)
                        EnableInteractiveService(FALSE);

                }

                if (bSuccess) {
                    ShowDebug(TEXT("bSuccess ExitProcess"));
                    ExitProcess(0);
                    return;
                }
            } //bServiceRun
        }
        else {
            if (bServiceRun) {
                MessageBox(0, TEXT("Administrative privileges required to run as LocalSystem account."), NULL, 0);
                ExitProcess(0);
                return;
            }
        }
    }
    else {
        CloseHandle(hEvent123);
    }
    ShowDebug(TEXT("NormalStart"));
}


VOID FORCEINLINE InitializeListHead(
    _In_ PLIST_ENTRY ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

VOID FORCEINLINE InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

/*
* OutputConsoleMessage
*
* Purpose:
*
* Output text to screen.
*
*/
VOID OutputConsoleMessage(
    _In_ LPCSTR lpMessage)
{
    ULONG r;

    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
        lpMessage,
        (DWORD)_strlen_a(lpMessage),
        &r,
        NULL);
}

/*
* IsReactOS
*
* Purpose:
*
* Return TRUE if the given system is identified as ReactOS.
*
*/
BOOL IsReactOS(
    VOID
)
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
* BlackListCreateFromFile
*
* Purpose:
*
* Read blacklist from ini file to allocated memory.
*
*/
BOOL BlackListCreateFromFile(
    _In_ BLACKLIST *BlackList,
    _In_ LPCSTR ConfigFileName,
    _In_ LPCSTR ConfigSectionName
)
{
    BOOL    bResult = FALSE;
    LPSTR   Section = NULL, SectionPtr;
    ULONG   nSize, SectionSize, BytesRead, Length;
    CHAR    ConfigFilePath[MAX_PATH + 16];

    HANDLE BlackListHeap;

    PBL_ENTRY Entry = NULL;

    do {

        RtlSecureZeroMemory(ConfigFilePath, sizeof(ConfigFilePath));
        GetModuleFileNameA(NULL, (LPSTR)&ConfigFilePath, MAX_PATH);
        _filepath_a(ConfigFilePath, ConfigFilePath);
        _strcat_a(ConfigFilePath, ConfigFileName);

        BlackListHeap = HeapCreate(HEAP_GROWABLE, 0, 0);
        if (BlackListHeap == NULL)
            break;

        HeapSetInformation(BlackListHeap, HeapEnableTerminationOnCorruption, NULL, 0);

        nSize = 2 * (1024 * 1024);

        Section = (LPSTR)HeapAlloc(BlackListHeap, HEAP_ZERO_MEMORY, nSize);
        if (Section == NULL)
            break;

        SectionSize = GetPrivateProfileSectionA(ConfigSectionName, Section, nSize, ConfigFilePath);
        if (SectionSize == 0)
            break;

        BytesRead = 0;
        SectionPtr = Section;

        memset(BlackList, 0, sizeof(BLACKLIST));

        InitializeListHead(&BlackList->ListHead);

        do {

            if (*SectionPtr == 0)
                break;

            Length = _strlen_a(SectionPtr) + 1;
            BytesRead += Length;

            Entry = (BL_ENTRY*)HeapAlloc(BlackListHeap, HEAP_ZERO_MEMORY, sizeof(BL_ENTRY));
            if (Entry == NULL) {
                goto Cleanup;
            }

            Entry->Hash = BlackListHashString(SectionPtr);

            InsertTailList(&BlackList->ListHead, &Entry->ListEntry);

            BlackList->NumberOfEntries += 1;

            SectionPtr += Length;

        } while (BytesRead < SectionSize);

        BlackList->HeapHandle = BlackListHeap;

        bResult = TRUE;

    } while (FALSE);

Cleanup:

    if (bResult == FALSE) {
        if (BlackListHeap) HeapDestroy(BlackListHeap);
    }
    return bResult;
}

/*
* BlackListEntryPresent
*
* Purpose:
*
* Return TRUE if syscall is in blacklist.
*
*/
BOOL BlackListEntryPresent(
    _In_ BLACKLIST *BlackList,
    _In_ LPCSTR SyscallName
)
{
    DWORD Hash = BlackListHashString(SyscallName);

    PLIST_ENTRY Head, Next;
    BL_ENTRY *entry;

    Head = &BlackList->ListHead;
    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {
        entry = CONTAINING_RECORD(Next, BL_ENTRY, ListEntry);
        if (entry->Hash == Hash)
            return TRUE;

        Next = Next->Flink;
    }

    return FALSE;
}

/*
* BlackListHashString
*
* Purpose:
*
* DJB hash string.
*
*/
DWORD BlackListHashString(
    _In_ LPCSTR Name
)
{
    DWORD Hash = 5381;
    PCHAR p = (PCHAR)Name;

    while (*p)
        Hash = 33 * Hash ^ *p++;

    return Hash;
}

/*
* BlackListDestroy
*
* Purpose:
*
* Destroy blacklist heap and zero blacklist structure.
*
*/
VOID BlackListDestroy(
    _In_ BLACKLIST *BlackList
)
{
    if (BlackList) {
        if (BlackList->HeapHandle) HeapDestroy(BlackList->HeapHandle);
        memset(BlackList, 0, sizeof(BLACKLIST));
    }
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
    _Out_opt_ ULONG *MajorVersion,
    _Out_opt_ ULONG *MinorVersion,
    _Out_opt_ ULONG *Build,
    _Out_opt_ ULONG *Revision
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO *pFileInfo;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID *)&pFileInfo, (PUINT)&Length);
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
* GetReactOSVersion
*
* Purpose:
*
* Return ReactOS version based on AFD.SYS version info.
*
*/
BOOL GetReactOSVersion(
    _Out_ ULONG *MajorVersion,
    _Out_ ULONG *MinorVersion,
    _Out_ ULONG *Build,
    _Out_ ULONG *Revision
)
{
    BOOL bResult = FALSE;
    DWORD cch;
    WCHAR szFilePath[MAX_PATH * 2];

    //
    // Assume failure.
    //
    if (MajorVersion)
        *MajorVersion = 0;
    if (MinorVersion)
        *MinorVersion = 0;
    if (Build)
        *Build = 0;
    if (Revision)
        *Revision = 0;

    RtlSecureZeroMemory(szFilePath, sizeof(szFilePath));
    cch = GetSystemDirectory(szFilePath, MAX_PATH);
    if ((cch == 0) || (cch > MAX_PATH))
        return FALSE;

    _strcat_w(szFilePath, L"\\drivers\\afd.sys");

    bResult = InternalGetImageVersionInfo(szFilePath,
        MajorVersion,
        MinorVersion,
        Build,
        Revision);

    return bResult;
}

/*
* IsUserInAdminGroup
*
* Purpose:
*
* Returns TRUE if current user is in admin group.
*
*/
BOOLEAN IsUserInAdminGroup()
{
    BOOLEAN bResult = FALSE;
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
* IsLocalSystem
*
* Purpose:
*
* Returns TRUE if current user is LocalSystem.
*
*/
BOOLEAN IsLocalSystem()
{
    BOOLEAN bResult = FALSE;
    ULONG returnLength;
    HANDLE hToken;
    TOKEN_USER *ptu;

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

/*
* QuerySystemInformationByClass
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with HeapFree after usage.
*
*/
PVOID QuerySystemInformationByClass(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT			TryNumber = 0;
    PVOID		Buffer = NULL;
    ULONG		Size = PAGE_SIZE;
    NTSTATUS	Status;
    ULONG       Dummy;

    HANDLE      ProcessHeap = GetProcessHeap();

    do {
        Buffer = HeapAlloc(ProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)Size);
        if (Buffer != NULL) {
            Status = NtQuerySystemInformation(InfoClass, Buffer, Size, &Dummy);
        }
        else {
            return NULL;
        }
        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(ProcessHeap, 0, Buffer);
            Buffer = NULL;
            Size *= 2;
            if (++TryNumber > 20) {
                Status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(Status)) {
        return Buffer;
    }

    if (Buffer) {
        HeapFree(ProcessHeap, 0, Buffer);
    }
    return NULL;
}

/*
* SessionParamsRemove
*
* Purpose:
*
* Remove session params from registry.
*
*/
VOID SessionParamsRemove()
{
    RegDeleteKey(HKEY_LOCAL_MACHINE, ROCALL_CFG_KEY);
}

/*
* SessionParamsManage
*
* Purpose:
*
* Save/Read session params from registry.
*
*/
VOID SessionParamsManage(
    _In_ BOOLEAN fSet,
    _Inout_ ROCALL_PARAMS *SessionParams)
{
    BOOL bSuccess = TRUE;
    HKEY hKey = NULL;
    DWORD dwType = REG_BINARY;
    DWORD cbData = sizeof(ROCALL_PARAMS);

    ROCALL_PARAMS localSessionParams;

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
                (BYTE*)SessionParams,
                sizeof(ROCALL_PARAMS)) == ERROR_SUCCESS);
        }
        else {

            dwType = REG_NONE;
            cbData = sizeof(ROCALL_PARAMS);
            RtlSecureZeroMemory(&localSessionParams, sizeof(ROCALL_PARAMS));
            if (RegQueryValueEx(hKey,
                TEXT("Params"),
                0,
                &dwType,
                (BYTE*)&localSessionParams,
                &cbData) == ERROR_SUCCESS)
            {
                if (dwType == REG_BINARY) {
                    if (localSessionParams.PassCount == 0)
                        localSessionParams.PassCount = FUZZ_PASS_COUNT;
                    if (localSessionParams.WaitTimeout == 0)
                        localSessionParams.WaitTimeout = DEFAULT_WAIT_TIMEOUT;

                    RtlCopyMemory(SessionParams, &localSessionParams, sizeof(ROCALL_PARAMS));
                    bSuccess = TRUE;
                }
            }
        }
        RegCloseKey(hKey);

    }

    if (bSuccess == FALSE)
        ShowDebug(TEXT("Error managing session params"));
}

/*
* IsRCHDrvLoaded
*
* Purpose:
*
* Check if supervising driver loaded.
*
*/
BOOLEAN IsRCHDrvLoaded()
{
    ULONG i;
    PRTL_PROCESS_MODULES Modules = QuerySystemInformationByClass(SystemModuleInformation);

    if (Modules) {
        for (i = 0; i < Modules->NumberOfModules; i++) {
            if (_strstri_a(Modules->Modules[i].FullPathName, "rchdrv.sys")) {
                HeapFree(GetProcessHeap(), 0, Modules);
                return TRUE;
            }
        }
        HeapFree(GetProcessHeap(), 0, Modules);
    }
    return FALSE;
}
