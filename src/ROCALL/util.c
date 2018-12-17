/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       UTIL.C
*
*  VERSION:     1.00
*
*  DATE:        05 Dec 2018
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
* ForcePrivilegeEnabled
*
* Purpose:
*
* Attempt to enable all known privileges.
*
*/
void ForcePrivilegeEnabled()
{
    ULONG c;
    BOOLEAN bWasEnabled;


    for (c = 2; c <= 35; c++) {
        RtlAdjustPrivilege(c, TRUE, FALSE, &bWasEnabled);
    }
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
    LPWSTR lpBuffer;
    HANDLE hSection = NULL;
    const WCHAR szRegKey[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    STATIC_UNICODE_STRING(usSectionName, L"\\KnownDlls\\kernel32_vista.dll");
    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES(&usSectionName, OBJ_CASE_INSENSITIVE);

    if (NT_SUCCESS(NtOpenSection(&hSection, SECTION_QUERY, &obja))) {
        CloseHandle(hSection);
        bResult = TRUE;
    }

    if (bResult == FALSE) {

        if (ERROR_SUCCESS == RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            szRegKey, 0, KEY_QUERY_VALUE, &hKey))
        {
            if (ERROR_SUCCESS == RegQueryValueEx(hKey,
                L"ProductName", NULL, &dwType, NULL, &dwSize))
            {
                if (dwType == REG_SZ) {
                    lpBuffer = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
                    if (lpBuffer) {

                        if (ERROR_SUCCESS == RegQueryValueExW(hKey,
                            L"ProductName", NULL, &dwType, (LPBYTE)lpBuffer, &dwSize))
                        {
                            bResult = (_strcmpi_w(lpBuffer, L"ReactOS") == 0);
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
    BOOL    bCond = FALSE, bResult = FALSE;
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

    } while (bCond);

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
