/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       BLACKLIST.H
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
*  Syscall blacklist header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define BLACKLIST_HASH_TABLE_SIZE 256

typedef struct _BL_ENTRY {
    LIST_ENTRY ListEntry;
    DWORD Hash;
    PCHAR Name;
} BL_ENTRY, * PBL_ENTRY;

typedef struct _BLACKLIST {
    HANDLE HeapHandle;
    ULONG NumberOfEntries;
    LIST_ENTRY HashTable[BLACKLIST_HASH_TABLE_SIZE];
} BLACKLIST, * PBLACKLIST;

#define CFG_FILE    "badcalls.ini"

DWORD BlackListHashString(
    _In_ LPCSTR Name);

ULONG BlackListAddEntry(
    _In_ BLACKLIST* BlackList,
    _In_ LPCSTR SyscallName);

BOOL BlackListCreateFromFile(
    _In_ BLACKLIST* BlackList,
    _In_ LPCSTR ConfigFileName,
    _In_ LPCSTR ConfigSectionName);

BOOL BlackListEntryPresent(
    _In_ BLACKLIST* BlackList,
    _In_ LPCSTR SyscallName);

VOID BlackListDestroy(
    _In_ BLACKLIST* BlackList);
