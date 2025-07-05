/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       LOG.H
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
*  Log support header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define LOG_MAX_ARGS 16

typedef struct _LOG_PARAMS {
    BOOL LogToFile;
    HANDLE LogHandle;
} LOG_PARAMS, * PLOG_PARAMS;

#pragma pack(push, 1)
typedef struct _SYSCALL_LOG_ENTRY {
    ULONG SyscallNumber;
    ULONG ArgCount;
    ULONG_PTR Arguments[LOG_MAX_ARGS];
} SYSCALL_LOG_ENTRY, * _SYSCALL_LOG_ENTRY;
#pragma pack(pop)

VOID FuzzLogLastService(
    _In_ LPCSTR ServiceName);

BOOLEAN FuzzOpenLog(
    _In_ LPWSTR LogDeviceFileName,
    _In_ PLOG_PARAMS LogParams);

VOID FuzzCloseLog(
    _In_ PLOG_PARAMS LogParams);

VOID FuzzLogCallBinary(
    _In_ PLOG_PARAMS LogParams,
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG_PTR* Arguments);
