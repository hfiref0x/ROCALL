/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       FUZZ.H
*
*  VERSION:     2.00
*
*  DATE:        05 Jul 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define SYSCALL_ENTRY_FIRST 0
#define W32SYSCALLSTART     0x1000
#define KiServiceLimit      sizeof(KiServiceTable) / sizeof(SYSCALL_ENTRY)
#define W32pServiceLimit    sizeof(W32pServiceTable) / sizeof(SYSCALL_ENTRY)

#define MAX_PARAMETERS  32 //while actual implemented maximum is 17 according to tables
#define FUZZ_PASS_COUNT 65536
#define FUZZ_THREAD_TIMEOUT_SEC 30 //in seconds

#define MAX_STRUCT_BUFFER_SIZE   4096
#define MAX_KEYVALUE_BUFFER_SIZE 1024

typedef struct _CALL_PARAM {
    ULONG Syscall;
    ULONG NumberOfArguments;
    ULONG ThreadTimeout;
    ULONG NumberOfPassesForCall;
    PVOID LogParams;
    BOOL LogEnabled;
    BOOL EnableParamsHeuristic;
    LPCSTR ServiceName;
} CALL_PARAM, *PCALL_PARAM;

typedef struct _FUZZ_STATS {
    ULONG TotalCalls;
    ULONG TimeoutCalls;
    ULONG SuccessCalls;
    ULONG ErrorCalls;
    ULONG CrashedCalls;
} FUZZ_STATS, * PFUZZ_STATS;

// Define ReactOS parameter types
typedef enum _PARAM_TYPE_HINT {
    ParamTypeGeneral = 0,    // No specific type known
    ParamTypeHandle,         // NT handle
    ParamTypeAddress,        // Memory address/pointer
    ParamTypeStatus,         // Status block
    ParamTypeFlag,           // Flags or options
    ParamTypeAccess,         // Access mask
    ParamTypeUnicodeStr,     // UNICODE_STRING structure
    ParamTypeObjectAttr,     // OBJECT_ATTRIBUTES structure
    ParamTypeWinHandle,      // Window handle
    ParamTypeGdiHandle,      // GDI object handle
    ParamTypeToken,          // Token handle
    ParamTypePrivilege,      // TOKEN_PRIVILEGES structure 
    ParamTypeInfoClass,      // Information class value
    ParamTypeBufferSize,     // Buffer size for I/O operations
    ParamTypeTimeout,        // Timeout value
    ParamTypeRetLength,      // Return length pointer
    ParamTypeSecDesc,        // Security descriptor
    ParamTypeClientId,       // CLIENT_ID structure
    ParamTypeKeyValue,       // Registry key value info
    ParamTypeOutPtr          // Output pointer receiving a value
} PARAM_TYPE_HINT;

// Structure for known syscall parameter types
typedef struct _SYSCALL_PARAM_INFO {
    LPCSTR Name;                                // Name of the syscall
    PARAM_TYPE_HINT ParamTypes[MAX_PARAMETERS]; // Type hints for up to MAX_PARAMETERS
} SYSCALL_PARAM_INFO, * PSYSCALL_PARAM_INFO;

VOID FuzzTrackAllocation(
    _In_ PVOID Address,
    _In_ FUZZ_ALLOC_TYPE Type);

VOID FuzzCleanupAllocations();

VOID FuzzDetectParameterTypes(
    _In_ LPCSTR ServiceName,
    _In_ ULONG ParameterCount,
    _In_ BOOL IsWin32kSyscall,
    _Out_writes_(ParameterCount) PARAM_TYPE_HINT* TypeHints);

DWORD FuzzGenerateParameter(
    _In_ ULONG ParameterIndex,
    _In_ PARAM_TYPE_HINT TypeHint,
    _In_ BOOL IsWin32kSyscall,
    _In_ BOOL EnableParamsHeuristic,
    _In_ PBYTE FuzzStructBuffer);

UINT FuzzRun(
    _In_ BLACKLIST* BlackList,
    _In_ PFUZZ_PARAMS Context);

PSECURITY_DESCRIPTOR CreateFuzzedSecurityDescriptor(_In_ BYTE* FuzzStructBuffer);
PCLIENT_ID CreateFuzzedClientId(_In_ BYTE* FuzzStructBuffer);
PIO_STATUS_BLOCK CreateFuzzedIoStatusBlock(_In_ BYTE* FuzzStructBuffer);
PTOKEN_PRIVILEGES CreateFuzzedTokenPrivileges(_In_ BYTE* FuzzStructBuffer);
POBJECT_ATTRIBUTES CreateFuzzedObjectAttributes(_In_ BYTE* FuzzStructBuffer);
PUNICODE_STRING CreateFuzzedUnicodeString(_In_ BYTE* FuzzStructBuffer);
PLARGE_INTEGER CreateFuzzedLargeInteger(_In_ BYTE* FuzzStructBuffer);
PKERNEL_USER_TIMES CreateFuzzedProcessTimes(_In_ BYTE* FuzzStructBuffer);
PSECTION_IMAGE_INFORMATION CreateFuzzedSectionImageInfo(_In_ BYTE* FuzzStructBuffer);
PVOID CreateFuzzedReturnLength(VOID);
PVOID CreateFuzzedOutputPointer(_In_ ULONG ParameterIndex);
PVOID CreateFuzzedKeyValueParameter(VOID);

/*void SyscallDBGen();
void OutputSortedWin32kSyscalls();*/
