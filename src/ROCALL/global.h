/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     2.00
*
*  DATE:        05 Jul 2025
*
*  Global definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma comment(lib, "version.lib")

#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up

#define ROOS_ENABLE_LIST_ENTRY_MACRO

#include <Windows.h>
#include <ntstatus.h>
#include <intrin.h>
#include <TlHelp32.h>
#include "safestr.h"
#include "roos.h"
#include "minirtl/minirtl.h"
#include "minirtl/_filename.h"
#include "minirtl/cmdline.h"
#include "blacklist.h"

#define TEXT_COLOR_CYAN FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define TEXT_COLOR_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define TEXT_COLOR_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)

typedef struct _FUZZ_PARAMS {
    BOOL ProbeWin32k;
    BOOL LogEnabled;
    BOOL LogToFile;
    BOOL EnableParamsHeuristic;
    BOOL ProbeFromSyscallId;
    DWORD SyscallStartFrom;
    DWORD PassCount;
    DWORD WaitTimeout;
    WCHAR szLogDeviceOrFile[MAX_PATH + 1];
} FUZZ_PARAMS, *PFUZZ_PARAMS;

typedef enum _FUZZ_ALLOC_TYPE {
    AllocTypeVirtualAlloc,
    AllocTypeSid
} FUZZ_ALLOC_TYPE;

#define MAX_FUZZING_ALLOCATIONS 32
typedef struct _FUZZ_MEMORY_TRACKER {
    ULONG Count;
    PVOID Addresses[MAX_FUZZING_ALLOCATIONS];
    FUZZ_ALLOC_TYPE Types[MAX_FUZZING_ALLOCATIONS];
    BOOLEAN InUse;
} FUZZ_MEMORY_TRACKER, * PFUZZ_MEMORY_TRACKER;

#include "sup.h"
#include "log.h"
#include "syscall.h"
#include "fuzz.h"

extern FUZZ_MEMORY_TRACKER g_MemoryTracker;
extern FUZZ_STATS g_FuzzStats;
extern LOG_PARAMS g_Log;
extern BLACKLIST g_BlackList;


