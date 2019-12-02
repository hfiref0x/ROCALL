/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.02
*
*  DATE:        30 Nov 2019
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
#if (_MSC_VER >= 1900) //VS15, 17 etc
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up

#include <Windows.h>
#include <ntstatus.h>
#include "roos.h"
#include "minirtl/minirtl.h"
#include "minirtl/_filename.h"
#include "minirtl/cmdline.h"

typedef struct _ROCALL_PARAMS {

    //
    // Custom options enabled.
    //
    BOOL ProbeWin32kOption;
    BOOL EnableLogOption;
    BOOL VerboseLogOption;
    BOOL SyscallStartFromOption;
    BOOL PassCountOption;
    BOOL WaitTimeoutOption;

    //
    // Actual settings.
    //
    BOOL ProbeWin32k;
    BOOL EnableLog;
    BOOL VerboseLog;
    DWORD SyscallStartFrom;
    DWORD PassCount;
    DWORD WaitTimeout;
} ROCALL_PARAMS, *PROCALL_PARAMS;

#include "util.h"
#include "fuzz.h"
#include "syscall.h"
