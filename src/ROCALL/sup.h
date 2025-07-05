/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       SUP.H
*
*  VERSION:     2.00
*
*  DATE:        07 Jul 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef struct _REACTOS_VERSION {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
    ULONG Revision;
} REACTOS_VERSION, * PREACTOS_VERSION;

BOOL ConsoleInit(
    VOID);

VOID ConsoleShowMessage(
    _In_ LPCSTR lpMessage,
    _In_ WORD wColor);

VOID ConsoleShowMessage2(
    _In_ LPCSTR lpMessage,
    _In_ WORD wColor);

BOOL supGetReactOSVersion(
    _Inout_ REACTOS_VERSION* OsVersion);

BOOL supIsReactOS();
BOOL supIsUserInAdminGroup();
BOOL supIsLocalSystem();
BOOL supIsCheckedBuild();

_Success_(return)
BOOL supGetParamOption(
    _In_ LPCWSTR params,
    _In_ LPCWSTR optionName,
    _In_ BOOL isParametric,
    _Out_opt_ LPWSTR value,
    _In_ ULONG valueLength, //in chars
    _Out_opt_ PULONG paramLength);

VOID supTryRunAsService(
    _In_ BOOL IsRunAsLocalSystem,
    _In_ PFUZZ_PARAMS FuzzParams);

BOOL supIsComPort(
    _In_ LPCWSTR wsz);

BOOL supSessionParamsManage(
    _In_ BOOLEAN fSet,
    _Inout_ PFUZZ_PARAMS FuzzParams);

VOID supSessionParamsRemove();
