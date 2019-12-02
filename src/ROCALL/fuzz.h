/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       FUZZ.H
*
*  VERSION:     1.02
*
*  DATE:        30 Nov 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef struct _CALL_PARAM {
    ULONG ServiceId;
    ULONG NumberOfArguments;
    ULONG PassCount;
} CALL_PARAM, *PCALL_PARAM;

typedef struct _REACTOS_VERSION {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
    ULONG Revision;
} REACTOS_VERSION, *PREACTOS_VERSION;

#define ARGUMENT_COUNT  32 //while actual implemented maximum is 17 according to tables
#define FUZZ_PASS_COUNT 1024
#define DEFAULT_WAIT_TIMEOUT 30 //in seconds


#define SIZEOF_FUZZDATA 10 
static const DWORD fuzzdata[SIZEOF_FUZZDATA] = {
            0x00000000, 0x0000001, 0x0000ffff, 0x0000fffe, 0x7fffffff,
            0x7ffffffe, 0x80000000, 0x80000001, 0xffffffff, 0xfffffffe
};
