/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025
*
*  TITLE:       SAFESTR.C
*
*  VERSION:     2.00
*
*  DATE:        01 Jul 2025
*
*  StringCchPrintfA replacement with no C runtime dependencies.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

//
// Since that ReactOS shit doesn't support somewhat modern API 
// (which is available for hmmm like ~20 years) we have to reinvent the wheel
// Only %s, %lu, %04lu
void StringCchPrintfA(char* dst, size_t cchDst, const char* format, ...)
{
    if (cchDst == 0) return;

    va_list args;
    va_start(args, format);

    char* pDst = dst;
    size_t remaining = cchDst;
    const char* p = format;

    while (*p != '\0' && remaining > 1) {
        if (*p == '%') {
            if (p[1] == 's') {
                p += 2; // Skip "%s"
                const char* str = va_arg(args, const char*);
                while (*str != '\0' && remaining > 1) {
                    *pDst++ = *str++;
                    remaining--;
                }
            }
            else if (p[1] == 'l' && p[2] == 'u') {
                p += 3; // Skip "%lu"
                unsigned long num = va_arg(args, unsigned long);
                char buffer[20];
                int idx = 0;

                if (num == 0) {
                    buffer[idx++] = '0';
                }
                else {
                    while (num > 0) {
                        buffer[idx++] = '0' + (num % 10);
                        num /= 10;
                    }
                }

                for (int j = idx - 1; j >= 0; j--) {
                    if (remaining <= 1) break;
                    *pDst++ = buffer[j];
                    remaining--;
                }
            }
            else if (p[1] == '0' && p[2] == '4' && p[3] == 'l' && p[4] == 'u') {
                p += 5; // Skip "%04lu"
                unsigned long num = va_arg(args, unsigned long);
                char buffer[20];
                int idx = 0;

                if (num == 0) {
                    buffer[idx++] = '0';
                }
                else {
                    while (num > 0) {
                        buffer[idx++] = '0' + (num % 10);
                        num /= 10;
                    }
                }

                int zeroCount = 4 - idx;
                while (zeroCount-- > 0 && remaining > 1) {
                    *pDst++ = '0';
                    remaining--;
                }

                for (int j = idx - 1; j >= 0; j--) {
                    if (remaining <= 1) break;
                    *pDst++ = buffer[j];
                    remaining--;
                }
            }
            else {
                *pDst++ = '%';
                remaining--;
                p++; // Skip '%' in format string
            }
        }
        else {
            *pDst++ = *p++;
            remaining--;
        }
    }

    *pDst = '\0';
    va_end(args);
}
