/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025
*
*  TITLE:       FUZZ_PARAM.C
*
*  VERSION:     2.00
*
*  DATE:        05 Jul 2025
*
*  Parameter type detection and structure generation for syscall fuzzing.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "fuzz_data.h"

/*
void SyscallDBGen()
{
    BOOL bFound = FALSE;
    ULONG i, j;
    ULONG c = ARRAYSIZE(W32pServiceTable);

    OutputDebugStringA("===================================\r\n");
    OutputDebugStringA("Missing in KnownWin32kSyscalls\r\n");
    OutputDebugStringA("===================================\r\n");

    for (i = 0; i < c; i++) {
        LPCSTR name = W32pServiceTable[i].Name;
        bFound = FALSE;
        for (j = 0; j < ARRAYSIZE(KnownWin32kSyscalls); j++)
        {
            if (_strcmpi_a(name, KnownWin32kSyscalls[j].Name) == 0) {
                bFound = TRUE;
                break;
            }
        }
        if (!bFound)
        {
            OutputDebugStringA(name);
            OutputDebugStringA("\r\n");
        }
    }

    OutputDebugStringA("===================================\r\n");
    OutputDebugStringA("Missing in W32pServiceTable\r\n");
    OutputDebugStringA("===================================\r\n");

    for (i = 0; i < ARRAYSIZE(KnownWin32kSyscalls); i++) {
        LPCSTR name = KnownWin32kSyscalls[i].Name;
        bFound = FALSE;
        for (j = 0; j < ARRAYSIZE(W32pServiceTable); j++)
        {
            if (_strcmpi_a(name, W32pServiceTable[j].Name) == 0) {
                bFound = TRUE;
                break;
            }
        }
        if (!bFound)
        {
            OutputDebugStringA(name);
            OutputDebugStringA("\r\n");
        }
    }
}

// Comparison function for qsort to sort syscall entries by name
int CompareWin32kSyscalls(const void* a, const void* b) {
    const SYSCALL_PARAM_INFO* syscallA = (const SYSCALL_PARAM_INFO*)a;
    const SYSCALL_PARAM_INFO* syscallB = (const SYSCALL_PARAM_INFO*)b;

    // Handle NULL entries (terminator) - they go to the end
    if (syscallA->Name == NULL) return 1;
    if (syscallB->Name == NULL) return -1;

    // Compare the syscall names
    return strcmp(syscallA->Name, syscallB->Name);
}

// Helper function to convert ParamTypeHint to string
const char* ParamTypeToString(PARAM_TYPE_HINT hint) {
    switch (hint) {
    case ParamTypeGeneral: return "ParamTypeGeneral";
    case ParamTypeHandle: return "ParamTypeHandle";
    case ParamTypeAddress: return "ParamTypeAddress";
    case ParamTypeStatus: return "ParamTypeStatus";
    case ParamTypeFlag: return "ParamTypeFlag";
    case ParamTypeAccess: return "ParamTypeAccess";
    case ParamTypeUnicodeStr: return "ParamTypeUnicodeStr";
    case ParamTypeObjectAttr: return "ParamTypeObjectAttr";
    case ParamTypeWinHandle: return "ParamTypeWinHandle";
    case ParamTypeGdiHandle: return "ParamTypeGdiHandle";
    case ParamTypeToken: return "ParamTypeToken";
    case ParamTypePrivilege: return "ParamTypePrivilege";
    case ParamTypeInfoClass: return "ParamTypeInfoClass";
    case ParamTypeBufferSize: return "ParamTypeBufferSize";
    case ParamTypeTimeout: return "ParamTypeTimeout";
    case ParamTypeRetLength: return "ParamTypeRetLength";
    case ParamTypeSecDesc: return "ParamTypeSecDesc";
    case ParamTypeClientId: return "ParamTypeClientId";
    case ParamTypeKeyValue: return "ParamTypeKeyValue";
    case ParamTypeOutPtr: return "ParamTypeOutPtr";
    default: return "ParamTypeGeneral";
    }
}

void OutputSortedWin32kSyscalls() {
    int syscallCount = 0;
    while (KnownWin32kSyscalls[syscallCount].Name != NULL) {
        syscallCount++;
    }

    // Allocate memory for a copy of the array
    SYSCALL_PARAM_INFO* sortedSyscalls = (SYSCALL_PARAM_INFO*)malloc(
        (syscallCount + 1) * sizeof(SYSCALL_PARAM_INFO));

    if (sortedSyscalls == NULL) {
        OutputDebugStringA("Memory allocation failed!");
        return;
    }

    memcpy(sortedSyscalls, KnownWin32kSyscalls,
        (syscallCount + 1) * sizeof(SYSCALL_PARAM_INFO));

    qsort(sortedSyscalls, syscallCount, sizeof(SYSCALL_PARAM_INFO),
        CompareWin32kSyscalls);

    OutputDebugStringA("======================\r\n");

    char buffer[512];

    for (int i = 0; i < syscallCount; i++) {
        sprintf(buffer, "   {\"%s\", {", sortedSyscalls[i].Name);

        int paramCount = 0;
        while (paramCount < MAX_PARAMETERS &&
            sortedSyscalls[i].ParamTypes[paramCount] != 0) {
            paramCount++;
        }

        if (paramCount == 0) {
            strcat(buffer, "ParamTypeGeneral");
        }
        else {

            for (int j = 0; j < paramCount; j++) {
                char paramBuffer[64];
                sprintf(paramBuffer, "%s%s",
                    ParamTypeToString(sortedSyscalls[i].ParamTypes[j]),
                    (j < paramCount - 1) ? ", " : "");
                strcat(buffer, paramBuffer);
            }
        }

        strcat(buffer, "}},\r\n");
        OutputDebugStringA(buffer);
    }

    OutputDebugStringA("======================\r\n");
    free(sortedSyscalls);
}*/

/*
* FuzzTrackAllocation
*
* Purpose:
*
* Track allocated memory so it can be freed even if the stack is corrupted.
*
*/
VOID FuzzTrackAllocation(
    _In_ PVOID Address,
    _In_ FUZZ_ALLOC_TYPE Type
)
{
    if (Address == NULL)
        return;

    if (g_MemoryTracker.Count < MAX_FUZZING_ALLOCATIONS) {
        g_MemoryTracker.Addresses[g_MemoryTracker.Count] = Address;
        g_MemoryTracker.Types[g_MemoryTracker.Count] = Type;
        g_MemoryTracker.Count++;
    }
}
/*
* FuzzCleanupAllocations
*
* Purpose:
*
* Free all tracked memory allocations.
* This is called from a separate context to handle stack corruption.
*
*/
VOID FuzzCleanupAllocations()
{
    ULONG i;

    if (!g_MemoryTracker.InUse)
        return;

    for (i = 0; i < g_MemoryTracker.Count; i++) {
        if (g_MemoryTracker.Addresses[i] != NULL) {
            switch (g_MemoryTracker.Types[i]) {
            case AllocTypeVirtualAlloc:
                VirtualFree(g_MemoryTracker.Addresses[i], 0, MEM_RELEASE);
                break;
            case AllocTypeSid:
                FreeSid(g_MemoryTracker.Addresses[i]);
                break;
            }
            g_MemoryTracker.Addresses[i] = NULL;
        }
    }
    g_MemoryTracker.Count = 0;
    g_MemoryTracker.InUse = FALSE;
}

/*
* SyscallBinarySearch
*
* Purpose:
*
* Performs binary search on a sorted syscall database to find parameter type information.
*
*/
PARAM_TYPE_HINT FuzzSyscallBinarySearch(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParamIndex,
    _In_ const SYSCALL_PARAM_INFO* Database
)
{
    int left = 0;
    int right = 0;
    int mid, result;

    while (Database[right].Name != NULL) {
        right++;
    }
    right--;

    while (left <= right) {
        mid = left + ((right - left) / 2);
        result = _strcmpi_a(SyscallName, Database[mid].Name);
        if (result == 0) {
            return Database[mid].ParamTypes[ParamIndex];
        }

        if (result < 0) {
            right = mid - 1;
        }
        else {
            left = mid + 1;
        }
    }

    return ParamTypeGeneral;
}

/*
* FuzzDetermineParameterTypeHeuristic
*
* Purpose:
*
* Heuristic to determine parameter type based on syscall name and parameter position
* when the syscall is not found in the predefined database.
*
*/
PARAM_TYPE_HINT FuzzDetermineParameterTypeHeuristic(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParameterIndex,
    _In_ BOOL IsWin32kSyscall
)
{
    BOOL hasCreatePrefix = _strstr_a(SyscallName, "Create") != NULL;
    BOOL hasOpenPrefix = _strstr_a(SyscallName, "Open") != NULL;
    BOOL hasQueryPrefix = _strstr_a(SyscallName, "Query") != NULL;
    BOOL hasSetPrefix = _strstr_a(SyscallName, "Set") != NULL;
    BOOL hasEnumeratePrefix = _strstr_a(SyscallName, "Enumerate") != NULL;
    BOOL hasAllocPrefix = _strstr_a(SyscallName, "Allocate") != NULL;
    BOOL hasFreePrefix = _strstr_a(SyscallName, "Free") != NULL;
    BOOL hasGetPrefix = _strstr_a(SyscallName, "Get") != NULL;

    BOOL hasFileTerm = _strstr_a(SyscallName, "File") != NULL;
    BOOL hasKeyTerm = _strstr_a(SyscallName, "Key") != NULL;
    BOOL hasRegistryTerm = hasKeyTerm || _strstr_a(SyscallName, "Registry") != NULL;
    BOOL hasMemoryTerm = _strstr_a(SyscallName, "Memory") != NULL || _strstr_a(SyscallName, "Virtual") != NULL;
    BOOL hasProcessTerm = _strstr_a(SyscallName, "Process") != NULL;
    BOOL hasThreadTerm = _strstr_a(SyscallName, "Thread") != NULL;
    BOOL hasTokenTerm = _strstr_a(SyscallName, "Token") != NULL;
    BOOL hasInfoTerm = _strstr_a(SyscallName, "Information") != NULL;
    BOOL hasReadTerm = _strstr_a(SyscallName, "Read") != NULL;
    BOOL hasWriteTerm = _strstr_a(SyscallName, "Write") != NULL;
    BOOL hasSecurityTerm = _strstr_a(SyscallName, "Security") != NULL ||
        _strstr_a(SyscallName, "Sacl") != NULL ||
        _strstr_a(SyscallName, "Dacl") != NULL;
    BOOL hasTimeTerm = _strstr_a(SyscallName, "Time") != NULL ||
        _strstr_a(SyscallName, "Timer") != NULL ||
        _strstr_a(SyscallName, "Delay") != NULL ||
        _strstr_a(SyscallName, "Wait") != NULL;
    BOOL hasSectionTerm = _strstr_a(SyscallName, "Section") != NULL;
    BOOL hasValueTerm = _strstr_a(SyscallName, "Value") != NULL;
    BOOL hasClientTerm = _strstr_a(SyscallName, "Client") != NULL || _strstr_a(SyscallName, "PID") != NULL;
    BOOL hasPrivilegeTerm = _strstr_a(SyscallName, "Privilege") != NULL;

    BOOL isUserFunction = IsWin32kSyscall && _strstr_a(SyscallName, "NtUser") != NULL;
    BOOL isGdiFunction = IsWin32kSyscall && _strstr_a(SyscallName, "NtGdi") != NULL;
    BOOL hasWindowTerm = _strstr_a(SyscallName, "Window") != NULL;
    BOOL hasMenuTerm = _strstr_a(SyscallName, "Menu") != NULL;
    BOOL hasDCTerm = _strstr_a(SyscallName, "DC") != NULL;
    BOOL hasDrawTerm = _strstr_a(SyscallName, "Draw") != NULL ||
        _strstr_a(SyscallName, "Paint") != NULL ||
        _strstr_a(SyscallName, "Fill") != NULL;

    BOOL isFirstParam = (ParameterIndex == 0);
    BOOL isSecondParam = (ParameterIndex == 1);
    BOOL isThirdParam = (ParameterIndex == 2);
    BOOL isFourthParam = (ParameterIndex == 3);
    BOOL isFifthParam = (ParameterIndex == 4);
    BOOL isHighIndexParam = (ParameterIndex >= 5);

    // ========== SYSTEM-WIDE PATTERNS ==========

    // Security descriptor parameters
    if (hasSecurityTerm) {
        if (isThirdParam || isFourthParam) {
            return ParamTypeSecDesc;
        }
    }

    // Time and interval parameters
    if (hasTimeTerm) {
        if (isSecondParam || isThirdParam) {
            return ParamTypeTimeout; // Likely a LARGE_INTEGER time value
        }
    }

    // Section-related parameters
    if (hasSectionTerm) {
        if (isFirstParam) return ParamTypeHandle;
        if (isThirdParam || isFourthParam) return ParamTypeAddress;
        if (isSecondParam && hasQueryPrefix) return ParamTypeInfoClass;
    }

    // Client ID parameters for thread/process identification
    if ((hasProcessTerm || hasThreadTerm) && hasClientTerm) {
        if (isThirdParam || isFourthParam) {
            return ParamTypeClientId;
        }
    }

    // Privilege-related parameters
    if (hasPrivilegeTerm && (hasTokenTerm || hasSetPrefix)) {
        if (isSecondParam || isThirdParam) {
            return ParamTypePrivilege;
        }
    }

    // ========== WIN32K SYSCALLS ==========

    if (IsWin32kSyscall) {
        // User function parameter patterns
        if (isUserFunction) {
            if (isFirstParam) {
                if (hasWindowTerm || hasMenuTerm) {
                    return ParamTypeWinHandle;
                }
                if (hasCreatePrefix || hasOpenPrefix) {
                    return ParamTypeAddress; // Output handle pointer
                }

                return ParamTypeWinHandle; // Default for first param in NtUser
            }

            // String related parameters
            if ((isSecondParam || isThirdParam) &&
                (hasCreatePrefix || _strstr_a(SyscallName, "Name") != NULL ||
                    _strstr_a(SyscallName, "Text") != NULL))
            {
                return ParamTypeUnicodeStr;
            }

            // Common patterns for second parameters
            if (isSecondParam) {
                if (hasCreatePrefix || hasOpenPrefix) {
                    return ParamTypeAccess; // For Create/Open, second param often access rights
                }
                if (hasSetPrefix || hasQueryPrefix) {
                    return ParamTypeInfoClass; // For Set/Query, often info class
                }
                if (hasGetPrefix) {
                    return ParamTypeOutPtr; // For Get, often output buffer
                }
                return ParamTypeFlag; // Default fallback
            }

            // Output pointers in User calls
            if ((isThirdParam || isFourthParam) &&
                (hasGetPrefix || hasQueryPrefix)) {
                return ParamTypeOutPtr;
            }
        }

        // GDI function parameter patterns
        if (isGdiFunction) {
            if (isFirstParam) {
                if (hasDCTerm ||
                    _strstr_a(SyscallName, "Select") != NULL ||
                    hasDrawTerm)
                {
                    return ParamTypeGdiHandle;
                }

                if (hasCreatePrefix) {
                    return ParamTypeFlag; // Often width/height for creation
                }

                return ParamTypeGdiHandle; // Default for first param in NtGdi
            }

            // Common patterns for GDI parameters
            if (hasDrawTerm && (isSecondParam || isThirdParam || isFourthParam)) {
                return ParamTypeFlag; // Often coordinates or dimensions
            }

            if (isSecondParam &&
                (_strstr_a(SyscallName, "Select") != NULL ||
                    _strstr_a(SyscallName, "Get") != NULL))
            {
                return ParamTypeGdiHandle;
            }

            if (isSecondParam || isThirdParam) {
                if (_strstr_a(SyscallName, "Color") != NULL) {
                    return ParamTypeFlag; // COLORREF value
                }
                if (_strstr_a(SyscallName, "Create") != NULL ||
                    _strstr_a(SyscallName, "Set") != NULL)
                {
                    return ParamTypeFlag; // Properties for creation/setting
                }
            }
        }

        // General patterns for Win32k parameters
        if (isHighIndexParam) {
            // Common pattern: alternating address and flag/value
            return (ParameterIndex % 2 == 0) ? ParamTypeAddress : ParamTypeFlag;
        }
    }
    // ========== NT SYSCALLS ==========
    else {
        // ======= COMMON NT SYSCALL PATTERNS ========

        // Create/Open pattern - most common NT API pattern
        if (hasCreatePrefix || hasOpenPrefix) {
            if (isFirstParam) return ParamTypeAddress;  // Output handle pointer
            if (isSecondParam) return ParamTypeAccess;  // Access mask
            if (isThirdParam) return ParamTypeObjectAttr; // Object attributes
        }

        // Query pattern - second most common NT API pattern
        if (hasQueryPrefix || hasGetPrefix) {
            if (isFirstParam) {
                // Handle for object-specific queries, info class for system-wide
                return hasInfoTerm ? ParamTypeInfoClass : ParamTypeHandle;
            }

            if (isSecondParam && hasInfoTerm) {
                return ParamTypeInfoClass; // Information class
            }

            if (isThirdParam) return ParamTypeAddress; // Output buffer
            if (isFourthParam) return ParamTypeBufferSize; // Buffer size

            // Final parameter in query functions often returns length
            if (isFifthParam && hasInfoTerm) {
                return ParamTypeRetLength;
            }
        }

        // Set pattern
        if (hasSetPrefix) {
            if (isFirstParam) return ParamTypeHandle;

            if (isSecondParam && hasInfoTerm) {
                return ParamTypeInfoClass; // Information class
            }

            if (isThirdParam) return ParamTypeAddress; // Input buffer
            if (isFourthParam) return ParamTypeBufferSize; // Buffer size
        }

        // Memory operations
        if (hasMemoryTerm || hasAllocPrefix || hasFreePrefix) {
            if (isFirstParam) return ParamTypeHandle; // Process handle
            if (isSecondParam || isThirdParam) return ParamTypeAddress; // Memory address/pointer
            if (isFourthParam) return ParamTypeFlag; // Allocation type/flags
        }

        // File operations
        if (hasFileTerm || hasReadTerm || hasWriteTerm) {
            if (isFirstParam) return ParamTypeHandle;
            if (isSecondParam && (hasReadTerm || hasWriteTerm)) {
                return ParamTypeHandle; // Event handle
            }
            if (isFourthParam && hasFileTerm) return ParamTypeStatus; // IO_STATUS_BLOCK
        }

        // Registry patterns
        if (hasRegistryTerm) {
            if (isSecondParam && (hasQueryPrefix || hasSetPrefix)) {
                return ParamTypeUnicodeStr; // Key name
            }

            if (hasValueTerm && (isFourthParam || isFifthParam) && hasQueryPrefix) {
                return ParamTypeKeyValue;
            }
        }

        // Process/thread operations
        if (hasProcessTerm || hasThreadTerm) {
            if (isFirstParam) return ParamTypeHandle;
            if (isSecondParam && hasQueryPrefix) return ParamTypeInfoClass;
        }

        // Token operations
        if (hasTokenTerm) {
            if (isFirstParam) return ParamTypeToken;
            if ((hasSetPrefix || hasQueryPrefix) && isSecondParam) return ParamTypeInfoClass;

            // Special case for token privileges
            if (hasPrivilegeTerm && isThirdParam) {
                return ParamTypePrivilege;
            }
        }

        // Enumerate patterns
        if (hasEnumeratePrefix) {
            if (ParameterIndex >= 1 && ParameterIndex <= 3) return ParamTypeAddress;
        }
    }

    // Default patterns when no specific rule matches
    switch (ParameterIndex) {
    case 0:
        return IsWin32kSyscall ?
            (isUserFunction ? ParamTypeWinHandle : ParamTypeGdiHandle) :
            ParamTypeHandle;
    case 1:
    case 3:
    case 4:
        return ParamTypeFlag;
    case 2:
        return ParamTypeAddress;
    default:
        return (ParameterIndex % 2) ? ParamTypeFlag : ParamTypeAddress;
    }
}

/*
* FuzzGetSyscallParamType
*
* Purpose:
*
* Lookup parameter type for a syscall in the known syscalls database.
*
*/
PARAM_TYPE_HINT FuzzGetSyscallParamType(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParamIndex,
    _In_ BOOL IsWin32kSyscall
)
{
    const SYSCALL_PARAM_INFO* pDatabase;
    PARAM_TYPE_HINT result;

    if (!SyscallName || ParamIndex >= 18)
        return ParamTypeGeneral;

    pDatabase = IsWin32kSyscall ? KnownWin32kSyscalls : KnownNtSyscalls;

    // Search in known syscalls database using binary search
    result = FuzzSyscallBinarySearch(SyscallName, ParamIndex, pDatabase);

    // If not found using binary search, use heuristic approach
    if (result == ParamTypeGeneral) {
        return FuzzDetermineParameterTypeHeuristic(SyscallName, ParamIndex, IsWin32kSyscall);
    }

    return result;
}

/*
* FuzzGenerateParameter
*
* Purpose:
*
* Generate a parameter value for fuzzing based on parameter type and index.
*
*/
ULONG_PTR FuzzGenerateParameter(
    _In_ ULONG ParameterIndex,
    _In_ PARAM_TYPE_HINT TypeHint,
    _In_ BOOL IsWin32kSyscall,
    _In_ BOOL EnableParamsHeuristic,
    _In_ PBYTE FuzzStructBuffer
)
{
    // If heuristics is disabled return random data
    if (!EnableParamsHeuristic) {
        return FuzzData[__rdtsc() % FUZZDATA_COUNT];
    }

    ULONG variation = __rdtsc() % 20;
    if (variation == 0) {
        return FuzzData[__rdtsc() % FUZZDATA_COUNT]; // 5% chance of using general fuzz data
    }

    // For the rest, use type-specific generation
    switch (TypeHint) {
    case ParamTypeAddress:
        if (variation < 15) { // 75% valid addresses
            // Allocate memory and return its address for certain indices
            if (ParameterIndex == 1 || ParameterIndex == 2 || ParameterIndex == 4) {
                PVOID buffer = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buffer) {
                    RtlSecureZeroMemory(buffer, 4096);
                    FuzzTrackAllocation(buffer, AllocTypeVirtualAlloc);
                    return (ULONG_PTR)buffer;
                }
            }
        }
        return FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case ParamTypeHandle:
        return FuzzHandleData[__rdtsc() % FUZZHANDLE_COUNT];

    case ParamTypeStatus:
        // 25% chance of using fuzzed IO_STATUS_BLOCK
        if (variation < 5) {
            return (ULONG_PTR)CreateFuzzedIoStatusBlock(FuzzStructBuffer);
        }
        return FuzzStatusData[__rdtsc() % FUZZSTATUS_COUNT];

    case ParamTypeAccess:
        return FuzzAccessData[__rdtsc() % FUZZACCESS_COUNT];

    case ParamTypeFlag:
        // Bit flags with 1-3 random bits set
        if (variation < 15) {
            ULONG numBits = (__rdtsc() % 3) + 1;
            ULONG_PTR result = 0;

            for (ULONG i = 0; i < numBits; i++) {
                result |= (1ULL << (__rdtsc() % 32));
            }

            return result;
        }
        return FuzzData[__rdtsc() % FUZZDATA_COUNT];

    case ParamTypeUnicodeStr:
        return (ULONG_PTR)CreateFuzzedUnicodeString(FuzzStructBuffer);

    case ParamTypeObjectAttr:
        return (ULONG_PTR)CreateFuzzedObjectAttributes(FuzzStructBuffer);

    case ParamTypeToken:
        return FuzzTokenData[__rdtsc() % FUZZTOKEN_COUNT];

    case ParamTypePrivilege:
        return (ULONG_PTR)CreateFuzzedTokenPrivileges(FuzzStructBuffer);

    case ParamTypeInfoClass:
        return FuzzInfoClassData[__rdtsc() % FUZZINFOCLASS_COUNT];

    case ParamTypeBufferSize:
        return FuzzBufSizeData[__rdtsc() % FUZZBUFSIZE_COUNT];

    case ParamTypeTimeout:
        // Use LARGE_INTEGER for timeouts
        if (variation < 15) { // 75% of the time use proper time structure
            return (ULONG_PTR)CreateFuzzedLargeInteger(FuzzStructBuffer);
        }
        else {
            static const ULONG timeoutValues[] = {
                0, 1, 10, 100, 1000, 10000, 60000,
                0x7FFFFFFF, 0xFFFFFFFF, 0x80000000 };
            return timeoutValues[__rdtsc() % _countof(timeoutValues)];
        }

    case ParamTypeRetLength:
        return (ULONG_PTR)CreateFuzzedReturnLength();

    case ParamTypeWinHandle:
        return FuzzWin32Data[__rdtsc() % FUZZWIN32_COUNT];

    case ParamTypeGdiHandle:
        return FuzzGdiData[__rdtsc() % FUZZGDI_COUNT];

    case ParamTypeSecDesc:
        return (ULONG_PTR)CreateFuzzedSecurityDescriptor(FuzzStructBuffer);

    case ParamTypeClientId:
        return (ULONG_PTR)CreateFuzzedClientId(FuzzStructBuffer);

    case ParamTypeKeyValue:
        return (ULONG_PTR)CreateFuzzedKeyValueParameter();

    case ParamTypeOutPtr:
        return (ULONG_PTR)CreateFuzzedOutputPointer(ParameterIndex);

    case ParamTypeGeneral:
    default:
        // Context-sensitive guessing for general parameters
        if (ParameterIndex >= 2 && ParameterIndex <= 4 && variation < 5) {
            // For indexes 2-4, sometimes use other complex structures that might be relevant
            ULONG structType = __rdtsc() % 3;

            switch (structType) {
            case 0:
                return (ULONG_PTR)CreateFuzzedProcessTimes(FuzzStructBuffer);
            case 1:
                return (ULONG_PTR)CreateFuzzedSectionImageInfo(FuzzStructBuffer);
            case 2:
                return (ULONG_PTR)CreateFuzzedLargeInteger(FuzzStructBuffer);
            }
        }

        if (IsWin32kSyscall && variation < 10) {
            if (__rdtsc() % 2 == 0) {
                return FuzzWin32Data[__rdtsc() % FUZZWIN32_COUNT];
            }
            else {
                return FuzzGdiData[__rdtsc() % FUZZGDI_COUNT];
            }
        }
        return FuzzData[__rdtsc() % FUZZDATA_COUNT];
    }
}

/*
* FuzzDetectParameterTypes
*
* Purpose:
*
* Determine parameter types for all parameters of a syscall.
*
*/
VOID FuzzDetectParameterTypes(
    _In_ LPCSTR ServiceName,
    _In_ ULONG ParameterCount,
    _In_ BOOL IsWin32kSyscall,
    _Out_writes_(ParameterCount) PARAM_TYPE_HINT* TypeHints
)
{
    if (!ServiceName || !TypeHints || ParameterCount == 0) {
        return;
    }

    for (ULONG i = 0; i < ParameterCount; i++) {
        TypeHints[i] = FuzzGetSyscallParamType(ServiceName, i, IsWin32kSyscall);
    }
}

//
// Structure generation START
//

#pragma warning(push)
#pragma warning(disable: 6248)

/*
* CreateFuzzedSecurityDescriptor
*
* Purpose:
*
* Create a fuzzed SECURITY_DESCRIPTOR structure with various access control settings.
*
*/
PSECURITY_DESCRIPTOR CreateFuzzedSecurityDescriptor(
    _In_ BYTE* FuzzStructBuffer
)
{
    PSECURITY_DESCRIPTOR pSD;
    PACL pAcl = NULL;
    DWORD dwAclSize;
    ULONG mode = __rdtsc() % 8;
    BOOL bResult = FALSE;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    PSID pEveryoneSid = NULL;
    PSID pSystemSid = NULL;

    pSD = (PSECURITY_DESCRIPTOR)FuzzStructBuffer;

    switch (mode) {
    case 0: // NULL security descriptor
        return NULL;

    case 1: // Invalid security descriptor
        return (PSECURITY_DESCRIPTOR)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 2: // Empty but initialized security descriptor
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;
        return pSD;

    case 3: // Security descriptor with NULL DACL (everyone access)
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        bResult = SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);
        return bResult ? pSD : NULL;

    case 4: // Security descriptor with Deny-All DACL
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        // Create a PSID for Everyone
        if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid))
            return NULL;

        // Create a deny-all ACL
        dwAclSize = sizeof(ACL) + sizeof(ACCESS_DENIED_ACE) + GetLengthSid(pEveryoneSid);
        pAcl = (PACL)VirtualAlloc(NULL, dwAclSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pAcl) {
            FuzzTrackAllocation(pAcl, AllocTypeVirtualAlloc);

            if (InitializeAcl(pAcl, dwAclSize, ACL_REVISION)) {
                // Add a deny ACE for Everyone
                if (AddAccessDeniedAce(pAcl, ACL_REVISION, GENERIC_ALL, pEveryoneSid)) {
                    if (SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE)) {
                        FreeSid(pEveryoneSid);
                        return pSD;
                    }
                }
            }
            FreeSid(pEveryoneSid);
        }
        return NULL;

    case 5: // Security descriptor with owner but no DACL
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        // Create a PSID for Local System
        if (!AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
            return NULL;

        if (SetSecurityDescriptorOwner(pSD, pSystemSid, FALSE)) {
            // Note: We intentionally leak the SID here for fuzzing purposes
            FuzzTrackAllocation(pSystemSid, AllocTypeSid);
            return pSD;
        }
        FreeSid(pSystemSid);
        return NULL;

    case 6: // Invalid security descriptor with bad revision
        if (!InitializeSecurityDescriptor(pSD, 0xFF)) // Bad revision number
            return NULL;
        return pSD;

    case 7: // Security descriptor with corrupted control bits
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        *(USHORT*)((PUCHAR)pSD + 2) = 0xFFFF; // Corrupt control bits
        return pSD;

    default: // Minimal valid security descriptor
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);
        SetSecurityDescriptorSacl(pSD, FALSE, NULL, FALSE);
        return pSD;
    }
}

/*
* CreateFuzzedUnicodeString
*
* Purpose:
*
* Create a fuzzed UNICODE_STRING structure. This randomly creates valid or invalid structures.
*
*/
PUNICODE_STRING CreateFuzzedUnicodeString(
    _In_ BYTE* FuzzStructBuffer
)
{
    PUNICODE_STRING UnicodeString;
    PWSTR buffer = NULL, stringBuf;
    USHORT length = 0, maxLength = 0;
    ULONG mode = __rdtsc() % 25;
    ULONG i, patternLen;

    UnicodeString = (PUNICODE_STRING)FuzzStructBuffer;
    stringBuf = (PWSTR)(FuzzStructBuffer + sizeof(UNICODE_STRING));

    // Create different variants of UNICODE_STRING
    switch (mode) {
    case 0: // NULL structure
        return NULL;

    case 1: // Valid empty string
        length = 0;
        maxLength = 0;
        buffer = NULL;
        break;

    case 2: // Valid string with content for file paths
        _strcpy_w((PWSTR)stringBuf, L"\\??\\C:\\ReactOS\\System32\\kernel32.dll");
        length = (USHORT)(_strlen_w((PWSTR)stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = (PWSTR)stringBuf;
        break;

    case 3: // Valid string with registry path
        _strcpy_w((PWSTR)stringBuf, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
        length = (USHORT)(_strlen_w((PWSTR)stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = (PWSTR)stringBuf;
        break;

    case 4: // Invalid: Length > MaximumLength
        _strcpy_w((PWSTR)stringBuf, L"BadString");
        length = 20;
        maxLength = 10;
        buffer = (PWSTR)stringBuf;
        break;

    case 5: // Invalid: NULL buffer with non-zero length
        length = 10;
        maxLength = 10;
        buffer = NULL;
        break;

    case 6: // Invalid: Bad pointer
        length = 10;
        maxLength = 10;
        buffer = (PWSTR)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        break;

    case 7: // Odd lengths (unaligned)
        _strcpy_w((PWSTR)stringBuf, L"OddString");
        length = 7; // Intentionally wrong (not bytes but chars)
        maxLength = 7;
        buffer = (PWSTR)stringBuf;
        break;

    case 8: // Very long string (boundary testing)
    {
        PWCHAR p = (PWCHAR)stringBuf;
        for (i = 0; i < 500; i++) {
            *p++ = L'A' + (i % 26);
        }
        *p = 0;
        length = 1000;
        maxLength = 1020;
        buffer = (PWSTR)stringBuf;
    }
    break;

    case 9: // String with format specifiers (potential format string bugs)
        _strcpy_w((PWSTR)stringBuf, L"%s%n%p%d%x%X%c%S%hs%ls%ws%Z%u%i%o");
        length = (USHORT)(_strlen_w((PWSTR)stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = (PWSTR)stringBuf;
        break;

    case 10: // String points to self (recursive structure)
        UnicodeString->Length = sizeof(UNICODE_STRING);
        UnicodeString->MaximumLength = sizeof(UNICODE_STRING);
        UnicodeString->Buffer = (PWSTR)UnicodeString;
        return UnicodeString;

    case 11: // Buffer points inside parent
        length = 6;
        maxLength = 8;
        buffer = (PWSTR)((BYTE*)UnicodeString - 4);
        break;

    case 12: // Buffer is unaligned
        length = 8;
        maxLength = 16;
        buffer = (PWSTR)(((ULONG_PTR)stringBuf) | 1);
        break;

    case 13: // Length/MaximumLength overflows
        length = (USHORT)0xFFFF;
        maxLength = (USHORT)0x0000; // wrap-around
        buffer = stringBuf;
        break;

    case 14: // All fields are 0xFF
        memset(UnicodeString, 0xFF, sizeof(UNICODE_STRING));
        return UnicodeString;

    case 15: // Length not multiple of WCHAR
        _strcpy_w(stringBuf, L"ABC");
        length = 3; // Not divisible by 2 (bytes vs chars confusion)
        maxLength = 5;
        buffer = stringBuf;
        break;

    case 16: // Path traversal
    {
        static const WCHAR* traversalStrings[] = {
            L"..\\..\\..\\ReactOS\\System32\\cmd.exe",
            L"\\??\\..\\..\\ReactOS",
            L"C:\\ReactOS\\..\\ReactOS\\..\\ReactOS",
            L"\\??\\GLOBALROOT\\Device\\HarddiskVolume1",
            L"..\\.\\..\\.\\..\\"
        };
        ULONG index = __rdtsc() % 5;
        _strcpy_w(stringBuf, traversalStrings[index]);
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = stringBuf;
    }
    break;

    case 17: // Device paths and named pipes
    {
        static const WCHAR* deviceStrings[] = {
            L"\\Device\\NamedPipe\\Pipe",
            L"\\Device\\LanmanRedirector\\server\\share\\file.txt",
            L"\\Device\\Null",
            L"\\Device\\ConDrv\\Console",
            L"\\??\\PIPE\\ProtectedPrefix\\Administrators\\Pipe"
        };
        ULONG index = __rdtsc() % 5;
        _strcpy_w(stringBuf, deviceStrings[index]);
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = stringBuf;
    }
    break;

    case 18: // String with embedded NULLs
    {
        // Create string with internal NULL characters
        PWCHAR p = (PWCHAR)stringBuf;
        p[0] = L'A'; p[1] = L'B'; p[2] = 0; p[3] = L'C'; p[4] = 0;
        p[5] = L'D'; p[6] = L'E'; p[7] = 0;

        // Set length including NULLs
        length = 16; // 8 WCHARs * 2 bytes
        maxLength = 20;
        buffer = stringBuf;
    }
    break;

    case 19: // MaximumLength == Length (no null termination)
    {
        _strcpy_w(stringBuf, L"NoTerminator");
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length; // No room for null terminator
        buffer = stringBuf;
    }
    break;

    case 20: // MaximumLength < Length (logical error)
    {
        _strcpy_w(stringBuf, L"InvalidSize");
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = (USHORT)(length - 4); // Less than length
        buffer = stringBuf;
    }
    break;

    case 21: // Unicode surrogate pairs and normalization
    {
        // Include surrogate pairs and combining characters
        _strcpy_w(stringBuf, L"\xD800\xDF00\x0041\x030A\xFEFF\x00A0");
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = stringBuf;
    }
    break;

    case 22: // String with all NULL characters
    {
        // Fill buffer with zeros but set non-zero length
        memset(stringBuf, 0, 32);
        length = 30;
        maxLength = 32;
        buffer = stringBuf;
    }
    break;

    case 23: // String with extreme repetition pattern
    {
        PWCHAR p = (PWCHAR)stringBuf;
        patternLen = __rdtsc() % 10 + 1; // 1-10 character pattern

        // Create repeating pattern
        for (i = 0; i < patternLen; i++) {
            p[i] = L'A' + (WCHAR)(i % 26);
        }

        // Repeat the pattern many times
        for (i = patternLen; i < 200; i++) {
            p[i] = p[i % patternLen];
        }
        p[200] = 0;

        length = 400; // 200 WCHARs * 2 bytes
        maxLength = 404;
        buffer = stringBuf;
    }
    break;

    case 24: // String with specific special paths
    {
        static const WCHAR* specialPaths[] = {
            L"\\SystemRoot\\System32",
            L"\\??\\UNC\\server\\share",
            L"\\??\\C:",
            L"\\DosDevices\\",
            L"\\BaseNamedObjects\\",
            L"\\Sessions\\0\\DosDevices\\",
            L"\\Registry\\Machine\\HARDWARE",
            L"\\\\.\\"
        };
        ULONG index = __rdtsc() % 8;
        _strcpy_w(stringBuf, specialPaths[index]);
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = stringBuf;
    }
    break;
    }

    // Set the fields unless the case already returned
    UnicodeString->Length = length;
    UnicodeString->MaximumLength = maxLength;
    UnicodeString->Buffer = buffer;

    return UnicodeString;
}

/*
* CreateFuzzedObjectAttributes
*
* Purpose:
*
* Create a fuzzed OBJECT_ATTRIBUTES structure.
*
*/
POBJECT_ATTRIBUTES CreateFuzzedObjectAttributes(
    _In_ BYTE* FuzzStructBuffer
)
{
    POBJECT_ATTRIBUTES ObjectAttributes;
    PUNICODE_STRING ObjectName;
    PBYTE stringBuffer;
    PSECURITY_QUALITY_OF_SERVICE pQos;
    PSECURITY_DESCRIPTOR pSecDesc;
    ULONG mode = __rdtsc() % 22;

    ObjectAttributes = (POBJECT_ATTRIBUTES)FuzzStructBuffer;
    stringBuffer = (PBYTE)FuzzStructBuffer + sizeof(OBJECT_ATTRIBUTES);

    ObjectName = CreateFuzzedUnicodeString(stringBuffer);
    RtlZeroMemory(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));

    switch (mode) {
    case 0: // NULL structure
        return NULL;

    case 1: // Invalid Length field
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES) + 100;
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 2: // Valid structure with random attributes (OBJ_* flags)
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = (ULONG)FuzzAttrData[__rdtsc() % FUZZATTR_COUNT];
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 3: // Invalid security descriptor
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 4: // All fields fuzzed
        ObjectAttributes->Length = (__rdtsc() % 2 == 0) ? sizeof(OBJECT_ATTRIBUTES) : (__rdtsc() % 256);
        ObjectAttributes->RootDirectory = (HANDLE)FuzzHandleData[__rdtsc() % FUZZHANDLE_COUNT];
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = (ULONG)FuzzAttrData[__rdtsc() % FUZZATTR_COUNT];
        ObjectAttributes->SecurityDescriptor = (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        ObjectAttributes->SecurityQualityOfService = (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        break;

    case 5: // All fields are 0xAA (pattern fill)
        memset(ObjectAttributes, 0xAA, sizeof(OBJECT_ATTRIBUTES));
        break;

    case 6: // ObjectName points to ObjectAttributes itself (recursive structure)
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->ObjectName = (PUNICODE_STRING)ObjectAttributes;
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 7: // ObjectName NULL, Length valid
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->ObjectName = NULL;
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 8: // NULL ObjectName with OBJ_OPENLINK
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = NULL;
        ObjectAttributes->Attributes = OBJ_OPENLINK; // Special case for symbolic links
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 9: // System directory with case sensitivity testing
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;

        // Create mixed-case Windows path to test case handling
        {
            PWSTR tempBuffer = (PWSTR)(stringBuffer + sizeof(UNICODE_STRING));
            _strcpy_w(tempBuffer, L"\\SystemRoot\\sYsTeM32");

            ObjectName = (PUNICODE_STRING)stringBuffer;
            ObjectName->Buffer = tempBuffer;
            ObjectName->Length = (USHORT)(_strlen_w(tempBuffer) * sizeof(WCHAR));
            ObjectName->MaximumLength = ObjectName->Length + sizeof(WCHAR);

            ObjectAttributes->ObjectName = ObjectName;
        }

        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 10: // Valid QoS structure
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;

        // Create QoS structure after the object name
        pQos = (PSECURITY_QUALITY_OF_SERVICE)(stringBuffer + sizeof(UNICODE_STRING) + 256);
        pQos->Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        pQos->ImpersonationLevel = SecurityImpersonation;
        pQos->ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        pQos->EffectiveOnly = TRUE;

        ObjectAttributes->SecurityQualityOfService = pQos;
        break;

    case 11: // Invalid QoS structure
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;

        // Create invalid QoS structure
        pQos = (PSECURITY_QUALITY_OF_SERVICE)(stringBuffer + sizeof(UNICODE_STRING) + 256);
        pQos->Length = 0xFF; // Invalid length
        pQos->ImpersonationLevel = 0xFF; // Invalid level
        pQos->ContextTrackingMode = 0xFF; // Invalid mode
        pQos->EffectiveOnly = 0xFF; // Invalid boolean

        ObjectAttributes->SecurityQualityOfService = pQos;
        break;

    case 12: // RootDirectory with empty name
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = (HANDLE)FuzzHandleData[__rdtsc() % FUZZHANDLE_COUNT];

        // Create empty name
        {
            PWSTR tempBuffer = (PWSTR)(stringBuffer + sizeof(UNICODE_STRING));
            tempBuffer[0] = L'\0';

            ObjectName = (PUNICODE_STRING)stringBuffer;
            ObjectName->Buffer = tempBuffer;
            ObjectName->Length = 0;
            ObjectName->MaximumLength = sizeof(WCHAR);

            ObjectAttributes->ObjectName = ObjectName;
        }

        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 13: // Length field = 0
        ObjectAttributes->Length = 0; // Invalid length
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 14: // Length field smaller than actual structure
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES) / 2; // Too small
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 15: // Multiple contradicting attributes
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE | // Normal
            OBJ_OPENIF |           // Open if exists
            OBJ_EXCLUSIVE |        // Exclusive access
            OBJ_OPENLINK;          // Conflicting flag
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 16: // Valid security descriptor with empty DACL
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;

        // Create security descriptor after the object name
        pSecDesc = (PSECURITY_DESCRIPTOR)(stringBuffer + sizeof(UNICODE_STRING) + 256);
        InitializeSecurityDescriptor(pSecDesc, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(pSecDesc, TRUE, NULL, FALSE);

        ObjectAttributes->SecurityDescriptor = pSecDesc;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 17: // Invalid security descriptor (wrong revision)
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;

        // Create invalid security descriptor
        pSecDesc = (PSECURITY_DESCRIPTOR)(stringBuffer + sizeof(UNICODE_STRING) + 256);
        InitializeSecurityDescriptor(pSecDesc, 0xFF); // Wrong revision

        ObjectAttributes->SecurityDescriptor = pSecDesc;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 18: // Object path with trailing backslash
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;

        // Create path with trailing backslash
        {
            PWSTR tempBuffer = (PWSTR)(stringBuffer + sizeof(UNICODE_STRING));
            _strcpy_w(tempBuffer, L"\\Device\\HarddiskVolume1\\");

            ObjectName = (PUNICODE_STRING)stringBuffer;
            ObjectName->Buffer = tempBuffer;
            ObjectName->Length = (USHORT)(_strlen_w(tempBuffer) * sizeof(WCHAR));
            ObjectName->MaximumLength = ObjectName->Length + sizeof(WCHAR);

            ObjectAttributes->ObjectName = ObjectName;
        }

        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 19: // Object name with leading spaces
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;

        // Create path with leading spaces
        {
            PWSTR tempBuffer = (PWSTR)(stringBuffer + sizeof(UNICODE_STRING));
            _strcpy_w(tempBuffer, L"   \\Device\\HarddiskVolume1");

            ObjectName = (PUNICODE_STRING)stringBuffer;
            ObjectName->Buffer = tempBuffer;
            ObjectName->Length = (USHORT)(_strlen_w(tempBuffer) * sizeof(WCHAR));
            ObjectName->MaximumLength = ObjectName->Length + sizeof(WCHAR);

            ObjectAttributes->ObjectName = ObjectName;
        }

        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 20: // "." and ".." in path
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;

        // Create path with dots
        {
            PWSTR tempBuffer = (PWSTR)(stringBuffer + sizeof(UNICODE_STRING));
            _strcpy_w(tempBuffer, L"\\Device\\..\\Device\\HarddiskVolume1\\.");

            ObjectName = (PUNICODE_STRING)stringBuffer;
            ObjectName->Buffer = tempBuffer;
            ObjectName->Length = (USHORT)(_strlen_w(tempBuffer) * sizeof(WCHAR));
            ObjectName->MaximumLength = ObjectName->Length + sizeof(WCHAR);

            ObjectAttributes->ObjectName = ObjectName;
        }

        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 21: // UNC paths
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;

        // Create UNC path
        {
            PWSTR tempBuffer = (PWSTR)(stringBuffer + sizeof(UNICODE_STRING));
            _strcpy_w(tempBuffer, L"\\??\\UNC\\server\\share\\fuckyou.txt");

            ObjectName = (PUNICODE_STRING)stringBuffer;
            ObjectName->Buffer = tempBuffer;
            ObjectName->Length = (USHORT)(_strlen_w(tempBuffer) * sizeof(WCHAR));
            ObjectName->MaximumLength = ObjectName->Length + sizeof(WCHAR);

            ObjectAttributes->ObjectName = ObjectName;
        }

        ObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;
    }

    return ObjectAttributes;
}

/*
* CreateFuzzedTokenPrivileges
*
* Purpose:
*
* Create a fuzzed TOKEN_PRIVILEGES structure for NtAdjustPrivilegesToken testing.
*
*/
PTOKEN_PRIVILEGES CreateFuzzedTokenPrivileges(
    _In_ BYTE* FuzzStructBuffer
)
{
    PTOKEN_PRIVILEGES pPrivileges;
    ULONG variation;
    ULONG i, maxPrivileges, actualCount;

    maxPrivileges = (MAX_STRUCT_BUFFER_SIZE - sizeof(ULONG)) / sizeof(LUID_AND_ATTRIBUTES);

    // Use high variation for more patterns
    variation = __rdtsc() % 10;

    // Base struct at start of buffer
    pPrivileges = (PTOKEN_PRIVILEGES)FuzzStructBuffer;

    switch (variation) {
    case 0: // Valid privilege structure - single privilege
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 1: // Valid privilege structure - multiple privileges
        actualCount = (maxPrivileges >= 3) ? 3 : 1;
        pPrivileges->PrivilegeCount = actualCount;
        for (i = 0; i < actualCount; ++i) {
            pPrivileges->Privileges[i].Luid.LowPart = SE_DEBUG_PRIVILEGE + i;
            pPrivileges->Privileges[i].Luid.HighPart = 0;
            pPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        }
        break;

    case 2: // Valid structure with zero count (edge case)
        pPrivileges->PrivilegeCount = 0;
        break;

    case 3: // Invalid - count too high
        actualCount = maxPrivileges - 1;
        pPrivileges->PrivilegeCount = actualCount;
        for (i = 0; i < actualCount; ++i) {
            pPrivileges->Privileges[i].Luid.LowPart = (ULONG)(__rdtsc() % 35);
            pPrivileges->Privileges[i].Luid.HighPart = 0;
            pPrivileges->Privileges[i].Attributes = (__rdtsc() & 1) ? SE_PRIVILEGE_ENABLED : 0;
        }
        break;

    case 4: // Zero attributes 
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = 0; // No attributes
        break;

    case 5: // All attributes set 
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = 0xFFFFFFFF; // All bits set
        break;

    case 6: // Invalid LUIDs (high part)
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0xFFFFFFFF; // Invalid high part
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 7: // Unusual privileges
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = 0xFFFF; // Very high privilege number
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 8: // NULL struct - rarely valid
        return NULL;

    case 9: // Boundary case - just below user/kernel space
        return (PTOKEN_PRIVILEGES)0x7FFFFFFF;

    default: // Standard valid structure
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = (__rdtsc() % 35) + 1; // Random valid privilege
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;
    }

    return pPrivileges;
}

/*
* CreateFuzzedIoStatusBlock
*
* Purpose:
*
* Create a fuzzed IO_STATUS_BLOCK structure for file and device I/O operations.
*
*/
PIO_STATUS_BLOCK CreateFuzzedIoStatusBlock(
    _In_ BYTE* FuzzStructBuffer
)
{
    PIO_STATUS_BLOCK IoStatusBlock;
    ULONG variation = __rdtsc() % 8;

    IoStatusBlock = (PIO_STATUS_BLOCK)FuzzStructBuffer;

    switch (variation) {
    case 0: // NULL status block
        return NULL;

    case 1: // Valid but zeroed
        // Already zeroed above
        break;

    case 2: // Valid with successful status
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
        break;

    case 3: // Status pending
        IoStatusBlock->Status = STATUS_PENDING;
        IoStatusBlock->Information = 0;
        break;

    case 4: // Error status
        IoStatusBlock->Status = (ULONG)STATUS_ACCESS_DENIED;
        IoStatusBlock->Information = 0;
        break;

    case 5: // Information contains byte count
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 1024; // Simulated bytes transferred
        break;

    case 6: // Invalid pointer
        return (PIO_STATUS_BLOCK)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 7: // Random values
        IoStatusBlock->Status = (NTSTATUS)FuzzStatusData[__rdtsc() % FUZZSTATUS_COUNT];
        IoStatusBlock->Information = FuzzData[__rdtsc() % FUZZDATA_COUNT];
        break;
    }

    return IoStatusBlock;
}

/*
* CreateFuzzedClientId
*
* Purpose:
*
* Create a fuzzed CLIENT_ID structure for thread/process operations.
*
*/
PCLIENT_ID CreateFuzzedClientId(
    _In_ BYTE* FuzzStructBuffer
)
{
    PCLIENT_ID ClientId;
    ULONG variation = __rdtsc() % 11;

    ClientId = (PCLIENT_ID)FuzzStructBuffer;

    switch (variation) {
    case 0: // NULL client ID
        return NULL;

    case 1: // Current process/thread
        ClientId->UniqueProcess = UlongToHandle(GetCurrentProcessId());
        ClientId->UniqueThread = UlongToHandle(GetCurrentThreadId());
        break;

    case 2: // System process
        ClientId->UniqueProcess = UlongToHandle(4); // System process ID
        ClientId->UniqueThread = (HANDLE)FuzzHandleData[__rdtsc() % FUZZHANDLE_COUNT];
        break;

    case 3: // Invalid process/valid thread
        ClientId->UniqueProcess = UlongToHandle(0xFFFF);
        ClientId->UniqueThread = UlongToHandle(GetCurrentThreadId());
        break;

    case 4: // Valid process/invalid thread
        ClientId->UniqueProcess = UlongToHandle(GetCurrentProcessId());
        ClientId->UniqueThread = UlongToHandle(0xFFFFFFFF);
        break;

    case 5: // Invalid pointer
        return (PCLIENT_ID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 6: // Zero process/thread IDs
        ClientId->UniqueProcess = NULL;
        ClientId->UniqueThread = NULL;
        break;

    case 7: // Boundary values - process
        ClientId->UniqueProcess = UlongToHandle(0xFFFFFFFF);
        ClientId->UniqueThread = UlongToHandle(GetCurrentThreadId());
        break;

    case 8: // Special system PIDs
    {
        static const DWORD systemPids[] = {
            0,    // Idle process
            4,    // System process
            8,    // csrss.exe usually
            500,  // Likely a system service (lsass.exe, etc.)
        };
        ClientId->UniqueProcess = UlongToHandle(systemPids[__rdtsc() % 4]);
        ClientId->UniqueThread = UlongToHandle((__rdtsc() % 1000) + 4);
    }
    break;

    case 9: // Same ID for both process and thread
    {
        DWORD id = GetCurrentProcessId();
        ClientId->UniqueProcess = UlongToHandle(id);
        ClientId->UniqueThread = UlongToHandle(id);
    }
    break;

    case 10: // Negative values (high bit set)
        ClientId->UniqueProcess = UlongToHandle(0x80000000);
        ClientId->UniqueThread = UlongToHandle(0x80000001);
        break;
    }

    return ClientId;
}

/*
* CreateFuzzedLargeInteger
*
* Purpose:
*
* Create a fuzzed LARGE_INTEGER structure for time/interval operations.
*
*/
PLARGE_INTEGER CreateFuzzedLargeInteger(
    _In_ BYTE* FuzzStructBuffer
)
{
    PLARGE_INTEGER LargeInteger;
    ULONG variation = __rdtsc() % 7;

    LargeInteger = (PLARGE_INTEGER)FuzzStructBuffer;

    switch (variation) {
    case 0: // NULL large integer
        return NULL;

    case 1: // Zero
        LargeInteger->QuadPart = 0;
        break;

    case 2: // Small positive value
        LargeInteger->QuadPart = __rdtsc() % 1000;
        break;

    case 3: // Large positive value
        LargeInteger->QuadPart = 0x7FFFFFFFFFFFFFFF;
        break;

    case 4: // Negative value
        LargeInteger->QuadPart = -10000;
        break;

    case 5: // Invalid pointer
        return (PLARGE_INTEGER)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 6: // Special time values
    {
        // Array of special time values in 100ns units
        static const LONGLONG specialTimes[] = {
            0,                      // Zero time
            10000000,               // 1 second
            36000000000,            // 1 hour
            864000000000,           // 1 day
            -10000000,              // -1 second (relative time)
            0x7FFFFFFFFFFFFFFF,     // Max positive value
            0x8000000000000000      // Min negative value
        };
        LargeInteger->QuadPart = specialTimes[__rdtsc() % 7];
    }
    break;
    }

    return LargeInteger;
}

/*
* CreateFuzzedProcessTimes
*
* Purpose:
*
* Create fuzzed process times structure for NtQueryInformationProcess
*
*/
PKERNEL_USER_TIMES CreateFuzzedProcessTimes(
    _In_ BYTE* FuzzStructBuffer
)
{
    PKERNEL_USER_TIMES Times;
    ULONG variation = __rdtsc() % 5;

    Times = (PKERNEL_USER_TIMES)FuzzStructBuffer;
    RtlZeroMemory(Times, sizeof(KERNEL_USER_TIMES));

    switch (variation) {
    case 0: // NULL
        return NULL;

    case 1: // Invalid pointer
        return (PKERNEL_USER_TIMES)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 2: // All zeros
        // Already zeroed
        break;

    case 3: // Invalid values (very large)
        Times->CreateTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->ExitTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->KernelTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->UserTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        break;

    case 4: // Realistic values
    {
        LARGE_INTEGER currentTime;
        QueryPerformanceCounter(&currentTime);

        // Set a creation time in the past
        Times->CreateTime.QuadPart = currentTime.QuadPart - 10000000000; // 1000s ago
        Times->ExitTime.QuadPart = 0; // Not exited
        Times->KernelTime.QuadPart = 2500000; // 0.25s kernel time
        Times->UserTime.QuadPart = 5000000;   // 0.5s user time
    }
    break;
    }

    return Times;
}

/*
* CreateFuzzedSectionImageInfo
*
* Purpose:
*
* Create a fuzzed SECTION_IMAGE_INFORMATION structure
*
*/
PSECTION_IMAGE_INFORMATION CreateFuzzedSectionImageInfo(
    _In_ BYTE* FuzzStructBuffer
)
{
    PSECTION_IMAGE_INFORMATION SectionInfo;
    ULONG variation = __rdtsc() % 4;

    SectionInfo = (PSECTION_IMAGE_INFORMATION)FuzzStructBuffer;
    RtlZeroMemory(SectionInfo, sizeof(SECTION_IMAGE_INFORMATION));

    switch (variation) {
    case 0: // NULL
        return NULL;

    case 1: // All zeros
        // Already zeroed
        break;

    case 2: // Realistic PE values
        SectionInfo->TransferAddress = (PVOID)0x400000;
        SectionInfo->ZeroBits = 0;
        SectionInfo->MaximumStackSize = 0x100000;
        SectionInfo->CommittedStackSize = 0x10000;
        SectionInfo->SubSystemType = IMAGE_SUBSYSTEM_WINDOWS_GUI;
        SectionInfo->SubsystemVersionLow = 0;
        SectionInfo->SubsystemVersionHigh = 6;
        SectionInfo->GpValue = 0;
        SectionInfo->ImageCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
        SectionInfo->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
        SectionInfo->Machine = IMAGE_FILE_MACHINE_I386;
        SectionInfo->ImageContainsCode = TRUE;
        // Using the union structure for ImageFlags
        SectionInfo->ImageFlags = 0;
        SectionInfo->ComPlusNativeReady = 0;
        SectionInfo->ComPlusILOnly = 0;
        SectionInfo->ImageDynamicallyRelocated = 0;
        SectionInfo->ImageMappedFlat = 0;
        SectionInfo->BaseBelow4gb = 1;
        SectionInfo->LoaderFlags = 0;
        SectionInfo->ImageFileSize = 0x100000;
        SectionInfo->CheckSum = 0x12345;
        break;

    case 3: // Invalid values
        SectionInfo->TransferAddress = (PVOID)0xFFFFFFFF;
        SectionInfo->ZeroBits = 0xFF;
        SectionInfo->MaximumStackSize = 0xFFFFFFFF;
        SectionInfo->CommittedStackSize = 0xFFFFFFFF;
        SectionInfo->SubSystemType = 0xFF;
        SectionInfo->SubsystemVersionLow = 0xFF;
        SectionInfo->SubsystemVersionHigh = 0xFF;
        SectionInfo->GpValue = 0xFFFFFFFF;
        SectionInfo->ImageCharacteristics = 0xFFFF;
        SectionInfo->DllCharacteristics = 0xFFFF;
        SectionInfo->Machine = 0xFFFF;
        SectionInfo->ImageContainsCode = TRUE;
        // Setting all bits in the flags
        SectionInfo->ImageFlags = 0xFF;
        SectionInfo->LoaderFlags = 0xFFFFFFFF;
        SectionInfo->ImageFileSize = 0xFFFFFFFF;
        SectionInfo->CheckSum = 0xFFFFFFFF;
        break;
    }

    return SectionInfo;
}

/*
* CreateFuzzedKeyValueParameter
*
* Purpose:
*
* Create a fuzzed registry value structure
*
*/
PVOID CreateFuzzedKeyValueParameter(VOID)
{
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, MAX_KEYVALUE_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf)
        return NULL;

    FuzzTrackAllocation(buf, AllocTypeVirtualAlloc);

    RtlZeroMemory(buf, MAX_KEYVALUE_BUFFER_SIZE);

    ULONG variation = (ULONG)__rdtsc();
    ULONG keyType = variation % 10;

    switch (keyType) {
    case 0: {
        //
        // KEY_VALUE_BASIC_INFORMATION - normal, buffer-safe
        //
        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)buf;
        ULONG maxNameLen = (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + sizeof(WCHAR)) / sizeof(WCHAR);
        ULONG nameLen = (variation >> 4) % (maxNameLen + 1);
        info->TitleIndex = (variation >> 8) & 0xFF;
        info->Type = (variation >> 16) & 0xF;
        info->NameLength = nameLen * sizeof(WCHAR);
        if (sizeof(*info) - sizeof(WCHAR) + info->NameLength > MAX_KEYVALUE_BUFFER_SIZE)
            info->NameLength = (MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - sizeof(WCHAR))) & ~1UL;
        for (ULONG i = 0; i < info->NameLength / sizeof(WCHAR); ++i)
            info->Name[i] = (WCHAR)(L'A' + (variation + i) % 26);
        break;
    }
    case 1: {
        //
        // KEY_VALUE_FULL_INFORMATION - normal, buffer-safe
        //
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)buf;
        ULONG maxNameLen = (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + sizeof(WCHAR)) / sizeof(WCHAR);
        ULONG nameLen = (variation >> 5) % (maxNameLen + 1);
        info->NameLength = nameLen * sizeof(WCHAR);
        if (sizeof(*info) - sizeof(WCHAR) + info->NameLength > MAX_KEYVALUE_BUFFER_SIZE)
            info->NameLength = (MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - sizeof(WCHAR))) & ~1UL;

        ULONG dataOffset = sizeof(*info) - sizeof(WCHAR) + info->NameLength;
        ULONG maxDataLen = (dataOffset < MAX_KEYVALUE_BUFFER_SIZE)
            ? (MAX_KEYVALUE_BUFFER_SIZE - dataOffset)
            : 0;
        ULONG dataLen = (variation >> 9) % (maxDataLen + 1);

        info->TitleIndex = (variation >> 12) & 0xFF;
        info->Type = (variation >> 20) & 0xF;
        info->DataLength = dataLen;
        info->DataOffset = dataOffset;

        for (ULONG i = 0; i < info->NameLength / sizeof(WCHAR); ++i)
            info->Name[i] = (WCHAR)(L'B' + (variation + i) % 26);

        BYTE* data = buf + info->DataOffset;
        for (ULONG i = 0; i < dataLen && (info->DataOffset + i) < MAX_KEYVALUE_BUFFER_SIZE; ++i)
            data[i] = (BYTE)((variation >> (i % 16)) & 0xFF);
        break;
    }
    case 2: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION - normal, buffer-safe
        //
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        ULONG maxDataLen = (MAX_KEYVALUE_BUFFER_SIZE > sizeof(*info))
            ? (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + 1)
            : 0;
        ULONG dataLen = (variation >> 4) % (maxDataLen + 1);
        if (sizeof(*info) - 1 + dataLen > MAX_KEYVALUE_BUFFER_SIZE)
            dataLen = MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - 1);
        info->TitleIndex = (variation >> 1) & 0xFF;
        info->Type = (variation >> 10) & 0xF;
        info->DataLength = dataLen;
        for (ULONG i = 0; i < dataLen; ++i)
            info->Data[i] = (UCHAR)((variation + i) & 0xFF);
        break;
    }
    case 3: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 - normal, buffer-safe
        //
        PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 info = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)buf;
        ULONG maxDataLen = (MAX_KEYVALUE_BUFFER_SIZE > sizeof(*info))
            ? (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + 1)
            : 0;
        ULONG dataLen = (variation >> 2) % (maxDataLen + 1);
        if (sizeof(*info) - 1 + dataLen > MAX_KEYVALUE_BUFFER_SIZE)
            dataLen = MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - 1);
        info->Type = (variation >> 6) & 0xF;
        info->DataLength = dataLen;
        for (ULONG i = 0; i < dataLen; ++i)
            info->Data[i] = (UCHAR)(((variation >> (i % 8)) ^ 0xAA) & 0xFF);
        break;
    }
    case 4: {
        //
        // KEY_VALUE_FULL_INFORMATION - edge/invalid metadata values
        //
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0xDEADBEEF;
        info->NameLength = 0x10000;
        info->DataLength = 0x10000;
        info->DataOffset = 0xFFFFFFF0;
        // Name/Data purposely uninitialized for edge testing
        break;
    }
    case 5: {
        //
        // KEY_VALUE_BASIC_INFORMATION - edge/invalid metadata values (NameLength, etc.)
        //
        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0x1BADB002;
        info->NameLength = 0xFFFFFFFC;
        // Name purposely uninitialized for edge testing
        break;
    }
    case 6: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION - edge/invalid DataLength
        //
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0xABCD1234;
        info->DataLength = 0xFFFFFFFF;
        // Data purposely uninitialized
        break;
    }
    case 7: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 - edge/invalid DataLength
        //
        PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 info = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)buf;
        info->Type = 0xF00DFACE;
        info->DataLength = 0xFFFFFFFF;
        // Data purposely uninitialized
        break;
    }
    case 8: {
        //
        // KEY_VALUE_FULL_INFORMATION - conflicting/overlapping metadata
        //
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)buf;
        info->TitleIndex = 0x0;
        info->Type = 0x0;
        info->NameLength = 0x80000000;
        info->DataLength = 0x80000000;
        info->DataOffset = 0x10;
        // Name/Data purposely uninitialized
        break;
    }
    default:
        //
        // Return random fuzz data
        //
        return (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
    }

    return buf;
}

/*
* CreateFuzzedReturnLength
*
* Purpose:
*
* Create fuzzed length parameter for enhanced syscall testing.
*
*/
PVOID CreateFuzzedReturnLength(
    VOID
)
{
    ULONG variation = __rdtsc() % 20; // More variations
    PVOID pLength = NULL;

    if (variation == 0) {
        return NULL; // NULL pointer (5% of the time)
    }
    else if (variation == 1) {
        // Invalid pointer
        return (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
    }
    else if (variation == 2) {
        // Return pointer to read-only memory
        PVOID readOnlyMem = VirtualAlloc(NULL, sizeof(ULONG_PTR),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (readOnlyMem) {
            FuzzTrackAllocation(readOnlyMem, AllocTypeVirtualAlloc);

            // Initialize with non-zero value
            *(PULONG_PTR)readOnlyMem = 0xFFFFFFFF;

            // Change to read-only after initialization
            DWORD oldProtect;
            if (VirtualProtect(readOnlyMem, sizeof(ULONG_PTR), PAGE_READONLY, &oldProtect)) {
                return readOnlyMem;
            }
        }
        // Fall through if allocation or protection change fails
    }
    else if (variation == 3) {
        // Small buffer for 16-bit length
        PUSHORT pLength16 = (PUSHORT)VirtualAlloc(NULL, sizeof(USHORT),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pLength16) {
            // Initialize with interesting 16-bit value
            *pLength16 = 0xFFFF; // Max USHORT
            FuzzTrackAllocation(pLength16, AllocTypeVirtualAlloc);
            return pLength16;
        }
        // Fall through if allocation fails
    }
    else if (variation == 4) {
        // Large buffer for 64-bit length
        PULONGLONG pLength64 = (PULONGLONG)VirtualAlloc(NULL, sizeof(ULONGLONG),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pLength64) {
            // Initialize with interesting 64-bit value
            *pLength64 = 0x100000000ULL; // 4GB
            FuzzTrackAllocation(pLength64, AllocTypeVirtualAlloc);
            return pLength64;
        }
        // Fall through if allocation fails
    }
    else if (variation == 5) {
        // Unaligned pointer (with padding)
        PVOID alignedMem = VirtualAlloc(NULL, sizeof(ULONG) + 3,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (alignedMem) {
            // Create an unaligned pointer (offset by 1 byte)
            PULONG pUnaligned = (PULONG)((ULONG_PTR)alignedMem + 1);
            *pUnaligned = 0xABCD1234;

            FuzzTrackAllocation(alignedMem, AllocTypeVirtualAlloc);
            return pUnaligned;
        }
        // Fall through if allocation fails
    }
    else if (variation == 6) {
        // Create an array of length values
        PULONG pLengthArray = (PULONG)VirtualAlloc(NULL, sizeof(ULONG) * 8,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pLengthArray) {
            // Initialize with a pattern
            pLengthArray[0] = 0;
            pLengthArray[1] = 1;
            pLengthArray[2] = 0xFFFFFFFF;
            pLengthArray[3] = 0x80000000;
            pLengthArray[4] = 0x7FFFFFFF;
            pLengthArray[5] = 0x00010000;
            pLengthArray[6] = 0x0000FFFF;
            pLengthArray[7] = 0x00000004;

            FuzzTrackAllocation(pLengthArray, AllocTypeVirtualAlloc);
            return pLengthArray;
        }
        // Fall through if allocation fails
    }
    else if (variation <= 10) {
        // Initialize with specific edge case values
        static const ULONG edgeValues[] = {
            0,                // Zero
            1,                // Minimum positive
            0x7FFFFFFF,       // Maximum positive 32-bit signed
            0x80000000,       // Minimum negative 32-bit signed
            0xFFFFFFFF        // Maximum 32-bit unsigned
        };

        PULONG pLengthVal = (PULONG)VirtualAlloc(NULL, sizeof(ULONG),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pLengthVal) {
            *pLengthVal = edgeValues[variation - 7];
            FuzzTrackAllocation(pLengthVal, AllocTypeVirtualAlloc);
            return pLengthVal;
        }
        // Fall through if allocation fails
    }

    // Default case (and fallback for failed allocations above)
    // Standard buffer for 32-bit length with random initialization
    pLength = (PULONG)VirtualAlloc(NULL, sizeof(ULONG),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pLength) {
        // For variations 11-13, use specific patterns
        if (variation == 11) {
            *(PULONG)pLength = 0x1000;  // Typical page size
        }
        else if (variation == 12) {
            *(PULONG)pLength = 16; // Small fixed size
        }
        else if (variation == 13) {
            *(PULONG)pLength = 0xC0FFEE; // Magic number
        }
        else {
            // Random value for other variations
            *(PULONG)pLength = __rdtsc() % 0x10000; // Random 0-64KB
        }

        FuzzTrackAllocation(pLength, AllocTypeVirtualAlloc);
    }

    return pLength;
}

/*
* CreateFuzzedOutputPointer
*
* Purpose:
*
* Create fuzzed output pointer for enhanced syscall testing.
* Output pointers should usually be writable memory buffers,
* but we also test edge cases like NULL or read-only memory.
*
*/
PVOID CreateFuzzedOutputPointer(
    _In_ ULONG ParameterIndex
)
{
    ULONG variation = __rdtsc() % 20; // Multiple variations
    ULONG bufferSize;
    PVOID outputBuffer = NULL;
    DWORD oldProtect;

    // Use parameter index to create some variety among multiple output params
    bufferSize = 0x100 << (ParameterIndex % 4); // 0x100, 0x200, 0x400, or 0x800 based on param index

    switch (variation) {
    case 0: // NULL pointer (5%)
        return NULL;

    case 1: // Invalid pointer (5%)
        return (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 2: // Tiny buffer (16 bytes)
        bufferSize = 16;
        break;

    case 3: // Small buffer (64 bytes)
        bufferSize = 64;
        break;

    case 4: // Medium buffer (256 bytes) - most common
        bufferSize = 256;
        break;

    case 5: // Large buffer (4KB)
        bufferSize = 4096;
        break;

    case 6: // Very large buffer (64KB)
        bufferSize = 65536;
        break;

    case 7: // Read-only memory (should fail for output params)
        outputBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Initialize with pattern
            memset(outputBuffer, 0xCC, bufferSize);

            // Change to read-only
            if (VirtualProtect(outputBuffer, bufferSize, PAGE_READONLY, &oldProtect)) {
                FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
                return outputBuffer;
            }

            // If protection change failed, free memory and try another approach
            VirtualFree(outputBuffer, 0, MEM_RELEASE);
        }
        // Fall through if allocation or protection failed

    case 8: // Execute-only memory (should fail for output params)
        outputBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Initialize with pattern
            memset(outputBuffer, 0xCC, bufferSize);

            // Change to execute-only
            if (VirtualProtect(outputBuffer, bufferSize, PAGE_EXECUTE, &oldProtect)) {
                FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
                return outputBuffer;
            }

            // If protection change failed, free memory and try another approach
            VirtualFree(outputBuffer, 0, MEM_RELEASE);
        }
        // Fall through if allocation or protection failed

    case 9: // Unaligned pointer
        outputBuffer = VirtualAlloc(NULL, bufferSize + 3, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Create an unaligned pointer (offset by 1, 2, or 3 bytes)
            PVOID unaligned = (PVOID)((ULONG_PTR)outputBuffer + (ParameterIndex % 3) + 1);

            // Initialize with pattern
            memset(unaligned, 0xAA, bufferSize);

            FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
            return unaligned;
        }
        // Fall through if allocation failed

    case 10: // Already initialized with pattern
        outputBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Initialize with incrementing pattern
            PBYTE ptr = (PBYTE)outputBuffer;
            for (ULONG i = 0; i < bufferSize; i++) {
                ptr[i] = (BYTE)(i & 0xFF);
            }

            FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
            return outputBuffer;
        }
        // Fall through if allocation failed

    case 11: // Pre-initialized with all 0xFF
        outputBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Initialize with 0xFF
            memset(outputBuffer, 0xFF, bufferSize);

            FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
            return outputBuffer;
        }
        // Fall through if allocation failed

    case 12: // Pre-initialized with all 0x00
        outputBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Initialize with 0x00
            memset(outputBuffer, 0x00, bufferSize);

            FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
            return outputBuffer;
        }
        // Fall through if allocation failed

    case 13: // Buffer with guard page at the end
    {
        // Allocate one extra page for guard
        SIZE_T guardSize = bufferSize + 4096;
        outputBuffer = VirtualAlloc(NULL, guardSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Set guard page at the end of the buffer
            PVOID guardPage = (PVOID)((ULONG_PTR)outputBuffer + bufferSize);
            if (VirtualProtect(guardPage, 4096, PAGE_READONLY | PAGE_GUARD, &oldProtect)) {
                FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
                // Initialize normal part
                memset(outputBuffer, 0xBB, bufferSize);
                return outputBuffer;
            }

            // If guard page setup failed, free memory
            VirtualFree(outputBuffer, 0, MEM_RELEASE);
        }
    }
    // Fall through if allocation or guard page setup failed

    case 14: // Nearly inaccessible memory (just 1 byte at the start of page)
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        // Allocate full page
        outputBuffer = VirtualAlloc(NULL, sysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Protect most of the page, leaving just first few bytes accessible
            PVOID protectStart = (PVOID)((ULONG_PTR)outputBuffer + 4);
            SIZE_T protectSize = sysInfo.dwPageSize - 4;

            if (VirtualProtect(protectStart, protectSize, PAGE_NOACCESS, &oldProtect)) {
                FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
                // Initialize accessible part
                *(PDWORD)outputBuffer = 0xDEADC0DE;
                return outputBuffer;
            }

            // If protection failed, free memory
            VirtualFree(outputBuffer, 0, MEM_RELEASE);
        }
    }
    // Fall through if allocation or protection failed

    default: // Standard allocation with various patterns based on parameter index
        outputBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (outputBuffer) {
            // Different initialization pattern based on parameter index
            switch (ParameterIndex % 4) {
            case 0:
                // 0xAA pattern
                memset(outputBuffer, 0xAA, bufferSize);
                break;

            case 1:
                // Alternating bytes
            {
                PBYTE ptr = (PBYTE)outputBuffer;
                for (ULONG i = 0; i < bufferSize; i++) {
                    ptr[i] = (i % 2) ? 0x55 : 0xAA;
                }
            }
            break;

            case 2:
                // Repeating DWORD pattern
            {
                PDWORD ptr = (PDWORD)outputBuffer;
                for (ULONG i = 0; i < (bufferSize / sizeof(DWORD)); i++) {
                    ptr[i] = 0xCAFEBABE;
                }
            }
            break;

            case 3:
                // Random data
            {
                PBYTE ptr = (PBYTE)outputBuffer;
                for (ULONG i = 0; i < bufferSize; i++) {
                    ptr[i] = (BYTE)(__rdtsc() & 0xFF);
                }
            }
            break;
            }

            FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
            return outputBuffer;
        }

        return NULL;
    }

    outputBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (outputBuffer) {
        memset(outputBuffer, 0xDD, bufferSize);
        FuzzTrackAllocation(outputBuffer, AllocTypeVirtualAlloc);
    }

    return outputBuffer;
}

#pragma warning(pop)

//
// Structure generation END
//
