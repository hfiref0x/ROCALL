# ROCALL
## ReactOS syscall fuzzer

ROCALL is a fuzzer for ReactOS system calls with enhanced parameter type detection, critical structure testing, and improved output handling. This version supports x86-32 ReactOS platform.

# System Requirements

+ ReactOS x86-32 (tested with 0.4.15);
+ Account with administrative privileges (optional).

# Usage
ROCALL [-win32k] [-logn | -logv] [-o Value] [-pc Value] [-wt Value] [-sc Value] [-s] [-h] [-cr]
* -log      - Enable logging to file last call parameters (warning: this will drop performance)
* -o Value  - Output log destination (port name like COM1, COM2... or file name), default rocall64.log (-log required)
* -win32k   - Launch win32k service table fuzzing, default ntoskrnl service table fuzzing
* -pc Value - Number of passes for each service, default value 65536
* -wt Value - Wait timeout in seconds, default value 30
* -sc Value - Start fuzzing from service entry number (index from 0), default 0
* -s        - Restart program under LocalSystem account
* -h        - Enable heuristic parameter building for more targeted fuzzing

When used without parameters RoCall will start fuzzing the system service table.

Example: 
+ ROCALL
+ ROCALL -log
+ ROCALL -log -o COM1
+ ROCALL -log -o rocall_output.log
+ ROCALL -log -pc 1234
+ ROCALL -log -pc 1234 -sc 100
+ ROCALL -win32k
+ ROCALL -win32k -h -pc 10000

Note: Make sure to configure virtual machine COM port settings before trying this tool with COM port logging.

# Advanced Features

## Heuristic Parameter Building
When using the `-h` parameter, ROCALL uses enhanced type detection to generate more appropriate test values for each parameter based on its usage pattern:

- Output pointer parameters receive specialized memory regions
- Token parameters receive proper token handles
- Timeout parameters receive appropriate timeout values
- Registry key parameters get valid key formats

The fuzzer includes dedicated structure generation routines for common NT API structures:

- **UNICODE_STRING**: Generates valid and invalid strings with various edge cases (embedded NULLs, buffer overflows, special path formats)
- **OBJECT_ATTRIBUTES**: Creates complex object attributes structures with various security descriptors and QoS settings
- **CLIENT_ID**: Produces process/thread identifier pairs with realistic and boundary values
- **LARGE_INTEGER**: Creates time values and intervals with special cases for both absolute and relative values
- **SECURITY_DESCRIPTOR**: Generates security descriptors with varying permissions and DACL configurations
- **TOKEN_PRIVILEGES**: Creates privilege arrays with different privilege types and attribute combinations
- **IO_STATUS_BLOCK**: Produces status blocks with different completion codes and information values
- **KEY_VALUE_***: Creates registry value structures with multiple data types and formats

These dedicated fuzzing functions ensure comprehensive coverage of structure-specific edge cases and validation failures.

# How it works

ROCALL uses multiple techniques to test system services:

1. **Brute-force testing**: Calls services with parameters randomly taken from predefined "bad arguments" lists
2. **Type-aware fuzzing**: When heuristics are enabled, generates parameter values based on parameter types
3. **Enhanced output handling**: Supports both COM port and file-based logging

# Configuration

By using blacklist.ini configuration file you can blacklist certain services. To do this - add service name (case sensitive) to the corresponding section of the blacklist.ini, e.g. if you want to blacklist NtClose service add it to the [ntos] section.

Example of blacklist.ini (default config shipped with program)


```
[ntos] 
NtClose
NtShutdownSystem 
NtSuspendProcess 
NtSuspendThread 
NtTerminateProcess 
NtTerminateThread

[win32k] 
NtUserSwitchDesktop 
NtUserLockWorkStation
NtUserPostMessage
```

# Warning

This program may crash the operating system, affect system stability, and may result in data loss or program crashes.

# Build

ROCALL comes with full source code written in C with minimal assembler usage.
In order to build from source you need Microsoft Visual Studio 2019 or later versions.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v142 for Visual Studio 2019
  * v143 for Visual Studio 2022
* For each toolset set Target Platform Version (Project->Properties->General):
  * If v141 then select 10
  * If v142/v143 then select 10 or later
* Minimum required Windows SDK version is 10.0

# Bugs found with ROCALL

* Making ReactOS Great Again, https://www.kernelmode.info/forum/viewtopic6f46.html?f=11&t=5302 (Long list and explanation) (webarchive, https://web.archive.org/web/20240909192734/https://www.kernelmode.info/forum/viewtopic6f46.html?f=11&t=5302)
* Is ReactOS Great Again (2019), https://swapcontext.blogspot.com/2019/12/is-reactos-great-again-2019.html

# Authors

(c) 2018 - 2025 ROCALL Project