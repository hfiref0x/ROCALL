
# ROCALL
## ReactOS x86-32 syscall fuzzer.

# System Requirements

+ ReactOS x86-32;
+ Account with administrative privileges (optional).

# Usage
ROCALL [-win32k] [-logn | logv ] [-pc Value] [-wt Value] [-sc Value] [-s]
* -logn     - enable logging via COM1 port, service name will be logged, default disabled;
* -logv     - enable logging via COM1 port, service name and call parameters will be logged(slow), default disabled;
* -win32k   - launch win32k service table fuzzing, default ntoskrnl service table fuzzing;
* -pc Value - number of passes for each service, default value 1024;
* -wt Value - wait timeout in seconds, default value 30;
* -sc Value - start fuzzing from service entry number (index from 0), default 0;
* -s        - restart program under LocalSystem account.

When used without parameters RoCall will start fuzzing system service table.

Example: 
+ ROCALL
+ ROCALL -logn
+ ROCALL -logv
+ ROCALL -logn -pc 1234
+ ROCALL -logv -pc 1234
+ ROCALL -logn -pc 1234 -sc 100
+ ROCALL -logv -pc 1234 -sc 100
+ ROCALL -win32k
+ ROCALL -win32k -logn
+ ROCALL -win32k -logv
+ ROCALL -win32k -logn -pc 1234
+ ROCALL -win32k -logv -pc 1234
+ ROCALL -win32k -logn -pc 1234 -sc 100
+ ROCALL -win32k -logv -pc 1234 -sc 100
+ ROCALL -wt 40
+ ROCALL -s


Note: make sure to configure virtual machine COM1 port settings before trying this tool.

# How it work

It brute-force through system services and call them multiple times with input parameters randomly taken from predefined "bad arguments" list.


# Configuration

By using blacklist.ini configuration file you can blacklist certain services. To do this - add service name (case sensitive) to the corresponding section of the blacklist.ini, e.g. if you want to blacklist services from KiServiceTable then use [ntos] section.

Example of blacklist.ini (default config shipped with program)

<pre>[ntos]
NtClose
NtShutdownSystem
NtSuspendProcess
NtSuspendThread
NtTerminateProcess
NtTerminateThread

[win32k]
NtUserSwitchDesktop
NtUserLockWorkStation
</pre>

# Warning

This program may crash the operation system, affect it stability, which may result in data lost or program crash itself. You use it at your own risk.

# Build

ROCALL comes with full source code written in C with tiny assembler usage.
In order to build from source you need Microsoft Visual Studio 2015 and later versions.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017;
  * v142 for Visual Studio 2019.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1;
  * If v141/v142 then select 10. 
* Minimum required Windows SDK version is 8.1.

# Bugs found with ROCALL

* Making ReactOS Great Again, https://www.kernelmode.info/forum/viewtopic6f46.html?f=11&t=5302 (Long list and explanation)
* Is ReactOS Great Again (2019), https://swapcontext.blogspot.com/2019/12/is-reactos-great-again-2019.html

# Authors

(c) 2018 - 2019 ROCALL Project
