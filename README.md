# KernelExplorer V2.0 Lite

**Researching NT Kernel & System Objects (Win32 API)**

Interactive Services Detection

Authorization with Highest System Rights

Switching Desktops & Sessions Utility

## System requirements

Windows Vista or higher, only 64-bit.

Recommended to use with Windows 10 or Windows 11.  
_Note: The __FDUI0Input.sys__ driver does not work on Windows 11 24H2 (build 26100 and newer)._

## Features

* Works under an account `NT AUTHORITY\\SYSTEM`.
* Access to protected objects of the operating system kernel.
* Management of processes and services of the operating system.
* Access to the terminal session (SessionId 0), Workstations and Desktops.
* Creating system processes in terminal and user sessions.
* 100% [Free Software](https://www.gnu.org/philosophy/free-sw.en.html) ([GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html))

## How to use
* Run the program as Administrator.
* Push the button `Privilege & Access Manager` and select privilege `SeDebugPrivilrge`, Apply.
* Push the button `SuperUser (as Winlogon)`. Now you are a SYSTEM account.
* If necessary, use a `LocalSystem Token` (smss.exe token) or `TrustedInstaller Token` (TrustedInstaller.exe token).
* For access the SACL, DACL and SDDL string of a ___Token Process Descriptor___ apply privilege `SeSecurityPrivilege`.
* For access the SACL, DACL and SDDL string of a ___Process Descriptor___ apply `Access System Security (SACL)` and `Read Control (DACL)` in the `Access Manager`.
* For remove protection from the Service, you must to accept a token `TrustedInstaller Token`.
* For open the `Properties` window, select a line in the Process List or Service List and double-click the left mouse button, or call the context menu with the right mouse button.

## Download
[GitHub Releases](https://github.com/LunarResearch/SystemResearch/releases)

<img align="left" src="https://raw.githubusercontent.com/LunarResearch/SystemResearch/main/skin_.png" width="830" height="360">
