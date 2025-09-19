#include "Defines.h"


int ErrPrint(HWND hDlg)
{
	TCHAR msgBuffer[MAX_PATH] = { 0 }, errBuffer[MAX_PATH] = { 0 };
	DWORD dwMessageId = 0;

	dwMessageId = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, dwMessageId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msgBuffer, MAX_PATH, nullptr);
	swprintf(errBuffer, MAX_PATH, TEXT("Error: %u"), dwMessageId);

	return MessageBox(hDlg, msgBuffer, errBuffer, MB_ICONERROR);
}


DWORD ErrPrint2(HWND hDlg, PCTCH AdditionalText)
{
	TCHAR msgBuffer[MAX_PATH] = { 0 }, strBuffer[MAX_PATH] = { 0 };
	DWORD dwMessageId = 0;

	dwMessageId = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, dwMessageId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), strBuffer, MAX_PATH, nullptr);
	swprintf(msgBuffer, MAX_PATH, TEXT("%ls<Error: %u> %ls"), AdditionalText, dwMessageId, strBuffer);
	
	SetWindowText(hDlg, msgBuffer);

	return dwMessageId;
}


BOOL IsUserAnSystem(void)
{
	return SHTestTokenMembership(nullptr, SECURITY_LOCAL_SYSTEM_RID);
}


DWORD GetBuildOSNumber(void)
{
	HMODULE hModule = nullptr;

	hModule = GetModuleHandle(TEXT("ntdll"));
	if (hModule)
		RtlGetNtVersionNumbers = (_RtlGetNtVersionNumbers)GetProcAddress(hModule, "RtlGetNtVersionNumbers");

	DWORD BuildOSNumber = 0; // MajorOSVersion = 0, MinorOSVersion = 0,

	RtlGetNtVersionNumbers(NULL, NULL, &BuildOSNumber);
	
	BuildOSNumber &= BITWISE_ASSIGNMENT_OPERATOR;
	//BuildOSNumber = BuildOSNumber - 0xF0000000;

	return BuildOSNumber;
}


BOOL SetDesktopComposition(HWND hDlg)
{
	DWORD DwmWCP = DWMWCP_ROUNDSMALL, DwmSBT = DWMSBT_TABBEDWINDOW;
	
	if ((DwmSetWindowAttribute(hDlg, DWMWA_WINDOW_CORNER_PREFERENCE, &DwmWCP, sizeof(DWORD)) == DWM_E_COMPOSITIONDISABLED) &
		(DwmSetWindowAttribute(hDlg, DWMWA_SYSTEMBACKDROP_TYPE, &DwmSBT, sizeof(DWORD)) == DWM_E_COMPOSITIONDISABLED))
		return FALSE;

	return TRUE;
}


BOOL UI0DetectServiceExists(void)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, TEXT("UI0Detect"), SERVICE_QUERY_STATUS);
	if (ERROR_SERVICE_DOES_NOT_EXIST == GetLastError()) {
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;
}


BOOL FDUI0InputServiceExists(void)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, TEXT("FDUI0Input"), SERVICE_QUERY_STATUS);
	if (ERROR_SERVICE_DOES_NOT_EXIST == GetLastError()) {
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;
}


BOOL HypervisorExists(void)
{
	DWORD InvalidResponse[4] = { 0 }, ValidResponse[4] = { 0 };

#pragma warn(disable:2215)
	_cpuid((int*)InvalidResponse, 0x13371337);
	_cpuid((int*)ValidResponse, 0x40000000);

	if ((InvalidResponse[0] == ValidResponse[0]) ||
		(InvalidResponse[1] == ValidResponse[1]) ||
		(InvalidResponse[2] == ValidResponse[2]) ||
		(InvalidResponse[3] == ValidResponse[3]))
		return FALSE;

	return TRUE;
}


HANDLE SnapshotTISvcSecurity(void)
{	
	SC_HANDLE hSCManager = nullptr, hService = nullptr;	

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);

	hService = OpenService(hSCManager, TEXT("TrustedInstaller"), SERVICE_QUERY_STATUS | SERVICE_START);
	CloseServiceHandle(hSCManager);

	SERVICE_STATUS ServiceStatus = { 0 };

	if (QueryServiceStatus(hService, &ServiceStatus)) {
		switch (ServiceStatus.dwCurrentState)
		{
			case SERVICE_STOPPED:
				StartService(hService, 0, nullptr);
				break;

			default:
				break;
		}
	}
	CloseServiceHandle(hService);

	HANDLE hProcess = nullptr, hSnapshot = nullptr;
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		do {
			if (wcscmp(ProcessEntry.szExeFile, TEXT("TrustedInstaller.exe")) == 0) {
				hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshot, &ProcessEntry));
	}
	CloseHandle(hSnapshot);

	return hProcess;
}


VOID WINAPI StopTISvcSecurity(LPVOID)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);

	hService = OpenService(hSCManager, TEXT("TrustedInstaller"), SERVICE_QUERY_STATUS | SERVICE_STOP);
	CloseServiceHandle(hSCManager);

	SERVICE_STATUS ServiceStatus = { 0 };

	QueryServiceStatus(hService, &ServiceStatus);
	Sleep(ServiceStatus.dwWaitHint);

	if (QueryServiceStatus(hService, &ServiceStatus)) {
		switch (ServiceStatus.dwCurrentState)
		{
			case SERVICE_RUNNING:
				ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
				break;

			default:
				break;
		}
	}
	CloseServiceHandle(hService);

	return;
}


BOOL GetSecurityDescInfo(HWND hDlg)
{
	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
	PTCHAR 	StringSecurityDescriptorOwner = nullptr, StringSidOwner = nullptr, DomainNameOwner = nullptr, AccountNameOwner = nullptr,
		StringSecurityDescriptorGroup = nullptr, StringSidGroup = nullptr, DomainNameGroup = nullptr, AccountNameGroup = nullptr;
	PSID pSidOwner = nullptr, pSidGroup = nullptr;
	TCHAR StringOwner[MAX_PATH] = { 0 }, StringGroup[MAX_PATH] = { 0 };
	DWORD cchAccountNameOwner = 0, cchDomainNameOwner = 0, cchAccountNameGroup = 0, cchDomainNameGroup = 0;
	SID_NAME_USE peUseOwner, peUseGroup;

	if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
			&pSidOwner, &pSidGroup, nullptr, nullptr, &pSecurityDescriptor) != ERROR_SUCCESS)
		goto exit_t;

	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecurityDescriptor, SDDL_REVISION_1,
			OWNER_SECURITY_INFORMATION, &StringSecurityDescriptorOwner, nullptr) &
		!ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecurityDescriptor, SDDL_REVISION_1,
			GROUP_SECURITY_INFORMATION, &StringSecurityDescriptorGroup, nullptr))
		goto exit_t;

	if (!ConvertSidToStringSidW(pSidOwner, &StringSidOwner) & !ConvertSidToStringSidW(pSidGroup, &StringSidGroup))
		goto exit_t;

	if (!LookupAccountSidW(nullptr, pSidOwner, nullptr, &cchAccountNameOwner, nullptr, &cchDomainNameOwner, &peUseOwner))
		if(ERROR_INSUFFICIENT_BUFFER != GetLastError())
			goto exit_t;
	
	AccountNameOwner = (PTCHAR)LocalAlloc(LPTR, MAX_PATH * sizeof(TCHAR));
	DomainNameOwner = (PTCHAR)LocalAlloc(LPTR, MAX_PATH * sizeof(TCHAR));
	if ((AccountNameOwner != nullptr) & (DomainNameOwner != nullptr)) 
		if (!LookupAccountSidW(nullptr, pSidOwner, AccountNameOwner, &cchAccountNameOwner, DomainNameOwner, &cchDomainNameOwner, &peUseOwner))
			goto exit_t;

	if (!LookupAccountSidW(nullptr, pSidGroup, nullptr, &cchAccountNameGroup, nullptr, &cchDomainNameGroup, &peUseGroup))
		if(ERROR_INSUFFICIENT_BUFFER != GetLastError())
			goto exit_t;

	AccountNameGroup = (PTCHAR)LocalAlloc(LPTR, MAX_PATH * sizeof(TCHAR));
	DomainNameGroup = (PTCHAR)LocalAlloc(LPTR, MAX_PATH * sizeof(TCHAR));
	if ((AccountNameGroup != nullptr) & (DomainNameGroup != nullptr))
		if (!LookupAccountSidW(nullptr, pSidGroup, AccountNameGroup, &cchAccountNameGroup, DomainNameGroup, &cchDomainNameGroup, &peUseGroup))
			goto exit_t;

	if (wcscmp(StringSecurityDescriptorOwner, TEXT("O:BA")) == 0)
		swprintf(StringOwner, MAX_PATH, TEXT("%ls (SDDL_BUILTIN_ADMINISTRATORS)\nSid: %ls\nDomain\\Account: %ls\\%ls"),
			StringSecurityDescriptorOwner, StringSidOwner, DomainNameOwner, AccountNameOwner);
	else if (wcscmp(StringSecurityDescriptorOwner, TEXT("O:SY")) == 0)
		swprintf(StringOwner, MAX_PATH, TEXT("%ls (SDDL_LOCAL_SYSTEM)\nSid: %ls\nDomain\\Account: %ls\\%ls"),
			StringSecurityDescriptorOwner, StringSidOwner, DomainNameOwner, AccountNameOwner);
	else swprintf(StringOwner, MAX_PATH, TEXT("%ls\nSid: %ls\nDomain\\Account: %ls\\%ls"),
			StringSecurityDescriptorOwner, StringSidOwner, DomainNameOwner, AccountNameOwner);

	if (wcscmp(StringSecurityDescriptorGroup, TEXT("G:BA")) == 0)
		swprintf(StringGroup, MAX_PATH, TEXT("%ls (SDDL_BUILTIN_ADMINISTRATORS)\nSid: %ls\nDomain\\Account: %ls\\%ls"),
			StringSecurityDescriptorGroup, StringSidGroup, DomainNameGroup, AccountNameGroup);
	else if (wcscmp(StringSecurityDescriptorGroup, TEXT("G:SY")) == 0)
		swprintf(StringGroup, MAX_PATH, TEXT("%ls (SDDL_LOCAL_SYSTEM)\nSid: %ls\nDomain\\Account: %ls\\%ls"),
			StringSecurityDescriptorGroup, StringSidGroup, DomainNameGroup, AccountNameGroup);
	else swprintf(StringGroup, MAX_PATH, TEXT("%ls\nSid: %ls\nDomain\\Account: %ls\\%ls"),
			StringSecurityDescriptorGroup, StringSidGroup, DomainNameGroup, AccountNameGroup);

	if (!SetWindowText(GetDlgItem(hDlg, 4007), StringOwner) &
		!SetWindowText(GetDlgItem(hDlg, 4008), StringGroup))
		goto exit_t;

	if (AccountNameOwner != nullptr) LocalFree(AccountNameOwner);
	if (DomainNameOwner != nullptr) LocalFree(DomainNameOwner);
	if (AccountNameGroup != nullptr) LocalFree(AccountNameGroup);
	if (DomainNameGroup != nullptr) LocalFree(DomainNameGroup);
	if (StringSidOwner != nullptr) LocalFree(StringSidOwner);
	if (StringSidGroup != nullptr) LocalFree(StringSidGroup);
	if (StringSecurityDescriptorOwner != nullptr) LocalFree(StringSecurityDescriptorOwner);
	if (StringSecurityDescriptorGroup != nullptr) LocalFree(StringSecurityDescriptorGroup);
	if (pSecurityDescriptor != nullptr) LocalFree(pSecurityDescriptor);

	return TRUE;

exit_t:
	if (AccountNameOwner != nullptr) LocalFree(AccountNameOwner);
	if (DomainNameOwner != nullptr) LocalFree(DomainNameOwner);
	if (AccountNameGroup != nullptr) LocalFree(AccountNameGroup);
	if (DomainNameGroup != nullptr) LocalFree(DomainNameGroup);
	if (StringSidOwner != nullptr) LocalFree(StringSidOwner);
	if (StringSidGroup != nullptr) LocalFree(StringSidGroup);
	if (StringSecurityDescriptorOwner != nullptr) LocalFree(StringSecurityDescriptorOwner);
	if (StringSecurityDescriptorGroup != nullptr) LocalFree(StringSecurityDescriptorGroup);
	if (pSecurityDescriptor != nullptr) LocalFree(pSecurityDescriptor);

	return FALSE;
}


BOOL DataCompare(LPBYTE lpBuffer, LPBYTE lpPattern, PCTCH pMask)
{
	for (; *pMask; pMask++, lpPattern++, lpBuffer++)
		if (*pMask == 'x' && *lpBuffer != *lpPattern)
			return FALSE;

	return TRUE;
}


SIZE_T FindPattern(LPVOID lpAddress, ULONG Length, LPBYTE lpPattern, PCTCH pMask)
{
	MEMORY_BASIC_INFORMATION MemoryBasicInfo = { 0 };
	SIZE_T Offset = 0;
	LPBYTE lpBuffer = nullptr;

	while (Offset < Length) {
		VirtualQuery((LPCVOID)((SIZE_T)lpAddress + Offset), &MemoryBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
		if (MemoryBasicInfo.State != MEM_FREE) {
			lpBuffer = (LPBYTE)malloc(MemoryBasicInfo.RegionSize);
			if (!ReadProcessMemory(GetCurrentProcess(), MemoryBasicInfo.BaseAddress, lpBuffer, MemoryBasicInfo.RegionSize, nullptr))
				return EXIT_FAILURE;
			for (SIZE_T i = 0; i < MemoryBasicInfo.RegionSize; i++)
				if (DataCompare(lpBuffer + i, lpPattern, pMask)) {
					free(lpBuffer);
					return (SIZE_T)MemoryBasicInfo.BaseAddress + i;
				}
			free(lpBuffer);
		}
		Offset += MemoryBasicInfo.RegionSize;
	}

	return EXIT_SUCCESS;
}


SIZE_T GetProcAddressFromPattern(PCTCH dllName, LPBYTE lpPattren, PCTCH pMask)
{
	HMODULE hModule = nullptr;
	MODULEINFO hModuleInfo = { 0 };
	SIZE_T Result = 0;
	
	hModule = GetModuleHandle(dllName);
	if (hModule)
		if (!GetModuleInformation(GetCurrentProcess(), hModule, &hModuleInfo, sizeof(MODULEINFO)))
			return EXIT_FAILURE;

	Result = FindPattern(hModuleInfo.lpBaseOfDll, hModuleInfo.SizeOfImage, lpPattren, pMask);

	return Result;
}


BOOL PrivilegeManager(HANDLE hProcess, DWORD PrivilegeAttribute, PCTCH PrivilegeName)
{
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = PrivilegeAttribute;

	HANDLE hToken = nullptr;

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(nullptr, PrivilegeName, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
		
	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}


BOOL PrivilegeManager2(HANDLE hProcess, DWORD PrivilegeAttribute, DWORD LowPart)
{
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = PrivilegeAttribute;
	TokenPrivileges.Privileges[0].Luid.LowPart = LowPart;

	HANDLE hToken = nullptr;

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}


BOOL IsProcessPrivilegeEnable(HANDLE hToken, PCTCH PrivilegeName)
{
	PRIVILEGE_SET PrivilegeSet = { 0 };

	PrivilegeSet.PrivilegeCount = 1;

	if (!LookupPrivilegeValue(nullptr, PrivilegeName, &PrivilegeSet.Privilege[0].Luid))
		return FALSE;

	BOOL Result = 0;

	if (!PrivilegeCheck(hToken, &PrivilegeSet, &Result))
		return FALSE;

	return Result;
}


BOOL IsProcessPrivilegeEnable2(HANDLE hToken, DWORD LowPart)
{
	PRIVILEGE_SET PrivilegeSet = { 0 };

	PrivilegeSet.PrivilegeCount = 1;
	PrivilegeSet.Privilege[0].Luid.LowPart = LowPart;

	BOOL Result = 0;

	if (!PrivilegeCheck(hToken, &PrivilegeSet, &Result))
		return FALSE;

	return Result;
}


