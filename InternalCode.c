#include "Defines.h"


BOOL UI0DetectServiceRuns(HWND hDlg)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, TEXT("UI0Detect"), SERVICE_QUERY_STATUS);

	SERVICE_STATUS ServiceStatus = { 0 };
	TCHAR Buffer[MAX_PATH] = { 0 };

	QueryServiceStatus(hService, &ServiceStatus);

	if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
		LoadString(g_hInstance, 10235, Buffer, MAX_PATH);
		if (MessageBox(hDlg, Buffer, MB_CAPTIONWARNING, MB_YESNO | MB_ICONWARNING) == IDYES) {
			CloseServiceHandle(hService);
			hService = OpenService(hSCManager, TEXT("UI0Detect"), SERVICE_START);
			if (ERROR_ACCESS_DENIED == GetLastError()) {
				CloseServiceHandle(hSCManager);
				LoadString(g_hInstance, 10236, Buffer, MAX_PATH);
				MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
				return FALSE;
			}
			StartService(hService, 0, nullptr);
		}
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}
	
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;
}


BOOL CreateUI0DetectService(HWND hDlg)
{
	TCHAR Buffer[USHRT_MAX] = { 0 }, Path_UI0Detect[MAX_PATH] = { 0 }, Path_Wls0wndh[MAX_PATH] = { 0 };

	GetSystemDirectory(Buffer, MAX_PATH);

	swprintf(Path_UI0Detect, MAX_PATH, TEXT("%ls\\%ls"), Buffer, TEXT("UI0Detect.exe"));	
	if (!PathFileExists(Path_UI0Detect)) {
		LoadString(g_hInstance, 10240, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	if (GetBuildOSNumber() >= 17134) {
		swprintf(Path_Wls0wndh, MAX_PATH, TEXT("%ls\\%ls"), Buffer, TEXT("Wls0wndh.dll"));
		if (!PathFileExists(Path_Wls0wndh)) {
			LoadString(g_hInstance, 10241, Buffer, MAX_PATH);
			MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
			return FALSE;
		}
	}

	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
	if (ERROR_ACCESS_DENIED == GetLastError()) {
		LoadString(g_hInstance, 10236, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	hService = CreateService(hSCManager, TEXT("UI0Detect"), TEXT("Interactive Services Detection"),
		SERVICE_CHANGE_CONFIG,
		SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
		SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
		Path_UI0Detect, nullptr, nullptr, nullptr, nullptr, nullptr);

	SERVICE_SID_INFO ServiceSidInfo = { 0 };
	ServiceSidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
	ChangeServiceConfig2(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &ServiceSidInfo);

	SERVICE_REQUIRED_PRIVILEGES_INFO ServiceRequiredPrivilegesInfo = { 0 };
	ServiceRequiredPrivilegesInfo.pmszRequiredPrivileges = TEXT("SeAssignPrimaryTokenPrivilege\0SeDebugPrivilege\0SeIncreaseQuotaPrivilege\0SeTcbPrivilege\0\0");
	ChangeServiceConfig2(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &ServiceRequiredPrivilegesInfo);

	SERVICE_DESCRIPTION ServiceDescription = { 0 };
	LoadString(g_hInstance, 10238, Buffer, USHRT_MAX);
	ServiceDescription.lpDescription = Buffer;
	ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &ServiceDescription);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;
}


BOOL DeleteUI0DetectService(HWND hDlg)
{
	TCHAR Buffer[MAX_PATH] = { 0 };
	if(GetBuildOSNumber() <= 16299) {
		LoadString(g_hInstance, 10239, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONSTOP, MB_ICONSTOP);
		return FALSE;
	}

	HANDLE hSnapshop = nullptr;
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (wcscmp(ProcessEntry.szExeFile, TEXT("Wls0wndh.dll")) == 0) {
				if (!WTSTerminateProcess(WTS_CURRENT_SERVER_HANDLE, ProcessEntry.th32ProcessID, 0)) {
					LoadString(g_hInstance, 10236, Buffer, MAX_PATH);
					MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
					return FALSE;
				}
				break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	CloseHandle(hSnapshop);

	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, TEXT("UI0Detect"), SERVICE_STOP | DELETE);
	if (ERROR_ACCESS_DENIED == GetLastError()) {
		CloseServiceHandle(hSCManager);
		LoadString(g_hInstance, 10236, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	SERVICE_STATUS ServiceStatus = { 0 };

	if (!ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus)) {
		switch (GetLastError()) {
			case ERROR_SERVICE_NOT_ACTIVE:
				break;
			case ERROR_DEPENDENT_SERVICES_RUNNING:
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				LoadString(g_hInstance, 10242, Buffer, MAX_PATH);
				MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
				return FALSE;
			case ERROR_SERVICE_CANNOT_ACCEPT_CTRL:
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				LoadString(g_hInstance, 10243, Buffer, MAX_PATH);
				MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
				return FALSE;
		}
	}

	if (!DeleteService(hService)) {
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		LoadString(g_hInstance, 10244, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;
}


BOOL SwitchToServicesSession(HWND hDlg)
{
	TCHAR Buffer[MAX_PATH] = { 0 };
	if (UI0DetectServiceExists())
		UI0DetectServiceRuns(hDlg);
	else {
		LoadString(g_hInstance, 10245, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	HMODULE hModule = nullptr;
	bool IsLoadDll = false;

	hModule = GetModuleHandle(TEXT("winsta"));
	if (!hModule) {
		hModule = LoadLibrary(TEXT("winsta"));
		IsLoadDll = true;
	}

	if (hModule)
		WinStationSwitchToServicesSession = (_WinStationSwitchToServicesSession)GetProcAddress(hModule, "WinStationSwitchToServicesSession");

	if (GetBuildOSNumber() >= 17134) {
		if (!FDUI0InputServiceExists()) {
			LoadString(g_hInstance, 10246, Buffer, MAX_PATH);
			MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
			if (IsLoadDll == true)
				FreeLibrary(hModule);
			return FALSE;
		}
	}

	if (HypervisorExists()) {
		LoadString(g_hInstance, 10247, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONSTOP, MB_ICONSTOP);
		if (IsLoadDll == true)
			FreeLibrary(hModule);
		return FALSE;
	}

	if (!WinStationSwitchToServicesSession()) {
		if (IsLoadDll == true)
			FreeLibrary(hModule);
		return FALSE;
	}

	if (IsLoadDll == true)
		FreeLibrary(hModule);

	return TRUE;
}


BOOL CreateSystemProcess(HWND hDlg)
{
	TCHAR Buffer[MAX_PATH] = { 0 };
	if (!IsUserAnSystem()) {
		LoadString(g_hInstance, 10237, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	HANDLE hCurrentProcessToken = nullptr, hToken = nullptr;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &hCurrentProcessToken))
		return FALSE;

	if (!DuplicateTokenEx(hCurrentProcessToken, MAXIMUM_ALLOWED, nullptr, DEFAULT_IMPERSONATION_LEVEL, TokenPrimary, &hToken)) {
		CloseHandle(hCurrentProcessToken);
		return FALSE;
	}
	CloseHandle(hCurrentProcessToken);

	DWORD dwSessionId = 0;

	LoadString(g_hInstance, 10248, Buffer, MAX_PATH);
	if (MessageBox(hDlg, Buffer, MB_CAPTIONQUESTION, MB_YESNO | MB_ICONQUESTION) == IDNO)
		dwSessionId = WTSGetActiveConsoleSessionId();

	if (!SetTokenInformation(hToken, TokenSessionId, &dwSessionId, sizeof(DWORD))) {
		CloseHandle(hToken);
		return FALSE;
	}
	
	STARTUPINFO StartupInfo = { sizeof(STARTUPINFO) };

	StartupInfo.lpDesktop = TEXT("WinSta0\\Default");

	TCHAR FileName[MAX_PATH] = { 0 };
	OPENFILENAME OpenFileName = { sizeof(OPENFILENAME) };

	OpenFileName.lpstrFilter = TEXT("Executable Files (*.exe)\0*.exe\0Dynamic Link Libraries (*.dll)\0*.dll\0Windows System Files (*.sys)\0*.sys\0All File Types (*.*)\0*.*\0");
    OpenFileName.lpstrFile = FileName;
    OpenFileName.nMaxFile = MAXWORD;
	OpenFileName.Flags = OFN_EXPLORER | OFN_FORCESHOWHIDDEN | OFN_NOCHANGEDIR;

	LPVOID lpEnvironment = nullptr;
	PROCESS_INFORMATION ProcessInfo = { 0 };
	
	CreateEnvironmentBlock(&lpEnvironment, hToken, FALSE);
	if (GetOpenFileName(&OpenFileName)) {
		if (!CreateProcessAsUser(hToken, FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED |
			CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo)) {
			DestroyEnvironmentBlock(lpEnvironment);
			CloseHandle(hToken);
			return FALSE;
		}
	}	
	DestroyEnvironmentBlock(lpEnvironment);
	CloseHandle(hToken);

	ResumeThread(ProcessInfo.hThread);

	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);

	return TRUE;
}


BOOL SuperUserAsWinlogon(HWND hDlg, WPARAM wParam)
{
	TCHAR Buffer[MAX_PATH] = { 0 };
	if (!IsUserAnAdmin()) {
		LoadString(g_hInstance, 10236, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return FALSE;

	if (!IsProcessPrivilegeEnable(hToken, SE_DEBUG_NAME)) {
		LoadString(g_hInstance, 10249, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONSTOP, MB_ICONSTOP);
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);

	HANDLE hSnapshop = nullptr, hProcess = nullptr;
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (wcscmp(ProcessEntry.szExeFile, TEXT("winlogon.exe")) == 0) {
				hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	CloseHandle(hSnapshop);
	
	HMODULE hModule = nullptr;

	hModule = GetModuleHandle(TEXT("ntdll"));
	if (hModule) {
		RtlDosPathNameToNtPathName_U = (_RtlDosPathNameToNtPathName_U)GetProcAddress(hModule, "RtlDosPathNameToNtPathName_U");
		RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(hModule, "RtlCreateProcessParametersEx");
		RtlCreateUserProcess = (_RtlCreateUserProcess)GetProcAddress(hModule, "RtlCreateUserProcess");
		RtlDestroyProcessParameters = (_RtlDestroyProcessParameters)GetProcAddress(hModule, "RtlDestroyProcessParameters");
	}

	UNICODE_STRING uStr = { 0 };
	PRTL_USER_PROCESS_PARAMETERS pRtlUserProcessParam = { 0 };
	RTL_USER_PROCESS_INFORMATION RtlUserProcessInfo = { 0 };

	RtlDosPathNameToNtPathName_U(TEXT("SystemResearch.exe"), &uStr, nullptr, nullptr);
	RtlCreateProcessParametersEx(&pRtlUserProcessParam, &uStr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, RTL_USER_PROC_PARAMS_NORMALIZED);
	RtlCreateUserProcess(&uStr, OBJ_KERNEL_HANDLE, pRtlUserProcessParam, nullptr, nullptr, hProcess, FALSE, nullptr, nullptr, &RtlUserProcessInfo);
	RtlDestroyProcessParameters(pRtlUserProcessParam);

	CloseHandle(hProcess);

	ResumeThread(RtlUserProcessInfo.hThread);

	CloseHandle(RtlUserProcessInfo.hThread);
	CloseHandle(RtlUserProcessInfo.hProcess);

	EndDialog(hDlg, wParam);

	return TRUE;
}


BOOL RestartApp(HWND hDlg, WPARAM wParam)
{
	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;

	if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, GROUP_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &pSecurityDescriptor) != ERROR_SUCCESS)
		return FALSE;

	PTCH pStringSecurityDescriptor = nullptr;

	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecurityDescriptor, SDDL_REVISION_1, GROUP_SECURITY_INFORMATION, &pStringSecurityDescriptor, nullptr)) {
		LocalFree(pSecurityDescriptor);
		return FALSE;
	}

	LocalFree(pSecurityDescriptor);

	if (wcscmp(pStringSecurityDescriptor, TEXT("G:SY")) == 0) {
		LocalFree(pStringSecurityDescriptor);
		return TRUE;
	}

	LocalFree(pStringSecurityDescriptor);

	HANDLE hSnapshop = nullptr, hProcess = nullptr, hToken = nullptr;
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (wcscmp(ProcessEntry.szExeFile, TEXT("winlogon.exe")) == 0) {
				hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	CloseHandle(hSnapshop);

	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	LPVOID lpEnvironment = nullptr;
	STARTUPINFO StartupInfo = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION ProcessInfo = { 0 };

	CreateEnvironmentBlock(&lpEnvironment, hToken, FALSE);
	if (!CreateProcessAsUser(hToken, TEXT("SystemResearch.exe"), nullptr, nullptr, nullptr, FALSE,
			CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo)) {
		DestroyEnvironmentBlock(lpEnvironment);
		CloseHandle(hToken);
		return FALSE;
	}
	DestroyEnvironmentBlock(lpEnvironment);

	CloseHandle(hToken);
	ResumeThread(ProcessInfo.hThread);

	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);

	EndDialog(hDlg, wParam);

	return TRUE;
}


BOOL LocalSystemToken(HWND hDlg, WPARAM wParam)
{
	TCHAR Buffer[MAX_PATH] = { 0 };
	if (!IsUserAnSystem()) {
		LoadString(g_hInstance, 10237, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	HANDLE hSnapshop = nullptr, hProcess = nullptr, hToken = nullptr, hDuplicateToken = nullptr;
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (wcscmp(ProcessEntry.szExeFile, TEXT("smss.exe")) == 0) {
				hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	CloseHandle(hSnapshop);

	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, DEFAULT_IMPERSONATION_LEVEL, TokenPrimary, &hDuplicateToken)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);

	DWORD dwUserSessionId = 0;

	dwUserSessionId = WTSGetActiveConsoleSessionId();

	if (!SetTokenInformation(hDuplicateToken, TokenSessionId, &dwUserSessionId, sizeof(DWORD))) {
		CloseHandle(hDuplicateToken);
		return FALSE;
	}

	LPVOID lpEnvironment = nullptr;
	STARTUPINFO StartupInfo = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION ProcessInfo = { 0 };

	CreateEnvironmentBlock(&lpEnvironment, hDuplicateToken, FALSE);
	if (!CreateProcessAsUser(hDuplicateToken, TEXT("SystemResearch.exe"), nullptr, nullptr, nullptr, FALSE,
			CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo)) {
		DestroyEnvironmentBlock(lpEnvironment);
		CloseHandle(hDuplicateToken);
		return FALSE;
	}
	DestroyEnvironmentBlock(lpEnvironment);
	CloseHandle(hDuplicateToken);

	if (!OpenProcessToken(ProcessInfo.hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		CloseHandle(ProcessInfo.hThread);
		CloseHandle(ProcessInfo.hProcess);
		return FALSE;
	}

	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED;

	if (!LookupPrivilegeValue(nullptr, SE_CREATE_TOKEN_NAME, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	ResumeThread(ProcessInfo.hThread);

	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);

	EndDialog(hDlg, wParam);

	return TRUE;
}


BOOL TrustedInstallerToken(HWND hDlg, WPARAM wParam)
{
	TCHAR Buffer[MAX_PATH] = { 0 };
	if (!IsUserAnSystem()) {
		LoadString(g_hInstance, 10237, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
		return FALSE;
	}

	HANDLE hProcess = nullptr, hToken = nullptr, hThread = nullptr, hDuplicateToken = nullptr;

	hProcess = SnapshotTISvcSecurity();

	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, DEFAULT_IMPERSONATION_LEVEL, TokenPrimary, &hDuplicateToken)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);

	DWORD dwUserSessionId = WTSGetActiveConsoleSessionId();

	if (!SetTokenInformation(hDuplicateToken, TokenSessionId, &dwUserSessionId, sizeof(DWORD))) {
		CloseHandle(hDuplicateToken);
		return FALSE;
	}

	LPVOID lpEnvironment = nullptr;
	STARTUPINFO StartupInfo = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION ProcessInfo = { 0 };

	CreateEnvironmentBlock(&lpEnvironment, hDuplicateToken, FALSE);
	if (!CreateProcessAsUser(hDuplicateToken, TEXT("SystemResearch.exe"), nullptr, nullptr, nullptr, FALSE,
			CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo)) {
		DestroyEnvironmentBlock(lpEnvironment);
		CloseHandle(hDuplicateToken);
		return FALSE;
	}
	DestroyEnvironmentBlock(lpEnvironment);

	CloseHandle(hDuplicateToken);
	ResumeThread(ProcessInfo.hThread);

	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);

	EndDialog(hDlg, wParam);

	hThread = (HANDLE)_beginthread(StopTISvcSecurity, 0, nullptr);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	return TRUE;
}


BOOL DeleteLockFile(HWND hDlg)
{
	OPENFILENAME OpenFileName = { sizeof(OPENFILENAME) };
	TCHAR FileName[MAX_PATH] = { 0 }, Buffer[MAX_PATH] = { 0 };

    OpenFileName.lpstrFile = FileName;
    OpenFileName.nMaxFile = MAXWORD;
	OpenFileName.Flags = OFN_EXPLORER | OFN_FORCESHOWHIDDEN | OFN_NOCHANGEDIR;

	if (!GetOpenFileName(&OpenFileName))
		return FALSE;

	HANDLE hFile = nullptr;

	hFile = CreateFile(FileName, DELETE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile)
		return FALSE;

	FILE_RENAME_INFO FileReNameInfo = { 0 };
	PCTCH StreamReName = TEXT(":wtfbbq");
		
	FileReNameInfo.FileNameLength = sizeof(PCTCH);
#pragma warn(disable:2802)
	RtlCopyMemory(FileReNameInfo.FileName, StreamReName, sizeof(PCTCH));

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, &FileReNameInfo, sizeof(FILE_RENAME_INFO) + sizeof(PCTCH))) {
		TCHAR newFileName[MAX_PATH] = { 0 };
		swprintf(newFileName, MAX_PATH, TEXT("%ls_del"), FileName);
		if (_wrename(FileName, newFileName) != 0) {
			if (ERROR_ACCESS_DENIED == GetLastError()) {
				LoadString(g_hInstance, 10236, Buffer, MAX_PATH);
				MessageBox(hDlg, Buffer, MB_CAPTIONERROR, MB_ICONERROR);
			}
			else ErrPrint(hDlg);
			return FALSE;
		}
		LoadString(g_hInstance, 10250, Buffer, MAX_PATH);
		MessageBox(hDlg, Buffer, MB_CAPTIONEXCLAMATION, MB_ICONWARNING);
		return FALSE;
	}

	if (hFile)
		CloseHandle(hFile);

	hFile = CreateFile(FileName, DELETE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile)
		return FALSE;

	FILE_DISPOSITION_INFO FileDispositionInfoDelete = { 0 };
	FileDispositionInfoDelete.DeleteFile = TRUE;

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &FileDispositionInfoDelete, sizeof(FILE_DISPOSITION_INFO)))
		return FALSE;

	if (hFile)
		CloseHandle(hFile);

	if (PathFileExists(FileName))
		return FALSE;

	LoadString(g_hInstance, 10251, Buffer, MAX_PATH);
	MessageBox(hDlg, Buffer, MB_CAPTIONINFORMATION, MB_ICONINFORMATION);

	return TRUE;
}
