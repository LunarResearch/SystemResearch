#include "Defines.h"


BOOL ListService(HWND hWndServiceList)
{
	SC_HANDLE hSCManager = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!hSCManager)
		return FALSE;

	DWORD dwServiceType = 0, dwBytesNeeded = 0, ServicesReturned = 0, ResumeHandle = 0;

	if (GetBuildOSNumber() < 10240)
		dwServiceType = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS;
	else
		dwServiceType = SERVICE_TYPE_ALL;

	if (!EnumServicesStatus(hSCManager, dwServiceType, SERVICE_STATE_ALL, nullptr, 0, &dwBytesNeeded, &ServicesReturned, nullptr)) {
		if (ERROR_MORE_DATA != GetLastError()) {
			CloseServiceHandle(hSCManager);
			return FALSE;
		}
	}

	LPENUM_SERVICE_STATUS lpEnumServiceStatus = { 0 };
	lpEnumServiceStatus = (LPENUM_SERVICE_STATUS)_alloca(dwBytesNeeded);

	if (!EnumServicesStatus(hSCManager, dwServiceType, SERVICE_STATE_ALL, lpEnumServiceStatus, dwBytesNeeded, &dwBytesNeeded, &ServicesReturned, &ResumeHandle)) {
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hSCManager);

	for (DWORD i = 0; i < ServicesReturned; i++)
		SendMessage(hWndServiceList, LB_ADDSTRING, 0, (LPARAM)(lpEnumServiceStatus + i)->lpServiceName);

	return TRUE;
}


BOOL CheckServiceProtectInfo(HWND hDlg, PCTCH pszServiceName)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, pszServiceName, SERVICE_QUERY_CONFIG);
	CloseServiceHandle(hSCManager);

	DWORD dwBytesNeeded = 0;

	if (!QueryServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, nullptr, 0, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseServiceHandle(hService);
			return FALSE;
		}
	}

	PSERVICE_LAUNCH_PROTECTED_INFO pServiceLaunchProtectedInfo = { 0 };
	pServiceLaunchProtectedInfo = (PSERVICE_LAUNCH_PROTECTED_INFO)_alloca(dwBytesNeeded);

	if (!QueryServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, (LPBYTE)pServiceLaunchProtectedInfo, dwBytesNeeded, &dwBytesNeeded)) {
		CloseServiceHandle(hService);
		return FALSE;
	}

	switch (pServiceLaunchProtectedInfo->dwLaunchProtected)
	{
		case SERVICE_LAUNCH_PROTECTED_NONE:
			CheckRadioButton(hDlg, 4003, 4006, 4003);
			break;

		case SERVICE_LAUNCH_PROTECTED_WINDOWS:
			CheckRadioButton(hDlg, 4003, 4006, 4004);
			break;

		case SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT:
			CheckRadioButton(hDlg, 4003, 4006, 4005);
			break;

		case SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT:
			CheckRadioButton(hDlg, 4003, 4006, 4006);
			break;

		default:
			break;
	}

	return TRUE;
}


BOOL UnProtectService(PCTCH pszServiceName, DWORD dwLaunchProtected)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, pszServiceName, SERVICE_CHANGE_CONFIG);
	CloseServiceHandle(hSCManager);

	SERVICE_LAUNCH_PROTECTED_INFO ServiceLaunchProtectedInfo = { 0 };

	ServiceLaunchProtectedInfo.dwLaunchProtected = dwLaunchProtected;

	if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo)) {
		CloseServiceHandle(hService);
		return FALSE;
	}

	CloseServiceHandle(hService);

	return TRUE;
}


BOOL GetServiceConfig(HWND hDlg)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;
	TCHAR Buffer[USHRT_MAX] = { 0 }, ServiceDllPath[MAX_PATH] = { 0 }, FirstDependency[MAX_PATH] = { 0 };

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, g_ServiceName, SERVICE_QUERY_CONFIG | ACCESS_SYSTEM_SECURITY | READ_CONTROL);
	if (!hService) hService = OpenService(hSCManager, g_ServiceName, SERVICE_QUERY_CONFIG);
	CloseServiceHandle(hSCManager);

	DWORD dwBytesNeeded = 0, cbData = 260;

	if (!QueryServiceConfig(hService, nullptr, 0, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseServiceHandle(hService);
			return FALSE;
		}
	}

	LPQUERY_SERVICE_CONFIG lpQueryServiceConfig = { 0 };
	lpQueryServiceConfig = (LPQUERY_SERVICE_CONFIG)_alloca(dwBytesNeeded);

	if (!QueryServiceConfig(hService, lpQueryServiceConfig, dwBytesNeeded, &dwBytesNeeded)) {
		CloseServiceHandle(hService);
		return FALSE;
	}

	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
	PTCH pStringSecurityDescriptor = nullptr;

	if (!QueryServiceObjectSecurity(hService, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, nullptr, 0, &dwBytesNeeded))
	{
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
		{
			pSecurityDescriptor = (PSECURITY_DESCRIPTOR)_alloca(dwBytesNeeded);

			if (!QueryServiceObjectSecurity(hService, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, pSecurityDescriptor, dwBytesNeeded, &dwBytesNeeded)) {
				CloseServiceHandle(hService);
				return FALSE;
			}

			if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecurityDescriptor, SDDL_REVISION,
					OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
					&pStringSecurityDescriptor, nullptr)) {
				CloseServiceHandle(hService);
				return FALSE;
			}
		}
	}
	
	CloseServiceHandle(hService);

	switch (lpQueryServiceConfig->dwServiceType)
	{
		case SERVICE_KERNEL_DRIVER:
			EnableWindow(GetDlgItem(hDlg, 4027), FALSE);
			LoadString(g_hInstance, 10258, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4031), Buffer);
			SetWindowText(GetDlgItem(hDlg, 4007), g_ServiceName);
			break;

		case SERVICE_FILE_SYSTEM_DRIVER:
			EnableWindow(GetDlgItem(hDlg, 4027), FALSE);
			LoadString(g_hInstance, 10259, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4031), Buffer);
			SetWindowText(GetDlgItem(hDlg, 4007), g_ServiceName);
			break;

		default:
			LoadString(g_hInstance, 10260, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4031), Buffer);
			SetWindowText(GetDlgItem(hDlg, 4007), g_ServiceName);
			break;
	}

	if (lpQueryServiceConfig->lpDisplayName != nullptr && wcscmp(lpQueryServiceConfig->lpDisplayName, TEXT("")) != 0)
		SetWindowText(GetDlgItem(hDlg, 4010), lpQueryServiceConfig->lpDisplayName);
	else {
		LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
		SetWindowText(GetDlgItem(hDlg, 4010), Buffer);
	}

	if (lpQueryServiceConfig->lpServiceStartName != nullptr && wcscmp(lpQueryServiceConfig->lpServiceStartName, TEXT("")) != 0)
		SetWindowText(GetDlgItem(hDlg, 4011), lpQueryServiceConfig->lpServiceStartName);
	else {
		LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
		SetWindowText(GetDlgItem(hDlg, 4011), Buffer);
	}

	if (lpQueryServiceConfig->lpBinaryPathName != nullptr && wcscmp(lpQueryServiceConfig->lpBinaryPathName, TEXT("")) != 0)
		SetWindowText(GetDlgItem(hDlg, 4012), lpQueryServiceConfig->lpBinaryPathName);
	else {
		LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
		SetWindowText(GetDlgItem(hDlg, 4012), Buffer);
	}

	swprintf(Buffer, MAX_PATH, TEXT("%ls\\%ls\\%ls"), TEXT("SYSTEM\\CurrentControlSet\\Services"), g_ServiceName, TEXT("Parameters"));
	if (RegGetValueW(HKEY_LOCAL_MACHINE, Buffer, TEXT("ServiceDll"), RRF_RT_ANY, nullptr, (LPVOID)&ServiceDllPath, &cbData) != ERROR_SUCCESS) {
		swprintf(Buffer, MAX_PATH, TEXT("%ls\\%ls"), TEXT("SYSTEM\\CurrentControlSet\\Services"), g_ServiceName);
		if (RegGetValueW(HKEY_LOCAL_MACHINE, Buffer, TEXT("ServiceDll"), RRF_RT_ANY, nullptr, (LPVOID)&ServiceDllPath, &cbData) != ERROR_SUCCESS) {
			LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
			goto Continue;
		}
	}
	swprintf(Buffer, MAX_PATH, TEXT("%ls"), ServiceDllPath);
Continue:
	SetWindowText(GetDlgItem(hDlg, 4013), Buffer);

	if (lpQueryServiceConfig->lpDependencies != nullptr && wcscmp(lpQueryServiceConfig->lpDependencies, TEXT("")) != 0) {
		for (PTCHAR NextDependency = lpQueryServiceConfig->lpDependencies; *NextDependency; NextDependency += wcslen(NextDependency) + 1) {
			if (NextDependency[0] == SC_GROUP_IDENTIFIER)
				continue;
			swprintf(FirstDependency, MAX_PATH, TEXT("%ls ◉ %ls"), FirstDependency, NextDependency);
		}
		swprintf(Buffer, MAX_PATH, TEXT("%ls ◉ "), FirstDependency);
	}
	else
		LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
	SetWindowText(GetDlgItem(hDlg, 4014), Buffer);

	if (lpQueryServiceConfig->lpLoadOrderGroup != nullptr && wcscmp(lpQueryServiceConfig->lpLoadOrderGroup, TEXT("")) != 0)
		SetWindowText(GetDlgItem(hDlg, 4015), lpQueryServiceConfig->lpLoadOrderGroup);
	else {
		LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
		SetWindowText(GetDlgItem(hDlg, 4015), Buffer);
	}

	switch (lpQueryServiceConfig->dwTagId)
	{
		case 0:
			swprintf(Buffer, MAX_PATH, TEXT("<%ls> has not been assigned a tag"), g_ServiceName);
			break;

		default:
			swprintf(Buffer, MAX_PATH, TEXT("%u"), lpQueryServiceConfig->dwTagId);
			break;
	}
	SetWindowText(GetDlgItem(hDlg, 4016), Buffer);

	if (IsValidSecurityDescriptor(pSecurityDescriptor)) {
		EnableWindow(GetDlgItem(hDlg, 4029), TRUE);
		swprintf(Buffer, USHRT_MAX, TEXT("%ls"), pStringSecurityDescriptor);
	}
	else
		LoadString(g_hInstance, 10261, Buffer, MAX_PATH);
	SetWindowText(GetDlgItem(hDlg, 4028), Buffer);

	return TRUE;
}


BOOL GetServiceStatus(HWND hDlg)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, g_ServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
	CloseServiceHandle(hSCManager);

	DWORD dwBytesNeeded = 0;

	if (!QueryServiceConfig(hService, nullptr, 0, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseServiceHandle(hService);
			return FALSE;
		}
	}

	LPQUERY_SERVICE_CONFIG lpQueryServiceConfig = { 0 };
	lpQueryServiceConfig = (LPQUERY_SERVICE_CONFIG)_alloca(dwBytesNeeded);

	if (!QueryServiceConfig(hService, lpQueryServiceConfig, dwBytesNeeded, &dwBytesNeeded)) {
		CloseServiceHandle(hService);
		return FALSE;
	}

	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, nullptr, 0, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseServiceHandle(hService);
			return FALSE;
		}
	}

	LPSERVICE_STATUS_PROCESS lpServiceStatusProcess = { 0 };
	lpServiceStatusProcess = (LPSERVICE_STATUS_PROCESS)malloc(dwBytesNeeded);

	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)lpServiceStatusProcess, dwBytesNeeded, &dwBytesNeeded)) {
		free(lpServiceStatusProcess);
		CloseServiceHandle(hService);
		return FALSE;
	}

	TCHAR Buffer[MAX_PATH] = { 0 };

	switch (lpQueryServiceConfig->dwStartType)
	{
		case SERVICE_DISABLED:
			LoadString(g_hInstance, 10262, Buffer, MAX_PATH);
			if (IsWindowEnabled(GetDlgItem(hDlg, 4023))) {
				SetWindowText(GetDlgItem(hDlg, 4023), TEXT("Start\\Stop"));
				EnableWindow(GetDlgItem(hDlg, 4023), FALSE);
			}
			SetWindowText(GetDlgItem(hDlg, 4025), TEXT("Enable"));
			EnableWindow(GetDlgItem(hDlg, 4025), TRUE);
			break;

		default:
			switch (lpServiceStatusProcess->dwCurrentState)
			{
				case SERVICE_STOPPED:
					LoadString(g_hInstance, 10263, Buffer, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4023), TEXT("Start"));
					EnableWindow(GetDlgItem(hDlg, 4023), TRUE);
					if (IsWindowEnabled(GetDlgItem(hDlg, 4024))) {
						SetWindowText(GetDlgItem(hDlg, 4024), TEXT("Pause\\Continue"));
						EnableWindow(GetDlgItem(hDlg, 4024), FALSE);
					}
					SetWindowText(GetDlgItem(hDlg, 4025), TEXT("Disable"));
					EnableWindow(GetDlgItem(hDlg, 4025), TRUE);
					EnableWindow(GetDlgItem(hDlg, 4022), FALSE);
					break;

				case SERVICE_RUNNING:
					LoadString(g_hInstance, 10264, Buffer, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4023), TEXT("Stop"));
					EnableWindow(GetDlgItem(hDlg, 4023), TRUE);
					if (IsWindowEnabled(GetDlgItem(hDlg, 4025))) {
						SetWindowText(GetDlgItem(hDlg, 4025), TEXT("Enable\\Disable"));
						EnableWindow(GetDlgItem(hDlg, 4025), FALSE);
					}
					break;

				case SERVICE_PAUSED:
					LoadString(g_hInstance, 10265, Buffer, MAX_PATH);
					if (IsWindowEnabled(GetDlgItem(hDlg, 4023))) {
						SetWindowText(GetDlgItem(hDlg, 4023), TEXT("Start\\Stop"));
						EnableWindow(GetDlgItem(hDlg, 4023), FALSE);
					}
					break;

				default:
					break;
			}
			break;
	}
	SetWindowText(GetDlgItem(hDlg, 4017), Buffer);

	switch (lpServiceStatusProcess->dwProcessId)
	{
		case 0:
			LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4018), Buffer);
			break;

		default:
			swprintf(Buffer, MAX_PATH, TEXT("%u"), lpServiceStatusProcess->dwProcessId);
			if (EnableWindow(GetDlgItem(hDlg, 4022), TRUE))
				g_dwProcessId = lpServiceStatusProcess->dwProcessId;
			SetWindowText(GetDlgItem(hDlg, 4018), Buffer);
			break;
	}

	switch (lpServiceStatusProcess->dwControlsAccepted)
	{
		case 0:
			LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4019), Buffer);
			break;

		default:
			ControlAcceptBruteForce(hDlg, lpServiceStatusProcess->dwControlsAccepted, lpServiceStatusProcess->dwCurrentState);
			break;
	}

	switch (lpServiceStatusProcess->dwWin32ExitCode)
	{
		case NO_ERROR:
			LoadString(g_hInstance, 10269, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4020), Buffer);
			break;

		case ERROR_INVALID_FUNCTION:
			LoadString(g_hInstance, 10270, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4020), Buffer);
			break;

		case ERROR_GEN_FAILURE:
			LoadString(g_hInstance, 10271, Buffer, MAX_PATH);
			break;

		case ERROR_SERVICE_SPECIFIC_ERROR:
			LoadString(g_hInstance, 10272, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4020), Buffer);
			break;

		case ERROR_SERVICE_NEVER_STARTED:
			LoadString(g_hInstance, 10273, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4020), Buffer);
			break;

		default:
			swprintf(Buffer, MAX_PATH, TEXT("%u"), lpServiceStatusProcess->dwWin32ExitCode);
			SetWindowText(GetDlgItem(hDlg, 4020), Buffer);
			break;
	}

	switch (lpServiceStatusProcess->dwServiceSpecificExitCode)
	{
		case NO_ERROR:
			LoadString(g_hInstance, 10269, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4021), Buffer);
			break;

		case ERROR_SERVICE_SPECIFIC_ERROR:
			LoadString(g_hInstance, 10272, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4021), Buffer);
			break;

		case RPC_S_SERVER_UNAVAILABLE:
			LoadString(g_hInstance, 10274, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4021), Buffer);
			break;

		default:
			swprintf(Buffer, MAX_PATH, TEXT("%u"), lpServiceStatusProcess->dwServiceSpecificExitCode);
			SetWindowText(GetDlgItem(hDlg, 4021), Buffer);
			break;
	}

	switch (lpServiceStatusProcess->dwServiceFlags)
	{
		case 0:
			if (lpServiceStatusProcess->dwProcessId != 0) {
				LoadString(g_hInstance, 10266, Buffer, MAX_PATH);
				SetWindowText(GetDlgItem(hDlg, 4026), Buffer);
			}
			else {
				LoadString(g_hInstance, 10267, Buffer, MAX_PATH);
				SetWindowText(GetDlgItem(hDlg, 4026), Buffer);
			}
			break;

		case SERVICE_RUNS_IN_SYSTEM_PROCESS:
			LoadString(g_hInstance, 10268, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4026), Buffer);
			break;
	}

	free(lpServiceStatusProcess);

	return TRUE;
}


BOOL StartStopService(HWND hDlg)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, g_ServiceName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
	if (ERROR_ACCESS_DENIED == GetLastError()) {
		CloseServiceHandle(hSCManager);
		ErrPrint(hDlg);
		return FALSE;
	}

	CloseServiceHandle(hSCManager);

	SERVICE_STATUS ServiceStatus = { 0 };

	QueryServiceStatus(hService, &ServiceStatus);

	switch (ServiceStatus.dwCurrentState)
	{
		case SERVICE_STOPPED:
			if (!StartService(hService, 0, nullptr)) {
				CloseServiceHandle(hService);
				ErrPrint(hDlg);
				return FALSE;
			}
			break;

		case SERVICE_RUNNING:
			if (!ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus)) {
				CloseServiceHandle(hService);
				ErrPrint(hDlg);
				return FALSE;
			}
			break;

		default:
			break;
	}
	
	CloseServiceHandle(hService);

	return TRUE;
}


BOOL PauseContinueService(HWND hDlg)
{
SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, g_ServiceName, SERVICE_QUERY_STATUS | SERVICE_PAUSE_CONTINUE);
	if (ERROR_ACCESS_DENIED == GetLastError()) {
		CloseServiceHandle(hSCManager);
		ErrPrint(hDlg);
		return FALSE;
	}

	CloseServiceHandle(hSCManager);

	SERVICE_STATUS ServiceStatus = { 0 };

	QueryServiceStatus(hService, &ServiceStatus);

	switch (ServiceStatus.dwCurrentState)
	{
		case SERVICE_RUNNING:
			if (!ControlService(hService, SERVICE_CONTROL_PAUSE, &ServiceStatus)) {
				CloseServiceHandle(hService);
				ErrPrint(hDlg);
				return FALSE;
			}
			break;

		case SERVICE_PAUSED:
			if (!ControlService(hService, SERVICE_CONTROL_CONTINUE, &ServiceStatus)) {
				CloseServiceHandle(hService);
				ErrPrint(hDlg);
				return FALSE;
			}
			break;

		default:
			break;
	}
	
	CloseServiceHandle(hService);

	return TRUE;
}


BOOL EnableDisableService(HWND hDlg)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, g_ServiceName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
	if (ERROR_ACCESS_DENIED == GetLastError()) {
		CloseServiceHandle(hSCManager);
		ErrPrint(hDlg);
		return FALSE;
	}

	CloseServiceHandle(hSCManager);

	DWORD dwBytesNeeded = 0;

	if (!QueryServiceConfig(hService, nullptr, 0, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseServiceHandle(hService);
			return FALSE;
		}
	}

	LPQUERY_SERVICE_CONFIG lpQueryServiceConfig = { 0 };
	lpQueryServiceConfig = (LPQUERY_SERVICE_CONFIG)_alloca(dwBytesNeeded);

	if (!QueryServiceConfig(hService, lpQueryServiceConfig, dwBytesNeeded, &dwBytesNeeded)) {
		CloseServiceHandle(hService);
		return FALSE;
	}

	switch (lpQueryServiceConfig->dwStartType)
	{
		case SERVICE_DISABLED:
			if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
				CloseServiceHandle(hService);
				ErrPrint(hDlg);
				return FALSE;
			}
			break;

		default:
			if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
				CloseServiceHandle(hService);
				ErrPrint(hDlg);
				return FALSE;
			}
			break;
	}

	CloseServiceHandle(hService);

	return TRUE;
}
