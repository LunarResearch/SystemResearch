#include "Defines.h"


VOID ToolTipPrivileges(HWND hDlg, PTCH strBuffer)
{
	CreateToolTip(hDlg, 4000, 10000, strBuffer);
	CreateToolTip(hDlg, 4001, 10001, strBuffer);
	CreateToolTip(hDlg, 4002, 10002, strBuffer);
	CreateToolTip(hDlg, 4003, 10003, strBuffer);
	CreateToolTip(hDlg, 4004, 10004, strBuffer);
	CreateToolTip(hDlg, 4005, 10005, strBuffer);
	CreateToolTip(hDlg, 4006, 10006, strBuffer);
	CreateToolTip(hDlg, 4007, 10007, strBuffer);
	CreateToolTip(hDlg, 4008, 10008, strBuffer);
	CreateToolTip(hDlg, 4009, 10009, strBuffer);
	CreateToolTip(hDlg, 4010, 10010, strBuffer);
	CreateToolTip(hDlg, 4011, 10011, strBuffer);
	CreateToolTip(hDlg, 4012, 10012, strBuffer);
	CreateToolTip(hDlg, 4013, 10013, strBuffer);
	CreateToolTip(hDlg, 4014, 10014, strBuffer);
	CreateToolTip(hDlg, 4015, 10015, strBuffer);
	CreateToolTip(hDlg, 4016, 10016, strBuffer);
	CreateToolTip(hDlg, 4017, 10017, strBuffer);
	CreateToolTip(hDlg, 4018, 10018, strBuffer);
	CreateToolTip(hDlg, 4019, 10019, strBuffer);
	CreateToolTip(hDlg, 4020, 10020, strBuffer);
	CreateToolTip(hDlg, 4021, 10021, strBuffer);
	CreateToolTip(hDlg, 4022, 10022, strBuffer);
	CreateToolTip(hDlg, 4023, 10023, strBuffer);
	CreateToolTip(hDlg, 4024, 10024, strBuffer);
	CreateToolTip(hDlg, 4025, 10025, strBuffer);
	CreateToolTip(hDlg, 4026, 10026, strBuffer);
	CreateToolTip(hDlg, 4027, 10027, strBuffer);
	CreateToolTip(hDlg, 4028, 10028, strBuffer);
	CreateToolTip(hDlg, 4029, 10029, strBuffer);
	CreateToolTip(hDlg, 4030, 10030, strBuffer);
	CreateToolTip(hDlg, 4031, 10031, strBuffer);
	CreateToolTip(hDlg, 4032, 10032, strBuffer);
	CreateToolTip(hDlg, 4033, 10033, strBuffer);
	CreateToolTip(hDlg, 4034, 10034, strBuffer);
	CreateToolTip(hDlg, 4035, 10035, strBuffer);
	CreateToolTip(hDlg, 4036, 10036, strBuffer);

	return;
}


VOID ProcessAccessRightCheck(HWND hDlg, BOOL IsDlgBtnChecked)
{
	if (!IsDlgBtnChecked)
	{
		if (g_IsCheckedSacl)
			CheckDlgButton(hDlg, 4039, BST_CHECKED);
		else CheckDlgButton(hDlg, 4039, BST_UNCHECKED);

		if (g_IsCheckedDacl)
			CheckDlgButton(hDlg, 4040, BST_CHECKED);
		else CheckDlgButton(hDlg, 4040, BST_UNCHECKED);

		if (g_IsCheckedTerminate)
			CheckDlgButton(hDlg, 4041, BST_CHECKED);
		else CheckDlgButton(hDlg, 4041, BST_UNCHECKED);

		if (g_IsCheckedCreateThread)
			CheckDlgButton(hDlg, 4042, BST_CHECKED);
		else CheckDlgButton(hDlg, 4042, BST_UNCHECKED);

		if (g_IsCheckedSetSessionId)
			CheckDlgButton(hDlg, 4043, BST_CHECKED);
		else CheckDlgButton(hDlg, 4043, BST_UNCHECKED);

		if (g_IsCheckedVMOperation)
			CheckDlgButton(hDlg, 4044, BST_CHECKED);
		else CheckDlgButton(hDlg, 4044, BST_UNCHECKED);

		if (g_IsCheckedVMRead)
			CheckDlgButton(hDlg, 4045, BST_CHECKED);
		else CheckDlgButton(hDlg, 4045, BST_UNCHECKED);

		if (g_IsCheckedVMWrite)
			CheckDlgButton(hDlg, 4046, BST_CHECKED);
		else CheckDlgButton(hDlg, 4046, BST_UNCHECKED);

		if (g_IsCheckedDuplicateHandle)
			CheckDlgButton(hDlg, 4047, BST_CHECKED);
		else CheckDlgButton(hDlg, 4047, BST_UNCHECKED);

		if (g_IsCheckedCreateProcess)
			CheckDlgButton(hDlg, 4048, BST_CHECKED);
		else CheckDlgButton(hDlg, 4048, BST_UNCHECKED);

		if (g_IsCheckedSetQuota)
			CheckDlgButton(hDlg, 4049, BST_CHECKED);
		else CheckDlgButton(hDlg, 4049, BST_UNCHECKED);

		if (g_IsCheckedSetInfo)
			CheckDlgButton(hDlg, 4050, BST_CHECKED);
		else CheckDlgButton(hDlg, 4050, BST_UNCHECKED);

		if (g_IsCheckedQueryInfo)
			CheckDlgButton(hDlg, 4051, BST_CHECKED);
		else CheckDlgButton(hDlg, 4051, BST_UNCHECKED);

		if (g_IsCheckedSuspendResume)
			CheckDlgButton(hDlg, 4052, BST_CHECKED);
		else CheckDlgButton(hDlg, 4052, BST_UNCHECKED);

		if (g_IsCheckedSetLimitedInfo)
			CheckDlgButton(hDlg, 4053, BST_CHECKED);
		else CheckDlgButton(hDlg, 4053, BST_UNCHECKED);

		if (g_IsCheckedDelete)
			CheckDlgButton(hDlg, 4054, BST_CHECKED);
		else CheckDlgButton(hDlg, 4054, BST_UNCHECKED);

		if (g_IsCheckedSynchronize)
			CheckDlgButton(hDlg, 4055, BST_CHECKED);
		else CheckDlgButton(hDlg, 4055, BST_UNCHECKED);

		if (g_IsCheckedRightOwner)
			CheckDlgButton(hDlg, 4056, BST_CHECKED);
		else CheckDlgButton(hDlg, 4056, BST_UNCHECKED);

		if (g_IsCheckedRightDAC)
			CheckDlgButton(hDlg, 4057, BST_CHECKED);
		else CheckDlgButton(hDlg, 4057, BST_UNCHECKED);
	}

	else
	{
		if (IsDlgButtonChecked(hDlg, 4039))
			g_IsCheckedSacl = TRUE;
		else g_IsCheckedSacl = FALSE;

		if (IsDlgButtonChecked(hDlg, 4040))
			g_IsCheckedDacl = TRUE;
		else g_IsCheckedDacl = FALSE;

		if (IsDlgButtonChecked(hDlg, 4041))
			g_IsCheckedTerminate = TRUE;
		else g_IsCheckedTerminate = FALSE;

		if (IsDlgButtonChecked(hDlg, 4042))
			g_IsCheckedCreateThread = TRUE;
		else g_IsCheckedCreateThread = FALSE;

		if (IsDlgButtonChecked(hDlg, 4043))
			g_IsCheckedSetSessionId = TRUE;
		else g_IsCheckedSetSessionId = FALSE;

		if (IsDlgButtonChecked(hDlg, 4044))
			g_IsCheckedVMOperation = TRUE;
		else g_IsCheckedVMOperation = FALSE;

		if (IsDlgButtonChecked(hDlg, 4045))
			g_IsCheckedVMRead = TRUE;
		else g_IsCheckedVMRead = FALSE;

		if (IsDlgButtonChecked(hDlg, 4046))
			g_IsCheckedVMWrite = TRUE;
		else g_IsCheckedVMWrite = FALSE;

		if (IsDlgButtonChecked(hDlg, 4047))
			g_IsCheckedDuplicateHandle = TRUE;
		else g_IsCheckedDuplicateHandle = FALSE;

		if (IsDlgButtonChecked(hDlg, 4048))
			g_IsCheckedCreateProcess = TRUE;
		else g_IsCheckedCreateProcess = FALSE;

		if (IsDlgButtonChecked(hDlg, 4049))
			g_IsCheckedSetQuota = TRUE;
		else g_IsCheckedSetQuota = FALSE;

		if (IsDlgButtonChecked(hDlg, 4050))
			g_IsCheckedSetInfo = TRUE;
		else g_IsCheckedSetInfo = FALSE;

		if (IsDlgButtonChecked(hDlg, 4051))
			g_IsCheckedQueryInfo = TRUE;
		else g_IsCheckedQueryInfo = FALSE;

		if (IsDlgButtonChecked(hDlg, 4052))
			g_IsCheckedSuspendResume = TRUE;
		else g_IsCheckedSuspendResume = FALSE;

		if (IsDlgButtonChecked(hDlg, 4053))
			g_IsCheckedSetLimitedInfo = TRUE;
		else g_IsCheckedSetLimitedInfo = FALSE;

		if (IsDlgButtonChecked(hDlg, 4054))
			g_IsCheckedDelete = TRUE;
		else g_IsCheckedDelete = FALSE;

		if (IsDlgButtonChecked(hDlg, 4055))
			g_IsCheckedSynchronize = TRUE;
		else g_IsCheckedSynchronize = FALSE;

		if (IsDlgButtonChecked(hDlg, 4056))
			g_IsCheckedRightOwner = TRUE;
		else g_IsCheckedRightOwner = FALSE;

		if (IsDlgButtonChecked(hDlg, 4057))
			g_IsCheckedRightDAC = TRUE;
		else g_IsCheckedRightDAC = FALSE;
	}

	return;
}


VOID ControlAcceptBruteForce(HWND hDlg, DWORD dwCtrlAccept, DWORD dwCrntState)
{
	TCHAR Buffer[USHRT_MAX] = { 0 }, Buffer1[MAX_PATH] = { 0 }, Buffer2[MAX_PATH] = { 0 }, Buffer3[MAX_PATH] = { 0 }, Buffer4[MAX_PATH] = { 0 },
		Buffer5[MAX_PATH] = { 0 }, Buffer6[MAX_PATH] = { 0 }, Buffer7[MAX_PATH] = { 0 }, Buffer8[MAX_PATH] = { 0 }, Buffer9[MAX_PATH] = { 0 },
		Buffer10[MAX_PATH] = { 0 }, Buffer11[MAX_PATH] = { 0 }, Buffer12[MAX_PATH] = { 0 }, Buffer13[MAX_PATH] = { 0 }, Buffer14[MAX_PATH] = { 0 },
		Buffer15[MAX_PATH] = { 0 };

	if (dwCtrlAccept & SERVICE_ACCEPT_STOP)
		LoadString(g_hInstance, 10186, Buffer1, MAX_PATH);
	else {
		SetWindowText(GetDlgItem(hDlg, 4023), TEXT("Start\\Stop"));
		EnableWindow(GetDlgItem(hDlg, 4023), FALSE);
	}

	if (dwCtrlAccept & SERVICE_ACCEPT_PAUSE_CONTINUE)
	{
		LoadString(g_hInstance, 10187, Buffer2, MAX_PATH);

		switch (dwCrntState)
		{
			case SERVICE_RUNNING:
				SetWindowText(GetDlgItem(hDlg, 4024), TEXT("Pause"));
				break;

			case SERVICE_PAUSED:
				SetWindowText(GetDlgItem(hDlg, 4024), TEXT("Continue"));
				break;
		}
		EnableWindow(GetDlgItem(hDlg, 4024), TRUE);
	}

	if (dwCtrlAccept & SERVICE_ACCEPT_SHUTDOWN)
		LoadString(g_hInstance, 10188, Buffer3, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_PARAMCHANGE)
		LoadString(g_hInstance, 10189, Buffer4, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_NETBINDCHANGE)
		LoadString(g_hInstance, 10190, Buffer5, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_HARDWAREPROFILECHANGE)
		LoadString(g_hInstance, 10191, Buffer6, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_POWEREVENT)
		LoadString(g_hInstance, 10192, Buffer7, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_SESSIONCHANGE)
		LoadString(g_hInstance, 10193, Buffer8, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_PRESHUTDOWN)
		LoadString(g_hInstance, 10194, Buffer9, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_TIMECHANGE)
		LoadString(g_hInstance, 10195, Buffer10, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_TRIGGEREVENT)
		LoadString(g_hInstance, 10196, Buffer11, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_USER_LOGOFF)
		LoadString(g_hInstance, 10197, Buffer12, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_INTERNAL_SECURITY)
		LoadString(g_hInstance, 10198, Buffer13, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_LOWRESOURCES)
		LoadString(g_hInstance, 10199, Buffer14, MAX_PATH);

	if (dwCtrlAccept & SERVICE_ACCEPT_SYSTEMLOWRESOURCES)
		LoadString(g_hInstance, 10200, Buffer15, MAX_PATH);

	swprintf(Buffer, USHRT_MAX, TEXT("%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls"),
		Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7, Buffer8, Buffer9, Buffer10, Buffer11, Buffer12, Buffer13, Buffer14, Buffer15);
	Buffer[wcslen(Buffer) - 3] = 0;
	SetWindowText(GetDlgItem(hDlg, 4019), Buffer);

	return;
}


VOID PrivilegeSwitchChecked(HWND hDlg, HANDLE hProcess)
{
	for (int i = 0; i <= 36; i++) {
		if (IsDlgButtonChecked(hDlg, 4000 + i))
			PrivilegeManager2(hProcess, SE_PRIVILEGE_ENABLED, i);
		else PrivilegeManager2(hProcess, SE_PRIVILEGE_DISABLED, i);
	}

	return;
}


VOID ProcessPrivilegeBruteForce(HWND hDlg, HANDLE hToken, DWORD LowPart)
{
	for (DWORD i = 0; i <= 36; i++) {
		if (LowPart == i) {
			EnableWindow(GetDlgItem(hDlg, 4000 + i), true);
			if (IsProcessPrivilegeEnable2(hToken, i)) {
				if (i == 0 || i == 1)
					CheckDlgButton(hDlg, 4000 + i, BST_INDETERMINATE | BST_CHECKED);
				else CheckDlgButton(hDlg, 4000 + i, BST_CHECKED);
			}
			else {
				if (i == 0 || i == 1)
					CheckDlgButton(hDlg, 4000 + i, BST_INDETERMINATE | BST_UNCHECKED);
				else CheckDlgButton(hDlg, 4000 + i, BST_UNCHECKED);
			}
		}
	}

	return;
}


VOID ServicePrivilegeBruteForce(HWND hDlg, DWORD LowPart)
{
	for (DWORD i = 0; i <= 36; i++) {
		if (LowPart == i) {
			EnableWindow(GetDlgItem(hDlg, 4000 + i), TRUE);
			CheckDlgButton(hDlg, 4000 + i, BST_CHECKED);
		}
	}

	return;
}


VOID SecurityDescriptorControlFlagsBruteForce(HWND hDlg, WORD Control)
{
	TCHAR Buffer[USHRT_MAX] = { 0 }, Buffer1[MAX_PATH] = { 0 }, Buffer2[MAX_PATH] = { 0 }, Buffer3[MAX_PATH] = { 0 }, Buffer4[MAX_PATH] = { 0 },
		Buffer5[MAX_PATH] = { 0 }, Buffer6[MAX_PATH] = { 0 }, Buffer7[MAX_PATH] = { 0 }, Buffer8[MAX_PATH] = { 0 }, Buffer9[MAX_PATH] = { 0 },
		Buffer10[MAX_PATH] = { 0 }, Buffer11[MAX_PATH] = { 0 }, Buffer12[MAX_PATH] = { 0 }, Buffer13[MAX_PATH] = { 0 }, Buffer14[MAX_PATH] = { 0 };

	if (Control & SE_OWNER_DEFAULTED)
		LoadString(g_hInstance, 10275, Buffer1, MAX_PATH);

	if (Control & SE_GROUP_DEFAULTED)
		LoadString(g_hInstance, 10276, Buffer2, MAX_PATH);

	if (Control & SE_DACL_PRESENT)
		LoadString(g_hInstance, 10277, Buffer3, MAX_PATH);

	if (Control & SE_DACL_DEFAULTED)
		LoadString(g_hInstance, 10278, Buffer4, MAX_PATH);

	if (Control & SE_SACL_PRESENT)
		LoadString(g_hInstance, 10279, Buffer5, MAX_PATH);

	if (Control & SE_SACL_DEFAULTED)
		LoadString(g_hInstance, 10280, Buffer6, MAX_PATH);

	if (Control & SE_DACL_AUTO_INHERIT_REQ)
		LoadString(g_hInstance, 10281, Buffer7, MAX_PATH);

	if (Control & SE_SACL_AUTO_INHERIT_REQ)
		LoadString(g_hInstance, 10282, Buffer8, MAX_PATH);

	if (Control & SE_DACL_AUTO_INHERITED)
		LoadString(g_hInstance, 10283, Buffer9, MAX_PATH);

	if (Control & SE_SACL_AUTO_INHERITED)
		LoadString(g_hInstance, 10284, Buffer10, MAX_PATH);

	if (Control & SE_DACL_PROTECTED)
		LoadString(g_hInstance, 10285, Buffer11, MAX_PATH);

	if (Control & SE_SACL_PROTECTED)
		LoadString(g_hInstance, 10286, Buffer12, MAX_PATH);

	if (Control & SE_RM_CONTROL_VALID)
		LoadString(g_hInstance, 10287, Buffer13, MAX_PATH);

	if (Control & SE_SELF_RELATIVE)
		LoadString(g_hInstance, 10288, Buffer14, MAX_PATH);

	swprintf(Buffer, USHRT_MAX, TEXT("%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls"),
		Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7, Buffer8, Buffer9, Buffer10, Buffer11, Buffer12, Buffer13, Buffer14);
	Buffer[wcslen(Buffer) - 3] = 0;

	SetWindowText(hDlg, Buffer);

	return;
}


BOOL GetTokenProcessPrivilegesInfo(HWND hDlg, HANDLE hProcess)
{
	HANDLE hToken = nullptr;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		return FALSE;

	DWORD ReturnLength = 0;

	if (!GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &ReturnLength)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseHandle(hToken);
			return FALSE;
		}
	}

	PTOKEN_PRIVILEGES pTokenPrivileges = { 0 };
	pTokenPrivileges = (PTOKEN_PRIVILEGES)_alloca(ReturnLength);

	if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, ReturnLength, &ReturnLength)) {
		CloseHandle(hToken);
		return FALSE;
	}

	for (DWORD i = 0; i <= pTokenPrivileges->PrivilegeCount; i++)
		ProcessPrivilegeBruteForce(hDlg, hToken, pTokenPrivileges->Privileges[i].Luid.LowPart);

	CloseHandle(hToken);

	return TRUE;
}


BOOL GetTokenServicePrivilegesInfo(HWND hDlg, PCTCH pszServiceName)
{
	SC_HANDLE hSCManager = nullptr, hService = nullptr;

	hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
		return FALSE;

	hService = OpenService(hSCManager, pszServiceName, SERVICE_QUERY_CONFIG);
	CloseServiceHandle(hSCManager);

	DWORD dwBytesNeeded = 0;

	if (!QueryServiceConfig2(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, nullptr, 0, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseServiceHandle(hService);
			return FALSE;
		}
	}

	LPSERVICE_REQUIRED_PRIVILEGES_INFO lpServiceRequiredPrivilegesInfo = { 0 };
	lpServiceRequiredPrivilegesInfo = (LPSERVICE_REQUIRED_PRIVILEGES_INFO)_alloca(dwBytesNeeded);

	if (!QueryServiceConfig2(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (LPBYTE)lpServiceRequiredPrivilegesInfo, dwBytesNeeded, &dwBytesNeeded)) {
		CloseServiceHandle(hService);
		return FALSE;
	}
	CloseServiceHandle(hService);

	if (!lpServiceRequiredPrivilegesInfo->pmszRequiredPrivileges)
		return FALSE;

	PTCH SvcReqPriv = nullptr;
	SvcReqPriv = lpServiceRequiredPrivilegesInfo->pmszRequiredPrivileges;

	while(*SvcReqPriv)
	{
		if (wcscmp(SvcReqPriv, SE_CREATE_TOKEN_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 2);
		if (wcscmp(SvcReqPriv, SE_ASSIGNPRIMARYTOKEN_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 3);
		if (wcscmp(SvcReqPriv, SE_LOCK_MEMORY_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 4);
		if (wcscmp(SvcReqPriv, SE_INCREASE_QUOTA_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 5);
		if (wcscmp(SvcReqPriv, SE_MACHINE_ACCOUNT_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 6);
		if (wcscmp(SvcReqPriv, SE_TCB_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 7);
		if (wcscmp(SvcReqPriv, SE_SECURITY_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 8);
		if (wcscmp(SvcReqPriv, SE_TAKE_OWNERSHIP_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 9);
		if (wcscmp(SvcReqPriv, SE_LOAD_DRIVER_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 10);
		if (wcscmp(SvcReqPriv, SE_SYSTEM_PROFILE_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 11);
		if (wcscmp(SvcReqPriv, SE_SYSTEMTIME_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 12);
		if (wcscmp(SvcReqPriv, SE_PROF_SINGLE_PROCESS_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 13);
		if (wcscmp(SvcReqPriv, SE_INC_BASE_PRIORITY_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 14);
		if (wcscmp(SvcReqPriv, SE_CREATE_PAGEFILE_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 15);
		if (wcscmp(SvcReqPriv, SE_CREATE_PERMANENT_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 16);
		if (wcscmp(SvcReqPriv, SE_BACKUP_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 17);
		if (wcscmp(SvcReqPriv, SE_RESTORE_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 18);
		if (wcscmp(SvcReqPriv, SE_SHUTDOWN_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 19);
		if (wcscmp(SvcReqPriv, SE_DEBUG_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 20);
		if (wcscmp(SvcReqPriv, SE_AUDIT_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 21);
		if (wcscmp(SvcReqPriv, SE_SYSTEM_ENVIRONMENT_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 22);
		if (wcscmp(SvcReqPriv, SE_CHANGE_NOTIFY_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 23);
		if (wcscmp(SvcReqPriv, SE_REMOTE_SHUTDOWN_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 24);
		if (wcscmp(SvcReqPriv, SE_UNDOCK_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 25);
		if (wcscmp(SvcReqPriv, SE_SYNC_AGENT_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 26);
		if (wcscmp(SvcReqPriv, SE_ENABLE_DELEGATION_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 27);
		if (wcscmp(SvcReqPriv, SE_MANAGE_VOLUME_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 28);
		if (wcscmp(SvcReqPriv, SE_IMPERSONATE_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 29);
		if (wcscmp(SvcReqPriv, SE_CREATE_GLOBAL_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 30);
		if (wcscmp(SvcReqPriv, SE_TRUSTED_CREDMAN_ACCESS_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 31);
		if (wcscmp(SvcReqPriv, SE_RELABEL_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 32);
		if (wcscmp(SvcReqPriv, SE_INC_WORKING_SET_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 33);
		if (wcscmp(SvcReqPriv, SE_TIME_ZONE_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 34);
		if (wcscmp(SvcReqPriv, SE_CREATE_SYMBOLIC_LINK_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 35);
		if (wcscmp(SvcReqPriv, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME) == 0) ServicePrivilegeBruteForce(hDlg, 36);

		SvcReqPriv = SvcReqPriv + wcslen(SvcReqPriv) + 1;
	}

	return TRUE;
}


HWND CreateToolTip(HWND hDlg, int nIDControl, int nIDText, PTCH pszText)
{
	int cchBuffer = 0;
	cchBuffer = LoadString(g_hInstance, nIDText, pszText, 0);
	LoadString(g_hInstance, nIDText, pszText, cchBuffer + 1);

	HWND hWndTool = nullptr, hWndTip = nullptr;

    hWndTool = GetDlgItem(hDlg, nIDControl);

	TOOLINFO ToolInfo = { sizeof(TOOLINFO) };

	ToolInfo.hwnd = hDlg;
    ToolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    ToolInfo.uId = (SIZE_T)hWndTool;
    ToolInfo.lpszText = pszText;
    
    hWndTip = CreateWindow(TOOLTIPS_CLASS, 0, WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hDlg, 0, g_hInstance, 0);

    SendMessage(hWndTip, TTM_ADDTOOL, 0, (LPARAM)&ToolInfo);

	SendMessage(hWndTip, TTM_SETMAXTIPWIDTH, 0, UCHAR_MAX); // SHRT_MAX (одной строкой)   UCHAR_MAX (с переносом строк)
	SendMessage(hWndTip, TTM_SETDELAYTIME, TTDT_AUTOPOP, SHRT_MAX); // временя, которое должно пройти до того, как ToolTip исчезнет (SHRT_MAX ~30 сек)
	SendMessage(hWndTip, TTM_SETDELAYTIME, TTDT_INITIAL, 1000); // интервал между моментом остановки курсора мыши и первым появлением подсказки
	SendMessage(hWndTip, TTM_SETDELAYTIME, TTDT_RESHOW, 200); // интервал между появлением следующей подсказки при перемещении курсора в другой круг

    return hWndTip;
}
