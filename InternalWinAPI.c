#include "Defines.h"


LRESULT CALLBACK PrivilegeManagerProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HANDLE hToken = nullptr;
	TCHAR msgBuffer[MAX_PATH] = { 0 }, errBuffer[MAX_PATH] = { 0 }, strBuffer[MAX_PATH] = { 0 };
	DWORD dwMessageId = 0;

	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			SetDesktopComposition(hDlg);

			if (lParam == PRIVILEGE_MANAGER)
				for (int i = 4039; i <= 4057; i++)
					EnableWindow(GetDlgItem(hDlg, i), TRUE);

			if (!GetTokenProcessPrivilegesInfo(hDlg, g_hProcess))
				EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);

			GetTokenServicePrivilegesInfo(hDlg, g_ServiceName);
			ToolTipPrivileges(hDlg, strBuffer);
			ProcessAccessRightCheck(hDlg, FALSE);
		}
		break;

		case WM_COMMAND:
		{
			if (wParam == IDOK)
			{
				if (!OpenProcessToken(g_hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
					dwMessageId = GetLastError();
					FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, dwMessageId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msgBuffer, MAX_PATH, nullptr);
					swprintf(errBuffer, MAX_PATH, TEXT("Error: %u"), dwMessageId);
					MessageBox(hDlg, msgBuffer, errBuffer, MB_ICONERROR);
					GetTokenProcessPrivilegesInfo(hDlg, g_hProcess);
					break;
				}
				CloseHandle(hToken);

				PrivilegeSwitchChecked(hDlg, g_hProcess);
				ProcessAccessRightCheck(hDlg, TRUE);

				if (g_IsCheckedSacl) OBJ_KERNEL_DESIRED_ACCESS = ACCESS_SYSTEM_SECURITY;
				if (g_IsCheckedDacl) OBJ_KERNEL_DESIRED_ACCESS += READ_CONTROL;
				if (g_IsCheckedRightOwner) OBJ_KERNEL_DESIRED_ACCESS += WRITE_OWNER;
				if (g_IsCheckedRightDAC) OBJ_KERNEL_DESIRED_ACCESS += WRITE_DAC;

				if (g_IsCheckedTerminate) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_TERMINATE;
				if (g_IsCheckedCreateThread) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_CREATE_THREAD;
				if (g_IsCheckedSetSessionId) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_SET_SESSIONID;
				if (g_IsCheckedVMOperation) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_VM_OPERATION;
				if (g_IsCheckedVMRead) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_VM_READ;
				if (g_IsCheckedVMWrite) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_VM_WRITE;
				if (g_IsCheckedDuplicateHandle) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_DUP_HANDLE;
				if (g_IsCheckedCreateProcess) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_CREATE_PROCESS;
				if (g_IsCheckedSetQuota) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_SET_QUOTA;
				if (g_IsCheckedSetInfo) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_SET_INFORMATION;
				if (g_IsCheckedQueryInfo) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_QUERY_INFORMATION;
				if (g_IsCheckedSuspendResume) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_SUSPEND_RESUME;
				if (g_IsCheckedSetLimitedInfo) OBJ_KERNEL_DESIRED_ACCESS += PROCESS_SET_LIMITED_INFORMATION;
				if (g_IsCheckedDelete) OBJ_KERNEL_DESIRED_ACCESS += DELETE;
				if (g_IsCheckedSynchronize) OBJ_KERNEL_DESIRED_ACCESS += SYNCHRONIZE;

				if (!g_IsCheckedSacl) OBJ_KERNEL_DESIRED_ACCESS -= ACCESS_SYSTEM_SECURITY;

				if (!g_IsCheckedSacl & !g_IsCheckedDacl &
					!g_IsCheckedRightOwner & !g_IsCheckedRightDAC &
					!g_IsCheckedTerminate & !g_IsCheckedCreateThread &
					!g_IsCheckedSetSessionId & !g_IsCheckedVMOperation &
					!g_IsCheckedVMRead & !g_IsCheckedVMWrite &
					!g_IsCheckedDuplicateHandle & !g_IsCheckedCreateProcess &
					!g_IsCheckedSetQuota & !g_IsCheckedSetInfo &
					!g_IsCheckedQueryInfo & !g_IsCheckedSuspendResume &
					!g_IsCheckedSetLimitedInfo & !g_IsCheckedDelete &
					!g_IsCheckedSynchronize) OBJ_KERNEL_DESIRED_ACCESS = (0x00000000L);

				CloseHandle(g_hProcess);
				g_hProcess = nullptr;
				EndDialog(hDlg, wParam);
				return TRUE;
			}

			if (wParam == IDCANCEL) {
				CloseHandle(g_hProcess);
				g_hProcess = nullptr;
				EndDialog(hDlg, wParam);
           		return TRUE;
			}
		}
		break;
	}

	return EXIT_SUCCESS;
}


LRESULT CALLBACK PropertiesProcessManagerProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static int TokenIntegrityLevelType = 0;

	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			SetDesktopComposition(hDlg);

			g_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | OBJ_KERNEL_DESIRED_ACCESS, FALSE, g_dwProcessId);

			GetProcessBasicInfo(hDlg);
			IsSecureProcess(hDlg);
			IsProtectedProcess(hDlg);
			GetTokenProcessInfo(hDlg);
			GetTokenIntegrityLevelInfo(hDlg);
		}
		break;

		case WM_COMMAND:
		{
			if (wParam == 4061)
				TokenIntegrityLevelType = 0;
			if (wParam == 4062)
				TokenIntegrityLevelType = 1;
			if (wParam == 4063)
				TokenIntegrityLevelType = 2;
			if (wParam == 4064)
				TokenIntegrityLevelType = 3;
			if (wParam == 4065)
				TokenIntegrityLevelType = 4;
			if (wParam == 4066)
				TokenIntegrityLevelType = 5;
			if (wParam == 4067)
				TokenIntegrityLevelType = 6;
			if (wParam == 4068)
				TokenIntegrityLevelType = 7;

			switch (wParam)
			{
				case 4001:
					if (!g_hProcess) g_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | OBJ_KERNEL_DESIRED_ACCESS, FALSE, g_dwProcessId);
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1002), hDlg, PrivilegeManagerProc, (LPARAM)0);
					break;

				case 4025:
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1005), hDlg, SystemAccessControlListProc, (LPARAM)PROCESS_MANAGER);
					break;

				case 4026:
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1005), hDlg, DiscretionaryAccessControlListProc, (LPARAM)PROCESS_MANAGER);
					break;

				case 4033:
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1005), hDlg, SystemAccessControlListProc, (LPARAM)PROCESS_TOKEN_MANAGER);
					break;

				case 4034:
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1005), hDlg, DiscretionaryAccessControlListProc, (LPARAM)PROCESS_TOKEN_MANAGER);
					break;

				case 4069:
					{
						switch (TokenIntegrityLevelType)
						{
							case 0:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_SECURE_PROCESS_RID)) ErrPrint(hDlg);
								break;

							case 1:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_PROTECTED_PROCESS_RID)) ErrPrint(hDlg);
								break;

							case 2:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_SYSTEM_RID)) ErrPrint(hDlg);
								break;

							case 3:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_HIGH_RID)) ErrPrint(hDlg);
								break;

							case 4:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_MEDIUM_PLUS_RID)) ErrPrint(hDlg);
								break;

							case 5:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_MEDIUM_RID)) ErrPrint(hDlg);
								break;

							case 6:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_LOW_RID)) ErrPrint(hDlg);
								break;

							case 7:
								if (!SetTokenIntegrityLevelInfo(SECURITY_MANDATORY_UNTRUSTED_RID)) ErrPrint(hDlg);
								break;
						}
						GetTokenIntegrityLevelInfo(hDlg);
					}
					break;

				case 4070:
					DialogBox(g_hInstance, MAKEINTRESOURCE(1006), hDlg, TokenGroupsProc);
					break;
			}

			if (wParam == IDCANCEL) {
				CloseHandle(g_hProcess);
				g_hProcess = nullptr;
				EndDialog(hDlg, wParam);
           		return TRUE;
			}
		}
		break;
	}

	return EXIT_SUCCESS;
}


LRESULT CALLBACK PropertiesServiceManagerProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	TCHAR ServiceName[MAX_PATH] = { 0 };
	static int ProtectServiceType = 0;

	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			SetDesktopComposition(hDlg);

			if (GetBuildOSNumber() >= 9600)
				for (int i = 4001; i <= 4006; i++)
					EnableWindow(GetDlgItem(hDlg, i), TRUE);

			CheckServiceProtectInfo(hDlg, g_ServiceName);
			GetServiceConfig(hDlg);
			GetServiceStatus(hDlg);
		}
		break;

		case WM_COMMAND:
		{
			if (wParam == 4003)
				ProtectServiceType = 0;
			if (wParam == 4004)
				ProtectServiceType = 1;
			if (wParam == 4005)
				ProtectServiceType = 2;
			if (wParam == 4006)
				ProtectServiceType = 3;

			switch (wParam)
			{
				case 4001:
					{
						switch (ProtectServiceType)
						{
							case 0:
								if (!UnProtectService(g_ServiceName, SERVICE_LAUNCH_PROTECTED_NONE)) ErrPrint(hDlg);
								break;

							case 1:
								if (!UnProtectService(g_ServiceName, SERVICE_LAUNCH_PROTECTED_WINDOWS)) ErrPrint(hDlg);
								break;

							case 2:
								if (!UnProtectService(g_ServiceName, SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT)) ErrPrint(hDlg);
								break;

							case 3:
								if (!UnProtectService(g_ServiceName, SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT)) ErrPrint(hDlg);
								break;
						}
						CheckServiceProtectInfo(hDlg, g_ServiceName);
					}
					break;

				case 4022:
					ServiceName[0] = g_ServiceName[0];
					g_ServiceName[0] = 0;
					DialogBox(g_hInstance, MAKEINTRESOURCE(1003), hDlg, PropertiesProcessManagerProc);
					g_ServiceName[0] = ServiceName[0];
					break;

				case 4023:
					StartStopService(hDlg);
					Sleep(200);
					GetServiceStatus(hDlg);
					break;

				case 4024:
					PauseContinueService(hDlg);
					GetServiceStatus(hDlg);
					break;

				case 4025:
					EnableDisableService(hDlg);
					GetServiceStatus(hDlg);
					break;

				case 4027:
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1002), hDlg, PrivilegeManagerProc, (LPARAM)0);
					break;

				case 4029:
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1005), hDlg, SystemAccessControlListProc, (LPARAM)SERVICE_MANAGER);
					break;

				case 4030:
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1005), hDlg, DiscretionaryAccessControlListProc, (LPARAM)SERVICE_MANAGER);
					break;
			}

			if (wParam == IDCANCEL) {
				g_ServiceName[0] = 0;
				EndDialog(hDlg, wParam);
           		return TRUE;
			}
		}
		break;
	}

	return EXIT_SUCCESS;
}


LRESULT CALLBACK SystemAccessControlListProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			SetDesktopComposition(hDlg);

			TCHAR Buffer[MAX_PATH] = { 0 };
			LoadString(g_hInstance, 10050, Buffer, MAX_PATH);
			SetWindowText(hDlg, Buffer);

			if (lParam == PROCESS_MANAGER) GetSystemACL(hDlg, PROCESS_MANAGER);
			if (lParam == PROCESS_TOKEN_MANAGER) GetSystemACL(hDlg, PROCESS_TOKEN_MANAGER);
			if (lParam == SERVICE_MANAGER) GetSystemACL(hDlg, SERVICE_MANAGER);
		}
		break;

		case WM_COMMAND:
		{
			//switch (wParam)
			//{
			//}

			if (wParam == IDCANCEL) {
				if (g_hProcess) {
					CloseHandle(g_hProcess);
					g_hProcess = nullptr;
				}
				EndDialog(hDlg, wParam);
				return TRUE;
			}
		}
		break;
	}

	return EXIT_SUCCESS;
}


LRESULT CALLBACK DiscretionaryAccessControlListProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			SetDesktopComposition(hDlg);

			TCHAR Buffer[MAX_PATH] = { 0 };
			LoadString(g_hInstance, 10051, Buffer, MAX_PATH);
			SetWindowText(hDlg, Buffer);

			if (lParam == PROCESS_MANAGER) GetDiscretionaryACL(hDlg, PROCESS_MANAGER);
			if (lParam == PROCESS_TOKEN_MANAGER) GetDiscretionaryACL(hDlg, PROCESS_TOKEN_MANAGER);
			if (lParam == SERVICE_MANAGER) GetDiscretionaryACL(hDlg, SERVICE_MANAGER);
		}
		break;

		/*
		case WM_NOTIFY:
		{
		    LPNMHDR pHdr = (LPNMHDR)lParam;
		    if(pHdr->hwndFrom == GetDlgItem(hDlg, 4001) && pHdr->code == NM_RCLICK)
		    {
		        HTREEITEM hItem = TreeView_GetNextItem(pHdr->hwndFrom, 0, TVGN_DROPHILITE);
		        if(hItem) {
					TreeView_SelectItem(pHdr->hwndFrom, hItem);
					MessageBox(0, L"test", L"test", 0);
				}
		    }
		}
		break;
		*/

		case WM_COMMAND:
		{
			if (wParam == IDCANCEL) {
				if (g_hProcess) {
					CloseHandle(g_hProcess);
					g_hProcess = nullptr;
				}
				EndDialog(hDlg, wParam);
				return TRUE;
			}
		}
		break;
	}

	return EXIT_SUCCESS;
}


LRESULT CALLBACK TokenGroupsProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			SetDesktopComposition(hDlg);

			GetTokenGroupsInfo(hDlg);
		}

		case WM_CONTEXTMENU:
		{
			LRESULT ListBoxIndex = SendMessage(GetDlgItem(hDlg, 4001), LB_GETCURSEL, 0, 0);
			if (LB_ERR != ListBoxIndex)
			{
				HMENU hMenu = CreatePopupMenu();
				InsertMenu(hMenu, 0, MF_BYCOMMAND | MF_STRING, 0, TEXT("Enable"));
				TrackPopupMenuEx(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_LEFTBUTTON, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), hDlg, nullptr);
				if (LB_ERR != ListBoxIndex)
					SetTokenGroupsInfo(hDlg);
			}
		}

		case WM_COMMAND:
		{
			if (wParam == IDCANCEL) {
				EndDialog(hDlg, wParam);
				return TRUE;
			}
		}
		break;
	}

	return EXIT_SUCCESS;
}
