#include "Defines.h"


LRESULT CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LONG_PTR i = 0;
	BOOL ContextMenuId = 0;
	TCHAR Buffer[MAX_PATH] = { 0 };

	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			SetDesktopComposition(hDlg);

			if (!IsUserAnAdmin()) {
				LoadString(g_hInstance, 10234, Buffer, MAX_PATH);
				MessageBox(hDlg, Buffer, MB_CAPTIONINFORMATION, MB_ICONINFORMATION);
			}

			GetSecurityDescInfo(hDlg);

        		g_hWndProcessList = GetDlgItem(hDlg, 4011);
        		g_hWndServiceList = GetDlgItem(hDlg, 4016);
			i = g_Idx;
			ListProcess(g_hWndProcessList);
			ListService(g_hWndServiceList);

			if (UI0DetectServiceExists())
				EnableWindow(GetDlgItem(hDlg, 4003), TRUE);
			else EnableWindow(GetDlgItem(hDlg, 4001), TRUE);

			if (IsUserAnSystem()) {
				EnableWindow(GetDlgItem(hDlg, 4005), FALSE);
				RestartApp(hDlg, wParam);
			}
		}
        break;

		case WM_COMMAND:
		{
			switch (wParam)
			{
				case 4001:
					if (CreateUI0DetectService(hDlg)) {
						EnableWindow(GetDlgItem(hDlg, 4001), FALSE);
						EnableWindow(GetDlgItem(hDlg, 4003), TRUE);
					}
					break;

				case 4002:
					SwitchToServicesSession(hDlg);
					break;

				case 4003:
					if (DeleteUI0DetectService(hDlg)) {
						EnableWindow(GetDlgItem(hDlg, 4001), TRUE);
						EnableWindow(GetDlgItem(hDlg, 4003), FALSE);
					}
					break;

				case 4004:
					CreateSystemProcess(hDlg);
					break;

				case 4005:
					SuperUserAsWinlogon(hDlg, wParam);
					break;

				case 4006:
					LocalSystemToken(hDlg, wParam);
					break;

				case 4012:
					g_hProcess = GetCurrentProcess();
					DialogBoxParam(g_hInstance, MAKEINTRESOURCE(1002), hDlg, PrivilegeManagerProc, (LPARAM)PRIVILEGE_MANAGER);
					break;

				case 4013:
					TrustedInstallerToken(hDlg, wParam);
					break;

				case 4017:
					DeleteLockFile(hDlg);
					break;

				case 4018:
					break;
			}

			if (HIWORD(wParam) == LBN_DBLCLK)
			{
				if (LOWORD(wParam) == 4011) {
					LRESULT ListBoxIndex = SendMessage(g_hWndProcessList, LB_GETCURSEL, 0, 0);
					while (1) {
						if (ListBoxIndex == i) {
							g_dwProcessId = g_IdxProcessId[i];
							DialogBox(g_hInstance, MAKEINTRESOURCE(1003), hDlg, PropertiesProcessManagerProc);
							break;
						}
						i++;
					}
				}
				
				if (LOWORD(wParam) == 4016) {
					LRESULT ListBoxIndex = SendMessage(g_hWndServiceList, LB_GETCURSEL, 0, 0);
					SendMessage(g_hWndServiceList, LB_GETTEXT, (WPARAM)ListBoxIndex, (LPARAM)g_ServiceName);
					DialogBox(g_hInstance, MAKEINTRESOURCE(1004), hDlg, PropertiesServiceManagerProc);
				}
			}

			if (wParam == IDCANCEL) {
				EndDialog(hDlg, wParam);
           		return TRUE;
			}
		}
		break;

		case WM_CONTEXTMENU:
		{
			if ((HWND)wParam == g_hWndProcessList)
			{
				HMENU hMenu = CreatePopupMenu();
				LoadString(g_hInstance, 10293, Buffer, MAX_PATH);
				InsertMenu(hMenu, 0, MF_BYCOMMAND | MF_STRING, 1, Buffer);
				LoadString(g_hInstance, 10291, Buffer, MAX_PATH);
				InsertMenu(hMenu, 0, MF_BYCOMMAND | MF_STRING, 2, Buffer);
            			ContextMenuId = TrackPopupMenuEx(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_LEFTBUTTON | TPM_RETURNCMD, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), hDlg, nullptr);
				switch (ContextMenuId)
				{
					case 1:
						LRESULT ListBoxIndex = SendMessage(g_hWndProcessList, LB_GETCURSEL, 0, 0);
						if (LB_ERR != ListBoxIndex) {
							while (1) {
								if (ListBoxIndex == i) {
									g_dwProcessId = g_IdxProcessId[i];
									DialogBox(g_hInstance, MAKEINTRESOURCE(1003), hDlg, PropertiesProcessManagerProc);
									break;
								}
								i++;
							}
						}
						break;

					case 2:
						SendMessage(g_hWndProcessList, LB_RESETCONTENT, 0, 0);
						ListProcess(g_hWndProcessList);
#pragma warn(disable:2802)
						g_IdxProcessId[1024] = 0;
						break;
				}
			}

			if ((HWND)wParam == g_hWndServiceList)
			{
				HMENU hMenu = CreatePopupMenu();
				LoadString(g_hInstance, 10293, Buffer, MAX_PATH);
				InsertMenu(hMenu, 0, MF_BYCOMMAND | MF_STRING, 1, Buffer);
				LoadString(g_hInstance, 10292, Buffer, MAX_PATH);
				InsertMenu(hMenu, 0, MF_BYCOMMAND | MF_STRING, 2, Buffer);
            			ContextMenuId = TrackPopupMenuEx(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_LEFTBUTTON | TPM_RETURNCMD, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), hDlg, nullptr);
				switch (ContextMenuId)
				{
					case 1:
						LRESULT ListBoxIndex = SendMessage(g_hWndServiceList, LB_GETCURSEL, 0, 0);
						if (LB_ERR != ListBoxIndex) {
							SendMessage(g_hWndServiceList, LB_GETTEXT, (WPARAM)ListBoxIndex, (LPARAM)g_ServiceName);
							DialogBox(g_hInstance, MAKEINTRESOURCE(1004), hDlg, PropertiesServiceManagerProc);
						}
						break;

					case 2:
						SendMessage(g_hWndServiceList, LB_RESETCONTENT, 0, 0);
						ListService(g_hWndServiceList);
						break;

					case 3:
						if (OpenClipboard(hDlg)) {
							EmptyClipboard();
							CloseClipboard();
						}
						break;
				}
			}
		}
		break;
	}

	return EXIT_SUCCESS;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PTCHAR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);

	g_hInstance = hInstance;

	DialogBox(hInstance, MAKEINTRESOURCE(1001), nullptr, DialogProc);

	return EXIT_SUCCESS;
}
