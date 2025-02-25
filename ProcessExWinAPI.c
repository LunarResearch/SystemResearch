#include "Defines.h"


BOOL ListProcess(HWND hWndProcessList)
{
	HANDLE hSnapshot = nullptr;
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		do {
			SendMessage(hWndProcessList, LB_ADDSTRING, 0, (LPARAM)ProcessEntry.szExeFile);
			g_IdxProcessId[g_Idx] = ProcessEntry.th32ProcessID;
			g_Idx++;
		} while (Process32Next(hSnapshot, &ProcessEntry));
	}
	CloseHandle(hSnapshot);

	return TRUE;
}


BOOL GetProcessBasicInfo(HWND hDlg)
{
	HANDLE hSnapshop = nullptr;
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 ThreadEntry = { sizeof(THREADENTRY32) };
	TCHAR Buffer[USHRT_MAX] = { 0 }, temp[MAX_PATH] = { 0 }, strBuffer[MAX_PATH] = { 0 };
	DWORD dwSessionId = 0, errCode = 0, dwRevision = 0;

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (ProcessEntry.th32ProcessID == g_dwProcessId) {
				SetWindowText(GetDlgItem(hDlg, 4019), ProcessEntry.szExeFile);
				swprintf(Buffer, MAX_PATH, TEXT("%u"), ProcessEntry.th32ProcessID);
				SetWindowText(GetDlgItem(hDlg, 4020), Buffer);
				if (!ProcessIdToSessionId(ProcessEntry.th32ProcessID, &dwSessionId)) {
					ErrPrint2(GetDlgItem(hDlg, 4021), TEXT(""));
					if (g_dwProcessId == 0)
						break;
					else
						CreateToolTip(hDlg, 4021, 10049, strBuffer);
					break;
				}
				swprintf(Buffer, MAX_PATH, TEXT("%u"), dwSessionId);
				SetWindowText(GetDlgItem(hDlg, 4021), Buffer);
                break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	CloseHandle(hSnapshop);

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (Thread32First(hSnapshop, &ThreadEntry)) {
		do {
			if (ThreadEntry.th32OwnerProcessID == g_dwProcessId) {
				g_dwThreadId = ThreadEntry.th32ThreadID;

				swprintf(Buffer, MAX_PATH, TEXT("%u"), ThreadEntry.th32ThreadID);
				SetWindowText(GetDlgItem(hDlg, 4027), Buffer);

				if (ThreadEntry.tpBasePri >= 0 && ThreadEntry.tpBasePri <= 4) {
					LoadString(g_hInstance, 10252, temp, MAX_PATH);
					swprintf(Buffer, MAX_PATH, temp, ThreadEntry.tpBasePri);
				}
				else if (ThreadEntry.tpBasePri >= 5 && ThreadEntry.tpBasePri <= 6) {
					LoadString(g_hInstance, 10253, temp, MAX_PATH);
					swprintf(Buffer, MAX_PATH, temp, ThreadEntry.tpBasePri);
				}
				else if (ThreadEntry.tpBasePri >= 7 && ThreadEntry.tpBasePri <= 8) {
					LoadString(g_hInstance, 10254, temp, MAX_PATH);
					swprintf(Buffer, MAX_PATH, temp, ThreadEntry.tpBasePri);
				}
				else if (ThreadEntry.tpBasePri >= 9 && ThreadEntry.tpBasePri <= 10) {
					LoadString(g_hInstance, 10255, temp, MAX_PATH);
					swprintf(Buffer, MAX_PATH, temp, ThreadEntry.tpBasePri);
				}
				else if (ThreadEntry.tpBasePri >= 11 && ThreadEntry.tpBasePri <= 23) {
					LoadString(g_hInstance, 10256, temp, MAX_PATH);
					swprintf(Buffer, MAX_PATH, temp, ThreadEntry.tpBasePri);
				}
				else if (ThreadEntry.tpBasePri >= 24 && ThreadEntry.tpBasePri <= 31) {
					LoadString(g_hInstance, 10257, temp, MAX_PATH);
					swprintf(Buffer, MAX_PATH, temp, ThreadEntry.tpBasePri);
				}
				SetWindowText(GetDlgItem(hDlg, 4030), Buffer);
				break;
			}
		} while (Thread32Next(hSnapshop, &ThreadEntry));
	}
	CloseHandle(hSnapshop);

	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
	PSID ppSidOwner = nullptr, ppSidGroup = nullptr;
	PACL ppDacl = { 0 }, ppSacl = { 0 };

	if (GetSecurityInfo(g_hProcess, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
		&ppSidOwner, &ppSidGroup, &ppDacl, &ppSacl, &pSecurityDescriptor) != ERROR_SUCCESS)
	{
		errCode = GetSecurityInfo(g_hProcess, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION, // | LABEL_SECURITY_INFORMATION // (need  READ_CONTROL in g_hProcess)
			nullptr, nullptr, nullptr, &ppSacl, &pSecurityDescriptor);

		if (ERROR_SUCCESS != errCode)
		{
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), strBuffer, MAX_PATH, nullptr);
			swprintf(Buffer, MAX_PATH, TEXT("<Error: %u> %ls"), errCode, strBuffer);
			swprintf(temp, MAX_PATH, TEXT("<Error: %u> %ls"), errCode, strBuffer);
			SetWindowText(GetDlgItem(hDlg, 4024), Buffer);
			SetWindowText(GetDlgItem(hDlg, 4031), temp);

			if (g_dwProcessId == 0)
				return FALSE;
			else {
				CreateToolTip(hDlg, 4024, 10046, strBuffer);
				CreateToolTip(hDlg, 4031, 10046, strBuffer);
			}
			return FALSE;
		}
	}

	if (IsValidAcl(ppSacl))
		EnableWindow(GetDlgItem(hDlg, 4025), TRUE);

	if (IsValidAcl(ppDacl))
		EnableWindow(GetDlgItem(hDlg, 4026), TRUE);

	PTCH pStringSecurityDescriptor = nullptr;

	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecurityDescriptor, SDDL_REVISION,
			OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
			&pStringSecurityDescriptor, nullptr)) {
		return FALSE;
	}

	if (IsValidSecurityDescriptor(pSecurityDescriptor))
		swprintf(Buffer, USHRT_MAX, TEXT("%ls"), pStringSecurityDescriptor);
	SetWindowText(GetDlgItem(hDlg, 4031), Buffer);

	SECURITY_DESCRIPTOR_CONTROL wControl = 0;

	if (!GetSecurityDescriptorControl(pSecurityDescriptor, &wControl, &dwRevision)) {
		LocalFree(pSecurityDescriptor);
		return FALSE;
	}
	LocalFree(pSecurityDescriptor);

	SecurityDescriptorControlFlagsBruteForce(GetDlgItem(hDlg, 4024), wControl);

	return TRUE;
}


BOOL GetTokenProcessInfo(HWND hDlg)
{
	HANDLE hProcess = nullptr, hToken = nullptr;
	TCHAR Buffer[USHRT_MAX] = { 0 }, temp[MAX_PATH] = { 0 }, strBuffer[MAX_PATH] = { 0 };
	DWORD dwMessageId = 0, ReturnLength = 0, errCode = 0, TOKEN_DESIRED_ACCESS = 0L;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return FALSE;

	if (IsProcessPrivilegeEnable(hToken, SE_SECURITY_NAME))
		TOKEN_DESIRED_ACCESS = ACCESS_SYSTEM_SECURITY | READ_CONTROL;
	CloseHandle(hToken);

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);

	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DESIRED_ACCESS, &hToken)) {
		dwMessageId = ErrPrint2(GetDlgItem(hDlg, 4010), TEXT(""));
		switch (g_dwProcessId)
		{
			case 0:
				break;

			default:
				if (dwMessageId == ERROR_ACCESS_DENIED)
					CreateToolTip(hDlg, 4010, 10047, strBuffer);
				else if (dwMessageId == ERROR_INVALID_HANDLE)
					CreateToolTip(hDlg, 4010, 10249, strBuffer);
				break;
		}
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	ShowWindow(GetDlgItem(hDlg, 4043), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4044), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4045), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4046), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4047), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4048), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4049), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4055), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4056), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4057), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4058), SW_SHOW);
	ShowWindow(GetDlgItem(hDlg, 4059), SW_SHOW);

	if (!GetTokenInformation(hToken, TokenAccessInformation, nullptr, 0, &ReturnLength)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseHandle(hToken);
			return FALSE;
		}
	}

	PTOKEN_ACCESS_INFORMATION pTokenAccessInfo = { 0 };
	pTokenAccessInfo = (PTOKEN_ACCESS_INFORMATION)_alloca(ReturnLength);

	if (!GetTokenInformation(hToken, TokenAccessInformation, pTokenAccessInfo, ReturnLength, &ReturnLength)) {
		CloseHandle(hToken);
		return FALSE;
	}

	switch (pTokenAccessInfo->AuthenticationId.LowPart)
	{
		case 0x3e3: // IUSER_LUID
			LoadString(g_hInstance, 10201, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4010), temp);
			break;

		case 0x3e4: // NETWORKSERVICE_LUID
			LoadString(g_hInstance, 10202, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4010), temp);
			break;

		case 0x3e5: // LOCALSERVICE_LUID
			LoadString(g_hInstance, 10203, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4010), temp);
			break;

		case 0x3e6: // ANONYMOUS_LOGON_LUID
			LoadString(g_hInstance, 10204, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4010), temp);
			break;

		case 0x3e7: // SYSTEM_LUID
			LoadString(g_hInstance, 10205, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4010), temp);
			break;

		default:
			swprintf(Buffer, MAX_PATH, TEXT("0x%X"), pTokenAccessInfo->AuthenticationId.LowPart);
			SetWindowText(GetDlgItem(hDlg, 4010), Buffer);
			break;
	}

	switch (pTokenAccessInfo->TokenType)
	{
		case TokenPrimary:
			LoadString(g_hInstance, 10206, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4011), temp);
			break;

		case TokenImpersonation:
			LoadString(g_hInstance, 10207, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4011), temp);
			break;
	}

	switch (pTokenAccessInfo->ImpersonationLevel)
	{
		case SecurityAnonymous:
			LoadString(g_hInstance, 10208, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4012), temp);
			break;

		case SecurityIdentification:
			LoadString(g_hInstance, 10209, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4012), temp);
			break;

		case SecurityImpersonation:
			LoadString(g_hInstance, 10210, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4012), temp);
			break;

		case SecurityDelegation:
			LoadString(g_hInstance, 10211, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4012), temp);
			break;
	}

	swprintf(Buffer, MAX_PATH, TEXT("0x%X"), pTokenAccessInfo->Flags);
	SetWindowText(GetDlgItem(hDlg, 4013), Buffer);

	switch (pTokenAccessInfo->MandatoryPolicy.Policy)
	{
		case TOKEN_MANDATORY_POLICY_OFF:
			LoadString(g_hInstance, 10212, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4018), temp);
			CreateToolTip(hDlg, 4018, 10040, strBuffer);
			break;

		case TOKEN_MANDATORY_POLICY_NO_WRITE_UP:
			LoadString(g_hInstance, 10213, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4018), temp);
			CreateToolTip(hDlg, 4018, 10041, strBuffer);
			break;

		case TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN:
			LoadString(g_hInstance, 10214, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4018), temp);
			CreateToolTip(hDlg, 4018, 10042, strBuffer);
			break;

		case TOKEN_MANDATORY_POLICY_VALID_MASK:
			LoadString(g_hInstance, 10215, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4018), temp);
			CreateToolTip(hDlg, 4018, 10043, strBuffer);
			break;
	}

	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
	PSID ppSidOwner = nullptr, ppSidGroup = nullptr;
	PACL ppDacl = { 0 }, ppSacl = { 0 };

	if (GetSecurityInfo(hToken, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
		&ppSidOwner, &ppSidGroup, &ppDacl, &ppSacl, &pSecurityDescriptor) != ERROR_SUCCESS)
	{
		errCode = GetSecurityInfo(hToken, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &ppSacl, &pSecurityDescriptor);

		if (ERROR_SUCCESS != errCode)
		{
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), strBuffer, MAX_PATH, nullptr);
			swprintf(Buffer, MAX_PATH, TEXT("<Error: %u> %ls"), errCode, strBuffer);
			SetWindowText(GetDlgItem(hDlg, 4032), Buffer);

			if (g_dwProcessId == 0)
				return FALSE;
			else CreateToolTip(hDlg, 4032, 10049, strBuffer);
		}
	}

	if (IsValidAcl(ppSacl))
		EnableWindow(GetDlgItem(hDlg, 4033), TRUE);

	if (IsValidAcl(ppDacl))
		EnableWindow(GetDlgItem(hDlg, 4034), TRUE);

	PTCH pStringSecurityDescriptor = nullptr;

	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecurityDescriptor, SDDL_REVISION,
			OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
			&pStringSecurityDescriptor, nullptr)) {
		return FALSE;
	}

	if (IsValidSecurityDescriptor(pSecurityDescriptor))
		swprintf(Buffer, USHRT_MAX, TEXT("%ls"), pStringSecurityDescriptor);
	SetWindowText(GetDlgItem(hDlg, 4032), Buffer);

	LocalFree(pSecurityDescriptor);

	if (GetBuildOSNumber() <= 7601) {
		LoadString(g_hInstance, 10221, temp, MAX_PATH);
		SetWindowText(GetDlgItem(hDlg, 4022), temp);
	}
	else {
		switch (pTokenAccessInfo->CapabilitiesHash->SidAttr->Attributes)
		{
			case 0x2:
			case 0x4:
			case 0x200:
			case 0x400:
				swprintf(Buffer, MAX_PATH, TEXT("0x%X"), pTokenAccessInfo->CapabilitiesHash->SidAttr->Attributes);
				SetWindowText(GetDlgItem(hDlg, 4022), Buffer);
				CreateToolTip(hDlg, 4022, 10044, strBuffer);
				break;

			default:
				LoadString(g_hInstance, 10221, temp, MAX_PATH);
				SetWindowText(GetDlgItem(hDlg, 4022), temp);
				break;
		}
	}

	PTCH StringTrustLevelSid = nullptr;
	StringTrustLevelSid = TEXT("");

	ConvertSidToStringSidW(pTokenAccessInfo->TrustLevelSid, &StringTrustLevelSid);

	if (wcscmp(StringTrustLevelSid, TEXT("")) == 0) {
		LoadString(g_hInstance, 10221, temp, MAX_PATH);
		SetWindowText(GetDlgItem(hDlg, 4014), temp);
		SetWindowText(GetDlgItem(hDlg, 4015), temp);
		SetWindowText(GetDlgItem(hDlg, 4016), temp);
		SetWindowText(GetDlgItem(hDlg, 4017), temp);
	}

	else
	{
		SetWindowText(GetDlgItem(hDlg, 4014), StringTrustLevelSid);
		LoadString(g_hInstance, 10233, temp, MAX_PATH);
		SetWindowText(GetDlgItem(hDlg, 4015), temp);

		if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-512-1024")) == 0) {
			LoadString(g_hInstance, 10222, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10223, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-512-1536")) == 0) {
			LoadString(g_hInstance, 10222, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10225, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-512-2048")) == 0) {
			LoadString(g_hInstance, 10222, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10230, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-512-4096")) == 0) {
			LoadString(g_hInstance, 10222, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10227, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-512-8192")) == 0) {
			LoadString(g_hInstance, 10222, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10228, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-1024-1024")) == 0) {
			LoadString(g_hInstance, 10219, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10223, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-1024-1536")) == 0) {
			LoadString(g_hInstance, 10219, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10225, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-1024-2048")) == 0) {
			LoadString(g_hInstance, 10219, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10230, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-1024-4096")) == 0) {
			LoadString(g_hInstance, 10219, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10227, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}

		else if (wcscmp(StringTrustLevelSid, TEXT("S-1-19-1024-8192")) == 0) {
			LoadString(g_hInstance, 10219, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4016), temp);
			LoadString(g_hInstance, 10228, temp, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4017), temp);
		}
	}

	TOKEN_ELEVATION TokenElevated = { 0 };

	if (!GetTokenInformation(hToken, TokenElevation, &TokenElevated, sizeof(TOKEN_ELEVATION), &ReturnLength)) {
		CloseHandle(hToken);
		return FALSE;
	}

	TOKEN_ELEVATION_TYPE TokenElevatedType;

	if (!GetTokenInformation(hToken, TokenElevationType, &TokenElevatedType, sizeof(TOKEN_ELEVATION_TYPE), &ReturnLength)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);

	switch (TokenElevated.TokenIsElevated)
	{
		case 0:
			switch (TokenElevatedType)
			{
				case TokenElevationTypeDefault:
					LoadString(g_hInstance, 10216, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4028), temp);
					LoadString(g_hInstance, 10218, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4029), temp);
					break;

				case TokenElevationTypeFull:
					LoadString(g_hInstance, 10216, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4028), temp);
					LoadString(g_hInstance, 10219, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4029), temp);
					break;

				case TokenElevationTypeLimited:
					LoadString(g_hInstance, 10216, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4028), temp);
					LoadString(g_hInstance, 10220, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4029), temp);
					break;
			}
			break;

		default:
			switch (TokenElevatedType)
			{
				case TokenElevationTypeDefault:
					LoadString(g_hInstance, 10217, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4028), temp);
					LoadString(g_hInstance, 10218, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4029), temp);
					break;

				case TokenElevationTypeFull:
					LoadString(g_hInstance, 10217, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4028), temp);
					LoadString(g_hInstance, 10219, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4029), temp);
					break;

				case TokenElevationTypeLimited:
					LoadString(g_hInstance, 10217, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4028), temp);
					LoadString(g_hInstance, 10220, temp, MAX_PATH);
					SetWindowText(GetDlgItem(hDlg, 4029), temp);
					break;
			}
			break;
	}

	return TRUE;
}


BOOL IsSecureProcess(HWND hDlg)
{
	HMODULE hModule = nullptr;

	hModule = GetModuleHandle(TEXT("ntdll"));

	if (hModule)
		NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

	NTSTATUS Status = 0;
	PROCESS_EXTENDED_BASIC_INFORMATION ProcExBasicInfo = { sizeof(PROCESS_EXTENDED_BASIC_INFORMATION) };

	Status = NtQueryInformationProcess(g_hProcess, ProcessBasicInformation, &ProcExBasicInfo, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), nullptr);

	BOOLEAN IsSecureProcess = 0, IsProtectedProcess = 0;
	TCHAR srtBuffer[MAX_PATH] = { 0 }, Buffer[MAX_PATH] = { 0 };

	if (NT_SUCCESS(Status))
		IsSecureProcess = (BOOLEAN)(ProcExBasicInfo.IsSecureProcess != 0);

	switch (IsSecureProcess)
	{
		case FALSE:
			LoadString(g_hInstance, 10216, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4002), Buffer);
			LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4003), Buffer);
			//CreateToolTip(hDlg, 4003, 10232, srtBuffer); // VTL0
			break;

		case TRUE:
			LoadString(g_hInstance, 10217, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4002), Buffer);
			LoadString(g_hInstance, 10231, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4003), Buffer);
			CreateToolTip(hDlg, 4003, 10045, srtBuffer);
			break;
	}

	if (NT_SUCCESS(Status))
		IsProtectedProcess = (BOOLEAN)(ProcExBasicInfo.IsProtectedProcess != 0);

	switch (IsProtectedProcess)
	{
		case FALSE:
			LoadString(g_hInstance, 10216, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4004), Buffer);
			break;

		case TRUE:
			LoadString(g_hInstance, 10217, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4004), Buffer);
			break;
	}

	return TRUE;
}


BOOL IsProtectedProcess(HWND hDlg)
{
	HMODULE hModule = nullptr;

	hModule = GetModuleHandle(TEXT("ntdll"));

	if (hModule)
		NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

	NTSTATUS Status = 0;
	PS_PROTECTION ProcessProtectionInfo = { 0 };

	Status = NtQueryInformationProcess(g_hProcess, ProcessProtectionInformation, &ProcessProtectionInfo, sizeof(PS_PROTECTION), nullptr);

	TCHAR Buffer[MAX_PATH] = { 0 };

	switch (ProcessProtectionInfo.Type)
	{
		case PsProtectedTypeNone:
			LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4005), Buffer);
			break;

		case PsProtectedTypeProtectedLight:
			LoadString(g_hInstance, 10222, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4005), Buffer);
			break;

		case PsProtectedTypeProtected:
			LoadString(g_hInstance, 10219, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4005), Buffer);
			break;
	}

	switch (ProcessProtectionInfo.Signer)
	{
		case PsProtectedSignerNone:
			LoadString(g_hInstance, 10221, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerAuthenticode:
			LoadString(g_hInstance, 10223, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerCodeGen:
			LoadString(g_hInstance, 10224, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerAntimalware:
			LoadString(g_hInstance, 10225, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerLsa:
			LoadString(g_hInstance, 10226, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerWindows:
			LoadString(g_hInstance, 10227, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerWinTcb:
			LoadString(g_hInstance, 10228, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerWinSystem:
			LoadString(g_hInstance, 10229, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;

		case PsProtectedSignerApp:
			LoadString(g_hInstance, 10230, Buffer, MAX_PATH);
			SetWindowText(GetDlgItem(hDlg, 4006), Buffer);
			break;
	}

	return TRUE;
}


BOOL GetTokenIntegrityLevelInfo(HWND hDlg)
{
	HANDLE hProcess = nullptr, hToken = nullptr;

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	DWORD ReturnLength = 0, dwIntegrityLevel = 0;

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &ReturnLength)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseHandle(hToken);
			return FALSE;
		}
	}

	PTOKEN_MANDATORY_LABEL pTokenMandatoryLabel = { 0 };
	pTokenMandatoryLabel = (PTOKEN_MANDATORY_LABEL)_alloca(ReturnLength);

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenMandatoryLabel, ReturnLength, &ReturnLength)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);

	dwIntegrityLevel = *GetSidSubAuthority(pTokenMandatoryLabel->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTokenMandatoryLabel->Label.Sid) - 1));

	switch (dwIntegrityLevel)
	{
		case SECURITY_MANDATORY_UNTRUSTED_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4068);
			break;

		case SECURITY_MANDATORY_LOW_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4067);
			break;

		case SECURITY_MANDATORY_MEDIUM_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4066);
			break;

		case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4065);
			break;

		case SECURITY_MANDATORY_HIGH_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4064);
			break;

		case SECURITY_MANDATORY_SYSTEM_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4063);
			break;

		case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4062);
			break;

		case SECURITY_MANDATORY_SECURE_PROCESS_RID:
			CheckRadioButton(hDlg, 4061, 4068, 4061);
			break;

		default:
			break;
	}

	return TRUE;
}


BOOL SetTokenIntegrityLevelInfo(DWORD SubAuthority)
{
	HANDLE hProcess = nullptr, hToken = nullptr;

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	/*
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, g_dwThreadId);

	if (!SetThreadToken(&hThread, hToken)) {
		CloseHandle(hThread);
		return FALSE;
	}

	if (!OpenThreadToken(hThread, TOKEN_ALL_ACCESS, FALSE, &hToken)) {
		// ERROR_NO_TOKEN - Threads only have their own tokens if you are using the impersonation APIs, otherwise there is only a process token.
		// Потоки имеют собственные токены только в том случае, если вы используете API олицетворения, в противном случае есть только токен процесса.
		CloseHandle(hThread);
		return FALSE;
	}
	CloseHandle(hThread);
	*/

	TOKEN_MANDATORY_LABEL TokenMandatoryLabel = { 0 };
	TokenMandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;

	static SID_IDENTIFIER_AUTHORITY SidAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;

	if (!AllocateAndInitializeSid(&SidAuthority, 1, SubAuthority, 0, 0, 0, 0, 0, 0, 0, &TokenMandatoryLabel.Label.Sid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!SetTokenInformation(hToken, TokenIntegrityLevel, &TokenMandatoryLabel, sizeof(TOKEN_MANDATORY_LABEL))) {
		FreeSid(TokenMandatoryLabel.Label.Sid);
		CloseHandle(hToken);
		return FALSE;
	}
	FreeSid(TokenMandatoryLabel.Label.Sid);
	CloseHandle(hToken);

	return TRUE;
}


BOOL GetTokenGroupsInfo(HWND hDlg)
{
	HANDLE hProcess = nullptr, hToken = nullptr;

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	DWORD ReturnLength = 0;

	if (!GetTokenInformation(hToken, TokenGroups, nullptr, 0, &ReturnLength)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseHandle(hToken);
			return FALSE;
		}
	}

	PTOKEN_GROUPS pTokenGroups = { 0 };
	pTokenGroups = (PTOKEN_GROUPS)_alloca(ReturnLength);

	if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, ReturnLength, &ReturnLength)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);

	PTCH StringSid = nullptr;

	for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
		ConvertSidToStringSidW(pTokenGroups->Groups[i].Sid, &StringSid);
		SendMessage(GetDlgItem(hDlg, 4001), LB_ADDSTRING, 0, (LPARAM)StringSid);
	}

	return TRUE;
}


BOOL SetTokenGroupsInfo(HWND hDlg)
{
	HANDLE hProcess = nullptr, hToken = nullptr;

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);

	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_GROUPS, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);

	DWORD ReturnLength = 0;

	if (!GetTokenInformation(hToken, TokenGroups, nullptr, 0, &ReturnLength)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseHandle(hToken);
			return FALSE;
		}
	}

	PTOKEN_GROUPS pTokenGroups = { 0 };
	pTokenGroups = (PTOKEN_GROUPS)_alloca(ReturnLength);

	if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, ReturnLength, &ReturnLength)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenGroups(hToken, FALSE, nullptr, 0, nullptr, &ReturnLength)) {
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseHandle(hToken);
			return FALSE;
		}
	}

	pTokenGroups = (PTOKEN_GROUPS)_alloca(ReturnLength);

	for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
		pTokenGroups->Groups[i].Attributes = SE_GROUP_ENABLED;
		if (!AdjustTokenGroups(hToken, FALSE, pTokenGroups, ReturnLength, nullptr, &ReturnLength)) {
			CloseHandle(hToken);
			return FALSE;
		}
	}
	CloseHandle(hToken);

	return TRUE;
}
