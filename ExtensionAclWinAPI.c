#include "Defines.h"


VOID AclAccessProtectedBruteForce(HWND hDlg, BOOL IsSacl, DWORD ListFlags, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, temp[MAX_PATH] = { 0 };

	switch (ListFlags)
	{
		case ACTRL_ACCESS_PROTECTED:
			LoadString(g_hInstance, 10185, temp, MAX_PATH);
			break;

		default:
			return;
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL PropertyAccessFlags: %ls"), temp);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL PropertyAccessFlags: %ls"), temp);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


HTREEITEM AclSizeBruteForce(HWND hDlg, BOOL IsSacl, WORD AclSize, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 };

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL Size: %u bytes"), AclSize);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL Size: %u bytes"), AclSize);
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return hTreeViewItem;
}


VOID AclBruteForce(HWND hDlg, PACL pAcl, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 };
	ACL_SIZE_INFORMATION AclSizeInfo = { 0 };

	if (!GetAclInformation(pAcl, &AclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
		return;

	swprintf(Buffer, MAX_PATH, TEXT("Space used: %u bytes"), AclSizeInfo.AclBytesInUse);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	swprintf(Buffer, MAX_PATH, TEXT("Space free: %u bytes"), AclSizeInfo.AclBytesFree);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


HTREEITEM AclExBruteForce(HWND hDlg, BOOL IsSacl, BYTE AclRevision, BYTE Sbz1, WORD Sbz2, WORD AceCount, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 };

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL Revision: %u"), AclRevision);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL Revision: %u"), AclRevision);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL Sbz1: %u"), Sbz1);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL Sbz1: %u"), Sbz1);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL Sbz2: %u"), Sbz2);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL Sbz2: %u"), Sbz2);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL AceCount: %u"), AceCount);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL AceCount: %u"), AceCount);
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return hTreeViewItem;
}


HTREEITEM PropertyAcl(HWND hDlg, BOOL IsSacl, WORD i, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 };

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("Property SACL::ACE[%u]"), i);
	else
		swprintf(Buffer, MAX_PATH, TEXT("Property DACL::ACE[%u]"), i);
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);
	SendMessage(GetDlgItem(hDlg, 4001), TVM_ENSUREVISIBLE, 0, (LPARAM)hTreeViewItem);

	return hTreeViewItem;
}


PTCH MandatoryLabelBruteForce(BOOL IsDomainName)
{
	HANDLE hProcess = nullptr, hToken = nullptr;

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		CloseHandle(hProcess);
		return nullptr;
	}
	CloseHandle(hProcess);

	DWORD ReturnLength = 0, cchSidName = 0, cchDomainName = 0;

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &ReturnLength))
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
			CloseHandle(hToken);
			return nullptr;
	}

	PTOKEN_MANDATORY_LABEL pTokenMandatoryLabel = { 0 };
	pTokenMandatoryLabel = (PTOKEN_MANDATORY_LABEL)_alloca(ReturnLength);

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenMandatoryLabel, ReturnLength, &ReturnLength)) {
		CloseHandle(hToken);
		return nullptr;
	}
	CloseHandle(hToken);

	if (!IsValidSid(pTokenMandatoryLabel->Label.Sid))
		return nullptr;

	PTCH Buffer = nullptr, SidName = nullptr, DomainName = nullptr;
	SID_NAME_USE peUse;

	LookupAccountSid(nullptr, pTokenMandatoryLabel->Label.Sid, nullptr, &cchSidName, nullptr, &cchDomainName, nullptr);
	if(ERROR_INSUFFICIENT_BUFFER != GetLastError())
		return nullptr;

	SidName = (PTCH)LocalAlloc(LPTR, MAX_PATH * sizeof(TCHAR));
	DomainName = (PTCH)LocalAlloc(LPTR, MAX_PATH * sizeof(TCHAR));

	LookupAccountSid(nullptr, pTokenMandatoryLabel->Label.Sid, SidName, &cchSidName, DomainName, &cchDomainName, &peUse);

	if (IsDomainName)
		Buffer = DomainName;
	else
		Buffer = SidName;

	return Buffer;
}


VOID MandatoryLabelPolicyBruteForce(HWND hDlg, DWORD Mask, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, Buffer1[MAX_PATH] = { 0 };

	switch (Mask)
	{
		case SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: // (SDDL = NW)
			LoadString(g_hInstance, 10213, Buffer1, MAX_PATH);
			break;

		case SYSTEM_MANDATORY_LABEL_NO_READ_UP: // (SDDL = NR)
			LoadString(g_hInstance, 10037, Buffer1, MAX_PATH);
			break;

		case SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP:
			LoadString(g_hInstance, 10038, Buffer1, MAX_PATH);
			break;

		case SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: // (SDDL = NE)
			LoadString(g_hInstance, 10039, Buffer1, MAX_PATH);
			break;

		case SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP:
			LoadString(g_hInstance, 10289, Buffer1, MAX_PATH);
			break;

		case SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP:
			LoadString(g_hInstance, 10290, Buffer1, MAX_PATH);
			break;

		case SYSTEM_MANDATORY_LABEL_VALID_MASK:
			LoadString(g_hInstance, 10048, Buffer1, MAX_PATH);
			break;
	}

	swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Policy: %ls"), i, Buffer1);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


VOID AceSizeBruteForce(HWND hDlg, BOOL IsSacl, WORD AceSize, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 };

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Size: %u bytes"), i, AceSize);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Size: %u bytes"), i, AceSize);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


VOID AceTypeBruteForce(HWND hDlg, BOOL IsSacl, BYTE AceType, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, temp[MAX_PATH] = { 0 };

	switch (AceType)
	{
		case ACCESS_ALLOWED_ACE_TYPE:
			LoadString(g_hInstance, 10052, temp, MAX_PATH);
			break;

		case ACCESS_DENIED_ACE_TYPE:
			LoadString(g_hInstance, 10053, temp, MAX_PATH);
			break;

		case SYSTEM_AUDIT_ACE_TYPE:
			LoadString(g_hInstance, 10054, temp, MAX_PATH);
			break;

		case SYSTEM_ALARM_ACE_TYPE:
			LoadString(g_hInstance, 10055, temp, MAX_PATH);
			break;

		case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
			LoadString(g_hInstance, 10056, temp, MAX_PATH);
			break;

		case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10057, temp, MAX_PATH);
			break;

		case ACCESS_DENIED_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10058, temp, MAX_PATH);
			break;

		case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10059, temp, MAX_PATH);
			break;

		case SYSTEM_ALARM_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10060, temp, MAX_PATH);
			break;

		case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
			LoadString(g_hInstance, 10061, temp, MAX_PATH);
			break;

		case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			LoadString(g_hInstance, 10062, temp, MAX_PATH);
			break;

		case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10063, temp, MAX_PATH);
			break;

		case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10064, temp, MAX_PATH);
			break;

		case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
			LoadString(g_hInstance, 10065, temp, MAX_PATH);
			break;

		case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
			LoadString(g_hInstance, 10066, temp, MAX_PATH);
			break;

		case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10067, temp, MAX_PATH);
			break;

		case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
			LoadString(g_hInstance, 10068, temp, MAX_PATH);
			break;

		case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
			LoadString(g_hInstance, 10069, temp, MAX_PATH);
			break;

		case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
			LoadString(g_hInstance, 10070, temp, MAX_PATH);
			break;

		case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
			LoadString(g_hInstance, 10071, temp, MAX_PATH);
			break;

		case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
			LoadString(g_hInstance, 10072, temp, MAX_PATH);
			break;
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Type: %ls"), i, temp);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Type: %ls"), i, temp);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


VOID AceAccessMaskBruteForce(HWND hDlg, BOOL IsSacl, DWORD AccessMaske, WORD i, TVINSERTSTRUCT TreeView, DWORD Manager)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, Buffer1[MAX_PATH] = { 0 }, Buffer2[MAX_PATH] = { 0 }, Buffer3[MAX_PATH] = { 0 }, Buffer4[MAX_PATH] = { 0 },
		Buffer5[MAX_PATH] = { 0 }, Buffer6[MAX_PATH] = { 0 }, Buffer7[MAX_PATH] = { 0 }, Buffer8[MAX_PATH] = { 0 }, Buffer9[MAX_PATH] = { 0 },
		Buffer10[MAX_PATH] = { 0 }, Buffer11[MAX_PATH] = { 0 }, Buffer12[MAX_PATH] = { 0 }, Buffer13[MAX_PATH] = { 0 }, Buffer14[MAX_PATH] = { 0 },
		Buffer15[MAX_PATH] = { 0 }, Buffer16[MAX_PATH] = { 0 }, Buffer17[MAX_PATH] = { 0 }, Buffer18[MAX_PATH] = { 0 }, Buffer19[MAX_PATH] = { 0 };
	BOOL IsAccess = FALSE, IsStandardAccess = FALSE;

	if (AccessMaske == 0x0)
		swprintf(Buffer1, MAX_PATH, TEXT("0   "));

	else
	{
		if (Manager == PROCESS_MANAGER)
		{
			if (AccessMaske & PROCESS_TERMINATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10073, Buffer1, MAX_PATH);
			}

			if (AccessMaske & PROCESS_CREATE_THREAD) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10074, Buffer2, MAX_PATH);
			}

			if (AccessMaske & PROCESS_SET_SESSIONID) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10075, Buffer3, MAX_PATH);
			}

			if (AccessMaske & PROCESS_VM_OPERATION) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10076, Buffer4, MAX_PATH);
			}

			if (AccessMaske & PROCESS_VM_READ) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10077, Buffer5, MAX_PATH);
			}

			if (AccessMaske & PROCESS_VM_WRITE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10078, Buffer6, MAX_PATH);
			}

			if (AccessMaske & PROCESS_DUP_HANDLE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10079, Buffer7, MAX_PATH);
			}

			if (AccessMaske & PROCESS_CREATE_PROCESS) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10080, Buffer8, MAX_PATH);
			}

			if (AccessMaske & PROCESS_SET_QUOTA) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10081, Buffer9, MAX_PATH);
			}

			if (AccessMaske & PROCESS_SET_INFORMATION) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10082, Buffer10, MAX_PATH);
			}

			if (AccessMaske & PROCESS_QUERY_INFORMATION) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10083, Buffer11, MAX_PATH);
			}

			if (AccessMaske & PROCESS_SUSPEND_RESUME) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10084, Buffer12, MAX_PATH);
			}

			if (AccessMaske & PROCESS_QUERY_LIMITED_INFORMATION) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10085, Buffer13, MAX_PATH);
			}

			if (AccessMaske & PROCESS_SET_LIMITED_INFORMATION) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10086, Buffer14, MAX_PATH);
			}
		}

		if (Manager == PROCESS_TOKEN_MANAGER)
		{
			if (AccessMaske & TOKEN_ASSIGN_PRIMARY) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10087, Buffer1, MAX_PATH);
			}

			if (AccessMaske & TOKEN_DUPLICATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10088, Buffer2, MAX_PATH);
			}

			if (AccessMaske & TOKEN_IMPERSONATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10089, Buffer3, MAX_PATH);
			}

			if (AccessMaske & TOKEN_QUERY) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10090, Buffer4, MAX_PATH);
			}

			if (AccessMaske & TOKEN_QUERY_SOURCE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10091, Buffer5, MAX_PATH);
			}

			if (AccessMaske & TOKEN_ADJUST_PRIVILEGES) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10092, Buffer6, MAX_PATH);
			}

			if (AccessMaske & TOKEN_ADJUST_GROUPS) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10093, Buffer7, MAX_PATH);
			}

			if (AccessMaske & TOKEN_ADJUST_DEFAULT) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10094, Buffer8, MAX_PATH);
			}

			if (AccessMaske & TOKEN_ADJUST_SESSIONID) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10095, Buffer9, MAX_PATH);
			}
		}

		if (Manager == SERVICE_MANAGER)
		{
			if (AccessMaske & SERVICE_QUERY_CONFIG) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10096, Buffer1, MAX_PATH);
			}

			if (AccessMaske & SERVICE_CHANGE_CONFIG) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10097, Buffer2, MAX_PATH);
			}

			if (AccessMaske & SERVICE_QUERY_STATUS) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10098, Buffer3, MAX_PATH);
			}

			if (AccessMaske & SERVICE_ENUMERATE_DEPENDENTS) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10099, Buffer4, MAX_PATH);
			}

			if (AccessMaske & SERVICE_START) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10100, Buffer5, MAX_PATH);
			}

			if (AccessMaske & SERVICE_STOP) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10101, Buffer6, MAX_PATH);
			}

			if (AccessMaske & SERVICE_PAUSE_CONTINUE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10102, Buffer7, MAX_PATH);
			}

			if (AccessMaske & SERVICE_INTERROGATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10103, Buffer8, MAX_PATH);
			}

			if (AccessMaske & SERVICE_USER_DEFINED_CONTROL) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10104, Buffer9, MAX_PATH);
			}
		}

		if (AccessMaske & DELETE) {
			IsStandardAccess = TRUE;
			LoadString(g_hInstance, 10105, Buffer15, MAX_PATH);
		}

		if (AccessMaske & READ_CONTROL) {
			IsStandardAccess = TRUE;
			LoadString(g_hInstance, 10106, Buffer16, MAX_PATH);
		}

		if (AccessMaske & WRITE_DAC) {
			IsStandardAccess = TRUE;
			LoadString(g_hInstance, 10107, Buffer17, MAX_PATH);
		}

		if (AccessMaske & WRITE_OWNER) {
			IsStandardAccess = TRUE;
			LoadString(g_hInstance, 10108, Buffer18, MAX_PATH);
		}

		if (AccessMaske & SYNCHRONIZE) {
			IsStandardAccess = TRUE;
			LoadString(g_hInstance, 10109, Buffer19, MAX_PATH);
		}
	}

	if (IsStandardAccess) {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].StandardAccess: %ls%ls%ls%ls%ls"), i,
				Buffer15, Buffer16, Buffer17, Buffer18, Buffer19);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].StandardAccess: %ls%ls%ls%ls%ls"), i,
				Buffer15, Buffer16, Buffer17, Buffer18, Buffer19);
	}
	else {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].StandardAccess: 0   "), i);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].StandardAccess: 0   "), i);
	}
	Buffer[wcslen(Buffer) - 3] = 0;
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	if (IsAccess) {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Access: %ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls"), i,
				Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7, Buffer8, Buffer9, Buffer10, Buffer11, Buffer12, Buffer13, Buffer14);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Access: %ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls"), i,
				Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7, Buffer8, Buffer9, Buffer10, Buffer11, Buffer12, Buffer13, Buffer14);
	}
	else {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Access: 0   "), i);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Access: 0   "), i);
	}
	Buffer[wcslen(Buffer) - 3] = 0;
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


HTREEITEM AceFlagsBruteForce(HWND hDlg, BOOL IsSacl, BYTE AceFlags, WORD i, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 }, Buffer1[MAX_PATH] = { 0 }, Buffer2[MAX_PATH] = { 0 }, Buffer3[MAX_PATH] = { 0 },
		Buffer4[MAX_PATH] = { 0 }, Buffer5[MAX_PATH] = { 0 }, Buffer6[MAX_PATH] = { 0 }, Buffer7[MAX_PATH] = { 0 };

	if (AceFlags == 0x0)
		swprintf(Buffer1, MAX_PATH, TEXT("0   "));

	else {
		if (AceFlags & OBJECT_INHERIT_ACE)
			LoadString(g_hInstance, 10110, Buffer1, MAX_PATH);

		if (AceFlags & CONTAINER_INHERIT_ACE)
			LoadString(g_hInstance, 10111, Buffer2, MAX_PATH);

		if (AceFlags & NO_PROPAGATE_INHERIT_ACE)
			LoadString(g_hInstance, 10112, Buffer3, MAX_PATH);

		if (AceFlags & INHERIT_ONLY_ACE)
			LoadString(g_hInstance, 10113, Buffer4, MAX_PATH);

		if (AceFlags & INHERITED_ACE)
			LoadString(g_hInstance, 10114, Buffer5, MAX_PATH);

		if (AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG)
			LoadString(g_hInstance, 10115, Buffer6, MAX_PATH);

		if (AceFlags & FAILED_ACCESS_ACE_FLAG)
			LoadString(g_hInstance, 10116, Buffer7, MAX_PATH);
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Flags: %ls%ls%ls%ls%ls%ls%ls"), i,
			Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Flags: %ls%ls%ls%ls%ls%ls%ls"), i,
			Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7);
	Buffer[wcslen(Buffer) - 3] = 0;
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return hTreeViewItem;
}


VOID AceInheritanceBruteForce(HWND hDlg, BOOL IsSacl, DWORD Inheritance, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, Buffer1[MAX_PATH] = { 0 }, Buffer2[MAX_PATH] = { 0 }, Buffer3[MAX_PATH] = { 0 }, Buffer4[MAX_PATH] = { 0 };

	if (Inheritance == 0x0)
		LoadString(g_hInstance, 10117, Buffer1, MAX_PATH);

	else {
		if (Inheritance & SUB_OBJECTS_ONLY_INHERIT)
			LoadString(g_hInstance, 10118, Buffer1, MAX_PATH);

		if (Inheritance & SUB_CONTAINERS_ONLY_INHERIT)
			LoadString(g_hInstance, 10119, Buffer2, MAX_PATH);

		if (Inheritance & NO_PROPAGATE_INHERIT_ACE)
			LoadString(g_hInstance, 10120, Buffer3, MAX_PATH);

		if (Inheritance & INHERIT_ONLY_ACE)
			LoadString(g_hInstance, 10121, Buffer4, MAX_PATH);
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Inheritance: %ls%ls%ls%ls"), i,
			Buffer1, Buffer2, Buffer3, Buffer4);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Inheritance: %ls%ls%ls%ls"), i,
			Buffer1, Buffer2, Buffer3, Buffer4);
	Buffer[wcslen(Buffer) - 3] = 0;
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


HTREEITEM AceSidBruteForce(HWND hDlg, BOOL IsSacl, PSID Sid, WORD i, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	PTCH SID = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 };

	ConvertSidToStringSidW(Sid, &SID);

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Sid: %ls"), i, SID);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Sid: %ls"), i, SID);
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return hTreeViewItem;
}


VOID AceTrusteeNameBruteForce(HWND hDlg, BOOL IsSacl, PTCH TrusteeName, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 };

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].TrusteeName: %ls"), i, TrusteeName);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].TrusteeName: %ls"), i, TrusteeName);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


VOID AceTrusteeFormBruteForce(HWND hDlg, BOOL IsSacl, int TrusteeForm, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, temp[MAX_PATH] = { 0 };

	switch (TrusteeForm)
	{
		case TRUSTEE_IS_SID:
			LoadString(g_hInstance, 10153, temp, MAX_PATH);
			break;
		case TRUSTEE_IS_NAME:
			LoadString(g_hInstance, 10154, temp, MAX_PATH);
			break;
		case TRUSTEE_BAD_FORM:
			LoadString(g_hInstance, 10155, temp, MAX_PATH);
			break;
		case TRUSTEE_IS_OBJECTS_AND_SID:
			LoadString(g_hInstance, 10156, temp, MAX_PATH);
			break;
		case TRUSTEE_IS_OBJECTS_AND_NAME:
			LoadString(g_hInstance, 10157, temp, MAX_PATH);
			break;
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].TrusteeForm: %ls"), i, temp);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].TrusteeForm: %ls"), i, temp);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


HTREEITEM AceTrusteeTypeBruteForce(HWND hDlg, BOOL IsSacl, int TrusteeType, WORD i, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 }, temp[MAX_PATH] = { 0 };

	switch (TrusteeType)
	{
/*0*/	case TRUSTEE_IS_UNKNOWN:
			LoadString(g_hInstance, 10158, temp, MAX_PATH);
			break;
/*1*/	case TRUSTEE_IS_USER: // SidTypeUser = 1 (from SID_NAME_USE)
			LoadString(g_hInstance, 10159, temp, MAX_PATH);
			break;
/*2*/	case TRUSTEE_IS_GROUP: // SidTypeGroup = 2 (from SID_NAME_USE)
			LoadString(g_hInstance, 10160, temp, MAX_PATH);
			break;
/*3*/	case TRUSTEE_IS_DOMAIN: // SidTypeDomain = 3 (from SID_NAME_USE)
			LoadString(g_hInstance, 10161, temp, MAX_PATH);
			break;
/*4*/	case TRUSTEE_IS_ALIAS: // SidTypeAlias = 4 (from SID_NAME_USE)
			LoadString(g_hInstance, 10162, temp, MAX_PATH);
			break;
/*5*/	case TRUSTEE_IS_WELL_KNOWN_GROUP: // SidTypeWellKnownGroup = 5 (from SID_NAME_USE)
			LoadString(g_hInstance, 10163, temp, MAX_PATH);
			break;
/*6*/	case TRUSTEE_IS_DELETED_ACCOUNT: // SidTypeDeletedAccount = 6 (from SID_NAME_USE)
			LoadString(g_hInstance, 10164, temp, MAX_PATH);
			break;
/*7*/	case TRUSTEE_IS_INVALID: // SidTypeInvalid = 7 (from SID_NAME_USE)
			LoadString(g_hInstance, 10165, temp, MAX_PATH);
			break;
/*8*/	case TRUSTEE_IS_UNKNOWN_TYPE: // SidTypeUnknown = 8 (from SID_NAME_USE)
			LoadString(g_hInstance, 10166, temp, MAX_PATH);
			break;
/*9*/	case TRUSTEE_IS_COMPUTER: // SidTypeComputer = 9 (from SID_NAME_USE)
			LoadString(g_hInstance, 10167, temp, MAX_PATH);
			break;
/*10*/	case TRUSTEE_IS_LABEL: // SidTypeLabel = 10 (from SID_NAME_USE)
			LoadString(g_hInstance, 10168, temp, MAX_PATH);
			break;
/*11*/	case TRUSTEE_IS_LOGON_SESSION: // SidTypeLogonSession = 11 (from SID_NAME_USE)
			LoadString(g_hInstance, 10169, temp, MAX_PATH);
			break;
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].TrusteeType: %ls"), i, temp);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].TrusteeType: %ls"), i, temp);
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return hTreeViewItem;
}


HTREEITEM AceTrusteeOperationBruteForce(HWND hDlg, BOOL IsSacl, int TrusteeOperation, WORD i, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 }, temp[MAX_PATH] = { 0 };

	switch (TrusteeOperation)
	{
		case NO_MULTIPLE_TRUSTEE:
			LoadString(g_hInstance, 10170, temp, MAX_PATH);
			break;
		case TRUSTEE_IS_IMPERSONATE:
			LoadString(g_hInstance, 10171, temp, MAX_PATH);
			break;
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].MultipleTrusteeOperation: %ls"), i, temp);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].MultipleTrusteeOperation: %ls"), i, temp);
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return hTreeViewItem;
}


VOID AceMultipleTrusteeBruteForce(HWND hDlg, BOOL IsSacl, PTRUSTEE MultipleTrustee, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 };

#pragma warn(disable:2234)
	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].MultipleTrustee: %i"), i, MultipleTrustee);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].MultipleTrustee: %i"), i, MultipleTrustee);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


HTREEITEM AceAccessFlagsBruteForce(HWND hDlg, BOOL IsSacl, DWORD AccessFlags, WORD i, TVINSERTSTRUCT TreeView)
{
	HTREEITEM hTreeViewItem = nullptr;
	TCHAR Buffer[MAX_PATH] = { 0 }, temp[MAX_PATH] = { 0 };

	switch (AccessFlags)// Этот элемент может быть одним из следующих значений:
	{
		case 0x0:
			swprintf(temp, MAX_PATH, TEXT("0"));
			break;
		case ACTRL_ACCESS_ALLOWED:
			LoadString(g_hInstance, 10172, temp, MAX_PATH);
			break;
		case ACTRL_ACCESS_DENIED:
			LoadString(g_hInstance, 10173, temp, MAX_PATH);
			break;
		case 0x3:
			LoadString(g_hInstance, 10174, temp, MAX_PATH);
			break;
		case ACTRL_AUDIT_SUCCESS:
			LoadString(g_hInstance, 10175, temp, MAX_PATH);
			break;
		case ACTRL_AUDIT_FAILURE:
			LoadString(g_hInstance, 10176, temp, MAX_PATH);
			break;
		case 0xC:
			LoadString(g_hInstance, 10177, temp, MAX_PATH);
			break;
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].AccessFlags: %ls"), i, temp);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].AccessFlags: %ls"), i, temp);
	TreeView.itemex.pszText = Buffer;
	hTreeViewItem = (HTREEITEM)SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return hTreeViewItem;
}


VOID AceAccessModeBruteForce(HWND hDlg, BOOL IsSacl, PACL pAcl, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, msgBuffer[MAX_PATH] = { 0 }, temp[MAX_PATH] = { 0 };
	DWORD errCode = 0, Count = 0;
	PEXPLICIT_ACCESS pExplicitAccess = { 0 };

	errCode = GetExplicitEntriesFromAcl(pAcl, &Count, &pExplicitAccess);
	if (errCode != ERROR_SUCCESS) {
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msgBuffer, MAX_PATH, nullptr);
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].AccessMode: <Error: %u> %ls"), i, errCode, msgBuffer);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].AccessMode: <Error: %u> %ls"), i, errCode, msgBuffer);
		TreeView.itemex.pszText = Buffer;
		SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);
		return;
	}
	else
		LocalFree(pExplicitAccess);

	switch (pExplicitAccess->grfAccessMode)
	{
		case NOT_USED_ACCESS:
			LoadString(g_hInstance, 10178, temp, MAX_PATH);
			break;

		case GRANT_ACCESS:
			LoadString(g_hInstance, 10179, temp, MAX_PATH);
			break;

		case SET_ACCESS:
			LoadString(g_hInstance, 10180, temp, MAX_PATH);
			break;

		case DENY_ACCESS:
			LoadString(g_hInstance, 10181, temp, MAX_PATH);
			break;

		case REVOKE_ACCESS:
			LoadString(g_hInstance, 10182, temp, MAX_PATH);
			break;

		case SET_AUDIT_SUCCESS:
			LoadString(g_hInstance, 10183, temp, MAX_PATH);
			break;

		case SET_AUDIT_FAILURE:
			LoadString(g_hInstance, 10184, temp, MAX_PATH);
			break;
	}

	if (IsSacl)
		swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].AccessMode: %ls"), i, temp);
	else
		swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].AccessMode: %ls"), i, temp);
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


VOID AceAccessBruteForce(HWND hDlg, BOOL IsSacl, DWORD Access, WORD i, TVINSERTSTRUCT TreeView, DWORD Manager)
{
	TCHAR Buffer[MAX_PATH] = { 0 }, Buffer1[MAX_PATH] = { 0 }, Buffer2[MAX_PATH] = { 0 }, Buffer3[MAX_PATH] = { 0 }, Buffer4[MAX_PATH] = { 0 },
		Buffer5[MAX_PATH] = { 0 }, Buffer6[MAX_PATH] = { 0 }, Buffer7[MAX_PATH] = { 0 }, Buffer8[MAX_PATH] = { 0 }, Buffer9[MAX_PATH] = { 0 },
		Buffer10[MAX_PATH] = { 0 }, Buffer11[MAX_PATH] = { 0 }, Buffer12[MAX_PATH] = { 0 }, Buffer13[MAX_PATH] = { 0 }, Buffer14[MAX_PATH] = { 0 },
		Buffer15[MAX_PATH] = { 0 }, Buffer16[MAX_PATH] = { 0 }, Buffer17[MAX_PATH] = { 0 }, Buffer18[MAX_PATH] = { 0 }, Buffer19[MAX_PATH] = { 0 },
		Buffer20[MAX_PATH] = { 0 }, Buffer21[MAX_PATH] = { 0 }, Buffer22[MAX_PATH] = { 0 };
	BOOL IsAccess = FALSE, IsStandardAceAccess = FALSE;

	if (Access == 0x0)
		swprintf(Buffer1, MAX_PATH, TEXT("0   "));

	else
	{
		if ((Manager == PROCESS_MANAGER) || (Manager == PROCESS_TOKEN_MANAGER))
		{
			if (Access & ACTRL_KERNEL_TERMINATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10122, Buffer1, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_THREAD) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10123, Buffer2, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_VM) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10124, Buffer3, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_VM_READ) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10125, Buffer4, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_VM_WRITE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10126, Buffer5, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_DUP_HANDLE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10127, Buffer6, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_PROCESS) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10128, Buffer7, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_SET_INFO) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10129, Buffer8, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_GET_INFO) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10130, Buffer9, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_CONTROL) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10131, Buffer10, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_ALERT) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10132, Buffer11, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_GET_CONTEXT) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10133, Buffer12, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_SET_CONTEXT) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10134, Buffer13, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_TOKEN) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10135, Buffer14, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_IMPERSONATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10136, Buffer15, MAX_PATH);
			}

			if (Access & ACTRL_KERNEL_DIMPERSONATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10137, Buffer16, MAX_PATH);
			}
		}

		if (Manager == SERVICE_MANAGER)
		{
			if (Access & ACTRL_SVC_GET_INFO) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10138, Buffer1, MAX_PATH);
			}

			if (Access & ACTRL_SVC_SET_INFO) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10139, Buffer2, MAX_PATH);
			}

			if (Access & ACTRL_SVC_STATUS) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10140, Buffer3, MAX_PATH);
			}

			if (Access & ACTRL_SVC_LIST) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10141, Buffer4, MAX_PATH);
			}

			if (Access & ACTRL_SVC_START) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10142, Buffer5, MAX_PATH);
			}

			if (Access & ACTRL_SVC_STOP) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10143, Buffer6, MAX_PATH);
			}

			if (Access & ACTRL_SVC_PAUSE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10144, Buffer7, MAX_PATH);
			}

			if (Access & ACTRL_SVC_INTERROGATE) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10145, Buffer8, MAX_PATH);
			}

			if (Access & ACTRL_SVC_UCONTROL) {
				IsAccess = TRUE;
				LoadString(g_hInstance, 10146, Buffer9, MAX_PATH);
			}
		}

		if (Access & ACTRL_SYSTEM_ACCESS) {
			IsStandardAceAccess = TRUE;
			LoadString(g_hInstance, 10147, Buffer17, MAX_PATH);
		}

		if (Access & ACTRL_DELETE) {
			IsStandardAceAccess = TRUE;
			LoadString(g_hInstance, 10148, Buffer18, MAX_PATH);
		}

		if (Access & ACTRL_READ_CONTROL) {
			IsStandardAceAccess = TRUE;
			LoadString(g_hInstance, 10149, Buffer19, MAX_PATH);
		}

		if (Access & ACTRL_CHANGE_ACCESS) {
			IsStandardAceAccess = TRUE;
			LoadString(g_hInstance, 10150, Buffer20, MAX_PATH);
		}

		if (Access & ACTRL_CHANGE_OWNER) {
			IsStandardAceAccess = TRUE;
			LoadString(g_hInstance, 10151, Buffer21, MAX_PATH);
		}

		if (Access & ACTRL_SYNCHRONIZE) {
			IsStandardAceAccess = TRUE;
			LoadString(g_hInstance, 10152, Buffer22, MAX_PATH);
		}
	}

	if (IsStandardAceAccess) {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].StandardAccess: %ls%ls%ls%ls%ls%ls"), i,
				Buffer17, Buffer18, Buffer19, Buffer20, Buffer21, Buffer22);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].StandardAccess: %ls%ls%ls%ls%ls%ls"), i,
				Buffer17, Buffer18, Buffer19, Buffer20, Buffer21, Buffer22);
	}
	else {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].StandardAccess: 0   "), i);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].StandardAccess: 0   "), i);
	}
	Buffer[wcslen(Buffer) - 3] = 0;
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	if (IsAccess) {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Access: %ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls"), i,
				Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7, Buffer8, Buffer9, Buffer10, Buffer11, Buffer12, Buffer13, Buffer14, Buffer15, Buffer16);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Access: %ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls"), i,
				Buffer1, Buffer2, Buffer3, Buffer4, Buffer5, Buffer6, Buffer7, Buffer8, Buffer9, Buffer10, Buffer11, Buffer12, Buffer13, Buffer14, Buffer15, Buffer16);
	}
	else {
		if (IsSacl)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Access: 0   "), i);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].Access: 0   "), i);
	}
	Buffer[wcslen(Buffer) - 3] = 0;
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}


VOID AceSpecificAccessBruteForce(HWND hDlg, BOOL IsSacl, DWORD SpecificAccess, WORD i, TVINSERTSTRUCT TreeView)
{
	TCHAR Buffer[MAX_PATH] = { 0 };

	if (IsSacl) {
		if (SpecificAccess == 0)
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].SpecificAccess: %u"), i, SpecificAccess);
		else
			swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].SpecificAccess: 0x%08X"), i, SpecificAccess);
	}
	else {
		if (SpecificAccess == 0)
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].SpecificAccess: %u"), i, SpecificAccess);
		else
			swprintf(Buffer, MAX_PATH, TEXT("DACL::ACE[%u].SpecificAccess: 0x%08X"), i, SpecificAccess);
	}
	TreeView.itemex.pszText = Buffer;
	SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

	return;
}
