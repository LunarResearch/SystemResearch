#include "Defines.h"


BYTE GetPattern_6000_7601[68] = {
	0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
	0x48,0x08,0x53,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x68,
	0x45,0x8B,0xE0,0x48,0x8B,0xF9,0x48,0x8D,0x00,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,
	0x00,0x00,0x8B,0xD8,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xFF,0x75,
	0x08,0x8D,0x5F,0x06
}; PCTCH GetMask_6000_7601 = TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?????x????xxxxxx????xxxxxxxx");

BYTE GetPattern_9600[65] = {
	0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
	0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
	0x60,0x45,0x8B,0xE8,0x4C,0x8B,0xF9,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x45,0x33,
	0xE4,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x4D,0x85,0xFF,0x75,0x08,0x8D,0x58,
	0x06
}; PCTCH GetMask_9600 = TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxx????xxxxxxxx");

BYTE GetPattern_9200_10240_22621[64] = {
	0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
	0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
	0x60,0x45,0x8B,0xF0,0x48,0x8B,0xF1,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,
	0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xF6,0x75,0x08,0x8D,0x58,0x06
}; PCTCH GetMask_9200_10240_22621 = TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");

BYTE GetPattern_22631_26100[62] = {
	0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x18,0x4C,0x89,0x48,0x20,0x89,
	0x50,0x10,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x70,0x41,
	0x8B,0xF0,0x4C,0x8B,0xE9,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,0x85,0xC0,
	0x0F,0x85,0x00,0x00,0x00,0x00,0x4D,0x85,0xED,0x75,0x08,0x8D,0x58,0x06
}; PCTCH GetMask_22631_26100 = TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");


BYTE SetPattern_19041_26100[40] = {
	0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x4C,0x89,0x60,0x20,0x89,0x50,0x10,0x48,0x89,
	0x48,0x08,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x00,0x01,0x00,0x00,0x4D,
	0x8B,0xE1,0x45,0x8B,0xF8,0x44,0x8B,0xEA
}; PCTCH SetMask_19041_26100 = TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");


BOOL GetSystemACL(HWND hDlg, DWORD Manager)
{
	switch (GetBuildOSNumber())
	{
		case 6000:
		case 6001:
		case 6002:
		case 7600:
		case 7601:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_6000_7601, GetMask_6000_7601);
			break;

		case 9600:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_9600, GetMask_9600);
			break;

		case 9200:
		case 10240:
		case 10586:
		case 14393:
		case 15063:
		case 16299:
		case 17134:
		case 17763:
		case 18362:
		case 18363:
		case 19041:
		case 19042:
		case 19043:
		case 19044:
		case 19045:
		case 22000:
		case 22621:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_9200_10240_22621, GetMask_9200_10240_22621);
			break;

		case 22631:
		case 26100:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_22631_26100, GetMask_22631_26100);
			break;
	}

	PACL pSacl = { 0 };
	PACTRL_AUDIT pObjKernelAuditList = { 0 };

	if (Manager == PROCESS_MANAGER)
	{
		if (!g_hProcess)
			g_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | OBJ_KERNEL_DESIRED_ACCESS, FALSE, g_dwProcessId);

		// https://habr.com/ru/articles/448472/

		if (GetSecurityInfo(g_hProcess, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &pSacl, nullptr) != ERROR_SUCCESS)
			GetSecurityInfo(g_hProcess, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &pSacl, nullptr);
		GetSecurityInfoEx(g_hProcess, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &pObjKernelAuditList, nullptr, nullptr);
	}

	if (Manager == PROCESS_TOKEN_MANAGER)
	{
		HANDLE hProcess = nullptr, hToken = nullptr;

		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);
		if (!OpenProcessToken(hProcess, TOKEN_QUERY | ACCESS_SYSTEM_SECURITY | READ_CONTROL, &hToken)) {
			CloseHandle(hProcess);
			return FALSE;
		}
		CloseHandle(hProcess);

		GetSecurityInfo(hToken, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &pSacl, nullptr);
		GetSecurityInfoEx(hToken, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &pObjKernelAuditList, nullptr, nullptr);

		CloseHandle(hToken);
	}

	if (Manager == SERVICE_MANAGER)
	{
		SC_HANDLE hSCManager = nullptr, hService = nullptr;

		hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
		if (!hSCManager)
			return FALSE;

		hService = OpenService(hSCManager, g_ServiceName, ACCESS_SYSTEM_SECURITY);
		CloseServiceHandle(hSCManager);

		GetSecurityInfo(hService, SE_SERVICE, SACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &pSacl, nullptr);
		GetSecurityInfoEx(hService, SE_SERVICE, SACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &pObjKernelAuditList, nullptr, nullptr);

		CloseServiceHandle(hService);
	}

	if (!IsValidAcl(pSacl))
		return FALSE;

	LPVOID pAce = nullptr;
	HTREEITEM hTreeViewItem_First = nullptr, hTreeViewItem_Second = nullptr, hTreeViewItem_Third = nullptr, hTreeViewItem_Fourth = nullptr;

	TVINSERTSTRUCT TreeView = { 0 };
	TreeView.itemex.mask = TVIF_TEXT;

	TCHAR Buffer[MAX_PATH] = { 0 };

	AclAccessProtectedBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->fListFlags, TreeView);
	hTreeViewItem_First = AclSizeBruteForce(hDlg, TRUE, pSacl->AclSize, TreeView);

	TreeView.hParent = hTreeViewItem_First;
	{
		AclBruteForce(hDlg, pSacl, TreeView);
	}

	TreeView.hParent = TVI_ROOT;
	{
		hTreeViewItem_First = AclExBruteForce(hDlg, TRUE, pSacl->AclRevision, pSacl->Sbz1, pSacl->Sbz2, pSacl->AceCount, TreeView);
	}

	TreeView.hParent = hTreeViewItem_First;

	for (DWORD k = 0; k < pObjKernelAuditList->cEntries; k++) {
		if (pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->cEntries == 0)
			goto Continue;
#pragma warn(disable:2229)
		for (DWORD j = 0; j < pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->cEntries; j++) {
Continue:
			for (WORD i = 0; i < pSacl->AceCount; i++) {
				
				if (!GetAce(pSacl, i, &pAce))
					return FALSE;

				TreeView.hParent = hTreeViewItem_First;
				{
					hTreeViewItem_Second = PropertyAcl(hDlg, TRUE, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Second;
				{
					AceSizeBruteForce(hDlg, TRUE, ((PACE_HEADER)pAce)->AceSize, i, TreeView);
					AceTypeBruteForce(hDlg, TRUE, ((PACE_HEADER)pAce)->AceType, i, TreeView);
					AceAccessMaskBruteForce(hDlg, TRUE, ((PSYSTEM_AUDIT_ACE)pAce)->Mask, i, TreeView, Manager);
					hTreeViewItem_Third = AceFlagsBruteForce(hDlg, TRUE, ((PACE_HEADER)pAce)->AceFlags, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Third;
				{
					if (pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->cEntries != 0)
						if (((PACE_HEADER)pAce)->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
							AceInheritanceBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Inheritance, i, TreeView);

					if (((PACE_HEADER)pAce)->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
						AceInheritanceBruteForce(hDlg, TRUE,((PACE_HEADER)pAce)->AceFlags, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Second;
				{
					if (((PACE_HEADER)pAce)->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
						hTreeViewItem_Third = AceSidBruteForce(hDlg, TRUE, (PSID)&((PSYSTEM_MANDATORY_LABEL_ACE)pAce)->SidStart, i, TreeView);
					else
						hTreeViewItem_Third = AceSidBruteForce(hDlg, TRUE, (PSID)&((PSYSTEM_AUDIT_ACE)pAce)->SidStart, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Third;
				{
					if (((PACE_HEADER)pAce)->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
					{
						swprintf(Buffer, MAX_PATH, TEXT("SACL::ACE[%u].Name: %ls\\%ls"), i, MandatoryLabelBruteForce(TRUE), MandatoryLabelBruteForce(FALSE));
						TreeView.itemex.pszText = Buffer;
						SendMessage(GetDlgItem(hDlg, 4001), TVM_INSERTITEM, 0, (LPARAM)&TreeView);

						MandatoryLabelPolicyBruteForce(hDlg, ((PSYSTEM_MANDATORY_LABEL_ACE)pAce)->Mask, i, TreeView);
					}
					else
						hTreeViewItem_Fourth = AceTrusteeTypeBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeType, i, TreeView);
				}

				if (((PACE_HEADER)pAce)->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
				{
					TreeView.hParent = hTreeViewItem_Fourth;
					{
						AceTrusteeFormBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeForm, i, TreeView);
						AceTrusteeNameBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.u.ptstrName, i, TreeView);
					}

					TreeView.hParent = hTreeViewItem_Third;
					{
						hTreeViewItem_Fourth = AceTrusteeOperationBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.MultipleTrusteeOperation, i, TreeView);
					}

					TreeView.hParent = hTreeViewItem_Fourth;
					{
						AceMultipleTrusteeBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.pMultipleTrustee, i, TreeView);
					}

					TreeView.hParent = hTreeViewItem_Third;
					{
						hTreeViewItem_Fourth = AceAccessFlagsBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->fAccessFlags, i, TreeView);
					}

					TreeView.hParent = hTreeViewItem_Fourth;
					{
						AceAccessModeBruteForce(hDlg, TRUE, pSacl, i, TreeView);
						AceAccessBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->Access, i, TreeView, Manager);
						AceSpecificAccessBruteForce(hDlg, TRUE, pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList->ProvSpecificAccess, i, TreeView);
					}
				}
				pObjKernelAuditList->pPropertyAccessList->pAccessEntryList->pAccessList++;
			}
			pObjKernelAuditList->pPropertyAccessList->pAccessEntryList++;
		}
		pObjKernelAuditList->pPropertyAccessList++;
	}

	return TRUE;
}


BOOL GetDiscretionaryACL(HWND hDlg, DWORD Manager)
{
	switch (GetBuildOSNumber())
	{
		case 6000:
		case 6001:
		case 6002:
		case 7600:
		case 7601:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_6000_7601, GetMask_6000_7601);
			break;

		case 9600:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_9600, GetMask_9600);
			break;

		case 9200:
		case 10240:
		case 10586:
		case 14393:
		case 15063:
		case 16299:
		case 17134:
		case 17763:
		case 18362:
		case 18363:
		case 19041:
		case 19042:
		case 19043:
		case 19044:
		case 19045:
		case 22000:
		case 22621:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_9200_10240_22621, GetMask_9200_10240_22621);
			break;

		case 22631:
		case 26100:
			GetSecurityInfoEx = (_GetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), GetPattern_22631_26100, GetMask_22631_26100);
			break;
	}

	PACL pDacl = { 0 };
	PACTRL_ACCESS pObjKernelAccessList = { 0 };

	if (Manager == PROCESS_MANAGER)
	{
		if (!g_hProcess)
			g_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | OBJ_KERNEL_DESIRED_ACCESS, FALSE, g_dwProcessId);

		GetSecurityInfo(g_hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pDacl, nullptr, nullptr);
		GetSecurityInfoEx(g_hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pObjKernelAccessList, nullptr, nullptr, nullptr);
	}

	if (Manager == PROCESS_TOKEN_MANAGER)
	{
		HANDLE hProcess = nullptr, hToken = nullptr;

		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_dwProcessId);
		if (!OpenProcessToken(hProcess, TOKEN_QUERY | ACCESS_SYSTEM_SECURITY | READ_CONTROL, &hToken)) {
			CloseHandle(hProcess);
			return FALSE;
		}
		CloseHandle(hProcess);

		GetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pDacl, nullptr, nullptr);
		GetSecurityInfoEx(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pObjKernelAccessList, nullptr, nullptr, nullptr);

		CloseHandle(hToken);
	}

	if (Manager == SERVICE_MANAGER)
	{
		SC_HANDLE hSCManager = nullptr, hService = nullptr;

		hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
		if (!hSCManager)
			return FALSE;

		hService = OpenService(hSCManager, g_ServiceName, READ_CONTROL);
		CloseServiceHandle(hSCManager);

		GetSecurityInfo(hService, SE_SERVICE, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pDacl, nullptr, nullptr);
		GetSecurityInfoEx(hService, SE_SERVICE, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pObjKernelAccessList, nullptr, nullptr, nullptr);

		CloseServiceHandle(hService);
	}

	if (!IsValidAcl(pDacl))
		return FALSE;

	LPVOID pAce = nullptr;
	HTREEITEM hTreeViewItem_First = nullptr, hTreeViewItem_Second = nullptr, hTreeViewItem_Third = nullptr, hTreeViewItem_Fourth = nullptr;

	TVINSERTSTRUCT TreeView = { 0 };
	TreeView.itemex.mask = TVIF_TEXT;

	AclAccessProtectedBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->fListFlags, TreeView);
	hTreeViewItem_First = AclSizeBruteForce(hDlg, FALSE, pDacl->AclSize, TreeView);

	TreeView.hParent = hTreeViewItem_First;
	{
		AclBruteForce(hDlg, pDacl, TreeView);
	}

	TreeView.hParent = TVI_ROOT;
	{
		hTreeViewItem_First = AclExBruteForce(hDlg, FALSE, pDacl->AclRevision, pDacl->Sbz1, pDacl->Sbz2, pDacl->AceCount, TreeView);
	}

	TreeView.hParent = hTreeViewItem_First;

	for (DWORD k = 0; k < pObjKernelAccessList->cEntries; k++) {
		for (DWORD j = 0; j < pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->cEntries; j++) {
			for (WORD i = 0; i < pDacl->AceCount; i++) {

				if (!GetAce(pDacl, i, &pAce))
					return FALSE;

				TreeView.hParent = hTreeViewItem_First;
				{
					hTreeViewItem_Second = PropertyAcl(hDlg, FALSE, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Second;
				{
					AceSizeBruteForce(hDlg, FALSE, ((PACE_HEADER)pAce)->AceSize, i, TreeView);
					AceTypeBruteForce(hDlg, FALSE, ((PACE_HEADER)pAce)->AceType, i, TreeView);
					AceAccessMaskBruteForce(hDlg, FALSE, ((PACCESS_ALLOWED_ACE)pAce)->Mask, i, TreeView, Manager);
					hTreeViewItem_Third = AceFlagsBruteForce(hDlg, FALSE, ((PACE_HEADER)pAce)->AceFlags, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Third;
				{
					AceInheritanceBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Inheritance, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Second;
				{
					hTreeViewItem_Third = AceSidBruteForce(hDlg, FALSE, (PSID)&((PACCESS_ALLOWED_ACE)pAce)->SidStart, i, TreeView);
				}

		    	TreeView.hParent = hTreeViewItem_Third;
				{
					hTreeViewItem_Fourth = AceTrusteeTypeBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeType, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Fourth;
				{
					AceTrusteeFormBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.TrusteeForm, i, TreeView);
					AceTrusteeNameBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.u.ptstrName, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Third;
				{
					hTreeViewItem_Fourth = AceTrusteeOperationBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.MultipleTrusteeOperation, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Fourth;
				{
					AceMultipleTrusteeBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Trustee.pMultipleTrustee, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Third;
				{
					hTreeViewItem_Fourth = AceAccessFlagsBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->fAccessFlags, i, TreeView);
				}

				TreeView.hParent = hTreeViewItem_Fourth;
				{
					AceAccessModeBruteForce(hDlg, FALSE, pDacl, i, TreeView);
					AceAccessBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->Access, i, TreeView, Manager);
					AceSpecificAccessBruteForce(hDlg, FALSE, pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList->ProvSpecificAccess, i, TreeView);
				}
				pObjKernelAccessList->pPropertyAccessList->pAccessEntryList->pAccessList++;
			}
			pObjKernelAccessList->pPropertyAccessList->pAccessEntryList++;
		}
		pObjKernelAccessList->pPropertyAccessList++;
	}
	
	return TRUE;
}


BOOL SetSystemACL(HWND hDlg, DWORD Manager)
{
	switch (GetBuildOSNumber()) 
	{
		case 19041:
		case 19042:
		case 19043:
		case 19044:
		case 19045:
		case 26100:
			SetSecurityInfoEx = (_SetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), SetPattern_19041_26100, SetMask_19041_26100);
			break;
	}

	if (Manager == PROCESS_MANAGER)
	{
	}

	if (Manager == PROCESS_TOKEN_MANAGER)
	{
	}

	if (Manager == SERVICE_MANAGER)
	{
	}

	return TRUE;
}


BOOL SetDiscretionaryACL(HWND hDlg, DWORD Manager)
{
	switch (GetBuildOSNumber()) 
	{
		case 19041:
		case 19042:
		case 19043:
		case 19044:
		case 19045:
		case 26100:
			SetSecurityInfoEx = (_SetSecurityInfoEx)GetProcAddressFromPattern(TEXT("advapi32"), SetPattern_19041_26100, SetMask_19041_26100);
			break;
	}

	if (Manager == PROCESS_MANAGER)
	{
	}

	if (Manager == PROCESS_TOKEN_MANAGER)
	{
	}

	if (Manager == SERVICE_MANAGER)
	{
	}

	return TRUE;
}
