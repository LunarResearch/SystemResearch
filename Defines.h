/*|*****************************************************************|*|
|*| Windows 10 1507 - Build 10240 |*|                               |*|
|*| Windows 10 1511 - Build 10586 |*|                               |*|
|*| Windows 10 1607 - Build 14393 |*|                               |*|
|*| Windows 10 1703 - Build 15063 |*|                               |*|
|*| Windows 10 1709 - Build 16299 |*|                               |*|
|*| Windows 10 1803 - Build 17134 |*|                               |*|
|*| Windows 10 1809 - Build 17763 |*|                               |*|
|*| Windows 10 1903 - Build 18362 |*|                               |*|
|*| Windows 10 1909 - Build 18363 |*|                               |*|
|*| Windows 10 2004 - Build 19041 |*|                               |*|
|*| Windows 10 20H2 - Build 19042 |*|                               |*|
|*| Windows 10 21H1 - Build 19043 |*|                               |*|
|*| Windows 10 21H2 - Build 19044 |*| Windows 11 21H2 - Build 22000 |*|
|*| Windows 10 22H2 - Build 19045 |*| Windows 11 22H2 - Build 22621 |*|
|*|                               |*| Windows 11 23H2 - Build 22631 |*|
|*|                               |*| Windows 11 24H2 - Build 26100 |*|
|*|                               |*| Windows 11 25H2 - Build 26200 |*|
|*|*****************************************************************|*/
#ifndef _DEFINES_H
#define _DEFINES_H


#define WIN32_LEAN_AND_MEAN
#define NOCOMM


#define _UNICODE
#define UNICODE


#include <windows.h>
#include <windowsx.h>
#include <winbase.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <subauth.h>
#include <commdlg.h>
#include <aclapi.h>
#include <sddl.h>
#include <process.h>
#include <intrin.h>
#include <psapi.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <dwmapi.h>

#pragma comment(lib, "Psapi")
#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "Shell32")
#pragma comment(lib, "Wtsapi32")
#pragma comment(lib, "Userenv")
#pragma comment(lib, "Dwmapi")


#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define RTL_MAX_DRIVE_LETTERS 32

#define OBJ_KERNEL_HANDLE 0x00000200

#define SERVICE_ACCEPT_INTERNAL_SECURITY 0x00001000

#define SECURITY_MANDATORY_SECURE_PROCESS_RID (0x00007000L)

#define BITWISE_ASSIGNMENT_OPERATOR 0x0FFFFFFF

#define SE_PRIVILEGE_DISABLED (0x00000000L)

#define SE_UNSOLICITED_INPUT_PRIVILEGE (0L)
#define SE_UNKNOWN_PRIVILEGE (1L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE (36L)


#define MB_CAPTIONSTOP TEXT("Stop")
#define MB_CAPTIONERROR TEXT("Error")
#define MB_CAPTIONWARNING TEXT("Warning")
#define MB_CAPTIONQUESTION TEXT("Question")
#define MB_CAPTIONINFORMATION TEXT("Information")
#define MB_CAPTIONEXCLAMATION TEXT("Notification")


constexpr LONG_PTR PRIVILEGE_MANAGER = 1;

constexpr DWORD PROCESS_MANAGER = 1;
constexpr DWORD PROCESS_TOKEN_MANAGER = 2;
constexpr DWORD SERVICE_MANAGER = 3;


/*******************
| Global Variables |
*******************/
HINSTANCE g_hInstance = NULL;
HANDLE g_hProcess = NULL;
HWND g_hWndProcessList = NULL, g_hWndServiceList = NULL;
TCHAR g_ServiceName[MAX_PATH] = { 0 };
DWORD g_dwProcessId = 0, g_dwThreadId = 0, g_IdxProcessId[1024] = { 0 }, OBJ_KERNEL_DESIRED_ACCESS = 0L, g_LowPart = 0L;
LONG_PTR g_Idx = 0;

BOOL g_IsCheckedSacl = FALSE, g_IsCheckedDacl = FALSE,
	g_IsCheckedTerminate = FALSE, g_IsCheckedCreateThread = FALSE, g_IsCheckedSetSessionId = FALSE,
	g_IsCheckedVMOperation = FALSE, g_IsCheckedVMRead = FALSE, g_IsCheckedVMWrite = FALSE,
	g_IsCheckedDuplicateHandle = FALSE, g_IsCheckedCreateProcess = FALSE, g_IsCheckedSetQuota = FALSE,
	g_IsCheckedSetInfo = FALSE, g_IsCheckedQueryInfo = FALSE, g_IsCheckedSuspendResume = FALSE,
	g_IsCheckedSetLimitedInfo = FALSE, g_IsCheckedDelete = FALSE, g_IsCheckedSynchronize = FALSE,
	g_IsCheckedRightOwner = FALSE, g_IsCheckedRightDAC = FALSE;


/************************
| Overridden Enumerates |
************************/
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessBreakOnTermination = 29,
	ProcessProtectionInformation = 61,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _PS_PROTECTED_TYPE {
	PsProtectedTypeNone,
	PsProtectedTypeProtectedLight,
	PsProtectedTypeProtected,
	PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
	PsProtectedSignerNone,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

typedef enum _TOKEN_SECURITY_ATTRIBUTE_OPERATION {
	TOKEN_SECURITY_ATTRIBUTE_OPERATION_NONE,
	TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL,
	TOKEN_SECURITY_ATTRIBUTE_OPERATION_ADD,
	TOKEN_SECURITY_ATTRIBUTE_OPERATION_DELETE,
	TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE
} TOKEN_SECURITY_ATTRIBUTE_OPERATION, *PTOKEN_SECURITY_ATTRIBUTE_OPERATION;


/************************
| Overridden Structures |
************************/
typedef struct _CLIENT_ID {
    SIZE_T ProcessId;
    SIZE_T ThreadId;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    union {
        struct {
            USHORT MajorOperatingSystemVersion;
            USHORT MinorOperatingSystemVersion;
        };
        ULONG OperatingSystemVersion;
    };
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union {
        UCHAR ImageFlags;
        struct {
            UCHAR ComPlusNativeReady : 1;
            UCHAR ComPlusILOnly : 1;
            UCHAR ImageDynamicallyRelocated : 1;
            UCHAR ImageMappedFlat : 1;
            UCHAR BaseBelow4gb : 1;
            UCHAR ComPlusPrefer32bit : 1;
            UCHAR Reserved : 2;
        };
    };
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_CURDIR_REF {
    LONG ReferenceCount;
    HANDLE DirectoryHandle;
} RTL_CURDIR_REF, *PRTL_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTL_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Length;
    HANDLE hProcess;
    HANDLE hThread;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	struct _PEB* PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
	SIZE_T Size;
	PROCESS_BASIC_INFORMATION BasicInfo;
	union {
		ULONG Flags;
		struct {
			ULONG IsProtectedProcess : 1;
			ULONG IsWow64Process : 1;
			ULONG IsProcessDeleting : 1;
			ULONG IsCrossSessionCreate : 1;
			ULONG IsFrozen : 1;
			ULONG IsBackground : 1;
			ULONG IsStronglyNamed : 1;
			ULONG IsSecureProcess : 1;
			ULONG IsSubsystemProcess : 1;
			ULONG SpareBits : 23;
		};
	};
} PROCESS_EXTENDED_BASIC_INFORMATION, * PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
			UCHAR Type : 3;
			UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
    ULONG64 Version;
    UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
    PVOID pValue;
    ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1 {
    UNICODE_STRING Name;
    USHORT ValueType;
    USHORT Reserved;
    ULONG Flags;
    ULONG ValueCount;
    union {
        PLONG64 pInt64;
        PULONG64 pUint64;
        PUNICODE_STRING pString;
        PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    } Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
    USHORT Version;
    USHORT Reserved;
    ULONG AttributeCount;
    union {
        PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
    } Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION {
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION Attributes;
    PTOKEN_SECURITY_ATTRIBUTE_OPERATION Operations;
} TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION;

typedef struct _TOKEN_PROCESS_TRUST_LEVEL {
    PSID TrustLevelSid;
} TOKEN_PROCESS_TRUST_LEVEL, *PTOKEN_PROCESS_TRUST_LEVEL;


/***********************
| Prototypes Functions |
***********************/
typedef BOOL(APIENTRY* _WinStationSwitchToServicesSession)(void);
_WinStationSwitchToServicesSession WinStationSwitchToServicesSession = NULL;

typedef void(NTAPI* _RtlGetNtVersionNumbers)(PULONG NtMajorVersion, PULONG NtMinorVersion, PULONG NtBuildNumber);
_RtlGetNtVersionNumbers RtlGetNtVersionNumbers = NULL;

typedef BOOLEAN(NTAPI* _RtlDosPathNameToNtPathName_U)(
	PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR *FilePart, PRTL_RELATIVE_NAME_U RelativeName);
_RtlDosPathNameToNtPathName_U RtlDosPathNameToNtPathName_U = NULL;

typedef NTSTATUS(NTAPI* _RtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS *ppUserProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath,
	PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle,
	PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = NULL;

typedef NTSTATUS(NTAPI* _RtlDestroyProcessParameters)(PRTL_USER_PROCESS_PARAMETERS pUserProcessParameters);
_RtlDestroyProcessParameters RtlDestroyProcessParameters = NULL;

typedef NTSTATUS(NTAPI* _RtlCreateUserProcess)(
    PUNICODE_STRING NtImagePathName, ULONG AttributesDeprecated, PRTL_USER_PROCESS_PARAMETERS pUserProcessParameters,
    PSECURITY_DESCRIPTOR pProcessSecurityDescriptor, PSECURITY_DESCRIPTOR pThreadSecurityDescriptor, HANDLE ParentProcess,
    BOOLEAN InheritHandles, HANDLE DebugPort, HANDLE TokenHandle, PRTL_USER_PROCESS_INFORMATION pUserProcessInformation);
_RtlCreateUserProcess RtlCreateUserProcess = NULL;

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
_NtQueryInformationProcess NtQueryInformationProcess = NULL;

SIZE_T GetProcAddressFromPattern(PCTCH, LPBYTE, PCTCH);

typedef DWORD(WINAPI* _GetSecurityInfoEx)(
	HANDLE hObject,
	SE_OBJECT_TYPE ObjectType,
	SECURITY_INFORMATION SecurityInfo,
	PCTCH lpProvider,
	PCTCH lpProperty,
	PACTRL_ACCESS* ppAccessList,
	PACTRL_AUDIT* ppAuditList,
	PTCH* lppOwner,
	PTCH* lppGroup
	);
_GetSecurityInfoEx GetSecurityInfoEx = NULL;

typedef DWORD(WINAPI* _SetSecurityInfoEx)(
    HANDLE hObject,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PCTCH lpProvider,
    PACTRL_ACCESS pAccessList,
    PACTRL_AUDIT pAuditList,
    PTCH lpOwner,
    PTCH lpGroup,
    PACTRL_OVERLAPPED pOverlapped
   );
_SetSecurityInfoEx SetSecurityInfoEx = NULL;


/***********************
| SourceCode Functions |
***********************/
LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);


/***************************
| InternalWinAPI Functions |
***************************/
LRESULT CALLBACK PrivilegeManagerProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK PropertiesProcessManagerProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK PropertiesServiceManagerProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SystemAccessControlListProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK DiscretionaryAccessControlListProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK TokenGroupsProc(HWND, UINT, WPARAM, LPARAM);


/****************************
| ExtensionWinAPI Functions |
****************************/
VOID ToolTipPrivileges(HWND, PTCH);
VOID PrivilegeSwitchChecked(HWND, HANDLE);
VOID ProcessAccessRightCheck(HWND, BOOL);
VOID ControlAcceptBruteForce(HWND, DWORD, DWORD);
VOID SecurityDescriptorControlFlagsBruteForce(HWND, WORD);
BOOL GetTokenProcessPrivilegesInfo(HWND, HANDLE);
BOOL GetTokenServicePrivilegesInfo(HWND, PCTCH);
HWND CreateToolTip(HWND, int, int, PTCH);


/*******************************
| ExtensionAclWinAPI Functions |
*******************************/
VOID AclAccessProtectedBruteForce(HWND, BOOL, DWORD, TVINSERTSTRUCT);
HTREEITEM AclSizeBruteForce(HWND, BOOL, WORD, TVINSERTSTRUCT);
VOID AclBruteForce(HWND, PACL, TVINSERTSTRUCT);
HTREEITEM AclExBruteForce(HWND, BOOL, BYTE, BYTE, WORD, WORD, TVINSERTSTRUCT);
HTREEITEM PropertyAcl(HWND, BOOL, WORD, TVINSERTSTRUCT);
PTCH MandatoryLabelBruteForce(BOOL);
VOID MandatoryLabelPolicyBruteForce(HWND, DWORD, WORD, TVINSERTSTRUCT);
VOID AceSizeBruteForce(HWND, BOOL, WORD, WORD, TVINSERTSTRUCT);
VOID AceTypeBruteForce(HWND, BOOL, BYTE, WORD, TVINSERTSTRUCT);
VOID AceAccessMaskBruteForce(HWND, BOOL, DWORD, WORD, TVINSERTSTRUCT, DWORD);
HTREEITEM AceFlagsBruteForce(HWND, BOOL, BYTE, WORD, TVINSERTSTRUCT);
VOID AceInheritanceBruteForce(HWND, BOOL, DWORD, WORD, TVINSERTSTRUCT);
HTREEITEM AceSidBruteForce(HWND, BOOL, PSID, WORD, TVINSERTSTRUCT);
VOID AceTrusteeNameBruteForce(HWND, BOOL, PTCH, WORD, TVINSERTSTRUCT);
VOID AceTrusteeFormBruteForce(HWND, BOOL, int, WORD, TVINSERTSTRUCT);
HTREEITEM AceTrusteeTypeBruteForce(HWND, BOOL, int, WORD, TVINSERTSTRUCT);
HTREEITEM AceTrusteeOperationBruteForce(HWND, BOOL, int, WORD, TVINSERTSTRUCT);
VOID AceMultipleTrusteeBruteForce(HWND, BOOL, PTRUSTEE, WORD, TVINSERTSTRUCT);
HTREEITEM AceAccessFlagsBruteForce(HWND, BOOL, DWORD, WORD, TVINSERTSTRUCT);
VOID AceAccessModeBruteForce(HWND, BOOL, PACL, WORD, TVINSERTSTRUCT);
VOID AceAccessBruteForce(HWND, BOOL, DWORD, WORD, TVINSERTSTRUCT, DWORD);
VOID AceSpecificAccessBruteForce(HWND, BOOL, DWORD, WORD, TVINSERTSTRUCT);


/*************************
| InternalCode Functions |
*************************/
BOOL UI0DetectServiceRuns(HWND);
BOOL CreateUI0DetectService(HWND);
BOOL DeleteUI0DetectService(HWND);
BOOL SwitchToServicesSession(HWND);
BOOL CreateSystemProcess(HWND);
BOOL SuperUserAsWinlogon(HWND, WPARAM);
BOOL RestartApp(HWND, WPARAM);
BOOL LocalSystemToken(HWND, WPARAM);
BOOL TrustedInstallerToken(HWND, WPARAM);
BOOL DeleteLockedFile(HWND);


/**************************
| ExtensionCode Functions |
**************************/
int ErrPrint(HWND);
DWORD ErrPrint2(HWND, PCTCH);
BOOL IsUserAnSystem(void);
DWORD GetBuildOSNumber(void);
BOOL SetDesktopComposition(HWND);
BOOL UI0DetectServiceExists(void);
BOOL FDUI0InputServiceExists(void);
BOOL HypervisorExists(void);
HANDLE SnapshotTISvcSecurity(void);
VOID WINAPI StopTISvcSecurity(LPVOID);
BOOL GetSecurityDescInfo(HWND);
SIZE_T GetProcAddressFromPattern(PCTCH, LPBYTE, PCTCH);
BOOL PrivilegeManager(HANDLE, DWORD, PCTCH);
BOOL PrivilegeManager2(HANDLE, DWORD, DWORD);
BOOL IsProcessPrivilegeEnable(HANDLE, PCTCH);
BOOL IsProcessPrivilegeEnable2(HANDLE, DWORD);


/****************************
| ProcessExWinAPI Functions |
****************************/
BOOL ListProcess(HWND);
BOOL GetProcessBasicInfo(HWND);
BOOL GetTokenProcessInfo(HWND);
BOOL IsSecureProcess(HWND);
BOOL IsProtectedProcess(HWND);
BOOL GetTokenIntegrityLevelInfo(HWND);
BOOL SetTokenIntegrityLevelInfo(DWORD);
BOOL GetTokenGroupsInfo(HWND);
BOOL SetTokenGroupsInfo(HWND);


/****************************
| ServiceExWinAPI Functions |
****************************/
BOOL ListService(HWND);
BOOL CheckServiceProtectInfo(HWND, PCTCH);
BOOL UnProtectService(PCTCH, DWORD);
BOOL GetServiceConfig(HWND);
BOOL GetServiceStatus(HWND);
BOOL StartStopService(HWND);
BOOL PauseContinueService(HWND);
BOOL EnableDisableService(HWND);


/**********************
| AclWinAPI Functions |
**********************/
BOOL GetSystemACL(HWND, DWORD);
BOOL GetDiscretionaryACL(HWND, DWORD);


#endif  /* _DEFINES_H */


