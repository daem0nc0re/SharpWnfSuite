using System;
using System.Runtime.InteropServices;

namespace SharpWnfServer.Interop
{
    class Win32Api
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AddAccessAllowedAce(
            IntPtr pAcl, 
            uint dwAceRevision, 
            Win32Const.ACCESS_MASK AccessMask, 
            IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateWellKnownSid(
            Win32Const.WELL_KNOWN_SID_TYPE WellKnownSidType,
            IntPtr DomainSid,
            IntPtr pSid,
            ref int cbSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool InitializeAcl(
            IntPtr pAcl,
            int nAclLength,
            int dwAclRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool InitializeSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            int dwRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor, 
            bool bDaclPresent, 
            IntPtr pDacl, 
            bool bDaclDefaulted);

        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateEvent(
            IntPtr lpEventAttributes, 
            bool bManualReset, 
            bool bInitialState, 
            IntPtr lpName);

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            int dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            int dwSize,
            uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int WaitForSingleObject(
            IntPtr hHandle, 
            int dwMilliseconds);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern int NtCreateWnfStateName(
            out ulong StateName,
            Win32Const.WNF_STATE_NAME_LIFETIME NameLifetime,
            Win32Const.WNF_DATA_SCOPE DataScope,
            bool PersistData,
            IntPtr TypeId,
            int MaximumStateSize,
            IntPtr SecurityDescriptor);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryWnfStateData(
            in ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            IntPtr Buffer,
            ref int BufferSize);

        [DllImport("ntdll.dll")]
        public static extern int NtUpdateWnfStateData(
            in ulong StateName,
            IntPtr Buffer,
            int Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            int MatchingChangeScope,
            int CheckStamp);

        [DllImport("ntdll.dll")]
        public static extern int RtlSubscribeWnfStateChangeNotification(
            out IntPtr Subscription,
            ulong StateName,
            int ChangeStamp,
            IntPtr Callback,
            IntPtr CallbackContext,
            IntPtr TypeId,
            int SerializationGroup,
            int Unknown);

        [DllImport("ntdll.dll")]
        public static extern int RtlUnsubscribeWnfStateChangeNotification(
            IntPtr Subscription);
    }
}
