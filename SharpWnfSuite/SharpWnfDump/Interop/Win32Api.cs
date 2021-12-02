using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWnfDump.Interop
{
    class Win32Api
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            int RequestedStringSDRevision,
            Win32Const.SECURITY_INFORMATION SecurityInformation,
            out StringBuilder StringSecurityDescriptor,
            IntPtr StringSecurityDescriptorLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSecurityDescriptor(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegEnumValue(
            IntPtr hKey,
            int dwIndex,
            StringBuilder lpValueName,
            ref int lpcValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            ref int lpcbData);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            IntPtr hKey,
            string lpSubKey,
            int ulOptions,
            int samDesired,
            out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            ref int lpcbData);

        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

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

        /*
         * ntdll.dll
         * 
         * Reference:
         *   + https://github.com/processhacker/processhacker/blob/master/phnt/include/ntexapi.h
         *
         */
        [DllImport("ntdll.dll")]
        public static extern int NtQueryWnfStateData(
            in ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            IntPtr Buffer,
            ref int BufferSize);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryWnfStateNameInformation(
            in ulong StateName,
            Win32Const.WNF_STATE_NAME_INFORMATION NameInfoClass,
            IntPtr ExplicitScope,
            ref int InfoBuffer,
            int InfoBufferSize);

        [DllImport("ntdll.dll")]
        public static extern int NtUpdateWnfStateData(
            in ulong StateName,
            IntPtr Buffer,
            int Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            int MatchingChangeScope,
            int CheckStamp);
    }
}
