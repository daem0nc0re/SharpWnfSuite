using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWnfDump.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            int RequestedStringSDRevision,
            SECURITY_INFORMATION SecurityInformation,
            out StringBuilder StringSecurityDescriptor,
            IntPtr StringSecurityDescriptorLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSecurityDescriptor(IntPtr pSecurityDescriptor);

        /*
         * ntdll.dll
         * 
         * Reference:
         *   + https://github.com/processhacker/processhacker/blob/master/phnt/include/ntexapi.h
         *
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtEnumerateValueKey(
            IntPtr KeyHandle,
            uint Index,
            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
            IntPtr KeyValueInformation,
            uint Length,
            out uint ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenKey(
            out IntPtr KeyHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryValueKey(
            IntPtr KeyHandle,
            in UNICODE_STRING ValueName,
            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
            IntPtr KeyValueInformation,
            uint Length,
            out uint ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryWnfStateData(
            in ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            IntPtr Buffer,
            ref uint BufferSize);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryWnfStateNameInformation(
            in ulong StateName,
            WNF_STATE_NAME_INFORMATION NameInfoClass,
            IntPtr ExplicitScope,
            IntPtr InfoBuffer,
            int InfoBufferSize);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtUpdateWnfStateData(
            in ulong StateName,
            IntPtr Buffer,
            int Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            int MatchingChangeScope,
            int CheckStamp);
    }
}
