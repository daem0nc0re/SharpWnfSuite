using System;

namespace SharpWnfDump.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_MORE_DATA = 0x000000EA;
        public const int SDDL_REVISION_1 = 1;
        public static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(-2147483646);
        public const int KEY_READ = 0x20019;
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_BUFFER_OVERFLOW = unchecked((NTSTATUS)0x80000005u);
        public const NTSTATUS STATUS_OPERATION_FAILED = unchecked((NTSTATUS)0xC0000001u);
        public const NTSTATUS STATUS_BUFFER_TOO_SMALL = unchecked((NTSTATUS)0xC0000023u);
    }
}
