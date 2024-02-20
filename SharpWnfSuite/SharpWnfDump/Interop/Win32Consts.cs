using System;

namespace SharpWnfDump.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const int ERROR_SUCCESS = 0;
        public static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(-2147483646);
        public const int KEY_READ = 0x20019;
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RELEASE = 0x00008000;
        public const uint PAGE_READWRITE = 0x04;
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_OPERATION_FAILED = Convert.ToInt32("0xC0000001", 16);
        public const ulong WNF_STATE_KEY = 0x41C64E6DA3BC0074;
    }
}
