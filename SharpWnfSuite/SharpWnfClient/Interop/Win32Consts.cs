using System;

namespace SharpWnfClient.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RELEASE = 0x00008000;
        public const uint PAGE_READWRITE = 0x04;
        public const NTSTATUS STATUS_SUCCESS = 0;
    }
}
