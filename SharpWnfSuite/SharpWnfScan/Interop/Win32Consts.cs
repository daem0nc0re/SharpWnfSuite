using System;

namespace SharpWnfScan.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const int ERROR_SUCCESS = 0;
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_BUFFER_OVERFLOW = unchecked((NTSTATUS)0x80000005u);
        public const NTSTATUS STATUS_NO_MORE_ENTRIES = unchecked((NTSTATUS)0x8000001Au);
        public const NTSTATUS STATUS_OPERATION_FAILED = unchecked((NTSTATUS)0xC0000001u);
        public const NTSTATUS STATUS_BUFFER_TOO_SMALL = unchecked((NTSTATUS)0xC0000023u);
        public const ulong WNF_STATE_KEY = 0x41C64E6DA3BC0074;
        public const uint MAX_PATH = 260;
        public const uint MAX_SYM_NAME = 2000;

        // Const for WNF_CONTEXT_HEADER.NodeTypeCode
        public const short WNF_NODE_SUBSCRIPTION_TABLE = 0x911;
        public const short WNF_NODE_NAME_SUBSCRIPTION = 0x912;
        public const short WNF_NODE_SERIALIZATION_GROUP = 0x913;
        public const short WNF_NODE_USER_SUBSCRIPTION = 0x914;
    }
}
