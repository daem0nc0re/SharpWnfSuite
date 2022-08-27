using System;

namespace SharpWnfInject.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_MR_MID_NOT_FOUND = 0x13D;
        public static IntPtr HKEY_LOCAL_MACHINE = new IntPtr(-2147483646);
        public const int KEY_READ = 0x20019;
        public const NTSTATUS STATUS_SUCCESS = 0;
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
