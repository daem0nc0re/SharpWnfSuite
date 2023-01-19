namespace SharpWnfServer.Interop
{
    internal class Win32Consts
    {
        public const int ACL_REVISION = 2;
        public const int ACL_REVISION_DS = 4;
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RELEASE = 0x00008000;
        public const uint PAGE_READWRITE = 0x04;
        public const int SECURITY_DESCRIPTOR_REVISION = 1;
        public const int SECURITY_MAX_SID_SIZE = 68;
        public const int STATUS_SUCCESS = 0;
        public const ulong WNF_STATE_KEY = 0x41C64E6DA3BC0074;
    }
}
