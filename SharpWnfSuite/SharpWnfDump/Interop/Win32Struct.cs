using System;
using System.Runtime.InteropServices;

namespace SharpWnfDump.Interop
{
    class Win32Struct
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct ACL
        {
            public byte AclRevision;
            public byte Sbz1;
            public ushort AclSize;
            public ushort AceCount;
            public ushort Sbz2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GUID
        {
            public uint Data1;
            public ushort Data2;
            public ushort Data3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Data4;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_DESCRIPTOR
        {
            public byte Revision;
            public byte Sbz1;
            public ushort Control; // SECURITY_DESCRIPTOR_CONTROL Enum
            public IntPtr Owner; // PSID
            public IntPtr Group; // PSID
            public IntPtr Sacl; // PACL
            public IntPtr Dacl; // PACL
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WNF_STATE_NAME
        {
            public ulong Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WNF_TYPE_ID
        {
            public uint Data1;
            public ushort Data2;
            public ushort Data3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Data4;
        }
    }
}
