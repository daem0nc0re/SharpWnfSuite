using System;
using System.Runtime.InteropServices;

namespace SharpWnfServer.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public int Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACE_HEADER
    {
        public byte AceType;
        public byte AceFlags;
        public short AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACL
    {
        public byte AclRevision;
        public byte Sbz1;
        public short AclSize;
        public short AceCount;
        public short Sbz2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_DESCRIPTOR
    {
        public byte Revision;
        public byte Sbz1;
        public ushort Control; // SECURITY_DESCRIPTOR_CONTROL Enum
        public IntPtr Owner; // PSID
        public IntPtr Group; // PSID
        public IntPtr Sacl; // PACL
        public IntPtr Dacl; // PACL
    }
}
