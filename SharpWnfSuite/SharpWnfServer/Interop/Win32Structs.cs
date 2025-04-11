using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWnfServer.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACE_HEADER
    {
        public ACE_TYPE AceType;
        public ACE_FLAGS AceFlags;
        public short AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACL
    {
        public ACL_REVISION AclRevision;
        public byte Sbz1;
        public short AclSize;
        public short AceCount;
        public short Sbz2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KEY_VALUE_FULL_INFORMATION
    {
        public uint TitleIndex;
        public REG_VALUE_TYPE Type;
        public uint DataOffset;
        public uint DataLength;
        public uint NameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] /* WCHAR[] */ Name;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;

        public LARGE_INTEGER(int _low, int _high)
        {
            QuadPart = 0L;
            Low = _low;
            High = _high;
        }

        public LARGE_INTEGER(long _quad)
        {
            Low = 0;
            High = 0;
            QuadPart = _quad;
        }

        public long ToInt64()
        {
            return ((long)High << 32) | (uint)Low;
        }

        public static LARGE_INTEGER FromInt64(long value)
        {
            return new LARGE_INTEGER
            {
                Low = (int)(value),
                High = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public OBJECT_ATTRIBUTES_FLAGS Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(
            string name,
            OBJECT_ATTRIBUTES_FLAGS attrs)
        {
            Length = 0;
            RootDirectory = IntPtr.Zero;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;

            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(
                 objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_DESCRIPTOR
    {
        public byte Revision;
        public byte Sbz1;
        public SECURITY_DESCRIPTOR_CONTROL Control;
        public int /* PSID */ Owner; // In this code, use relative offset
        public int /* PSID */ Group;
        public int /* PACL */ Sacl;
        public int /* PACL */ Dacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            byte[] bytes;

            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[2];
            }
            else
            {
                Length = (ushort)(s.Length * 2);
                bytes = Encoding.Unicode.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.AllocHGlobal(MaximumLength);

            Marshal.Copy(new byte[MaximumLength], 0, buffer, MaximumLength);
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer, Length / 2);
        }

        public IntPtr GetBuffer()
        {
            return buffer;
        }

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WNF_STATE_NAME
    {
        public ulong Data;

        public WNF_STATE_NAME(
            uint Version,
            WNF_STATE_NAME_LIFETIME NameLifeTime,
            WNF_DATA_SCOPE DataScope,
            uint PermanentData,
            uint SequenceNumber,
            uint OwnerTag)
        {
            Data = (ulong)Version & 0xF;
            Data |= ((ulong)NameLifeTime & 0x3) << 4;
            Data |= ((ulong)DataScope & 0xF) << 6;
            Data |= ((ulong)PermanentData & 0x1) << 10;
            Data |= ((ulong)SequenceNumber & 0x1FFFFF) << 11;
            Data |= ((ulong)OwnerTag & 0xFFFFFFFF) << 32;
            Data ^= 0x41C64E6DA3BC0074UL;
        }

        public uint GetVersion()
        {
            return (uint)((Data ^ 0x41C64E6DA3BC0074UL) & 0xF);
        }

        public WNF_STATE_NAME_LIFETIME GetNameLifeTime()
        {
            return (WNF_STATE_NAME_LIFETIME)(((Data ^ 0x41C64E6DA3BC0074UL) >> 4) & 0x3);
        }

        public WNF_DATA_SCOPE GetDataScope()
        {
            return (WNF_DATA_SCOPE)((((uint)Data ^ 0x41C64E6DA3BC0074UL) >> 6) & 0xF);
        }

        public uint GetPermanentData()
        {
            return (uint)(((Data ^ 0x41C64E6DA3BC0074UL) >> 10) & 0x1);
        }

        public uint GetSequenceNumber()
        {
            return (uint)(((Data ^ 0x41C64E6DA3BC0074UL) >> 11) & 0x1FFFFF);
        }

        public uint GetOwnerTag()
        {
            return (uint)(((Data ^ 0x41C64E6DA3BC0074UL) >> 32) & 0xFFFFFFFF);
        }

        public void SetVersion(uint version)
        {
            Data ^= 0x41C64E6DA3BC0074UL;
            Data &= 0xFFFFFFFFFFFFFFF0UL;
            Data |= (version & 0xF);
            Data ^= 0x41C64E6DA3BC0074UL;
        }

        public void SetNameLifeTime(WNF_STATE_NAME_LIFETIME nameLifeTime)
        {
            Data ^= 0x41C64E6DA3BC0074UL;
            Data &= 0xFFFFFFFFFFFFFFCFUL;
            Data |= (((uint)nameLifeTime & 0x3) << 4);
            Data ^= 0x41C64E6DA3BC0074UL;
        }

        public void SetDataScope(uint dataScope)
        {
            Data ^= 0x41C64E6DA3BC0074UL;
            Data &= 0xFFFFFFFFFFFFFC3FUL;
            Data |= ((dataScope & 0xF) << 6);
            Data ^= 0x41C64E6DA3BC0074UL;
        }

        public void SetPermanentData(uint parmanentData)
        {
            Data ^= 0x41C64E6DA3BC0074UL;
            Data &= 0xFFFFFFFFFFFFFBFFUL;
            Data |= ((parmanentData & 0x1) << 10);
            Data ^= 0x41C64E6DA3BC0074UL;
        }

        public void SetSequenceNumber(uint sequenceNumber)
        {
            Data ^= 0x41C64E6DA3BC0074UL;
            Data &= 0xFFFFFFFF000007FFUL;
            Data |= ((sequenceNumber & 0x1FFFFF) << 11);
            Data ^= 0x41C64E6DA3BC0074UL;
        }

        public void SetOwnerTag(uint ownerTag)
        {
            Data ^= 0x41C64E6DA3BC0074UL;
            Data &= 0x00000000FFFFFFFFUL;
            Data |= (ownerTag << 32);
            Data ^= 0x41C64E6DA3BC0074UL;
        }

        public bool IsValid()
        {
            var nameLifeTime = (uint)GetNameLifeTime();
            var dataScope = (uint)GetDataScope();

            return ((nameLifeTime < (uint)WNF_STATE_NAME_LIFETIME.Max) && (dataScope < (uint)WNF_DATA_SCOPE.Max));
        }
    }
}
