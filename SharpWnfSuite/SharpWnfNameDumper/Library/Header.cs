using System;
using System.Runtime.InteropServices;

namespace SharpWnfNameDumper.Library
{
    [Flags]
    public enum SectionFlags : uint
    {
        TYPE_NO_PAD = 0x00000008,
        CNT_CODE = 0x00000020,
        CNT_INITIALIZED_DATA = 0x00000040,
        CNT_UNINITIALIZED_DATA = 0x00000080,
        LNK_INFO = 0x00000200,
        LNK_REMOVE = 0x00000800,
        LNK_COMDAT = 0x00001000,
        NO_DEFER_SPEC_EXC = 0x00004000,
        GPREL = 0x00008000,
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000,
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        ALIGN_MASK = 0x00F00000,
        LNK_NRELOC_OVFL = 0x01000000,
        MEM_DISCARDABLE = 0x02000000,
        MEM_NOT_CACHED = 0x04000000,
        MEM_NOT_PAGED = 0x08000000,
        MEM_SHARED = 0x10000000,
        MEM_EXECUTE = 0x20000000,
        MEM_READ = 0x40000000,
        MEM_WRITE = 0x80000000
    }

    internal enum WNF_STATE_NAME_LIFETIME : uint
    {
        WellKnown = 0,
        Permanent,
        Volataile, // Persistent
        Temporary,
        Max
    }

    internal enum WNF_DATA_SCOPE : uint
    {
        System = 0,
        Session,
        User,
        Process,
        Machine,
        PhysicalMachine,
        Max
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public SectionFlags Characteristics;
    }

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
