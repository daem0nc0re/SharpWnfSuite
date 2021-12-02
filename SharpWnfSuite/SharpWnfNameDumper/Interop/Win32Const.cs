using System;

namespace SharpWnfNameDumper.Interop
{
    class Win32Const
    {
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

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

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }
    }
}
