using System;

namespace SharpWnfDump.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        NO_ACCESS = 0x00000000,

        // For Registries
        KEY_QUERY_VALUE = 0x00000001,
        KEY_SET_VALUE = 0x00000002,
        KEY_CREATE_SUB_KEY = 0x00000004,
        KEY_ENUMERATE_SUB_KEYS = 0x00000008,
        KEY_NOTIFY = 0x00000010,
        KEY_CREATE_LINK = 0x00000020,
        KEY_WRITE = 0x00020006,
        KEY_EXECUTE_READ = 0x00020019,
        KEY_ALL_ACCESS = 0x000F003F,

        // Standard and Generic Rights
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
    }

    internal enum KEY_VALUE_INFORMATION_CLASS
    {
        KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
        KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
        KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
        KeyValueFullInformationAlign64,
        KeyValuePartialInformationAlign64, // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
        KeyValueLayerInformation, // KEY_VALUE_LAYER_INFORMATION
        MaxKeyValueInfoClass
    }

    [Flags]
    internal enum OBJECT_ATTRIBUTES_FLAGS : uint
    {
        None = 0x00000000,
        ProtectClose = 0x00000001,
        Inherit = 0x00000002,
        AuditObjectClose = 0x00000004,
        NoEightsUpgrade = 0x00000008,
        Permanent = 0x00000010,
        Exclusive = 0x00000020,
        CaseInsensitive = 0x00000040,
        OpenIf = 0x00000080,
        OpenLink = 0x00000100,
        KernelHandle = 0x00000200,
        ForceAccessCheck = 0x00000400,
        IgnoreImpersonatedDevicemap = 0x00000800,
        DontReparse = 0x00001000,
        ValieAttributes = 0x00001FF2
    }

    internal enum REG_VALUE_TYPE
    {
        None = 0,
        Sz,
        ExpandSz,
        Binary,
        Dword,
        DwordBigEndian,
        Link,
        MultiSz,
        ResourceList,
        FullResourceDescriptor,
        ResourceRequirementsList,
        Qword
    }

    [Flags]
    internal enum SECURITY_INFORMATION : uint
    {
        Owner = 0x00000001,
        Group = 0x00000002,
        Dacl = 0x00000004,
        Sacl = 0x00000008,
        Label = 0x00000010,
        UnprotectedSacl = 0x10000000,
        UnprotectedDacl = 0x20000000,
        ProtectedSacl = 0x40000000,
        ProtectedDacl = 0x80000000
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

    internal enum WNF_STATE_NAME_INFORMATION : uint
    {
        WnfInfoStateNameExist = 0x0,
        WnfInfoSubscribersPresent = 0x1,
        WnfInfoIsQuiescent = 0x2
    }
}
