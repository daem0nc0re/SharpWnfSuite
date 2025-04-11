using System;

namespace SharpWnfClient.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
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

        // For Events
        EVENT_MODIFY_STATE = 0x00000002,
        EVENT_ALL_ACCESS = 0x001F0003,

        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000
    }

    [Flags]
    internal enum ACE_FLAGS : byte
    {
        NONE = 0x00,
        OBJECT_INHERIT_ACE = 0x01,
        CONTAINER_INHERIT_ACE = 0x02,
        NO_PROPAGATE_INHERIT_ACE = 0x04,
        INHERIT_ONLY_ACE = 0x08,
        INHERITED_ACE = 0x10,
        FAILED_ACCESS_ACE_FLAG = 0x40,
        SUCCESSFUL_ACCESS_ACE_FLAG = 0x80
    }

    internal enum ACE_TYPE : byte
    {
        ACCESS_ALLOWED,
        ACCESS_DENIED,
        SYSTEM_AUDIT,
        SYSTEM_ALARM,
        ACCESS_ALLOWED_COMPOUND,
        ACCESS_ALLOWED_OBJECT,
        ACCESS_DENIED_OBJECT,
        SYSTEM_AUDIT_OBJECT,
        SYSTEM_ALARM_OBJECT,
        ACCESS_ALLOWED_CALLBACK,
        ACCESS_DENIED_CALLBACK,
        ACCESS_ALLOWED_CALLBACK_OBJECT,
        ACCESS_DENIED_CALLBACK_OBJECT,
        SYSTEM_AUDIT_CALLBACK,
        SYSTEM_ALARM_CALLBACK,
        SYSTEM_AUDIT_CALLBACK_OBJECT,
        SYSTEM_ALARM_CALLBACK_OBJECT,
        SYSTEM_MANDATORY_LABEL,
        SYSTEM_RESOURCE_ATTRIBUTE,
        SYSTEM_SCOPED_POLICY_ID,
        SYSTEM_PROCESS_TRUST_LABEL,
        SYSTEM_ACCESS_FILTER,
        // ACCESS_MAX_MS_V5 = 0x15
    }

    internal enum ACL_REVISION : byte
    {
        ACL_REVISION = 2,
        ACL_REVISION_DS = 4,
    }

    internal enum BOOLEAN : byte
    {
        FALSE,
        TRUE
    }

    internal enum EVENT_TYPE
    {
        NotificationEvent,
        SynchronizationEvent
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
    internal enum SECURITY_DESCRIPTOR_CONTROL : ushort
    {
        NONE = 0x0000,
        SE_OWNER_DEFAULTED = 0x0001,
        SE_GROUP_DEFAULTED = 0x0002,
        SE_DACL_PRESENT = 0x0004,
        SE_DACL_DEFAULTED = 0x0008,
        SE_SACL_DEFAULTED = 0x0008,
        SE_SACL_PRESENT = 0x0010,
        SE_DACL_AUTO_INHERIT_REQ = 0x0100,
        SE_SACL_AUTO_INHERIT_REQ = 0x0200,
        SE_DACL_AUTO_INHERITED = 0x0400,
        SE_SACL_AUTO_INHERITED = 0x0800,
        SE_DACL_PROTECTED = 0x1000,
        SE_SACL_PROTECTED = 0x2000,
        SE_RM_CONTROL_VALID = 0x4000,
        SE_SELF_RELATIVE = 0x8000
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

    internal enum WNF_STATE_NAME_LIFETIME : uint
    {
        WellKnown = 0,
        Permanent,
        Volataile, // Persistent
        Temporary,
        Max
    }
}
