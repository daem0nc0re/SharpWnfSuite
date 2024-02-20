namespace SharpWnfDump.Library
{
    public enum WNF_DATA_SCOPE_Brief : uint
    {
        System = 0,
        session = 1,
        User = 2,
        Process = 3,
        Machine = 4,
        physicalMachine = 5
    }

    public struct WNF_STATE_NAME_Data
    {
        public ulong Version;
        public ulong NameLifeTime;
        public ulong DataScope;
        public ulong PermanentData;
        public ulong SequenceNumber;
        public ulong OwnerTag;
    }

    public enum WNF_STATE_NAME_LIFETIME_Brief : uint
    {
        WellKnown = 0,
        Permanent = 1,
        Volatile = 2,
        Temporary = 3
    }
}
