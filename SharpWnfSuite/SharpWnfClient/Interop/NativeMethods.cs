using System;
using System.Runtime.InteropServices;

namespace SharpWnfClient.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateEvent(
            out IntPtr EventHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr /* POBJECT_ATTRIBUTES */ ObjectAttributes,
            EVENT_TYPE EventType,
            BOOLEAN InitialState);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateWnfStateName(
            out ulong StateName,
            WNF_STATE_NAME_LIFETIME NameLifetime,
            WNF_DATA_SCOPE DataScope,
            bool PersistData,
            IntPtr TypeId,
            int MaximumStateSize,
            IntPtr SecurityDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenKey(
            out IntPtr KeyHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryValueKey(
            IntPtr KeyHandle,
            in UNICODE_STRING ValueName,
            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
            IntPtr KeyValueInformation,
            uint Length,
            out uint ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryWnfStateData(
            in ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            IntPtr Buffer,
            ref uint BufferSize);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtUpdateWnfStateData(
            in ulong StateName,
            IntPtr Buffer,
            int Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            int MatchingChangeScope,
            int CheckStamp);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            in LARGE_INTEGER Timeout);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlSubscribeWnfStateChangeNotification(
            out IntPtr Subscription,
            ulong StateName,
            int ChangeStamp,
            IntPtr Callback,
            IntPtr CallbackContext,
            IntPtr TypeId,
            int SerializationGroup,
            int Unknown);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlUnsubscribeWnfStateChangeNotification(
            IntPtr Subscription);
    }
}
