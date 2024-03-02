using System;
using System.Runtime.InteropServices;

namespace SharpWnfServer.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateEvent(
            IntPtr lpEventAttributes, 
            bool bManualReset, 
            bool bInitialState, 
            IntPtr lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int WaitForSingleObject(
            IntPtr hHandle, 
            int dwMilliseconds);

        /*
         * ntdll.dll
         */
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
