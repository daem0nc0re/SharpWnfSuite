using System;
using System.Runtime.InteropServices;

namespace SharpWnfScan.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct WNF_USER_SUBSCRIPTION_INFO
    {
        public IntPtr UserSubscription;
        public IntPtr Callback;
        public IntPtr Context;
    }
}
