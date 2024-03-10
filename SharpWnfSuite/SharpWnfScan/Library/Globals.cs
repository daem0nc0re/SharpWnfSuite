using System;

namespace SharpWnfScan.Library
{
    internal class Globals
    {
        public static IntPtr SubscriptionTablePointerAddress32 { get; set; } = IntPtr.Zero;
        public static IntPtr SubscriptionTablePointerAddress64 { get; set; } = IntPtr.Zero;
        public static bool IsWin11 { get; set; } = false;
    }
}
