using System;
using System.Collections.Generic;

namespace SharpWnfScan.Library
{
    internal class Globals
    {
        public static List<PROCESS_INFORMATION> ProcessInfo { get; set; } = new List<PROCESS_INFORMATION>();
        public static Dictionary<int, ulong> StateNameInfo { get; set; } = new Dictionary<int, ulong>();
        public static IntPtr SubscriptionTablePointerAddress32 { get; set; } = IntPtr.Zero;
        public static IntPtr SubscriptionTablePointerAddress64 { get; set; } = IntPtr.Zero;
        public static bool IsWin11 { get; set; } = false;
    }
}
