using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpWnfScan.Library
{
    class Header
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public string ProcessName;
            public int ProcessId;
            public string Architecture;
            public string ErrorMessage;
        }

        public static List<PROCESS_INFORMATION> g_ProcessInfo = new List<PROCESS_INFORMATION>();
        public static Dictionary<int, ulong> g_PidAndStateNames = new Dictionary<int, ulong>();
        public static IntPtr g_SubscriptionTablePointerAddressX86 = IntPtr.Zero;
        public static IntPtr g_SubscriptionTablePointerAddressX64 = IntPtr.Zero;
        public static bool g_IsWin11 = false;
    }
}
