using System;

namespace SharpWnfScan.Library
{
    internal class Globals
    {
        public static IntPtr SubscriptionTablePointerAddress32 { get; set; } = IntPtr.Zero;
        public static IntPtr SubscriptionTablePointerAddress64 { get; set; } = IntPtr.Zero;
        public static int MajorVersion { get; } = 0;
        public static int MinorVersion { get; } = 0;
        public static int BuildNumber { get; } = 0;
        public static string OsVersion { get; } = null;
        public static bool IsWin11 { get; } = false;
        public static bool IsSupported { get; } = false;

        static Globals()
        {
            bool bSuccess = Helpers.GetOsVersionNumbers(
                out int nMajorVersion,
                out int nMinorVersion,
                out int nBuildNumber);

            if (bSuccess)
            {
                MajorVersion = nMajorVersion;
                MinorVersion = nMinorVersion;
                BuildNumber = nBuildNumber;
                OsVersion = Helpers.GetOsVersionString(nMajorVersion, nMinorVersion, nBuildNumber);
                IsWin11 = ((MajorVersion == 10) && (BuildNumber >= 22000));
                IsSupported = ((MajorVersion >= 10) && !string.IsNullOrEmpty(OsVersion));
            }
        }
    }
}
