using System;

namespace SharpWnfDump.Library
{
    internal class Globals
    {
        public static string[] LifetimeKeyNameKeys { get; } = new string[]
        {
            @"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Notifications",
            @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications",
            @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\VolatileNotifications"
        };
        public static int MajorVersion { get; } = 0;
        public static int MinorVersion { get; } = 0;
        public static int BuildNumber { get; } = 0;
        public static string OsVersion { get; } = null;
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
                IsSupported = ((MajorVersion >= 10) && !string.IsNullOrEmpty(OsVersion));
            }
        }
    }
}
