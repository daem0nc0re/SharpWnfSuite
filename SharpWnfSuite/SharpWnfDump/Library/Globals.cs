﻿namespace SharpWnfDump.Library
{
    internal class Globals
    {
        public static readonly string[] LifetimeKeyNameKeys = new string[]
        {
            @"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Notifications",
            @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications",
            @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\VolatileNotifications"
        };
        public static readonly int MajorVersion = 0;
        public static readonly int MinorVersion = 0;
        public static readonly int BuildNumber = 0;

        static Globals()
        {
            bool bSuccess = Helpers.GetOsVersionNumbers(out int nMajorVersion, out int nMinorVersion, out int nBuildNumber);

            if (bSuccess)
            {
                MajorVersion = nMajorVersion;
                MinorVersion = nMinorVersion;
                BuildNumber = nBuildNumber;
            }
        }
    }
}
