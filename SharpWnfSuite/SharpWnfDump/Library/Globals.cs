using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpWnfDump.Library
{
    internal class Globals
    {
        public static string[] LifetimeKeyNames = new string[] {
            "SYSTEM\\CurrentControlSet\\Control\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\VolatileNotifications"
        };
    }
}
