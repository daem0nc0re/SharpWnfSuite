using System;
using System.Text.RegularExpressions;
using SharpWnfScan.Interop;
using SharpWnfScan.Library;

namespace SharpWnfScan.Handler
{
    class Execute
    {
        public static void Run(CommandLineParser options)
        {
            ulong stateName = 0UL;
            string wellKnownName;
            Regex rgx = new Regex(@"^0x[0-9a-fA-F]+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("statename")))
            {
                if (rgx.IsMatch(options.GetValue("statename")))
                {
                    stateName = (ulong)Convert.ToInt64(options.GetValue("statename"), 16);
                }
                else
                {
                    wellKnownName = options.GetValue("statename").ToUpper();
                    
                    try
                    {
                        stateName = (ulong)Enum.Parse(
                            typeof(Win32Const.WELL_KNOWN_WNF_NAME),
                            wellKnownName);
                    }
                    catch
                    {
                        Console.WriteLine("\n[!] Failed to resolve wnf state name.\n");

                        return;
                    }
                }
            }
            
            if (options.GetFlag("all"))
            {
                Console.WriteLine();

                if (options.GetFlag("debug"))
                {
                    Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                    if (Utilities.EnableDebugPrivilege())
                        Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.\n");
                    else
                        Console.WriteLine("[-] Failed to enable SeDebugPrivilege.\n");
                }

                Modules.DumpAllWnfSubscriptionInformation(stateName);
                Console.WriteLine();
            }
            else if (options.GetFlag("list"))
            {
                Console.WriteLine();

                if (options.GetFlag("debug"))
                {
                    Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                    if (Utilities.EnableDebugPrivilege())
                        Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.");
                    else
                        Console.WriteLine("[-] Failed to enable SeDebugPrivilege.");
                }

                Modules.ListStateNames(stateName);
                Console.WriteLine();
            }
            else if (!string.IsNullOrEmpty(options.GetValue("pid")))
            {
                int pid;

                Console.WriteLine();

                if (options.GetFlag("debug"))
                {
                    Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                    if (Utilities.EnableDebugPrivilege())
                        Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.\n");
                    else
                        Console.WriteLine("[-] Failed to enable SeDebugPrivilege.\n");
                }

                try
                {
                    pid = Int32.Parse(options.GetValue("pid"));
                }
                catch
                {
                    Console.WriteLine("[-] Failed to resolve PID.\n");

                    return;
                }

                Modules.DumpWnfSubscriptionInformation(pid, stateName);
                Console.WriteLine();
            }
            else if (!string.IsNullOrEmpty(options.GetValue("name")))
            {
                Console.WriteLine();

                if (options.GetFlag("debug"))
                {
                    Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                    if (Utilities.EnableDebugPrivilege())
                        Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.\n");
                    else
                        Console.WriteLine("[-] Failed to enable SeDebugPrivilege.\n");
                }

                Modules.DumpWnfSubscriptionInformationByName(
                    options.GetValue("name"),
                    stateName);
                Console.WriteLine();
            }
            else
            {
                options.GetHelp();
            }
        }
    }
}
