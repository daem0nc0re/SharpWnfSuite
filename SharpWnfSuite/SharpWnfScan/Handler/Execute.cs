using System;
using System.Text.RegularExpressions;
using SharpWnfScan.Interop;
using SharpWnfScan.Library;

namespace SharpWnfScan.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            ulong stateName = 0UL;
            string wellKnownName;
            Regex rgx = new Regex(@"^0x[0-9a-fA-F]+$");
            bool bVerbose = options.GetFlag("verbose");
            Globals.IsWin11 = Helpers.IsWin11();

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            do
            {
                if (!string.IsNullOrEmpty(options.GetValue("name")))
                {
                    if (rgx.IsMatch(options.GetValue("name")))
                    {
                        stateName = (ulong)Convert.ToInt64(options.GetValue("name"), 16);
                    }
                    else
                    {
                        wellKnownName = options.GetValue("name").ToUpper();

                        try
                        {
                            stateName = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME), wellKnownName);
                        }
                        catch
                        {
                            Console.WriteLine("[!] Failed to resolve WNF State Name.");
                            break;
                        }
                    }
                }

                if (options.GetFlag("debug"))
                {
                    if (Utilities.EnableDebugPrivilege())
                    {
                        Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.\n");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to enable SeDebugPrivilege.");
                        break;
                    }
                }

                if (options.GetFlag("all"))
                {
                    Modules.DumpAllWnfSubscriptionInformation(stateName, bVerbose);
                }
                else if (options.GetFlag("list"))
                {
                    Modules.ListStateNames(stateName, bVerbose);
                }
                else if (!string.IsNullOrEmpty(options.GetValue("pid")))
                {
                    int pid;

                    try
                    {
                        pid = Int32.Parse(options.GetValue("pid"));
                        Modules.DumpWnfSubscriptionInformation(pid, stateName, bVerbose);
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to resolve PID.");
                    }
                }
                else if (!string.IsNullOrEmpty(options.GetValue("processname")))
                {
                    Modules.DumpWnfSubscriptionInformationByName(
                        options.GetValue("processname"),
                        stateName,
                        bVerbose);
                }
                else
                {
                    Console.WriteLine("[-] No options. Try -h option.");
                }
            } while (false);

            Console.WriteLine();
        }
    }
}
