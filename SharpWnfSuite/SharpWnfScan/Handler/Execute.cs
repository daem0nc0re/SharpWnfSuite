using System;
using System.Text;
using System.Text.RegularExpressions;
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

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            do
            {
                var header = new StringBuilder();
                header.AppendFormat("[*] OS version is {0}.\n", Globals.OsVersion ?? "unspecified");

                if (!Globals.IsSupported)
                {
                    Console.Write(header.ToString());
                    Console.WriteLine("[-] This OS is not supported.");
                    break;
                }

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
                            stateName = Helpers.GetWnfStateName(wellKnownName);
                        }
                        catch
                        {
                            Console.Write(header.ToString());
                            Console.WriteLine("[!] Failed to resolve WNF State Name.");
                            break;
                        }
                    }
                }

                if (options.GetFlag("debug"))
                {
                    if (Utilities.EnableDebugPrivilege())
                    {
                        header.AppendLine("[+] SeDebugPrivilege is enabled successfully.");
                    }
                    else
                    {
                        Console.Write(header.ToString());
                        Console.WriteLine("[-] Failed to enable SeDebugPrivilege.");
                        break;
                    }
                }

                Console.WriteLine(header.ToString());

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
