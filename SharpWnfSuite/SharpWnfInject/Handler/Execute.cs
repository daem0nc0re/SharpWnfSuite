using System;
using System.Text.RegularExpressions;
using SharpWnfInject.Interop;
using SharpWnfInject.Library;

namespace SharpWnfInject.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            var rgxHex = new Regex(@"^(0x)?[0-9a-fA-F]+$");
            var rgxWellKnown = new Regex(@"^[a-zA-Z0-9]+(_[a-zA-Z0-9]+)+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            do
            {
                int pid;
                ulong stateName;

                if (rgxHex.IsMatch(options.GetValue("name")))
                {
                    try
                    {
                        stateName = Convert.ToUInt64(options.GetValue("name"), 16);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse WNF State Name.");
                        break;
                    }
                }
                else if (rgxWellKnown.IsMatch(options.GetValue("name")))
                {
                    try
                    {
                        stateName = (ulong)Enum.Parse(
                            typeof(WELL_KNOWN_WNF_NAME),
                            options.GetValue("name").ToUpper());
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse WNF State Name.");
                        break;
                    }
                }
                else
                {
                    Console.WriteLine("[!] The specfied WNF State Name is invalid format.\n");
                    break;
                }

                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"));
                }
                catch
                {
                    Console.WriteLine("[!] Failed to parse target PID.");
                    break;
                }

                Globals.g_IsWin11 = Helpers.IsWin11();
                Modules.InjectShellcode(
                    pid,
                    stateName,
                    options.GetValue("input"),
                    options.GetFlag("debug"));
            } while (false);

            Console.WriteLine();
        }
    }
}
