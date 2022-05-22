using System;
using System.Text.RegularExpressions;
using SharpWnfInject.Interop;
using SharpWnfInject.Library;

namespace SharpWnfInject.Handler
{
    class Execute
    {
        public static void Run(CommandLineParser options)
        {
            ulong stateName;
            int pid;
            string filePath;
            var rgxHex = new Regex(@"^(0x)?[0-9a-fA-F]+$");
            var rgxWellKnown = new Regex(@"^[a-zA-Z0-9]+(_[a-zA-Z0-9]+)+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            if (string.IsNullOrEmpty(options.GetValue("name")))
            {
                options.GetHelp();
                Console.WriteLine("[!] Missing WNF State Name.\n");

                return;
            }
            else if (rgxHex.IsMatch(options.GetValue("name")))
            {
                try
                {
                    stateName = Convert.ToUInt64(options.GetValue("name"), 16);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine("[!] Failed to parse WNF State Name.");
                    Console.WriteLine("    |-> {0}\n", ex.Message);

                    return;
                }
                catch (FormatException ex)
                {
                    Console.WriteLine("[!] Failed to parse WNF State Name.");
                    Console.WriteLine("    |-> {0}\n", ex.Message);

                    return;
                }
                catch (OverflowException ex)
                {
                    Console.WriteLine("[!] Failed to parse WNF State Name.");
                    Console.WriteLine("    |-> {0}\n", ex.Message);

                    return;
                }
            }
            else if (rgxWellKnown.IsMatch(options.GetValue("name")))
            {
                try
                {
                    stateName = (ulong)Enum.Parse(
                        typeof(Win32Const.WELL_KNOWN_WNF_NAME),
                        options.GetValue("name").ToUpper());
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine("[!] Failed to parse WNF State Name.");
                    Console.WriteLine("    |-> {0}\n", ex.Message);

                    return;
                }
                catch (OverflowException ex)
                {
                    Console.WriteLine("[!] Failed to parse WNF State Name.");
                    Console.WriteLine("    |-> {0}\n", ex.Message);

                    return;
                }
            }
            else
            {
                Console.WriteLine("[!] The specfied WNF State Name is invalid format.\n");

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("pid")))
            {
                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"));
                }
                catch (FormatException ex)
                {
                    Console.WriteLine("[!] Failed to parse target PID.");
                    Console.WriteLine("    |-> {0}\n", ex.Message);

                    return;
                }
                catch (OverflowException ex)
                {
                    Console.WriteLine("[!] Failed to parse target PID.");
                    Console.WriteLine("    |-> {0}\n", ex.Message);

                    return;
                }
            }
            else
            {
                Console.WriteLine("[!] Missing target PID.\n");

                return;
            }

            Header.g_IsWin11 = Helpers.IsWin11();

            if (!string.IsNullOrEmpty(options.GetValue("input")))
            {
                filePath = options.GetValue("input");

                if (Modules.InjectShellcode(
                    pid,
                    stateName,
                    filePath,
                    options.GetFlag("debug")))
                {
                    Console.WriteLine("[+] Code injection is completed successfully.\n");
                }
                else
                {
                    Console.WriteLine("[-] Code injection is failed.\n");
                }
            }
            else
            {
                Console.WriteLine("[!] Missing file path to shellcode file.\n");
            }
        }
    }
}
