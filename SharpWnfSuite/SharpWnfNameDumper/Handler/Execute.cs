using System;
using System.Collections.Generic;
using SharpWnfNameDumper.Library;

namespace SharpWnfNameDumper.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            if (options.GetFlag("dump"))
            {
                if (options.GetValue("format") == "c")
                    Console.WriteLine("[>] Output results in C style.\n");
                else if (options.GetValue("format") == "py")
                    Console.WriteLine("[>] Output results in Python style.\n");
                else
                    Console.WriteLine("[>] Output results in C# style.\n");

                Modules.DumpWellKnownWnfNames(
                    options.GetValue("FILE_NAME_1"),
                    out Dictionary<string, Dictionary<ulong, string>> stateNames);
                Modules.WriteWnfNamesToFile(
                    stateNames,
                    options.GetValue("output"),
                    false,
                    options.GetFlag("verbose"),
                    options.GetValue("format"));
            }
            else if (options.GetFlag("diff"))
            {
                if (string.IsNullOrEmpty(options.GetValue("FILE_NAME_2")))
                {
                    Console.WriteLine("[!] Missing newer DLL for diffing.");
                }
                else
                {
                    if (options.GetValue("format") == "c")
                        Console.WriteLine("[>] Output results in C style.\n");
                    else if (options.GetValue("format") == "py")
                        Console.WriteLine("[>] Output results in Python style.\n");
                    else
                        Console.WriteLine("[>] Output results in C# style.\n");

                    Modules.DumpWellKnownWnfNames(
                        options.GetValue("FILE_NAME_1"),
                        out Dictionary<string, Dictionary<ulong, string>> oldNames);
                    Modules.DumpWellKnownWnfNames(
                        options.GetValue("FILE_NAME_2"),
                        out Dictionary<string, Dictionary<ulong, string>> newNames);
                    Modules.DiffTables(
                        oldNames,
                        newNames,
                        out Dictionary<string, Dictionary<ulong, string>> added,
                        out Dictionary<string, Dictionary<ulong, string>> deleted,
                        out Dictionary<string, Dictionary<ulong, string>> modified);
                    Modules.PrintDiff(
                        added,
                        deleted,
                        modified,
                        options.GetValue("output"),
                        options.GetFlag("verbose"),
                        options.GetValue("format"));
                }
            }
            else
            {
                Console.WriteLine("[-] No options. Check -h option.");
                options.GetHelp();
            }

            Console.WriteLine();
        }
    }
}
