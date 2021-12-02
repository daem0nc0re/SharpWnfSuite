using System;
using System.Collections.Generic;
using SharpWnfNameDumper.Library;

namespace SharpWnfNameDumper.Handler
{
    class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }
            else if (options.GetFlag("dump"))
            {
                if (options.GetValue("format") == "c")
                {
                    Console.WriteLine("\n[>] Output results in C style.\n");
                }
                else if (options.GetValue("format") == "py")
                {
                    Console.WriteLine("\n[>] Output results in Python style.\n");
                }
                else
                {
                    Console.WriteLine("\n[>] Output results in C# style.\n");
                }

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
                if (options.GetValue("FILE_NAME_2") == string.Empty)
                {
                    Console.WriteLine("\n[!] Missing newer DLL for diffing.\n");
                    return;
                }

                if (options.GetValue("format") == "c")
                {
                    Console.WriteLine("\n[>] Output results in C style.\n");
                }
                else if (options.GetValue("format") == "py")
                {
                    Console.WriteLine("\n[>] Output results in Python style.\n");
                }
                else
                {
                    Console.WriteLine("\n[>] Output results in C# style.\n");
                }

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
            else
            {
                options.GetHelp();
                return;
            }
        }
    }
}
