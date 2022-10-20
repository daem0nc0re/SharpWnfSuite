using System;
using SharpWnfNameDumper.Handler;

namespace SharpWnfNameDumper
{
    internal class SharpWnfNameDumper
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();

            if (!Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("\n[!] Should be run in 64bit OS.\n");

                return;
            }

            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[!] Should be built as 64bit binary.\n");

                return;
            }

            try
            {
                options.SetTitle("SharpWnfNameDumper - Windows Notification Facility Well-Known State Name Dumper");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "d", "dump", "Dump WNF State Name from DLL.");
                options.AddFlag(false, "D", "diff", "Diff WNF State Name and dump the discrepancies from 2 DLLs.");
                options.AddFlag(false, "v", "verbose", "Flag for verbose result.");
                options.AddParameter(false, "f", "format", "csharp", "Determins output format. 'py' (Python) and 'c' (C/C++) are accepted (Default: csharp).");
                options.AddParameter(false, "o", "output", null, "Specify output file (e.g. \"-o result.txt\").");
                options.AddArgument(true, "FILE_NAME_1", "A PE file contains WNF State Name (typically perf_nt_c.dll).");
                options.AddArgument(false, "FILE_NAME_2", "Another PE file contains WNF State Name for diffing. Newer one specify here.");
                options.Parse(args);
                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);

                return;
            }
        }
    }
}
