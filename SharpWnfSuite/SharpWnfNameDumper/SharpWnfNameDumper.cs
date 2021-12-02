using SharpWnfNameDumper.Handler;

namespace SharpWnfNameDumper
{
    class SharpWnfNameDumper
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            options.SetTitle("SharpWnfNameDumper - Windows Notification Facility Well-Known State Name Dumper");
            options.Add(false, "h", "help", false, "Displays this help message.");
            options.Add(false, "d", "dump", false, "Dump WNF State Name from DLL.");
            options.Add(false, "D", "diff", false, "Diff WNF State Name and dump the discrepancies from 2 DLLs.");
            options.Add(false, "f", "format", "csharp", "Determins output format. 'py' (Python) and 'c' (C/C++) are accepted (Default: csharp).");
            options.Add(false, "v", "verbose", false, "Flag for verbose result.");
            options.Add(false, "o", "output", string.Empty, "Specify output file (e.g. \"-o result.txt\").");
            options.Add(true, "FILE_NAME_1", "A PE file contains WNF State Name (typically perf_nt_c.dll).");
            options.Add(false, "FILE_NAME_2", "Another PE file contains WNF State Name for diffing. Newer one specify here.");
            options.Parse(args);

            Execute.Run(options);
        }
    }
}
