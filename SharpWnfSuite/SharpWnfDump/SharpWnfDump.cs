using System;
using SharpWnfDump.Handler;
using SharpWnfDump.Interop;

namespace SharpWnfDump
{
    class SharpWnfDump
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("SharpWnfDump - Diagnostics Tool for Windows Notification Facility");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "i", "info", "Displays given state name. Can use with -s, -r or -v option.");
                options.AddFlag(false, "d", "dump", "Displays information on all non-temporary state names. Can use with -s, -r or -v option.");
                options.AddFlag(false, "b", "brut", "Displays information on all temporary state names. Can use with -r or -v option.");
                options.AddFlag(false, "r", "read", "Reads the current data stored in the given state name.");
                options.AddFlag(false, "w", "write", "Writes data into the given state name.");
                options.AddFlag(false, "v", "value", "Dump the value of each name.");
                options.AddFlag(false, "s", "sid", "Show the security descriptor for each name.");
                options.AddArgument(false, "WNF_NAME", "WNF State Name. Use with -i, -r or -w option.");
                options.AddArgument(false, "FILE_NAME", "Data source file path. Use with -w option.");
                options.Parse(args);
                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }
    }
}
