using SharpWnfDump.Handler;

namespace SharpWnfDump
{
    class SharpWnfDump
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            options.SetTitle("SharpWnfDump - Diagnostics Tool for Windows Notification Facility");
            options.Add(false, "h", "help", false, "Displays this help message.");
            options.Add(false, "i", "info", false, "Displays given state name. Can use with -s, -r or -v option.");
            options.Add(false, "d", "dump", false, "Displays information on all non-temporary state names. Can use with -s, -r or -v option.");
            options.Add(false, "b", "brut", false, "Displays information on all temporary state names. Can use with -r or -v option.");
            options.Add(false, "r", "read", false, "Reads the current data stored in the given state name.");
            options.Add(false, "w", "write", false, "Writes data into the given state name.");
            options.Add(false, "v", "value", false, "Dump the value of each name.");
            options.Add(false, "s", "sid", false, "Show the security descriptor for each name.");
            options.Add(false, "WNF_NAME", "WNF State Name. Use with -i, -r or -w option.");
            options.Add(false, "FILE_NAME", "Data source file path. Use with -w option.");
            options.Parse(args);

            Execute.Run(options);
        }
    }
}
