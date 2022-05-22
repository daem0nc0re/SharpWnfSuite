using System;
using System.Collections.Generic;
using SharpWnfScan.Handler;

namespace SharpWnfScan
{
    class SharpWnfScan
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            var exclusive1 = new List<string> { "all", "pid", "name", "list" };
            var exclusive2 = new List<string> { "brief", "list" };

            try
            {
                options.SetTitle("SharpWnfScan - Tool for dumping WNF information from process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "p", "pid", null, "Specifies the target PID.");
                options.AddParameter(false, "P", "processname", null, "Specifies the target process name.");
                options.AddParameter(false, "n", "name", null, "Specifies a wnf state name for filtering.");
                options.AddFlag(false, "a", "all", "Flag to dump information from all process.");
                options.AddFlag(false, "b", "brief", "Flag to exclude WNF_USER_SUBSCRIPTION information.");
                options.AddFlag(false, "l", "list", "Flag to list WNF State Name on this system.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege. Administrative privilege is required.");
                options.AddExclusive(exclusive1);
                options.AddExclusive(exclusive2);
                options.Parse(args);

                Handler.Execute.Run(options);
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
