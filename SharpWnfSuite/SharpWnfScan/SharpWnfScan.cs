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
            var exclusive = new List<string> { "all", "pid", "name" };

            try
            {
                options.SetTitle("SharpWnfScan - Tool for dumping WNF information from process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "p", "pid", null, "Specifies the target PID.");
                options.AddParameter(false, "n", "name", null, "Specifies the target process name.");
                options.AddParameter(false, "s", "statename", null, "Specifies a wnf state name for filtering.");
                options.AddFlag(false, "a", "all", "Flag to dump information from all process.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege. Administrative privilege is required.");
                options.AddExclusive(exclusive);
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
