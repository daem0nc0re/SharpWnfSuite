using System;
using SharpWnfClient.Handler;

namespace SharpWnfClient
{
    class SharpWnfClient
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();

            try
            {
                options.SetTitle("SharpWnfClient - Client Tool for Windows Notification Facility");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddArgument(true, "WNF_NAME", "WNF State Name.");
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }

            try
            {
                options.Parse(args);
                Execute.Run(options);
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
