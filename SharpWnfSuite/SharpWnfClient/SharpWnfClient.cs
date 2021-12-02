using SharpWnfClient.Handler;

namespace SharpWnfClient
{
    class SharpWnfClient
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            options.SetTitle("SharpWnfClient - Client Tool for Windows Notification Facility");
            options.Add(false, "h", "help", false, "Displays this help message.");
            options.Add(true, "WNF_NAME", "WNF State Name.");
            options.Parse(args);

            Execute.Run(options);
        }
    }
}
