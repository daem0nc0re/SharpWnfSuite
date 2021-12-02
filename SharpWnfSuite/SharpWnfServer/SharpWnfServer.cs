using SharpWnfServer.Handler;

namespace SharpWnfServer
{
    class SharpWnfServer
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            options.SetTitle("SharpWnfServer - Server Tool for Windows Notification Facility");
            options.Add(false, "h", "help", false, "Displays this help message.");
            options.Parse(args);

            Execute.Run(options);
        }
    }
}
