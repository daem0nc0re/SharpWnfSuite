﻿using System;
using SharpWnfServer.Handler;

namespace SharpWnfServer
{
    internal class SharpWnfServer
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("SharpWnfServer - Server Tool for Windows Notification Facility");
                options.AddFlag(false, "h", "help", "Displays this help message.");
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
