using System;
using System.Text;
using SharpWnfServer.Library;

namespace SharpWnfServer.Handler
{
    class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
            }
            else
            {
                string input;
                WnfCom wnfServer = new WnfCom();
                wnfServer.CreateServer();
                wnfServer.PrintInternalName();
                wnfServer.Write(Encoding.ASCII.GetBytes("Hello, world!"));

                while (true)
                {
                    Console.Write("[INPUT]> ");
                    input = Console.ReadLine();
                    wnfServer.Write(Encoding.ASCII.GetBytes(input));
                }
            }
        }
    }
}
