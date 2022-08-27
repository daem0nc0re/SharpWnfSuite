using SharpWnfClient.Library;

namespace SharpWnfClient.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
            }
            else
            {
                WnfCom wnfClient = new WnfCom();

                if (wnfClient.SetStateName(options.GetValue("WNF_NAME")))
                {
                    wnfClient.Listen();
                }
            }
        }
    }
}
