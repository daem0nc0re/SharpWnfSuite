using System;
using SharpWnfDump.Library;

namespace SharpWnfDump.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            ulong stateName;
            string wnfName;
            string fileName;
            bool showSd = options.GetFlag("sid");
            bool showData = options.GetFlag("read") || options.GetFlag("value");

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();
            
            if (options.GetFlag("info"))
            {
                wnfName = options.GetValue("WNF_NAME");

                if (string.IsNullOrEmpty(wnfName))
                {
                    Console.WriteLine("\n[!] Missing WNF State Name.\n");
                    return;
                }

                stateName = Helpers.GetWnfStateName(wnfName);

                if (stateName == 0)
                {
                    Console.WriteLine("[!] Failed to resolve WNF State Name.");
                    return;
                }

                Modules.DumpKeyInfo(stateName, showSd, showData);
            }
            else if (options.GetFlag("dump") || options.GetFlag("brut"))
            {
                if (options.GetFlag("dump"))
                    Modules.DumpWnfNames(showSd, showData, options.GetFlag("used"));
                else
                    Modules.BruteForceWnfNames(showData, options.GetFlag("used"));
            }
            else
            {
                if (options.GetFlag("read"))
                {
                    wnfName = options.GetValue("WNF_NAME");

                    if (string.IsNullOrEmpty(wnfName))
                    {
                        Console.WriteLine("\n[!] Missing WNF State Name.\n");
                        return;
                    }

                    try
                    {
                        stateName = Convert.ToUInt64(wnfName, 16);
                    }
                    catch
                    {
                        stateName = Helpers.GetWnfStateName(wnfName);
                    }

                    if (stateName == 0)
                    {
                        Console.WriteLine("[-] Failed to resolve WNF State Name ({0}).", wnfName);
                        return;
                    }

                    Modules.OperationRead(stateName);
                }
                else if (options.GetFlag("write"))
                {
                    wnfName = options.GetValue("WNF_NAME");
                    fileName = options.GetValue("FILE_NAME");

                    if (string.IsNullOrEmpty(wnfName))
                    {
                        Console.WriteLine("[!] Missing WNF State Name.");
                        return;
                    }

                    if (string.IsNullOrEmpty(fileName))
                    {
                        Console.WriteLine("[!] Missing data source file.");
                        return;
                    }

                    try
                    {
                        stateName = Convert.ToUInt64(wnfName, 16);
                    }
                    catch
                    {
                        stateName = Helpers.GetWnfStateName(wnfName);
                    }

                    if (stateName == 0)
                    {
                        Console.WriteLine("[-] Failed to resolve WNF State Name ({0}).", wnfName);
                        return;
                    }

                    Modules.OperationWrite(stateName, fileName);
                }
                else
                {
                    options.GetHelp();
                }
            }

            Console.WriteLine();
        }
    }
}
