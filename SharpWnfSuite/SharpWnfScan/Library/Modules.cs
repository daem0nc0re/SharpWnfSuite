using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    class Modules
    {
        private static IntPtr g_SubscriptionTablePointerAddressX86 = IntPtr.Zero;
        private static IntPtr g_SubscriptionTablePointerAddressX64 = IntPtr.Zero;

        public static void DumpAllWnfSubscriptionInformation(ulong stateName)
        {
            Process[] procs = Process.GetProcesses();

            for (var idx = 0; idx < procs.Length; idx++)
                DumpWnfSubscriptionInformation(procs[idx].Id, stateName);
        }

        public static void DumpWnfSubscriptionInformation(ulong stateName)
        {
            PeProcess proc;
            IntPtr pSubscriptionTable;
            string errorMessage;

            try
            {
                proc = new PeProcess();
            }
            catch (Win32Exception ex)
            {
                Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                Console.WriteLine("Error Message : {0}\n", ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                Console.WriteLine("Error Message : {0}\n", ex.Message);

                return;
            }
            catch (KeyNotFoundException ex)
            {
                Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                Console.WriteLine("Error Message : {0}\n", ex.Message);

                return;
            }

            if (proc.GetArchitecture() == "x64")
            {
                if (g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                {
                    g_SubscriptionTablePointerAddressX64 = Utilities.GetSubscriptionTablePointerAddress(proc);

                    if (g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                    {
                        errorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE";
                        Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                        Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                        Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                        Console.WriteLine("Error Message : {0}\n", errorMessage);

                        return;
                    }
                }

                pSubscriptionTable = g_SubscriptionTablePointerAddressX64;
            }
            else if (proc.GetArchitecture() == "x86")
            {
                if (g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                {
                    g_SubscriptionTablePointerAddressX86 = Utilities.GetSubscriptionTablePointerAddress(proc);

                    if (g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                    {
                        errorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE";
                        Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                        Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                        Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                        Console.WriteLine("Error Message : {0}\n", errorMessage);

                        return;
                    }
                }

                pSubscriptionTable = g_SubscriptionTablePointerAddressX86;
            }
            else
            {
                errorMessage = "Unsupported architecture";
                Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                Console.WriteLine("Error Message : {0}\n", errorMessage);

                return;
            }

            Win32Api.SymSetOptions(Win32Const.SYM_OPTIONS.SYMOPT_DEFERRED_LOADS);
            Utilities.DumpWnfSubscriptionTable(proc, pSubscriptionTable, stateName);
            proc.Dispose();

            return;
        }

        public static void DumpWnfSubscriptionInformation(int pid, ulong stateName)
        {
            PeProcess proc;
            IntPtr pSubscriptionTable;
            string errorMessage;

            if (pid == Process.GetCurrentProcess().Id)
            {
                DumpWnfSubscriptionInformation(stateName);

                return;
            }
            else
            {
                try
                {
                    proc = new PeProcess(pid);
                }
                catch (Win32Exception ex)
                {
                    Console.WriteLine("Process Name  : {0}", Process.GetProcessById(pid).ProcessName);
                    Console.WriteLine("Process ID    : {0}", pid);
                    Console.WriteLine("Architecture  : {0}", "N/A");
                    Console.WriteLine("Error Message : {0}\n", ex.Message);

                    return;
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                    Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                    Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                    Console.WriteLine("Error Message : {0}\n", ex.Message);

                    return;
                }
                catch (KeyNotFoundException ex)
                {
                    Console.WriteLine("Process Name  : {0}", Process.GetCurrentProcess().ProcessName);
                    Console.WriteLine("Process ID    : {0}", Process.GetCurrentProcess().Id);
                    Console.WriteLine("Architecture  : {0}", Environment.Is64BitProcess ? "x64" : "x86");
                    Console.WriteLine("Error Message : {0}\n", ex.Message);

                    return;
                }

                if (proc.GetArchitecture() == "x64")
                {
                    if (g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                    {
                        g_SubscriptionTablePointerAddressX64 = Utilities.GetSubscriptionTablePointerAddress(proc);

                        if (g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                        {
                            errorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE";
                            Console.WriteLine("Process Name  : {0}", proc.GetProcessName());
                            Console.WriteLine("Process ID    : {0}", proc.GetProcessId());
                            Console.WriteLine("Architecture  : {0}", proc.GetArchitecture());
                            Console.WriteLine("Error Message : {0}\n", errorMessage);

                            return;
                        }
                    }

                    pSubscriptionTable = g_SubscriptionTablePointerAddressX64;
                }
                else if (proc.GetArchitecture() == "x86")
                {
                    if (g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                    {
                        g_SubscriptionTablePointerAddressX86 = Utilities.GetSubscriptionTablePointerAddress(proc);
                        
                        if (g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                        {
                            errorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE";
                            Console.WriteLine("Process Name  : {0}", proc.GetProcessName());
                            Console.WriteLine("Process ID    : {0}", proc.GetProcessId());
                            Console.WriteLine("Architecture  : {0}", proc.GetArchitecture());
                            Console.WriteLine("Error Message : {0}\n", errorMessage);

                            return;
                        }
                    }

                    pSubscriptionTable = g_SubscriptionTablePointerAddressX86;
                }
                else
                {
                    errorMessage = "Unsupported architecture";
                    Console.WriteLine("Process Name  : {0}", proc.GetProcessName());
                    Console.WriteLine("Process ID    : {0}", proc.GetProcessId());
                    Console.WriteLine("Architecture  : {0}", proc.GetArchitecture());
                    Console.WriteLine("Error Message : {0}\n", errorMessage);

                    return;
                }

                Win32Api.SymSetOptions(Win32Const.SYM_OPTIONS.SYMOPT_DEFERRED_LOADS);
                Utilities.DumpWnfSubscriptionTable(proc, pSubscriptionTable, stateName);
                proc.Dispose();

                return;
            }
        }


        public static void DumpWnfSubscriptionInformationByName(
            string processName,
            ulong stateName)
        {
            Process[] procs;

            try
            {
                procs = Process.GetProcessesByName(processName);
            }
            catch
            {
                Console.WriteLine("[!] Failed to resolve process name.");
                return;
            }

            for (var idx = 0; idx < procs.Length; idx++)
                DumpWnfSubscriptionInformation(procs[idx].Id, stateName);
        }
    }
}
