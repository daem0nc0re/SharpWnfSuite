using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    class Modules
    {
        public static void DumpAllWnfSubscriptionInformation(
            ulong stateName,
            bool brief)
        {
            Process[] procs = Process.GetProcesses();

            for (var idx = 0; idx < procs.Length; idx++)
                DumpWnfSubscriptionInformation(procs[idx].Id, stateName, brief);
        }


        public static void DumpWnfSubscriptionInformation(
            ulong stateName,
            bool brief)
        {
            DumpWnfSubscriptionInformation(Process.GetCurrentProcess().Id, stateName, brief);
        }

        public static void DumpWnfSubscriptionInformation(
            int pid,
            ulong stateNameFilter,
            bool brief)
        {
            PeProcess proc;
            bool is64bit;
            ulong stateName;
            IntPtr pSubscriptionTable;
            IntPtr pNameSubscription;
            IntPtr pUserSubscription;
            IntPtr pCallback;
            IntPtr pCallbackContext;
            Dictionary<ulong, IntPtr> nameSubscriptions;
            Dictionary<IntPtr, Dictionary<IntPtr, IntPtr>> userSubscriptions;
            Dictionary<IntPtr, IntPtr> callbackInfo;
            Header.PROCESS_INFORMATION processInfo = new Header.PROCESS_INFORMATION {
                ProcessName = "N/A",
                ProcessId = pid,
                Architecture = "N/A",
                ErrorMessage = null
            };

            try
            {
                proc = new PeProcess(pid);
                processInfo.ProcessName = proc.GetProcessName();
                processInfo.Architecture = proc.GetArchitecture();
            }
            catch (Win32Exception ex)
            {
                processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                processInfo.ErrorMessage = ex.Message;
                Header.g_ProcessInfo.Add(processInfo);

                if (stateNameFilter == 0UL)
                    Helpers.PrintProcessInformation(processInfo);

                return;
            }
            catch (ArgumentException ex)
            {
                processInfo.ErrorMessage = ex.Message;
                Header.g_ProcessInfo.Add(processInfo);

                if (stateNameFilter == 0UL)
                    Helpers.PrintProcessInformation(processInfo);

                return;
            }
            catch (KeyNotFoundException ex)
            {
                processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                processInfo.ErrorMessage = ex.Message;
                Header.g_ProcessInfo.Add(processInfo);

                if (stateNameFilter == 0UL)
                    Helpers.PrintProcessInformation(processInfo);

                return;
            }

            is64bit = (proc.GetArchitecture() == "x64");

            if (is64bit)
            {
                if (Header.g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                {
                    Header.g_SubscriptionTablePointerAddressX64 = Utilities.GetSubscriptionTablePointerAddress(proc);

                    if (Header.g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                    {
                        processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                        processInfo.ErrorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.";
                        Header.g_ProcessInfo.Add(processInfo);
                        proc.Dispose();

                        if (stateNameFilter == 0UL)
                            Helpers.PrintProcessInformation(processInfo);

                        return;
                    }
                }

                pSubscriptionTable = Utilities.GetSubscriptionTable(
                    proc,
                    Header.g_SubscriptionTablePointerAddressX64,
                    out processInfo.ErrorMessage);

                if (pSubscriptionTable == IntPtr.Zero)
                {
                    if (stateNameFilter == 0UL)
                        Helpers.PrintProcessInformation(processInfo);

                    return;
                }
            }
            else
            {
                if (Header.g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                {
                    Header.g_SubscriptionTablePointerAddressX86 = Utilities.GetSubscriptionTablePointerAddress(proc);

                    if (Header.g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                    {
                        processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                        processInfo.ErrorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.";
                        Header.g_ProcessInfo.Add(processInfo);
                        proc.Dispose();

                        if (stateNameFilter == 0UL)
                            Helpers.PrintProcessInformation(processInfo);

                        return;
                    }
                }

                pSubscriptionTable = Utilities.GetSubscriptionTable(
                    proc,
                    Header.g_SubscriptionTablePointerAddressX86,
                    out processInfo.ErrorMessage);

                if (pSubscriptionTable == IntPtr.Zero)
                {
                    if (stateNameFilter == 0UL)
                        Helpers.PrintProcessInformation(processInfo);

                    return;
                }
            }

            Win32Api.SymSetOptions(Win32Const.SYM_OPTIONS.SYMOPT_DEFERRED_LOADS);

            if (stateNameFilter == 0UL)
            {
                Helpers.PrintProcessInformation(processInfo);
                Console.WriteLine(
                    "WNF_SUBSCRIPTION_TABLE @ 0x{0}\n",
                    pSubscriptionTable.ToString(is64bit ? "X16" : "X8"));
            }

            if (Header.g_IsWin11)
                nameSubscriptions = Utilities.GetNameSubscriptionsWin11(proc, pSubscriptionTable);
            else
                nameSubscriptions = Utilities.GetNameSubscriptions(proc, pSubscriptionTable);

            foreach (var nameEntry in nameSubscriptions)
            {
                stateName = nameEntry.Key;
                pNameSubscription = nameEntry.Value;

                if (stateNameFilter != 0 && stateName != stateNameFilter)
                {
                    continue;
                }
                else if (stateNameFilter != 0 && stateName == stateNameFilter)
                {
                    Helpers.PrintProcessInformation(processInfo);

                    Console.WriteLine(
                        "WNF_SUBSCRIPTION_TABLE @ 0x{0}\n",
                        pSubscriptionTable.ToString(is64bit ? "X16" : "X8"));
                }

                Console.WriteLine(
                    "\tWNF_NAME_SUBSCRIPTION @ 0x{0}",
                    pNameSubscription.ToString(is64bit ? "X16" : "X8"));
                Console.WriteLine(
                    "\tStateName : 0x{0} ({1})\n",
                    stateName.ToString("X16"),
                    Helpers.GetWnfName(stateName));

                if (brief)
                    continue;

                if (Header.g_IsWin11)
                    userSubscriptions = Utilities.GetUserSubscriptionsWin11(proc, pNameSubscription);
                else
                    userSubscriptions = Utilities.GetUserSubscriptions(proc, pNameSubscription);

                foreach (var userEntry in userSubscriptions)
                {
                    pUserSubscription = userEntry.Key;
                    callbackInfo = userEntry.Value;

                    Console.WriteLine(
                        "\t\tWNF_USER_SUBSCRIPTION @ 0x{0}",
                        pUserSubscription.ToString(is64bit ? "X16" : "X8"));

                    foreach (var callbackEntry in callbackInfo)
                    {
                        pCallback = callbackEntry.Key;
                        pCallbackContext = callbackEntry.Value;

                        Console.WriteLine(
                            "\t\tCallback @ 0x{0} ({1})",
                            pCallback.ToString(is64bit ? "X16" : "X8"),
                            Helpers.GetSymbolPath(proc.GetProcessHandle(), pCallback));
                        Console.WriteLine(
                            "\t\tContext  @ 0x{0} ({1})\n",
                            pCallbackContext.ToString(is64bit ? "X16" : "X8"),
                            Helpers.GetSymbolPath(proc.GetProcessHandle(), pCallbackContext));
                    }
                }
            }

            proc.Dispose();

            return;
        }


        public static void DumpWnfSubscriptionInformationByName(
            string processName,
            ulong stateName,
            bool brief)
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
                DumpWnfSubscriptionInformation(procs[idx].Id, stateName, brief);
        }


        public static void ListStateNames(ulong stateNameFilter)
        {
            int pid;
            PeProcess proc;
            bool is64bit;
            IntPtr pSubscriptionTable;
            Dictionary<ulong, IntPtr> nameSubscriptions;
            Header.PROCESS_INFORMATION processInfo;
            var stateNames = new Dictionary<ulong, List<Header.PROCESS_INFORMATION>>();
            var deniedProcesses = new Dictionary<int, string>();

            Process[] procs = Process.GetProcesses();

            Console.WriteLine("[>] Trying to list WNF State Names used in this system. Wait a moment.");

            for (var idx = 0; idx < procs.Length; idx++)
            {
                pid = procs[idx].Id;

                processInfo = new Header.PROCESS_INFORMATION {
                    ProcessName = "N/A",
                    ProcessId = pid,
                    Architecture = "N/A",
                    ErrorMessage = null
                };

                try
                {
                    proc = new PeProcess(pid);
                    processInfo.ProcessName = proc.GetProcessName();
                    processInfo.Architecture = proc.GetArchitecture();
                }
                catch (Win32Exception ex)
                {
                    processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                    processInfo.ErrorMessage = ex.Message;
                    Header.g_ProcessInfo.Add(processInfo);

                    if (string.Compare(
                        processInfo.ErrorMessage.TrimEnd(),
                        "Access is denied",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        deniedProcesses.Add(processInfo.ProcessId, processInfo.ProcessName);
                    }

                    continue;
                }
                catch (ArgumentException ex)
                {
                    processInfo.ErrorMessage = ex.Message;
                    Header.g_ProcessInfo.Add(processInfo);

                    continue;
                }
                catch (KeyNotFoundException ex)
                {
                    processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                    processInfo.ErrorMessage = ex.Message;
                    Header.g_ProcessInfo.Add(processInfo);

                    continue;
                }

                is64bit = (proc.GetArchitecture() == "x64");

                if (is64bit)
                {
                    if (Header.g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                    {
                        Header.g_SubscriptionTablePointerAddressX64 = Utilities.GetSubscriptionTablePointerAddress(proc);

                        if (Header.g_SubscriptionTablePointerAddressX64 == IntPtr.Zero)
                        {
                            processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                            processInfo.ErrorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.";
                            Header.g_ProcessInfo.Add(processInfo);
                            proc.Dispose();

                            continue;
                        }
                    }

                    pSubscriptionTable = Utilities.GetSubscriptionTable(
                        proc,
                        Header.g_SubscriptionTablePointerAddressX64,
                        out processInfo.ErrorMessage);

                    if (pSubscriptionTable == IntPtr.Zero)
                        continue;
                }
                else
                {
                    if (Header.g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                    {
                        Header.g_SubscriptionTablePointerAddressX86 = Utilities.GetSubscriptionTablePointerAddress(proc);

                        if (Header.g_SubscriptionTablePointerAddressX86 == IntPtr.Zero)
                        {
                            processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                            processInfo.ErrorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.";
                            Header.g_ProcessInfo.Add(processInfo);
                            proc.Dispose();

                            continue;
                        }
                    }

                    pSubscriptionTable = Utilities.GetSubscriptionTable(
                        proc,
                        Header.g_SubscriptionTablePointerAddressX86,
                        out processInfo.ErrorMessage);

                    if (pSubscriptionTable == IntPtr.Zero)
                        continue;
                }

                if (Header.g_IsWin11)
                    nameSubscriptions = Utilities.GetNameSubscriptionsWin11(proc, pSubscriptionTable);
                else
                    nameSubscriptions = Utilities.GetNameSubscriptions(proc, pSubscriptionTable);

                foreach (var stateName in nameSubscriptions.Keys)
                {
                    if (stateNames.ContainsKey(stateName))
                    {
                        stateNames[stateName].Add(processInfo);
                    }
                    else
                    {
                        stateNames.Add(stateName, new List<Header.PROCESS_INFORMATION>());
                        stateNames[stateName].Add(processInfo);
                    }
                }

                proc.Dispose();
            }

            if (stateNames.Count > 0)
            {
                Console.WriteLine("[+] Got {0} WNF State Names.", stateNames.Count);

                foreach (var entry in stateNames)
                {
                    if (stateNameFilter != 0UL && entry.Key != stateNameFilter)
                        continue;

                    Console.WriteLine(
                        "    |-> 0x{0} ({1})",
                        entry.Key.ToString("X16"),
                        Helpers.GetWnfName(entry.Key));
                }
            }
            else
            {
                Console.WriteLine("[-] Failed to list WNF State Names used in this system.");
            }

            if (deniedProcesses.Count > 0)
            {
                Console.WriteLine("[*] Access is denied by following {0} proccesses.", deniedProcesses.Count);

                foreach (var entry in deniedProcesses)
                    Console.WriteLine("    |-> {0} (PID : {1})", entry.Value, entry.Key);
            }

            Console.WriteLine("[*] Done.");
        }
    }
}
