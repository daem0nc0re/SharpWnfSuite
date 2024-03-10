using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static void DumpAllWnfSubscriptionInformation(ulong stateName, bool brief)
        {
            Process[] procs = Process.GetProcesses();

            for (var idx = 0; idx < procs.Length; idx++)
                DumpWnfSubscriptionInformation(procs[idx].Id, stateName, brief);
        }


        public static void DumpWnfSubscriptionInformation(
            int pid,
            ulong stateNameFilter,
            bool brief)
        {
            NTSTATUS ntstatus;
            IntPtr hProcess;
            IntPtr pSubscriptionTable;
            IMAGE_FILE_MACHINE architecture;
            string imageFileName;
            bool bIs32BitProcess;
            Dictionary<ulong, IntPtr> nameSubscriptions;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";

            using (var objectAttributes = new OBJECT_ATTRIBUTES {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) })
            {
                var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
                ntstatus = NativeMethods.NtOpenProcess(
                    out hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                    in objectAttributes,
                    in clientId);
            }

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open the specified process (NTSTATUS = 0x{0})", ntstatus.ToString("X8"));
                return;
            }

            imageFileName = Helpers.GetProcessImageFileName(hProcess);
            architecture = Helpers.GetProcessArchitecture(hProcess);
            bIs32BitProcess = Helpers.Is32BitProcess(hProcess);

            Console.WriteLine("Process ID      : {0}", pid);
            Console.WriteLine("Image File Name : {0}", imageFileName ?? "(N/A)");
            Console.WriteLine("Architecture    : {0}\n", architecture.ToString());

            if (!bIs32BitProcess)
            {
                if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                    Globals.SubscriptionTablePointerAddress64 = Utilities.GetSubscriptionTablePointerAddress(hProcess);

                if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.");
                    return;
                }

                pSubscriptionTable = Utilities.GetSubscriptionTable(hProcess, Globals.SubscriptionTablePointerAddress64);

                if (pSubscriptionTable == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.");
                    return;
                }
            }
            else
            {
                if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                    Globals.SubscriptionTablePointerAddress32 = Utilities.GetSubscriptionTablePointerAddress(hProcess);

                if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.");
                    return;
                }

                pSubscriptionTable = Utilities.GetSubscriptionTable(hProcess, Globals.SubscriptionTablePointerAddress32);

                if (pSubscriptionTable == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.");
                    return;
                }
            }

            if (Globals.IsWin11)
                nameSubscriptions = Utilities.GetNameSubscriptionsWin11(hProcess, pSubscriptionTable);
            else
                nameSubscriptions = Utilities.GetNameSubscriptions(hProcess, pSubscriptionTable);

            Console.WriteLine("WNF_SUBSCRIPTION_TABLE @ 0x{0}\n", pSubscriptionTable.ToString(addressFormat));
            NativeMethods.SymSetOptions(SYM_OPTIONS.SYMOPT_DEFERRED_LOADS);

            foreach (var subscription in nameSubscriptions)
            {
                Dictionary<IntPtr, KeyValuePair<IntPtr, IntPtr>> userSubscriptions;
                var outputBuilder = new StringBuilder();

                if ((stateNameFilter != 0) && (subscription.Key != stateNameFilter))
                    continue;
                else if ((stateNameFilter != 0) && (subscription.Key == stateNameFilter))
                    outputBuilder.AppendFormat("WNF_SUBSCRIPTION_TABLE @ 0x{0}\n\n", pSubscriptionTable.ToString(addressFormat));

                outputBuilder.AppendFormat("\tWNF_NAME_SUBSCRIPTION @ 0x{0}\n", subscription.Value.ToString(addressFormat));
                outputBuilder.AppendFormat("\tStateName : 0x{0} ({1})\n\n",
                    subscription.Key.ToString("X16"),
                    Helpers.GetWnfName(subscription.Key));

                if (!brief)
                {
                    userSubscriptions = Utilities.GetUserSubscriptions(hProcess, subscription.Value);

                    foreach (var entry in userSubscriptions)
                    {
                        outputBuilder.AppendFormat("\t\tWNF_USER_SUBSCRIPTION @ 0x{0}\n", entry.Key.ToString(addressFormat));
                        outputBuilder.AppendFormat("\t\tCallback @ 0x{0} ({1})\n",
                            entry.Value.Key.ToString(addressFormat),
                            Helpers.GetSymbolPath(hProcess, entry.Value.Key) ?? "N/A");
                        outputBuilder.AppendFormat("\t\tContext  @ 0x{0} ({1})\n\n",
                            entry.Value.Value.ToString(addressFormat),
                            Helpers.GetSymbolPath(hProcess, entry.Value.Value) ?? "N/A");
                    }
                }

                Console.Write(outputBuilder.ToString());
            }
        }


        public static void DumpWnfSubscriptionInformationByName(
            string processName,
            ulong stateName,
            bool brief)
        {
            try
            {
                Process[] procs = Process.GetProcessesByName(processName);

                for (var idx = 0; idx < procs.Length; idx++)
                    DumpWnfSubscriptionInformation(procs[idx].Id, stateName, brief);
            }
            catch
            {
                Console.WriteLine("[!] Failed to resolve process name.");
            }
        }


        public static void ListStateNames(ulong stateNameFilter)
        {
            int pid;
            PeProcess proc;
            bool is64bit;
            IntPtr pSubscriptionTable;
            Dictionary<ulong, IntPtr> nameSubscriptions;
            PROCESS_INFORMATION processInfo;
            var stateNames = new Dictionary<ulong, List<PROCESS_INFORMATION>>();
            var deniedProcesses = new Dictionary<int, string>();

            Process[] procs = Process.GetProcesses();

            Console.WriteLine("[>] Trying to list WNF State Names used in this system. Wait a moment.");

            for (var idx = 0; idx < procs.Length; idx++)
            {
                pid = procs[idx].Id;

                processInfo = new PROCESS_INFORMATION {
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
                    Globals.ProcessInfo.Add(processInfo);

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
                    Globals.ProcessInfo.Add(processInfo);

                    continue;
                }
                catch (KeyNotFoundException ex)
                {
                    processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                    processInfo.ErrorMessage = ex.Message;
                    Globals.ProcessInfo.Add(processInfo);

                    continue;
                }

                is64bit = (proc.GetArchitecture() == "x64");

                if (is64bit)
                {
                    if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                    {
                        Globals.SubscriptionTablePointerAddress64 = Utilities.GetSubscriptionTablePointerAddress(proc.GetProcessHandle());

                        if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                        {
                            processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                            processInfo.ErrorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.";
                            Globals.ProcessInfo.Add(processInfo);
                            proc.Dispose();

                            continue;
                        }
                    }

                    pSubscriptionTable = Utilities.GetSubscriptionTable(
                        proc.GetProcessHandle(),
                        Globals.SubscriptionTablePointerAddress64);

                    if (pSubscriptionTable == IntPtr.Zero)
                        continue;
                }
                else
                {
                    if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                    {
                        Globals.SubscriptionTablePointerAddress32 = Utilities.GetSubscriptionTablePointerAddress(proc.GetProcessHandle());

                        if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                        {
                            processInfo.ProcessName = Process.GetProcessById(pid).ProcessName;
                            processInfo.ErrorMessage = "Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.";
                            Globals.ProcessInfo.Add(processInfo);
                            proc.Dispose();

                            continue;
                        }
                    }

                    pSubscriptionTable = Utilities.GetSubscriptionTable(
                        proc.GetProcessHandle(),
                        Globals.SubscriptionTablePointerAddress32);

                    if (pSubscriptionTable == IntPtr.Zero)
                        continue;
                }

                if (Globals.IsWin11)
                    nameSubscriptions = Utilities.GetNameSubscriptionsWin11(proc.GetProcessHandle(), pSubscriptionTable);
                else
                    nameSubscriptions = Utilities.GetNameSubscriptions(proc.GetProcessHandle(), pSubscriptionTable);

                foreach (var stateName in nameSubscriptions.Keys)
                {
                    if (stateNames.ContainsKey(stateName))
                    {
                        stateNames[stateName].Add(processInfo);
                    }
                    else
                    {
                        stateNames.Add(stateName, new List<PROCESS_INFORMATION>());
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
