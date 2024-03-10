using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static void DumpAllWnfSubscriptionInformation(ulong stateName, bool bVerbose)
        {
            Process[] procs = Process.GetProcesses();

            for (var idx = 0; idx < procs.Length; idx++)
                DumpWnfSubscriptionInformation(procs[idx].Id, stateName, bVerbose);
        }


        public static void DumpWnfSubscriptionInformation(
            int pid,
            ulong stateNameFilter,
            bool bVerbose)
        {
            IMAGE_FILE_MACHINE architecture;
            string imageFileName;
            bool bIs32BitProcess;
            Dictionary<ulong, IntPtr> nameSubscriptions;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
            var pSubscriptionTable = IntPtr.Zero;
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                in objectAttributes,
                in clientId);

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

            do
            {
                if (!bIs32BitProcess)
                {
                    if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                        Globals.SubscriptionTablePointerAddress64 = Utilities.GetSubscriptionTablePointerAddress(hProcess);

                    if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                        break;

                    pSubscriptionTable = Utilities.GetSubscriptionTable(hProcess, Globals.SubscriptionTablePointerAddress64);
                }
                else
                {
                    if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                        Globals.SubscriptionTablePointerAddress32 = Utilities.GetSubscriptionTablePointerAddress(hProcess);

                    if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                        break;

                    pSubscriptionTable = Utilities.GetSubscriptionTable(hProcess, Globals.SubscriptionTablePointerAddress32);
                }
            } while (false);

            if (pSubscriptionTable == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get valid pointer for WNF_SUBSCRIPTION_TABLE.");
                NativeMethods.NtClose(hProcess);
                return;
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

                outputBuilder.AppendFormat("    WNF_NAME_SUBSCRIPTION @ 0x{0}\n", subscription.Value.ToString(addressFormat));
                outputBuilder.AppendFormat("    StateName : 0x{0} ({1})\n\n",
                    subscription.Key.ToString("X16"),
                    Helpers.GetWnfName(subscription.Key));

                if (bVerbose)
                {
                    userSubscriptions = Utilities.GetUserSubscriptions(hProcess, subscription.Value);

                    foreach (var entry in userSubscriptions)
                    {
                        outputBuilder.AppendFormat("        WNF_USER_SUBSCRIPTION @ 0x{0}\n", entry.Key.ToString(addressFormat));
                        outputBuilder.AppendFormat("        Callback @ 0x{0} ({1})\n",
                            entry.Value.Key.ToString(addressFormat),
                            Helpers.GetSymbolPath(hProcess, entry.Value.Key) ?? "N/A");
                        outputBuilder.AppendFormat("        Context  @ 0x{0} ({1})\n\n",
                            entry.Value.Value.ToString(addressFormat),
                            Helpers.GetSymbolPath(hProcess, entry.Value.Value) ?? "N/A");
                    }
                }

                Console.Write(outputBuilder.ToString());
            }

            NativeMethods.NtClose(hProcess);
        }


        public static void DumpWnfSubscriptionInformationByName(
            string processName,
            ulong stateName,
            bool bVerbose)
        {
            try
            {
                Process[] procs = Process.GetProcessesByName(processName);

                for (var idx = 0; idx < procs.Length; idx++)
                    DumpWnfSubscriptionInformation(procs[idx].Id, stateName, bVerbose);
            }
            catch
            {
                Console.WriteLine("[!] Failed to resolve process name.");
            }
        }


        public static void ListStateNames(ulong stateNameFilter, bool bVerbose)
        {
            var allowedProcesses = new Dictionary<int, string>();
            var deniedProcesses = new Dictionary<int, string>();
            var stateNames = new Dictionary<ulong, List<int>>();
            var outputBuilder = new StringBuilder();
            Process[] procs = Process.GetProcesses();

            Console.WriteLine("[>] Trying to list WNF State Names used in this system. Wait a moment.");

            for (var idx = 0; idx < procs.Length; idx++)
            {
                bool bIs32BitProcess;
                Dictionary<ulong, IntPtr> nameSubscriptions;
                var pSubscriptionTable = IntPtr.Zero;
                var objectAttributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                };
                var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(procs[idx].Id) };
                NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                    out IntPtr hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    deniedProcesses.Add(procs[idx].Id, procs[idx].ProcessName);
                    continue;
                }

                allowedProcesses.Add(procs[idx].Id, procs[idx].ProcessName);
                bIs32BitProcess = Helpers.Is32BitProcess(hProcess);

                do
                {
                    if (!bIs32BitProcess)
                    {
                        if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                            Globals.SubscriptionTablePointerAddress64 = Utilities.GetSubscriptionTablePointerAddress(hProcess);

                        if (Globals.SubscriptionTablePointerAddress64 == IntPtr.Zero)
                            break;

                        pSubscriptionTable = Utilities.GetSubscriptionTable(hProcess, Globals.SubscriptionTablePointerAddress64);
                    }
                    else
                    {
                        if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                            Globals.SubscriptionTablePointerAddress32 = Utilities.GetSubscriptionTablePointerAddress(hProcess);

                        if (Globals.SubscriptionTablePointerAddress32 == IntPtr.Zero)
                            break;

                        pSubscriptionTable = Utilities.GetSubscriptionTable(hProcess, Globals.SubscriptionTablePointerAddress32);
                    }
                } while (false);

                if (pSubscriptionTable == IntPtr.Zero)
                {
                    NativeMethods.NtClose(hProcess);
                    continue;
                }

                if (Globals.IsWin11)
                    nameSubscriptions = Utilities.GetNameSubscriptionsWin11(hProcess, pSubscriptionTable);
                else
                    nameSubscriptions = Utilities.GetNameSubscriptions(hProcess, pSubscriptionTable);

                foreach (var stateName in nameSubscriptions.Keys)
                {
                    if (stateNames.ContainsKey(stateName))
                        stateNames[stateName].Add(procs[idx].Id);
                    else
                        stateNames.Add(stateName, new List<int> { procs[idx].Id });
                }

                NativeMethods.NtClose(hProcess);
            }

            if (stateNames.Count > 0)
            {
                outputBuilder.AppendFormat("\n[{0} WNF State Names]\n\n", stateNames.Count);

                foreach (var entry in stateNames)
                {
                    string lineFormat;
                    var columnNames = new string[] { "PID", "Process Name", "Image File Name" };
                    var widths = new int[columnNames.Length];

                    if (stateNameFilter != 0UL && entry.Key != stateNameFilter)
                        continue;

                    outputBuilder.AppendFormat("[*] 0x{0} ({1})\n",
                        entry.Key.ToString("X16"),
                        Helpers.GetWnfName(entry.Key));

                    if (!bVerbose)
                        continue;

                    for (var idx = 0; idx < columnNames.Length; idx++)
                        widths[idx] = columnNames[idx].Length;

                    foreach (var pid in entry.Value)
                    {
                        if (pid.ToString().Length > widths[0])
                            widths[0] = pid.ToString().Length;

                        if (allowedProcesses[pid].Length > widths[1])
                            widths[1] = allowedProcesses[pid].Length;
                    }

                    lineFormat = string.Format("    {{0, {0}}} {{1, -{1}}} {{2, -{2}}}\n",
                        widths[0],
                        widths[1],
                        widths[2]);

                    outputBuilder.AppendLine();
                    outputBuilder.AppendFormat(lineFormat, columnNames[0], columnNames[1], columnNames[2]);
                    outputBuilder.AppendFormat(lineFormat,
                        new string('=', widths[0]),
                        new string('=', widths[1]),
                        new string('=', widths[2]));

                    foreach (var pid in entry.Value)
                    {
                        var objectAttributes = new OBJECT_ATTRIBUTES
                        {
                            Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                        };
                        var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
                        NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                            out IntPtr hProcess,
                            ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                            in objectAttributes,
                            in clientId);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        {
                            outputBuilder.AppendFormat(lineFormat, pid, allowedProcesses[pid], "(N/A)");
                            continue;
                        }

                        outputBuilder.AppendFormat(lineFormat,
                            pid,
                            allowedProcesses[pid],
                            Helpers.GetProcessImageFileName(hProcess) ?? "(N/A)");

                        NativeMethods.NtClose(hProcess);
                    }

                    outputBuilder.AppendLine();
                }
            }
            else
            {
                outputBuilder.AppendLine("[-] Failed to list WNF State Names used in this system.");
            }

            if (deniedProcesses.Count > 0)
            {
                outputBuilder.AppendFormat("\n[{0} Access Denied Processes]\n\n", deniedProcesses.Count);

                foreach (var entry in deniedProcesses)
                    outputBuilder.AppendFormat("[*] {0} (PID : {1})\n", entry.Value, entry.Key);

                outputBuilder.AppendLine();
            }

            Console.Write(outputBuilder.ToString());

            Console.WriteLine("[*] Done.");
        }
    }
}
