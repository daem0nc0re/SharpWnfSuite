using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    class Utilities
    {
        public static void DumpWnfSubscriptionTable(
            PeProcess proc,
            IntPtr pSubscriptionTablePointer,
            ulong filterStateName)
        {
            Win32Struct.WNF_CONTEXT_HEADER header;
            string errorMessage;
            IntPtr buffer;
            IntPtr pSubscriptionTable;
            bool is64bit;
            Dictionary<ulong, IntPtr> nameSubscriptions;
            Dictionary<IntPtr, Dictionary<IntPtr, IntPtr>> userSubscriptions;
            Dictionary<IntPtr, IntPtr> callbackInfo;
            IntPtr pNameSubscription;
            IntPtr pUserSubscription;
            IntPtr pCallback;
            IntPtr pCallbackContext;
            ulong stateName;

            is64bit = (proc.GetArchitecture() == "x64");
            pSubscriptionTable = proc.ReadIntPtr(pSubscriptionTablePointer);

            if (proc.IsHeapAddress(pSubscriptionTable))
            {
                buffer = proc.ReadMemory(pSubscriptionTable, 4);
                header = (Win32Struct.WNF_CONTEXT_HEADER)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.WNF_CONTEXT_HEADER));
                Win32Api.LocalFree(buffer);

                if (header.NodeTypeCode == Win32Const.WNF_NODE_SUBSCRIPTION_TABLE ||
                    header.NodeByteSize == Marshal.SizeOf(typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE64)))
                {
                    Console.WriteLine("Process Name : {0}", proc.GetProcessName());
                    Console.WriteLine("Process ID   : {0}", proc.GetProcessId());
                    Console.WriteLine("Architecture : {0}", proc.GetArchitecture());

                    if (proc.GetArchitecture() == "x86" && Environment.Is64BitProcess)
                    {
                        errorMessage = "To get detailed symbol information of WOW64 process, should be built as 32 bit binary.";
                        Console.WriteLine("Warning      : {0}", errorMessage);
                    }

                    Console.WriteLine();
                }
                else
                {
                    errorMessage = "Failed to get valid WNF_SUBSCRIPTION_TABLE";
                    Console.WriteLine("Process Name  : {0}", proc.GetProcessName());
                    Console.WriteLine("Process ID    : {0}", proc.GetProcessId());
                    Console.WriteLine("Architecture  : {0}", proc.GetArchitecture());
                    Console.WriteLine("Error Message : {0}\n", errorMessage);

                    return;
                }
            }
            else
            {
                errorMessage = "Passed invalid pointer to WNF_SUBSCRIPTION_TABLE";
                Console.WriteLine("Process Name  : {0}", proc.GetProcessName());
                Console.WriteLine("Process ID    : {0}", proc.GetProcessId());
                Console.WriteLine("Architecture  : {0}", proc.GetArchitecture());
                Console.WriteLine("Error Message : {0}\n", errorMessage);

                return;
            }

            Console.WriteLine(
                "WNF_SUBSCRIPTION_TABLE @ 0x{0}\n",
                pSubscriptionTable.ToString(is64bit ? "X16" : "X8"));

            nameSubscriptions = GetNameSubscriptions(proc, pSubscriptionTable);

            foreach (var nameEntry in nameSubscriptions)
            {
                stateName = nameEntry.Key;
                pNameSubscription = nameEntry.Value;

                if (filterStateName != 0 && stateName != filterStateName)
                    continue;

                Console.WriteLine(
                    "\tWNF_NAME_SUBSCRIPTION @ 0x{0}",
                    pNameSubscription.ToString(is64bit ? "X16" : "X8"));
                Console.WriteLine(
                    "\tStateName : 0x{0} ({1})\n",
                    stateName.ToString("X16"),
                    Helpers.GetWnfName(stateName));

                if (Helpers.IsWin11())
                    userSubscriptions = GetUserSubscriptionsWin11(proc, pNameSubscription);
                else
                    userSubscriptions = GetUserSubscriptions(proc, pNameSubscription);

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

            return;
        }


        public static bool EnableDebugPrivilege()
        {
            int error;
            Win32Api.LookupPrivilegeValue(
                null,
                "SeDebugPrivilege",
                out Win32Struct.LUID luid);

            Win32Struct.TOKEN_PRIVILEGES tp = new Win32Struct.TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!Win32Api.AdjustTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                return false;
            }

            error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(pTokenPrivilege);

            if (error != 0)
                return false;

            return true;
        }


        public static Dictionary<ulong, IntPtr> GetNameSubscriptions(
            PeProcess proc,
            IntPtr pSubscriptionTable)
        {
            IntPtr buffer;
            IntPtr pFirstNameSubscription;
            IntPtr pNameSubscription;
            IntPtr pCurrentNameSubscription;
            uint nSizeSubscriptionTable;
            uint nSizeNameSubscription;
            uint nNameTableEntryOffset;
            var results = new Dictionary<ulong, IntPtr>();

            if (proc.GetArchitecture() == "x64")
            {
                nSizeSubscriptionTable = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE64));
                Win32Struct.WNF_NAME_SUBSCRIPTION64 nameSubscription;
                nSizeNameSubscription = (uint)Marshal.SizeOf(
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64));
                nNameTableEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64),
                    "NamesTableEntry").ToInt32();
                buffer = proc.ReadMemory(pSubscriptionTable, nSizeSubscriptionTable);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_SUBSCRIPTION_TABLE.");

                    return results;
                }

                var subscriptionTable = (Win32Struct.WNF_SUBSCRIPTION_TABLE64)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE64));
                Win32Api.LocalFree(buffer);

                pFirstNameSubscription = new IntPtr(subscriptionTable.NamesTableEntry.Flink - nNameTableEntryOffset);
                pNameSubscription = pFirstNameSubscription;

                while (true)
                {
                    pCurrentNameSubscription = pNameSubscription;
                    buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                    if (buffer == IntPtr.Zero)
                        break;

                    nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION64)Marshal.PtrToStructure(
                        buffer,
                        typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64));
                    Win32Api.LocalFree(buffer);
                    pNameSubscription = new IntPtr(nameSubscription.NamesTableEntry.Flink - nNameTableEntryOffset);

                    if (pNameSubscription == pFirstNameSubscription)
                        break;

                    results.Add(nameSubscription.StateName, pCurrentNameSubscription);
                }
            }
            else if (proc.GetArchitecture() == "x86")
            {
                nSizeSubscriptionTable = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE32));
                Win32Struct.WNF_NAME_SUBSCRIPTION32 nameSubscription;
                nSizeNameSubscription = (uint)Marshal.SizeOf(
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32));
                nNameTableEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32),
                    "NamesTableEntry").ToInt32();
                buffer = proc.ReadMemory(pSubscriptionTable, nSizeSubscriptionTable);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_SUBSCRIPTION_TABLE.");

                    return results;
                }

                var subscriptionTable = (Win32Struct.WNF_SUBSCRIPTION_TABLE32)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE32));
                Win32Api.LocalFree(buffer);

                pFirstNameSubscription = new IntPtr(subscriptionTable.NamesTableEntry.Flink - nNameTableEntryOffset);
                pNameSubscription = pFirstNameSubscription;

                while (true)
                {
                    pCurrentNameSubscription = pNameSubscription;
                    buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                    if (buffer == IntPtr.Zero)
                        break;

                    nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION32)Marshal.PtrToStructure(
                        buffer,
                        typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32));
                    Win32Api.LocalFree(buffer);
                    pNameSubscription = new IntPtr(nameSubscription.NamesTableEntry.Flink - nNameTableEntryOffset);

                    if (pNameSubscription == pFirstNameSubscription)
                        break;

                    results.Add(nameSubscription.StateName, pCurrentNameSubscription);
                }
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture.");
            }

            return results;
        }


        public static IntPtr GetSubscriptionTablePointerAddress(PeProcess proc)
        {
            if (proc.GetCurrentModuleName() != "ntdll.dll")
            {
                proc.SetBaseModule("ntdll.dll");
            }

            IntPtr pDataSection = proc.GetSectionAddress(".data");
            uint nSizeSubscriptionTable;
            uint nSizeDataSection = proc.GetSectionVirtualSize(".data");
            uint count;
            uint nSizePointer;
            Win32Struct.WNF_CONTEXT_HEADER tableHeader;
            IntPtr pointer;
            IntPtr buffer;
            IntPtr pSubscriptionTable = IntPtr.Zero;

            if (proc.GetArchitecture() == "x64")
            {
                nSizeSubscriptionTable = (uint)Marshal.SizeOf(
                    typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE64));
                nSizePointer = 8u;
                count = nSizeDataSection / nSizePointer;
            }
            else if (proc.GetArchitecture() == "x86")
            {
                nSizeSubscriptionTable = (uint)Marshal.SizeOf(
                    typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE32));
                nSizePointer = 4u;
                count = nSizeDataSection / nSizePointer;
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture.");

                return IntPtr.Zero;
            }

            for (var idx = 0u; idx < count; idx++)
            {
                pointer = proc.ReadIntPtr(pDataSection, idx * nSizePointer);

                if (proc.IsHeapAddress(pointer))
                {
                    buffer = proc.ReadMemory(pointer, nSizeSubscriptionTable);

                    if (buffer != IntPtr.Zero)
                    {
                        tableHeader = (Win32Struct.WNF_CONTEXT_HEADER)Marshal.PtrToStructure(
                            buffer,
                            typeof(Win32Struct.WNF_CONTEXT_HEADER));

                        Win32Api.LocalFree(buffer);
                    }
                    else
                    {
                        continue;
                    }

                    if ((tableHeader.NodeTypeCode == Win32Const.WNF_NODE_SUBSCRIPTION_TABLE) &&
                        (tableHeader.NodeByteSize == nSizeSubscriptionTable))
                    {
                        pSubscriptionTable = new IntPtr(
                            pDataSection.ToInt64() + idx * nSizePointer);
                    }
                }
            }

            return pSubscriptionTable;
        }


        public static Dictionary<IntPtr, Dictionary<IntPtr, IntPtr>> GetUserSubscriptions(
            PeProcess proc,
            IntPtr pNameSubscription)
        {
            IntPtr buffer;
            IntPtr pCurrentUserSubscription;
            IntPtr pFirstUserSubscription;
            IntPtr pUserSubscription;
            uint nSizeNameSubscription;
            uint nSizeUserSubscription;
            uint nSubscriptionsListEntryOffset;
            Dictionary<IntPtr, IntPtr> callback;
            var results = new Dictionary<IntPtr, Dictionary<IntPtr, IntPtr>>();

            if (proc.GetArchitecture() == "x64")
            {
                nSizeNameSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64));
                Win32Struct.WNF_USER_SUBSCRIPTION64 userSubscription;
                buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_NAME_SUBSCRIPTION.");

                    return results;
                }

                var nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION64)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64));
                Win32Api.LocalFree(buffer);

                nSizeUserSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_USER_SUBSCRIPTION64));
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_USER_SUBSCRIPTION64),
                    "SubscriptionsListEntry").ToInt32();

                if (nameSubscription.Header.NodeTypeCode == Win32Const.WNF_NODE_NAME_SUBSCRIPTION)
                {
                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUserSubscription = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (Win32Struct.WNF_USER_SUBSCRIPTION64)Marshal.PtrToStructure(
                            buffer,
                            typeof(Win32Struct.WNF_USER_SUBSCRIPTION64));
                        Win32Api.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        callback = new Dictionary<IntPtr, IntPtr> {
                            { new IntPtr(userSubscription.Callback), new IntPtr(userSubscription.CallbackContext) }
                        };

                        results.Add(
                            pCurrentUserSubscription,
                            callback);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Failed to get valid WNF_NAME_SUBSCRIPTION.");
                }
            }
            else if (proc.GetArchitecture() == "x86")
            {
                nSizeNameSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32));
                Win32Struct.WNF_USER_SUBSCRIPTION32 userSubscription;
                buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_NAME_SUBSCRIPTION.");

                    return results;
                }

                var nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION32)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32));
                Win32Api.LocalFree(buffer);

                nSizeUserSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_USER_SUBSCRIPTION32));
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_USER_SUBSCRIPTION32),
                    "SubscriptionsListEntry").ToInt32();

                if (nameSubscription.Header.NodeTypeCode == Win32Const.WNF_NODE_NAME_SUBSCRIPTION)
                {
                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUserSubscription = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (Win32Struct.WNF_USER_SUBSCRIPTION32)Marshal.PtrToStructure(
                            buffer,
                            typeof(Win32Struct.WNF_USER_SUBSCRIPTION32));
                        Win32Api.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        callback = new Dictionary<IntPtr, IntPtr> {
                            { new IntPtr(userSubscription.Callback), new IntPtr(userSubscription.CallbackContext) }
                        };

                        results.Add(
                            pCurrentUserSubscription,
                            callback);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Failed to get valid WNF_NAME_SUBSCRIPTION.");
                }
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture.");
            }

            return results;
        }


        public static Dictionary<IntPtr, Dictionary<IntPtr, IntPtr>> GetUserSubscriptionsWin11(
            PeProcess proc,
            IntPtr pNameSubscription)
        {
            IntPtr buffer;
            IntPtr pCurrentUserSubscription;
            IntPtr pFirstUserSubscription;
            IntPtr pUserSubscription;
            uint nSizeNameSubscription;
            uint nSizeUserSubscription;
            uint nSubscriptionsListEntryOffset;
            Dictionary<IntPtr, IntPtr> callback;
            var results = new Dictionary<IntPtr, Dictionary<IntPtr, IntPtr>>();

            if (proc.GetArchitecture() == "x64")
            {
                nSizeNameSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64_WIN11));
                Win32Struct.WNF_USER_SUBSCRIPTION64 userSubscription;
                buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_NAME_SUBSCRIPTION.");

                    return results;
                }

                var nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION64_WIN11)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64_WIN11));
                Win32Api.LocalFree(buffer);

                nSizeUserSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_USER_SUBSCRIPTION64));
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_USER_SUBSCRIPTION64),
                    "SubscriptionsListEntry").ToInt32();

                if (nameSubscription.Header.NodeTypeCode == Win32Const.WNF_NODE_NAME_SUBSCRIPTION)
                {
                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUserSubscription = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (Win32Struct.WNF_USER_SUBSCRIPTION64)Marshal.PtrToStructure(
                            buffer,
                            typeof(Win32Struct.WNF_USER_SUBSCRIPTION64));
                        Win32Api.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        callback = new Dictionary<IntPtr, IntPtr> {
                            { new IntPtr(userSubscription.Callback), new IntPtr(userSubscription.CallbackContext) }
                        };

                        results.Add(
                            pCurrentUserSubscription,
                            callback);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Failed to get valid WNF_NAME_SUBSCRIPTION.");
                }
            }
            else if (proc.GetArchitecture() == "x86")
            {
                nSizeNameSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32_WIN11));
                Win32Struct.WNF_USER_SUBSCRIPTION32 userSubscription;
                buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_NAME_SUBSCRIPTION.");

                    return results;
                }

                var nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION32_WIN11)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32_WIN11));
                Win32Api.LocalFree(buffer);

                nSizeUserSubscription = (uint)Marshal.SizeOf(typeof(Win32Struct.WNF_USER_SUBSCRIPTION32));
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_USER_SUBSCRIPTION32),
                    "SubscriptionsListEntry").ToInt32();

                if (nameSubscription.Header.NodeTypeCode == Win32Const.WNF_NODE_NAME_SUBSCRIPTION)
                {
                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUserSubscription = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (Win32Struct.WNF_USER_SUBSCRIPTION32)Marshal.PtrToStructure(
                            buffer,
                            typeof(Win32Struct.WNF_USER_SUBSCRIPTION32));
                        Win32Api.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        callback = new Dictionary<IntPtr, IntPtr> {
                            { new IntPtr(userSubscription.Callback), new IntPtr(userSubscription.CallbackContext) }
                        };

                        results.Add(
                            pCurrentUserSubscription,
                            callback);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Failed to get valid WNF_NAME_SUBSCRIPTION.");
                }
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture.");
            }

            return results;
        }
    }
}
