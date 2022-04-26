using System;
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
            Win32Struct.SYMBOL_INFO symbolInfo = new Win32Struct.SYMBOL_INFO();
            StringBuilder pathBuilder = new StringBuilder();
            string symCallback;
            string symCallbackContext;
            string errorMessage;
            IntPtr buffer;
            IntPtr pSubscriptionTable;
            IntPtr pNameSubscription;
            IntPtr pUserSubscription;
            IntPtr pCurrentName;
            IntPtr pCurrentUser;
            Type tSubscriptionTable;
            Type tNameSubscription;
            Type tUserSubscription;
            IntPtr pCallback;
            IntPtr pCallbackContext;
            IntPtr pFirstNameSubscription;
            IntPtr pFirstUserSubscription;
            ulong stateName;
            uint nSizeSubscriptionTable;
            uint nSizeNameSubscription;
            uint nSizeUserSubscription;
            uint nNameTableEntryOffset;
            uint nSubscriptionsListEntryOffset;
            symbolInfo.SizeOfStruct = (uint)Marshal.SizeOf(typeof(Win32Struct.SYMBOL_INFO)) - Win32Const.MAX_SYM_NAME;
            symbolInfo.MaxNameLen = Win32Const.MAX_SYM_NAME;
            symbolInfo.Name = new byte[Win32Const.MAX_SYM_NAME];

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

            Win32Api.SymInitialize(proc.GetProcessHandle(), null, true);

            if (proc.GetArchitecture() == "x64")
            {
                Console.WriteLine("WNF_SUBSCRIPTION_TABLE @ 0x{0}\n", pSubscriptionTable.ToString("X16"));

                Win32Struct.WNF_SUBSCRIPTION_TABLE64 subscriptionTable;
                Win32Struct.WNF_NAME_SUBSCRIPTION64 nameSubscription;
                Win32Struct.WNF_USER_SUBSCRIPTION64 userSubscription;
                tSubscriptionTable = typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE64);
                tNameSubscription = typeof(Win32Struct.WNF_NAME_SUBSCRIPTION64);
                tUserSubscription = typeof(Win32Struct.WNF_USER_SUBSCRIPTION64);
                nSizeSubscriptionTable = (uint)Marshal.SizeOf(tSubscriptionTable);
                nSizeNameSubscription = (uint)Marshal.SizeOf(tNameSubscription);
                nSizeUserSubscription = (uint)Marshal.SizeOf(tUserSubscription);
                nNameTableEntryOffset = (uint)Marshal.OffsetOf(
                    tNameSubscription,
                    "NamesTableEntry").ToInt32();
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    tUserSubscription,
                    "SubscriptionsListEntry").ToInt32();

                buffer = proc.ReadMemory(pSubscriptionTable, nSizeSubscriptionTable);
                subscriptionTable = (Win32Struct.WNF_SUBSCRIPTION_TABLE64)Marshal.PtrToStructure(
                    buffer,
                    tSubscriptionTable);
                Win32Api.LocalFree(buffer);

                pFirstNameSubscription = new IntPtr(subscriptionTable.NamesTableEntry.Flink - nNameTableEntryOffset);
                pNameSubscription = pFirstNameSubscription;

                while (true)
                {
                    pCurrentName = pNameSubscription;
                    buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                    if (buffer == IntPtr.Zero)
                        break;

                    nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION64)Marshal.PtrToStructure(
                        buffer,
                        tNameSubscription);
                    Win32Api.LocalFree(buffer);
                    stateName = nameSubscription.StateName;
                    pNameSubscription = new IntPtr(nameSubscription.NamesTableEntry.Flink - nNameTableEntryOffset);

                    if (pNameSubscription == pFirstNameSubscription)
                        break;

                    if (filterStateName != 0 && stateName != filterStateName)
                        continue;

                    Console.WriteLine("\tWNF_NAME_SUBSCRIPTION @ 0x{0}", pCurrentName.ToString("X16"));
                    Console.WriteLine("\tStateName : 0x{0} ({1})\n", stateName.ToString("X16"), Helpers.GetWnfName(stateName));

                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUser = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (Win32Struct.WNF_USER_SUBSCRIPTION64)Marshal.PtrToStructure(
                            buffer,
                            tUserSubscription);
                        Win32Api.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);
                        
                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        pCallback = new IntPtr(userSubscription.Callback);
                        pCallbackContext = new IntPtr(userSubscription.CallbackContext);

                        pathBuilder.Clear();
                        pathBuilder.Capacity = (int)Win32Const.MAX_PATH;
                        Helpers.ZeroMemory(ref symbolInfo.Name, (int)Win32Const.MAX_PATH);
                        Win32Api.GetMappedFileName(
                            proc.GetProcessHandle(),
                            pCallback,
                            pathBuilder,
                            (uint)pathBuilder.Capacity);

                        if (Win32Api.SymFromAddr(
                            proc.GetProcessHandle(),
                            pCallback.ToInt64(),
                            IntPtr.Zero,
                            ref symbolInfo))
                        {
                            symCallback = string.Format(
                                "{0}!{1}",
                                Path.GetFileName(pathBuilder.ToString()),
                                Encoding.ASCII.GetString(symbolInfo.Name).TrimEnd('\0'));
                        }
                        else
                        {
                            symCallback = Path.GetFileName(pathBuilder.ToString());
                        }

                        if (string.IsNullOrEmpty(symCallback))
                        {
                            symCallback = "N/A";
                        }

                        pathBuilder.Clear();
                        pathBuilder.Capacity = (int)Win32Const.MAX_PATH;
                        Helpers.ZeroMemory(ref symbolInfo.Name, (int)Win32Const.MAX_PATH);
                        Win32Api.GetMappedFileName(
                            proc.GetProcessHandle(),
                            pCallbackContext,
                            pathBuilder,
                            (uint)pathBuilder.Capacity);

                        if (Win32Api.SymFromAddr(
                            proc.GetProcessHandle(),
                            pCallbackContext.ToInt64(),
                            IntPtr.Zero,
                            ref symbolInfo))
                        {
                            symCallbackContext = string.Format(
                                "{0}!{1}",
                                Path.GetFileName(pathBuilder.ToString()),
                                Encoding.ASCII.GetString(symbolInfo.Name).TrimEnd('\0'));
                        }
                        else
                        {
                            symCallbackContext = Path.GetFileName(pathBuilder.ToString());
                        }

                        if (string.IsNullOrEmpty(symCallbackContext))
                        {
                            symCallbackContext = "N/A";
                        }

                        Console.WriteLine("\t\tWNF_USER_SUBSCRIPTION @ 0x{0}", pCurrentUser.ToString("X16"));
                        Console.WriteLine("\t\tCallback @ 0x{0} ({1})", pCallback.ToString("X16"), symCallback);
                        Console.WriteLine("\t\tContext  @ 0x{0} ({1})\n", pCallbackContext.ToString("X16"), symCallbackContext);
                    }
                }
            }
            else if (proc.GetArchitecture() == "x86")
            {
                Console.WriteLine("WNF_SUBSCRIPTION_TABLE @ 0x{0}\n", pSubscriptionTable.ToString("X8"));

                Win32Struct.WNF_SUBSCRIPTION_TABLE32 subscriptionTable;
                Win32Struct.WNF_NAME_SUBSCRIPTION32 nameSubscription;
                Win32Struct.WNF_USER_SUBSCRIPTION32 userSubscription;
                tSubscriptionTable = typeof(Win32Struct.WNF_SUBSCRIPTION_TABLE32);
                tNameSubscription = typeof(Win32Struct.WNF_NAME_SUBSCRIPTION32);
                tUserSubscription = typeof(Win32Struct.WNF_USER_SUBSCRIPTION32);
                nSizeSubscriptionTable = (uint)Marshal.SizeOf(tSubscriptionTable);
                nSizeNameSubscription = (uint)Marshal.SizeOf(tNameSubscription);
                nSizeUserSubscription = (uint)Marshal.SizeOf(tUserSubscription);
                nNameTableEntryOffset = (uint)Marshal.OffsetOf(
                    tNameSubscription,
                    "NamesTableEntry").ToInt32();
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    tUserSubscription,
                    "SubscriptionsListEntry").ToInt32();

                buffer = proc.ReadMemory(pSubscriptionTable, nSizeSubscriptionTable);
                subscriptionTable = (Win32Struct.WNF_SUBSCRIPTION_TABLE32)Marshal.PtrToStructure(
                    buffer,
                    tSubscriptionTable);
                Win32Api.LocalFree(buffer);

                pFirstNameSubscription = new IntPtr(subscriptionTable.NamesTableEntry.Flink - nNameTableEntryOffset);
                pNameSubscription = pFirstNameSubscription;

                while (true)
                {
                    pCurrentName = pNameSubscription;
                    buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                    if (buffer == IntPtr.Zero)
                        break;

                    nameSubscription = (Win32Struct.WNF_NAME_SUBSCRIPTION32)Marshal.PtrToStructure(
                        buffer,
                        tNameSubscription);
                    Win32Api.LocalFree(buffer);
                    stateName = nameSubscription.StateName;
                    pNameSubscription = new IntPtr(nameSubscription.NamesTableEntry.Flink - nNameTableEntryOffset);

                    if (pNameSubscription == pFirstNameSubscription)
                        break;

                    if (filterStateName != 0 && stateName != filterStateName)
                        continue;

                    Console.WriteLine("\tWNF_NAME_SUBSCRIPTION @ 0x{0}", pCurrentName.ToString("X8"));
                    Console.WriteLine("\tStateName : 0x{0} ({1})\n", stateName.ToString("X8"), Helpers.GetWnfName(stateName));

                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUser = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (Win32Struct.WNF_USER_SUBSCRIPTION32)Marshal.PtrToStructure(
                            buffer,
                            tUserSubscription);
                        Win32Api.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        pCallback = new IntPtr(userSubscription.Callback);
                        pCallbackContext = new IntPtr(userSubscription.CallbackContext);

                        pathBuilder.Clear();
                        pathBuilder.Capacity = (int)Win32Const.MAX_PATH;
                        Win32Api.GetMappedFileName(
                            proc.GetProcessHandle(),
                            pCallback,
                            pathBuilder,
                            (uint)pathBuilder.Capacity);

                        if (Win32Api.SymFromAddr(
                            proc.GetProcessHandle(),
                            pCallback.ToInt64(),
                            IntPtr.Zero,
                            ref symbolInfo))
                        {
                            symCallback = string.Format(
                                "{0}!{1}",
                                Path.GetFileName(pathBuilder.ToString()),
                                Encoding.ASCII.GetString(symbolInfo.Name));
                        }
                        else
                        {
                            symCallback = Path.GetFileName(pathBuilder.ToString());
                        }

                        if (string.IsNullOrEmpty(symCallback))
                        {
                            symCallback = "N/A";
                        }

                        pathBuilder.Clear();
                        pathBuilder.Capacity = (int)Win32Const.MAX_PATH;
                        Win32Api.GetMappedFileName(
                            proc.GetProcessHandle(),
                            pCallbackContext,
                            pathBuilder,
                            (uint)pathBuilder.Capacity);

                        if (Win32Api.SymFromAddr(
                            proc.GetProcessHandle(),
                            pCallbackContext.ToInt64(),
                            IntPtr.Zero,
                            ref symbolInfo))
                        {
                            symCallbackContext = string.Format(
                                "{0}!{1}",
                                Path.GetFileName(pathBuilder.ToString()),
                                Encoding.ASCII.GetString(symbolInfo.Name));
                        }
                        else
                        {
                            symCallbackContext = Path.GetFileName(pathBuilder.ToString());
                        }

                        if (string.IsNullOrEmpty(symCallbackContext))
                        {
                            symCallbackContext = "N/A";
                        }

                        Console.WriteLine("\t\tWNF_USER_SUBSCRIPTION @ 0x{0}", pCurrentUser.ToString("X8"));
                        Console.WriteLine("\t\tCallback @ 0x{0} ({1})", pCallback.ToString("X8"), symCallback);
                        Console.WriteLine("\t\tContext  @ 0x{0} ({1})\n", pCallbackContext.ToString("X8"), symCallbackContext);
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture.");
            }

            Win32Api.SymCleanup(proc.GetProcessHandle());

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
    }
}
