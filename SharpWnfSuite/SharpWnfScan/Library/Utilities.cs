using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool EnableDebugPrivilege()
        {
            NTSTATUS ntstatus;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            var tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid.LowPart = 0x00000014;
            tp.Privileges[0].Luid.HighPart = 0;
            tp.Privileges[0].Attributes = (uint)PrivilegeAttributeFlags.ENABLED;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                WindowsIdentity.GetCurrent().Token,
                BOOLEAN.FALSE,
                pTokenPrivilege,
                0u,
                IntPtr.Zero,
                IntPtr.Zero);
            Marshal.FreeHGlobal(pTokenPrivilege);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static Dictionary<ulong, IntPtr> GetNameSubscriptions(
            IntPtr hProcess,
            IntPtr pSubscriptionTable)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(0x100);
            var results = new Dictionary<ulong, IntPtr>();

            do
            {
                NTSTATUS ntstatus;
                IntPtr pRootNameSubscription;
                IntPtr pNameSubscription;
                uint nSubscriptionTableSize;
                uint nNameSubscriptionSize;
                uint nNamesTableEntryOffset;
                bool bIs32BitProcess = Helpers.Is32BitProcess(hProcess);
                string fieldName = "NamesTableEntry";

                if (!bIs32BitProcess)
                {
                    nSubscriptionTableSize = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE64));
                    nNameSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION64));
                    nNamesTableEntryOffset = (uint)Marshal.OffsetOf(typeof(WNF_NAME_SUBSCRIPTION64), fieldName).ToInt32();
                }
                else
                {
                    nSubscriptionTableSize = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE32));
                    nNameSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION32));
                    nNamesTableEntryOffset = (uint)Marshal.OffsetOf(typeof(WNF_NAME_SUBSCRIPTION32), fieldName).ToInt32();
                }

                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pSubscriptionTable,
                    pInfoBuffer,
                    nSubscriptionTableSize,
                    out uint nReturnedSize);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nSubscriptionTableSize != nReturnedSize))
                    break;

                if (!bIs32BitProcess)
                {
                    var subscriptionTable64 = (WNF_SUBSCRIPTION_TABLE64)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_SUBSCRIPTION_TABLE64));
                    pRootNameSubscription = new IntPtr(subscriptionTable64.NamesTableEntry.Flink - nNamesTableEntryOffset);
                }
                else
                {
                    var subscriptionTable32 = (WNF_SUBSCRIPTION_TABLE32)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_SUBSCRIPTION_TABLE32));
                    pRootNameSubscription = new IntPtr(subscriptionTable32.NamesTableEntry.Flink - (int)nNamesTableEntryOffset);
                }

                pNameSubscription = pRootNameSubscription;

                while (true)
                {
                    ulong stateName;
                    IntPtr pNameSubsctiptionSaved = pNameSubscription;
                    ntstatus = NativeMethods.NtReadVirtualMemory(
                        hProcess,
                        pNameSubscription,
                        pInfoBuffer,
                        nNameSubscriptionSize,
                        out nReturnedSize);

                    if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nNameSubscriptionSize != nReturnedSize))
                        break;

                    if (!bIs32BitProcess)
                    {
                        var nameSubscription64 = (WNF_NAME_SUBSCRIPTION64)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(WNF_NAME_SUBSCRIPTION64));
                        pNameSubscription = new IntPtr(nameSubscription64.NamesTableEntry.Flink - nNamesTableEntryOffset);
                        stateName = nameSubscription64.StateName;
                    }
                    else
                    {
                        var nameSubscription32 = (WNF_NAME_SUBSCRIPTION32)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(WNF_NAME_SUBSCRIPTION32));
                        pNameSubscription = new IntPtr(nameSubscription32.NamesTableEntry.Flink - (int)nNamesTableEntryOffset);
                        stateName = nameSubscription32.StateName;
                    }

                    if (pNameSubscription == pRootNameSubscription)
                        break;

                    results.Add(stateName, pNameSubsctiptionSaved);
                }
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            return results;
        }


        public static Dictionary<ulong, IntPtr> GetNameSubscriptionsWin11(
            IntPtr hProcess,
            IntPtr pSubscriptionTable)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(0x100);
            var results = new Dictionary<ulong, IntPtr>();

            do
            {
                NTSTATUS ntstatus;
                IntPtr pNameSubscription;
                uint nSubscriptionTableSize;
                uint nNameTableEntryOffset;
                bool bIs32BitProcess = Helpers.Is32BitProcess(hProcess);
                string fieldName = "NamesTableEntry";

                if (!bIs32BitProcess)
                {
                    nSubscriptionTableSize = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE64_WIN11));
                    nNameTableEntryOffset = (uint)Marshal.OffsetOf(typeof(WNF_NAME_SUBSCRIPTION64_WIN11), fieldName).ToInt32();
                }
                else
                {
                    nSubscriptionTableSize = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE32_WIN11));
                    nNameTableEntryOffset = (uint)Marshal.OffsetOf(typeof(WNF_NAME_SUBSCRIPTION32_WIN11), fieldName).ToInt32();
                }

                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pSubscriptionTable,
                    pInfoBuffer,
                    nSubscriptionTableSize,
                    out uint nReturnedSize);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nSubscriptionTableSize != nReturnedSize))
                    break;

                if (!bIs32BitProcess)
                {
                    var subscriptionTable64 = (WNF_SUBSCRIPTION_TABLE64_WIN11)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_SUBSCRIPTION_TABLE64_WIN11));
                    pNameSubscription = new IntPtr(subscriptionTable64.NamesTableEntry.Root - nNameTableEntryOffset);
                }
                else
                {
                    var subscriptionTable32 = (WNF_SUBSCRIPTION_TABLE32_WIN11)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_SUBSCRIPTION_TABLE32_WIN11));
                    pNameSubscription = new IntPtr(subscriptionTable32.NamesTableEntry.Root - nNameTableEntryOffset);
                }

                ListWin11NameSubscriptions(hProcess, pNameSubscription, bIs32BitProcess, ref results);
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            return results;
        }


        public static IntPtr GetSubscriptionTable(IntPtr hProcess, IntPtr pTablePointer)
        {
            IntPtr pSubscriptionTable;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(0x10);

            do
            {
                WNF_CONTEXT_HEADER header;
                var nInfoLength = (uint)IntPtr.Size;
                NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pTablePointer,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nReturnedLength);
                pSubscriptionTable = Marshal.ReadIntPtr(pInfoBuffer);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nInfoLength != nReturnedLength))
                {
                    pSubscriptionTable = IntPtr.Zero;
                    break;
                }

                if (!Helpers.IsHeapAddress(hProcess, pSubscriptionTable))
                {
                    pSubscriptionTable = IntPtr.Zero;
                    break;
                }

                nInfoLength = (uint)Marshal.SizeOf(typeof(WNF_CONTEXT_HEADER));
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pSubscriptionTable,
                    pInfoBuffer,
                    nInfoLength,
                    out nReturnedLength);
                header = (WNF_CONTEXT_HEADER)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(WNF_CONTEXT_HEADER));

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nInfoLength != nReturnedLength))
                {
                    pSubscriptionTable = IntPtr.Zero;
                    break;
                }

                if ((header.NodeTypeCode != Win32Consts.WNF_NODE_SUBSCRIPTION_TABLE) &&
                    (header.NodeByteSize != Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE64))))
                {
                    pSubscriptionTable = IntPtr.Zero;
                }
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            return pSubscriptionTable;
        }


        public static IntPtr GetSubscriptionTablePointerAddress(IntPtr hProcess)
        {
            IntPtr pNtdll;
            IntPtr pDataSection;
            IntPtr pInfoBuffer;
            uint nIndexLimit;
            uint nPointerSize;
            uint nSubscriptionTableSize;
            Dictionary<string, IMAGE_SECTION_HEADER> sectionHeaders;
            var pSubscriptionTable = IntPtr.Zero;
            var modules = Helpers.GetProcessModules(
                hProcess,
                out Dictionary<string, IntPtr> wow32Modules);

            if (wow32Modules.Count > 0)
            {
                if (!wow32Modules.ContainsKey("ntdll.dll"))
                    return IntPtr.Zero;

                pNtdll = wow32Modules["ntdll.dll"];
                nPointerSize = 4u;
                nSubscriptionTableSize = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE32));
            }
            else
            {
                if (!modules.ContainsKey("ntdll.dll"))
                    return IntPtr.Zero;

                pNtdll = modules["ntdll.dll"];
                nPointerSize = Environment.Is64BitProcess ? 8u : 4u;

                if (Environment.Is64BitProcess)
                    nSubscriptionTableSize = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE64));
                else
                    nSubscriptionTableSize = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE32));
            }

            sectionHeaders = Helpers.GetModuleSectionHeaders(hProcess, pNtdll);

            if (!sectionHeaders.ContainsKey(".data"))
                return IntPtr.Zero;

            if (Environment.Is64BitProcess)
                pDataSection = new IntPtr(pNtdll.ToInt64() + sectionHeaders[".data"].VirtualAddress);
            else
                pDataSection = new IntPtr(pNtdll.ToInt32() + (int)sectionHeaders[".data"].VirtualAddress);

            nIndexLimit = sectionHeaders[".data"].VirtualSize / nPointerSize;
            pInfoBuffer = Marshal.AllocHGlobal(8);

            for (var idx = 0; idx < nIndexLimit; idx++)
            {
                uint nInfoLength;
                NTSTATUS ntstatus;
                IntPtr pBufferToRead;

                if (Environment.Is64BitProcess)
                    pBufferToRead = new IntPtr(pDataSection.ToInt64() + (nPointerSize * idx));
                else
                    pBufferToRead = new IntPtr(pDataSection.ToInt32() + (int)(nPointerSize * idx));

                nInfoLength = nPointerSize;
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pBufferToRead,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    continue;

                if (nPointerSize == 8u)
                    pBufferToRead = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
                else
                    pBufferToRead = new IntPtr(Marshal.ReadInt32(pInfoBuffer));

                if (!Helpers.IsHeapAddress(hProcess, pBufferToRead))
                    continue;

                nInfoLength = (uint)Marshal.SizeOf(typeof(WNF_CONTEXT_HEADER));
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pBufferToRead,
                    pInfoBuffer,
                    nInfoLength,
                    out nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    continue;

                var tableHeader = (WNF_CONTEXT_HEADER)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(WNF_CONTEXT_HEADER));

                if ((tableHeader.NodeTypeCode == Win32Consts.WNF_NODE_SUBSCRIPTION_TABLE) &&
                    (tableHeader.NodeByteSize == nSubscriptionTableSize))
                {
                    if (Environment.Is64BitProcess)
                        pSubscriptionTable = new IntPtr(pDataSection.ToInt64() + (nPointerSize * idx));
                    else
                        pSubscriptionTable = new IntPtr(pDataSection.ToInt32() + (int)(nPointerSize * idx));

                    break;
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return pSubscriptionTable;
        }


        public static Dictionary<IntPtr, KeyValuePair<IntPtr, IntPtr>> GetUserSubscriptions(
            IntPtr hProcess,
            IntPtr pNameSubscription)
        {
            IntPtr pInfoBuffer;
            uint nNameSubscriptionSize;
            uint nUserSubscriptionSize;
            int nListEntryOffset;
            string fieldName = "SubscriptionsListEntry";
            bool bIs32BitProcess = Helpers.Is32BitProcess(hProcess);
            var subscriptions = new Dictionary<IntPtr, KeyValuePair<IntPtr, IntPtr>>();

            if (!bIs32BitProcess)
            {
                nNameSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION64));
                nUserSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_USER_SUBSCRIPTION64));
                nListEntryOffset = Marshal.OffsetOf(typeof(WNF_USER_SUBSCRIPTION64), fieldName).ToInt32();
            }
            else
            {
                nNameSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION32));
                nUserSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_USER_SUBSCRIPTION32));
                nListEntryOffset = Marshal.OffsetOf(typeof(WNF_USER_SUBSCRIPTION32), fieldName).ToInt32();
            }

            pInfoBuffer = Marshal.AllocHGlobal(0x100);

            do
            {
                IntPtr pRootUserSubscription;
                IntPtr pUserSubscription;
                uint nInfoLength = nNameSubscriptionSize;
                NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pNameSubscription,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                if (!bIs32BitProcess)
                {
                    var nameSubscription = (WNF_NAME_SUBSCRIPTION64)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_NAME_SUBSCRIPTION64));

                    if (nameSubscription.Header.NodeTypeCode != Win32Consts.WNF_NODE_NAME_SUBSCRIPTION)
                        break;

                    pRootUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nListEntryOffset);
                }
                else
                {
                    var nameSubscription = (WNF_NAME_SUBSCRIPTION32)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_NAME_SUBSCRIPTION32));

                    if (nameSubscription.Header.NodeTypeCode != Win32Consts.WNF_NODE_NAME_SUBSCRIPTION)
                        break;

                    pRootUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nListEntryOffset);
                }

                pUserSubscription = pRootUserSubscription;
                nInfoLength = nUserSubscriptionSize;

                while (true)
                {
                    KeyValuePair<IntPtr, IntPtr> callback;
                    IntPtr pCurrentUserSubscription = pUserSubscription;
                    ntstatus = NativeMethods.NtReadVirtualMemory(
                        hProcess,
                        pUserSubscription,
                        pInfoBuffer,
                        nInfoLength,
                        out nReturnedLength);

                    if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                        break;

                    if (!bIs32BitProcess)
                    {
                        var userSubscription = (WNF_USER_SUBSCRIPTION64)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(WNF_USER_SUBSCRIPTION64));
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nListEntryOffset);
                        callback = new KeyValuePair<IntPtr, IntPtr>(new IntPtr(userSubscription.Callback), new IntPtr(userSubscription.CallbackContext));
                    }
                    else
                    {
                        var userSubscription = (WNF_USER_SUBSCRIPTION32)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(WNF_USER_SUBSCRIPTION32));
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nListEntryOffset);
                        callback = new KeyValuePair<IntPtr, IntPtr>(new IntPtr(userSubscription.Callback), new IntPtr(userSubscription.CallbackContext));
                    }

                    if (pUserSubscription == pRootUserSubscription)
                        break;

                    subscriptions.Add(pCurrentUserSubscription, callback);
                }
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            return subscriptions;
        }


        public static Dictionary<IntPtr, KeyValuePair<IntPtr, IntPtr>> GetUserSubscriptionsWin11(
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
            KeyValuePair<IntPtr, IntPtr> callback;
            var results = new Dictionary<IntPtr, KeyValuePair<IntPtr, IntPtr>>();

            if (proc.GetArchitecture() == "x64")
            {
                nSizeNameSubscription = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION64_WIN11));
                WNF_USER_SUBSCRIPTION64 userSubscription;
                buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_NAME_SUBSCRIPTION.");

                    return results;
                }

                var nameSubscription = (WNF_NAME_SUBSCRIPTION64_WIN11)Marshal.PtrToStructure(
                    buffer,
                    typeof(WNF_NAME_SUBSCRIPTION64_WIN11));
                NativeMethods.LocalFree(buffer);

                nSizeUserSubscription = (uint)Marshal.SizeOf(typeof(WNF_USER_SUBSCRIPTION64));
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(WNF_USER_SUBSCRIPTION64),
                    "SubscriptionsListEntry").ToInt32();

                if (nameSubscription.Header.NodeTypeCode == Win32Consts.WNF_NODE_NAME_SUBSCRIPTION)
                {
                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUserSubscription = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (WNF_USER_SUBSCRIPTION64)Marshal.PtrToStructure(
                            buffer,
                            typeof(WNF_USER_SUBSCRIPTION64));
                        NativeMethods.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        callback = new KeyValuePair<IntPtr, IntPtr>(
                            new IntPtr(userSubscription.Callback),
                            new IntPtr(userSubscription.CallbackContext)
                        );

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
                nSizeNameSubscription = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION32_WIN11));
                WNF_USER_SUBSCRIPTION32 userSubscription;
                buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read WNF_NAME_SUBSCRIPTION.");

                    return results;
                }

                var nameSubscription = (WNF_NAME_SUBSCRIPTION32_WIN11)Marshal.PtrToStructure(
                    buffer,
                    typeof(WNF_NAME_SUBSCRIPTION32_WIN11));
                NativeMethods.LocalFree(buffer);

                nSizeUserSubscription = (uint)Marshal.SizeOf(typeof(WNF_USER_SUBSCRIPTION32));
                nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(WNF_USER_SUBSCRIPTION32),
                    "SubscriptionsListEntry").ToInt32();

                if (nameSubscription.Header.NodeTypeCode == Win32Consts.WNF_NODE_NAME_SUBSCRIPTION)
                {
                    pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
                    pUserSubscription = pFirstUserSubscription;

                    while (true)
                    {
                        pCurrentUserSubscription = pUserSubscription;
                        buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                        if (buffer == IntPtr.Zero)
                            break;

                        userSubscription = (WNF_USER_SUBSCRIPTION32)Marshal.PtrToStructure(
                            buffer,
                            typeof(WNF_USER_SUBSCRIPTION32));
                        NativeMethods.LocalFree(buffer);
                        pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                        if (pUserSubscription == pFirstUserSubscription)
                            break;

                        callback = new KeyValuePair<IntPtr, IntPtr>(
                            new IntPtr(userSubscription.Callback),
                            new IntPtr(userSubscription.CallbackContext)
                        );

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


        public static void ListWin11NameSubscriptions(
            IntPtr hProcess,
            IntPtr pNameSubscription,
            bool b32BitProcess,
            ref Dictionary<ulong, IntPtr> nameSubscriptions)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            uint nNameSubscriptionSize;
            uint nNamesTableEntryOffset;
            string fieldName = "NamesTableEntry";

            if (!b32BitProcess)
            {
                nNameSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION64_WIN11));
                nNamesTableEntryOffset = (uint)Marshal.OffsetOf(typeof(WNF_NAME_SUBSCRIPTION64_WIN11), fieldName).ToInt32();
            }
            else
            {
                nNameSubscriptionSize = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION32_WIN11));
                nNamesTableEntryOffset = (uint)Marshal.OffsetOf(typeof(WNF_NAME_SUBSCRIPTION32_WIN11), fieldName).ToInt32();
            }

            pInfoBuffer = Marshal.AllocHGlobal((int)nNameSubscriptionSize);
            ntstatus = NativeMethods.NtReadVirtualMemory(
                hProcess,
                pNameSubscription,
                pInfoBuffer,
                nNameSubscriptionSize,
                out uint nReturnedSize);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) || (nReturnedSize == nNameSubscriptionSize))
            {
                IntPtr pNextNameSubscription;

                if (!b32BitProcess)
                {
                    var nameSubscription64 = (WNF_NAME_SUBSCRIPTION64_WIN11)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_NAME_SUBSCRIPTION64_WIN11));

                    if (!nameSubscriptions.ContainsKey(nameSubscription64.StateName))
                        nameSubscriptions.Add(nameSubscription64.StateName, pNameSubscription);

                    if (nameSubscription64.NamesTableEntry.Left != 0L)
                    {
                        pNextNameSubscription = new IntPtr(nameSubscription64.NamesTableEntry.Left - nNamesTableEntryOffset);
                        ListWin11NameSubscriptions(hProcess, pNextNameSubscription, b32BitProcess, ref nameSubscriptions);
                    }

                    if (nameSubscription64.NamesTableEntry.Right != 0L)
                    {
                        pNextNameSubscription = new IntPtr(nameSubscription64.NamesTableEntry.Right - nNamesTableEntryOffset);
                        ListWin11NameSubscriptions(hProcess, pNextNameSubscription, b32BitProcess, ref nameSubscriptions);
                    }
                }
                else
                {
                    var nameSubscription32 = (WNF_NAME_SUBSCRIPTION32_WIN11)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(WNF_NAME_SUBSCRIPTION32_WIN11));

                    if (!nameSubscriptions.ContainsKey(nameSubscription32.StateName))
                        nameSubscriptions.Add(nameSubscription32.StateName, pNameSubscription);

                    if (nameSubscription32.NamesTableEntry.Left != 0L)
                    {
                        pNextNameSubscription = new IntPtr(nameSubscription32.NamesTableEntry.Left - nNamesTableEntryOffset);
                        ListWin11NameSubscriptions(hProcess, pNextNameSubscription, b32BitProcess, ref nameSubscriptions);
                    }

                    if (nameSubscription32.NamesTableEntry.Right != 0L)
                    {
                        pNextNameSubscription = new IntPtr(nameSubscription32.NamesTableEntry.Right - nNamesTableEntryOffset);
                        ListWin11NameSubscriptions(hProcess, pNextNameSubscription, b32BitProcess, ref nameSubscriptions);
                    }
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);
        }
    }
}
