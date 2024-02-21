using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfDump.Interop;

namespace SharpWnfDump.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static void BruteForceWnfNames(bool showData)
        {
            long exists;
            var tableIndex = new StringBuilder();
            var wnfStateName = new WNF_STATE_NAME(1, WNF_STATE_NAME_LIFETIME.WnfTemporaryStateName, 0, 0, 0, 0);

            for (var scope = 0u; scope < (uint)WNF_DATA_SCOPE.WnfMaxScope; scope++)
            {
                wnfStateName.SetDataScope(scope);

                tableIndex.Clear();
                tableIndex.Append("\n");
                tableIndex.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n",
                    string.Format("WNF State Name [{0} Scope]", ((WNF_DATA_SCOPE)scope).ToString()));
                tableIndex.Append(new string('-', 118));
                Console.WriteLine(tableIndex);

                for (var number = 0u; number < 0x200000u; number++)
                {
                    wnfStateName.SetSequenceNumber(number);
                    exists = Helpers.QueryWnfInfoClass(
                        wnfStateName.Data,
                        WNF_STATE_NAME_INFORMATION.WnfInfoStateNameExist);

                    if (exists != 0)
                        Helpers.DumpWnfData(wnfStateName.Data, IntPtr.Zero, false, showData);
                }
            }
        }


        public static bool DumpKeyInfo(ulong stateName, bool showSd, bool showData)
        {
            NTSTATUS ntstatus;
            IntPtr dataBuffer;
            int dataSize = 0;
            var wnfStateName = new WNF_STATE_NAME { Data = stateName }; 
            var output = new StringBuilder();

            if (wnfStateName.GetNameLifeTime() != WNF_STATE_NAME_LIFETIME.WnfTemporaryStateName)
            {
                ntstatus = NativeMethods.RegOpenKeyEx(
                    Win32Consts.HKEY_LOCAL_MACHINE,
                    Globals.LifetimeKeyNames[(uint)wnfStateName.GetNameLifeTime()],
                    0,
                    Win32Consts.KEY_READ,
                    out IntPtr phkResult);

                if (ntstatus != Win32Consts.ERROR_SUCCESS)
                    return false;

                dataBuffer = NativeMethods.VirtualAlloc(
                        IntPtr.Zero, 0x1000, Win32Consts.MEM_COMMIT, Win32Consts.PAGE_READWRITE);

                if (dataBuffer == IntPtr.Zero)
                {
                    NativeMethods.RegCloseKey(phkResult);
                    return false;
                }

                ntstatus = NativeMethods.RegQueryValueEx(
                    phkResult,
                    string.Format("{0}", stateName.ToString("X16")),
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref dataSize);

                if (ntstatus != Win32Consts.ERROR_SUCCESS)
                {
                    NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
                    NativeMethods.RegCloseKey(phkResult);
                    return false;
                }

                ntstatus = NativeMethods.RegQueryValueEx(
                    phkResult,
                    string.Format("{0}", stateName.ToString("X16")),
                    0,
                    IntPtr.Zero,
                    dataBuffer,
                    ref dataSize);

                if (ntstatus != Win32Consts.ERROR_SUCCESS)
                {
                    NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
                    NativeMethods.RegCloseKey(phkResult);
                    return false;
                }

                output.Append("\n");
                output.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n",
                    "WNF State Name");
                output.Append(new string('-', 118));

                Console.WriteLine(output);

                Helpers.DumpWnfData(stateName, dataBuffer, showSd, showData);

                NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
                NativeMethods.RegCloseKey(phkResult);
            }

            return true;
        }


        public static bool DumpWnfNames(bool showSd, bool showData)
        {
            NTSTATUS ntstatus;
            IntPtr lpBuffer;
            int count;
            int lpcValueName = 255;
            int bufferSize = 0x1000;
            ulong stateName;
            bool status = true;
            var output = new StringBuilder();
            var lpValueName = new StringBuilder((int)lpcValueName);

            for (var idx = 0; idx < Globals.LifetimeKeyNames.Length; idx++)
            {
                ntstatus = NativeMethods.RegOpenKeyEx(
                    Win32Consts.HKEY_LOCAL_MACHINE,
                    Globals.LifetimeKeyNames[idx],
                    0,
                    Win32Consts.KEY_READ,
                    out IntPtr phkResult);

                if (ntstatus != Win32Consts.ERROR_SUCCESS)
                {
                    return false;
                }

                output.Clear();
                output.Append("\n");
                output.AppendFormat(
                    "| {0,-64}",
                    string.Format("WNF State Name [{0} Lifetime]",
                    Enum.GetName(typeof(WNF_STATE_NAME_LIFETIME), idx)));
                output.Append("| S | L | P | AC | N | CurSize | MaxSize | Changes |");
                output.Append("\n");
                output.Append(new string('-', 118));

                Console.WriteLine(output);
                count = 0;

                while (true)
                {
                    lpcValueName = 255;
                    bufferSize = 0x1000;
                    lpBuffer = NativeMethods.VirtualAlloc(
                        IntPtr.Zero, bufferSize, Win32Consts.MEM_COMMIT, Win32Consts.PAGE_READWRITE);

                    if (lpBuffer == IntPtr.Zero)
                    {
                        NativeMethods.RegCloseKey(phkResult);
                        return false;
                    }

                    ntstatus = NativeMethods.RegEnumValue(
                        phkResult,
                        count,
                        lpValueName,
                        ref lpcValueName,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        lpBuffer,
                        ref bufferSize);

                    if (ntstatus != Win32Consts.ERROR_SUCCESS)
                        break;

                    count++;

                    try
                    {
                        stateName = Convert.ToUInt64(lpValueName.ToString(), 16);
                        status = Helpers.DumpWnfData(stateName, lpBuffer, showSd, showData);
                    }
                    catch
                    {
                        continue;
                    }
                    finally
                    {
                        NativeMethods.VirtualFree(lpBuffer, 0, Win32Consts.MEM_RELEASE);
                    }
                }

                NativeMethods.RegCloseKey(phkResult);
            }

            return status;
        }


        public static void OperationRead(ulong stateName)
        {
            string nameString = Helpers.GetWnfName(stateName);

            if (Helpers.ReadWnfData(
                stateName,
                out int _,
                out IntPtr pInfoBuffer,
                out uint nInfoLength))
            {
                Console.WriteLine("\n{0}:\n", nameString);

                if (pInfoBuffer != IntPtr.Zero)
                {
                    HexDump.Dump(pInfoBuffer, nInfoLength, 1);
                    Marshal.FreeHGlobal(pInfoBuffer);
                }
                else
                {
                    Console.WriteLine("    (Data is empty.)");
                }
            }
            else
            {
                Console.WriteLine("\n[-] Failed to read data from {0}.", nameString);
            }
        }


        public static void OperationWrite(ulong stateName, string filePath)
        {
            string nameString = Helpers.GetWnfName(stateName);
            string fullFilePath = Path.GetFullPath(filePath);
            Console.WriteLine();
            Console.WriteLine("[>] Trying to write data.");
            Console.WriteLine("    |-> Target WNF Name : {0}", nameString);
            Console.WriteLine("    |-> Data Source     : {0}", fullFilePath);

            if (!Helpers.IsWritable(stateName))
            {
                Console.WriteLine("[!] {0} is not writable.\n", nameString);
                return;
            }

            if (!File.Exists(fullFilePath))
            {
                Console.WriteLine("[!] {0} is not found.\n", fullFilePath);
                return;
            }

            byte[] dataBytes = File.ReadAllBytes(fullFilePath);

            if (dataBytes.Length > 4096)
            {
                Console.WriteLine("[!] Data size cannot be above 4 KB.\n");
                return;
            }

            IntPtr dataBuffer = NativeMethods.VirtualAlloc(
                IntPtr.Zero,
                dataBytes.Length,
                Win32Consts.MEM_COMMIT,
                Win32Consts.PAGE_READWRITE);

            if (dataBuffer == IntPtr.Zero)
            {
                Console.WriteLine("\n[-] Failed to allocate buffer (error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            Marshal.Copy(dataBytes, 0, dataBuffer, dataBytes.Length);

            if (Helpers.WriteWnfData(stateName, dataBuffer, dataBytes.Length))
                Console.WriteLine("\n[+] Data is written successfully.\n");
            else
                Console.WriteLine("\n[-] Failed to write data (The data size may exceed the maximum size of the target WNF object).\n");

            NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
        }
    }
}
