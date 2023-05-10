using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfDump.Interop;

namespace SharpWnfDump.Library
{
    internal class Modules
    {
        public static void BruteForceWnfNames(bool showData)
        {
            Helpers.WNF_STATE_NAME_Data stateData;
            ulong stateName;
            long exists;
            stateData.Version = 1;
            stateData.NameLifeTime = (ulong)WNF_STATE_NAME_LIFETIME.WnfTemporaryStateName;
            stateData.PermanentData = 0;
            stateData.OwnerTag = 0;
            StringBuilder tableIndex = new StringBuilder();
            ulong scopeRange = (ulong)(Enum.GetNames(
                typeof(WNF_DATA_SCOPE)).Length);

            for (var scope = 0UL; scope < scopeRange; scope++)
            {
                stateData.DataScope = scope;

                tableIndex.Clear();
                tableIndex.Append("\n");
                tableIndex.Append(string.Format(
                    "| {0,-64}",
                    string.Format("WNF State Name [{0} Scope]",
                    Enum.GetName(typeof(WNF_DATA_SCOPE), scope))));
                tableIndex.Append("| S | L | P | AC | N | CurSize | MaxSize | Changes |");
                tableIndex.Append("\n");
                tableIndex.Append(new string('-', 118));
                Console.WriteLine(tableIndex);

                for (var number = 0UL; number < 0x200000UL; number++)
                {
                    stateData.SequenceNumber = number;
                    stateName = Helpers.ConvertFromStateDataToStateName(stateData);
                    exists = Helpers.QueryWnfInfoClass(
                        stateName,
                        WNF_STATE_NAME_INFORMATION.WnfInfoStateNameExist);

                    if (exists != 0)
                    {
                        Helpers.DumpWnfData(stateName, IntPtr.Zero, false, showData);
                    }
                }
            }
            return;
        }

        public static bool DumpKeyInfo(ulong stateName, bool showSd, bool showData)
        {
            int ntstatus;
            IntPtr dataBuffer;
            int dataSize = 0;
            Helpers.WNF_STATE_NAME_Data stateData = Helpers.ConvertFromStateNameToStateData(stateName);
            StringBuilder output = new StringBuilder();

            if (stateData.NameLifeTime !=
                (ulong)WNF_STATE_NAME_LIFETIME.WnfTemporaryStateName)
            {
                ntstatus = NativeMethods.RegOpenKeyEx(
                    Win32Consts.HKEY_LOCAL_MACHINE,
                    Helpers.g_LifetimeKeyNames[stateData.NameLifeTime],
                    0,
                    Win32Consts.KEY_READ,
                    out IntPtr phkResult);

                if (ntstatus != Win32Consts.ERROR_SUCCESS)
                {
                    return false;
                }

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
                output.Append(string.Format("| {0,-64}", "WNF State Name"));
                output.Append("| S | L | P | AC | N | CurSize | MaxSize | Changes |");
                output.Append("\n");
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
            int ntstatus;
            IntPtr lpBuffer;
            int count;
            int lpcValueName = 255;
            int bufferSize = 0x1000;
            ulong stateName;
            bool status = true;
            StringBuilder output = new StringBuilder();
            StringBuilder lpValueName = new StringBuilder((int)lpcValueName);

            for (var idx = 0; idx < Helpers.g_LifetimeKeyNames.Length; idx++)
            {
                ntstatus = NativeMethods.RegOpenKeyEx(
                    Win32Consts.HKEY_LOCAL_MACHINE,
                    Helpers.g_LifetimeKeyNames[idx],
                    0,
                    Win32Consts.KEY_READ,
                    out IntPtr phkResult);

                if (ntstatus != Win32Consts.ERROR_SUCCESS)
                {
                    return false;
                }

                output.Clear();
                output.Append("\n");
                output.Append(string.Format(
                    "| {0,-64}",
                    string.Format("WNF State Name [{0} Lifetime]",
                    Enum.GetName(typeof(WNF_STATE_NAME_LIFETIME), idx))));
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
                    {
                        break;
                    }

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

            if (!Helpers.ReadWnfData(
                stateName,
                out int changeStamp,
                out IntPtr dataBuffer,
                out int bufferSize))
            {
                Console.WriteLine("\n[-] Failed to read data from {0}.", nameString);
                return;
            }

            Console.WriteLine("\n{0}:\n", nameString);
            HexDump.Dump(dataBuffer, (uint)bufferSize, 1);
            NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
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
            {
                Console.WriteLine("\n[+] Data is written successfully.\n");
            }
            else
            {
                Console.WriteLine("\n[-] Failed to write data (The data size may exceed the maximum size of the target WNF object).\n");
            }

            NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
        }
    }
}
