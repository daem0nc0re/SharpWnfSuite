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
            var wnfStateName = new WNF_STATE_NAME(1, WNF_STATE_NAME_LIFETIME.Temporary, 0, 0, 0, 0);

            for (var dataScope = 0u; dataScope < (uint)WNF_DATA_SCOPE.Max; dataScope++)
            {
                var outputBuilder = new StringBuilder();
                wnfStateName.SetDataScope(dataScope);

                if (dataScope > 0)
                    outputBuilder.AppendLine();

                outputBuilder.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n",
                    string.Format("WNF State Name [{0} Scope]", ((WNF_DATA_SCOPE)dataScope).ToString()));
                outputBuilder.AppendLine(new string('-', 118));

                for (var number = 0u; number < 0x200000u; number++)
                {
                    wnfStateName.SetSequenceNumber(number);

                    if (Helpers.GetWnfSubscribersPresenceInfo(wnfStateName.Data) != 0)
                    {
                        var dataDump = Helpers.DumpWnfData(wnfStateName.Data, IntPtr.Zero, false, showData);
                        outputBuilder.Append(dataDump);
                    }
                }

                Console.Write(outputBuilder.ToString());
            }
        }


        public static bool DumpKeyInfo(ulong stateName, bool showSd, bool showData)
        {
            int error;
            var wnfStateName = new WNF_STATE_NAME { Data = stateName }; 

            if (wnfStateName.GetNameLifeTime() == WNF_STATE_NAME_LIFETIME.Temporary)
            {
                Console.WriteLine("[-] Temporary WNF State Name is not supported.");
                return false;
            }

            error = NativeMethods.RegOpenKeyEx(
                    Win32Consts.HKEY_LOCAL_MACHINE,
                    Globals.LifetimeKeyNames[(uint)wnfStateName.GetNameLifeTime()],
                    0,
                    Win32Consts.KEY_READ,
                    out IntPtr phkResult);

            if (error != Win32Consts.ERROR_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open regitry key (Error = 0x{0}).", error.ToString("X8"));
                return false;
            }

            do
            {
                IntPtr pInfoBuffer;
                int nInfoLength = 0;
                var outputBuilder = new StringBuilder();
                error = NativeMethods.RegQueryValueEx(
                    phkResult,
                    stateName.ToString("X16"),
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref nInfoLength);

                if (error != Win32Consts.ERROR_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to query registry value (Error = 0x{0}).", error.ToString("X8"));
                    break;
                }

                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                error = NativeMethods.RegQueryValueEx(
                    phkResult,
                    stateName.ToString("X16"),
                    0,
                    IntPtr.Zero,
                    pInfoBuffer,
                    ref nInfoLength);

                if (error != Win32Consts.ERROR_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to query registry value (Error = 0x{0}).", error.ToString("X8"));
                }
                else
                {
                    outputBuilder.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n", "WNF State Name");
                    outputBuilder.AppendLine(new string('-', 118));
                    outputBuilder.Append(Helpers.DumpWnfData(stateName, pInfoBuffer, showSd, showData));
                    Console.Write(outputBuilder.ToString());
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            } while (false);

            NativeMethods.RegCloseKey(phkResult);

            return true;
        }


        public static void DumpWnfNames(bool showSd, bool showData)
        {
            var outputBuilder = new StringBuilder();

            for (var idx = 0; idx < Globals.LifetimeKeyNames.Length; idx++)
            {
                int error = NativeMethods.RegOpenKeyEx(
                    Win32Consts.HKEY_LOCAL_MACHINE,
                    Globals.LifetimeKeyNames[idx],
                    0,
                    Win32Consts.KEY_READ,
                    out IntPtr phkResult);

                if (error != Win32Consts.ERROR_SUCCESS)
                    continue;

                if (idx > 0)
                    outputBuilder.AppendLine();

                outputBuilder.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n",
                    string.Format("WNF State Name [{0} Lifetime]", ((WNF_STATE_NAME_LIFETIME)idx).ToString()));
                outputBuilder.AppendLine(new string('-', 118));

                for (var count = 0; true; count++)
                {
                    IntPtr pInfoBuffer;
                    var nNameLength = 255;
                    var nameBuilder = new StringBuilder(nNameLength);
                    error = Win32Consts.ERROR_MORE_DATA;

                    for (var trial = 0; (error == Win32Consts.ERROR_MORE_DATA); trial++)
                    {
                        int nInfoLength = 0x1000 * trial;
                        pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                        error = NativeMethods.RegEnumValue(
                            phkResult,
                            count,
                            nameBuilder,
                            ref nNameLength,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            pInfoBuffer,
                            ref nInfoLength);

                        if (error == Win32Consts.ERROR_SUCCESS)
                        {
                            try
                            {
                                var stateName = Convert.ToUInt64(nameBuilder.ToString(), 16);
                                outputBuilder.Append(Helpers.DumpWnfData(stateName, pInfoBuffer, showSd, showData));
                            }
                            catch { }
                        }

                        Marshal.FreeHGlobal(pInfoBuffer);
                    }

                    if (error != Win32Consts.ERROR_SUCCESS)
                        break;
                }

                NativeMethods.RegCloseKey(phkResult);
            }

            Console.WriteLine(outputBuilder.ToString());
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
                    Console.Write(HexDump.Dump(pInfoBuffer, nInfoLength, 1));
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
            IntPtr pDataBuffer;
            byte[] dataBytes;
            string nameString = Helpers.GetWnfName(stateName);
            string fullFilePath = Path.GetFullPath(filePath);

            Console.WriteLine("[>] Trying to write data.");
            Console.WriteLine("    [*] Target WNF Name : {0}", nameString);
            Console.WriteLine("    [*] Data Source     : {0}", fullFilePath);

            if (!Helpers.IsWritable(stateName))
            {
                Console.WriteLine("[!] {0} is not writable.", nameString);
                return;
            }

            if (!File.Exists(fullFilePath))
            {
                Console.WriteLine("[!] {0} is not found.", fullFilePath);
                return;
            }

            dataBytes = File.ReadAllBytes(fullFilePath);

            if (dataBytes.Length > 4096)
            {
                Console.WriteLine("[!] Data size cannot be above 4 KB.");
                return;
            }

            pDataBuffer = Marshal.AllocHGlobal(dataBytes.Length);
            Marshal.Copy(dataBytes, 0, pDataBuffer, dataBytes.Length);

            if (Helpers.WriteWnfData(stateName, pDataBuffer, dataBytes.Length))
                Console.WriteLine("[+] Data is written successfully.");
            else
                Console.WriteLine("[-] Failed to write data (The data size may exceed the maximum size of the target WNF object).");

            Marshal.FreeHGlobal(pDataBuffer);
        }
    }
}
