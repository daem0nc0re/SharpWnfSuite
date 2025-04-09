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
        public static void BruteForceWnfNames(bool bShowData, bool bUsedOnly)
        {
            var wnfStateName = new WNF_STATE_NAME(1, WNF_STATE_NAME_LIFETIME.Temporary, 0, 0, 0, 0);
            string versionString = Helpers.GetOsVersionString(
                Globals.MajorVersion,
                Globals.MinorVersion,
                Globals.BuildNumber);

            Console.WriteLine("[*] OS version is {0}.\n", versionString ?? "unspecified");

            for (var nDataScope = 0u; nDataScope < (uint)WNF_DATA_SCOPE.Max; nDataScope++)
            {
                var outputBuilder = new StringBuilder();
                wnfStateName.SetDataScope(nDataScope);

                if (nDataScope > 0)
                    outputBuilder.AppendLine();

                outputBuilder.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n",
                    string.Format("WNF State Name [{0} Scope]", ((WNF_DATA_SCOPE)nDataScope).ToString()));
                outputBuilder.AppendLine(new string('-', 118));

                for (var nSequenceNumber = 0u; nSequenceNumber < 0x200000u; nSequenceNumber++)
                {
                    wnfStateName.SetSequenceNumber(nSequenceNumber);

                    if (Helpers.GetWnfSubscribersPresenceInfo(wnfStateName.Data) != 0)
                    {
                        outputBuilder.Append(Helpers.DumpWnfData(
                            wnfStateName.Data,
                            IntPtr.Zero,
                            false,
                            bShowData,
                            bUsedOnly));
                    }
                }

                Console.Write(outputBuilder.ToString());
            }
        }


        public static bool DumpKeyInfo(ulong stateName, bool bShowSd, bool bShowData)
        {
            int nErrorCode;
            NTSTATUS ntstatus;
            IntPtr hKey;
            var wnfStateName = new WNF_STATE_NAME { Data = stateName };
            string versionString = Helpers.GetOsVersionString(
                Globals.MajorVersion,
                Globals.MinorVersion,
                Globals.BuildNumber);

            Console.WriteLine("[*] OS version is {0}.\n", versionString ?? "unspecified");

            if (wnfStateName.GetNameLifeTime() == WNF_STATE_NAME_LIFETIME.Temporary)
            {
                Console.WriteLine("[-] Temporary WNF State Name is not supported.");
                return false;
            }

            using (var objectAttributes = new OBJECT_ATTRIBUTES(
                Globals.LifetimeKeyNameKeys[(uint)wnfStateName.GetNameLifeTime()],
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
            {
                ntstatus = NativeMethods.NtOpenKey(
                    out hKey,
                    ACCESS_MASK.KEY_QUERY_VALUE,
                    in objectAttributes);
            }

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open regitry key (Error = 0x{0}).", ntstatus.ToString("X8"));
                return false;
            }

            do
            {
                IntPtr pInfoBuffer;
                int nInfoLength = 0;
                var outputBuilder = new StringBuilder();
                nErrorCode = NativeMethods.RegQueryValueEx(
                    hKey,
                    stateName.ToString("X16"),
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref nInfoLength);

                if (nErrorCode != Win32Consts.ERROR_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to query registry value (Error = 0x{0}).", nErrorCode.ToString("X8"));
                    break;
                }

                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                nErrorCode = NativeMethods.RegQueryValueEx(
                    hKey,
                    stateName.ToString("X16"),
                    0,
                    IntPtr.Zero,
                    pInfoBuffer,
                    ref nInfoLength);

                if (nErrorCode != Win32Consts.ERROR_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to query registry value (Error = 0x{0}).", nErrorCode.ToString("X8"));
                }
                else
                {
                    outputBuilder.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n", "WNF State Name");
                    outputBuilder.AppendLine(new string('-', 118));
                    outputBuilder.Append(Helpers.DumpWnfData(stateName, pInfoBuffer, bShowSd, bShowData, false));
                    Console.Write(outputBuilder.ToString());
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            } while (false);

            NativeMethods.NtClose(hKey);

            return true;
        }


        public static void DumpWnfNames(bool bShowSd, bool bShowData, bool bUsedOnly)
        {
            var outputBuilder = new StringBuilder();
            string versionString = Helpers.GetOsVersionString(
                Globals.MajorVersion,
                Globals.MinorVersion,
                Globals.BuildNumber);

            Console.WriteLine("[*] OS version is {0}.\n", versionString ?? "unspecified");

            for (var idx = 0; idx < Globals.LifetimeKeyNames.Length; idx++)
            {
                NTSTATUS ntstatus;
                IntPtr hKey;

                using (var objectAttributes = new OBJECT_ATTRIBUTES(
                    Globals.LifetimeKeyNameKeys[idx],
                    OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
                {
                    ntstatus = NativeMethods.NtOpenKey(
                        out hKey,
                        ACCESS_MASK.KEY_QUERY_VALUE,
                        in objectAttributes);
                }

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    continue;

                if (idx > 0)
                    outputBuilder.AppendLine();

                outputBuilder.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n",
                    string.Format("WNF State Name [{0} Lifetime]",
                    ((WNF_STATE_NAME_LIFETIME)idx).ToString()));
                outputBuilder.AppendLine(new string('-', 118));

                for (var count = 0; true; count++)
                {
                    IntPtr pInfoBuffer;
                    var nNameLength = 255;
                    var nameBuilder = new StringBuilder(nNameLength);
                    int nErrorCode = Win32Consts.ERROR_MORE_DATA;

                    for (var nTrial = 0; (nErrorCode == Win32Consts.ERROR_MORE_DATA); nTrial++)
                    {
                        int nInfoLength = 0x1000 * nTrial;
                        pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                        nErrorCode = NativeMethods.RegEnumValue(
                            hKey,
                            count,
                            nameBuilder,
                            ref nNameLength,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            pInfoBuffer,
                            ref nInfoLength);

                        if (nErrorCode == Win32Consts.ERROR_SUCCESS)
                        {
                            try
                            {
                                var stateName = Convert.ToUInt64(nameBuilder.ToString(), 16);
                                var dataString = Helpers.DumpWnfData(
                                    stateName,
                                    pInfoBuffer,
                                    bShowSd,
                                    bShowData,
                                    bUsedOnly);
                                outputBuilder.Append(dataString);
                            }
                            catch { }
                        }

                        Marshal.FreeHGlobal(pInfoBuffer);
                    }

                    if (nErrorCode != Win32Consts.ERROR_SUCCESS)
                        break;
                }

                NativeMethods.NtClose(hKey);
            }

            Console.WriteLine(outputBuilder.ToString());
        }


        public static void OperationRead(ulong stateName)
        {
            string nameString = Helpers.GetWnfName(stateName);
            string versionString = Helpers.GetOsVersionString(
                Globals.MajorVersion,
                Globals.MinorVersion,
                Globals.BuildNumber);

            Console.WriteLine("[*] OS version is {0}.", versionString ?? "unspecified");

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
            string versionString = Helpers.GetOsVersionString(
                Globals.MajorVersion,
                Globals.MinorVersion,
                Globals.BuildNumber);

            Console.WriteLine("[*] OS version is {0}.", versionString ?? "unspecified");
            Console.WriteLine("[>] Trying to write data.");
            Console.WriteLine("    [*] Target WNF Name : {0}", nameString);
            Console.WriteLine("    [*] Data Source     : {0}", fullFilePath);

            if (!Helpers.IsWritableWnfStateName(stateName))
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
