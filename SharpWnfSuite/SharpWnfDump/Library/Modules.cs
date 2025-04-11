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

            Console.WriteLine("[*] OS version is {0}.\n", Globals.OsVersion ?? "unspecified");

            if (!Globals.IsSupported)
            {
                Console.WriteLine("[-] This OS is not supported.");
                return;
            }

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
            NTSTATUS ntstatus;
            IntPtr hKey;
            var wnfStateName = new WNF_STATE_NAME { Data = stateName };

            Console.WriteLine("[*] OS version is {0}.\n", Globals.OsVersion ?? "unspecified");

            if (!Globals.IsSupported)
            {
                Console.WriteLine("[-] This OS is not supported.");
                return false;
            }

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

            using (var valueName = new UNICODE_STRING(stateName.ToString("X16")))
            {
                IntPtr pInfoBuffer;
                var nInfoLength = 0x1000u;
                var outputBuilder = new StringBuilder();

                do
                {
                    pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                    ntstatus = NativeMethods.NtQueryValueKey(
                        hKey,
                        in valueName,
                        KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation,
                        pInfoBuffer,
                        nInfoLength,
                        out nInfoLength);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        Marshal.FreeHGlobal(pInfoBuffer);
                } while (ntstatus == Win32Consts.STATUS_BUFFER_OVERFLOW);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    IntPtr pDataBuffer;
                    var info = (KEY_VALUE_FULL_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(KEY_VALUE_FULL_INFORMATION));

                    if (Environment.Is64BitProcess)
                        pDataBuffer = new IntPtr(pInfoBuffer.ToInt64() + info.DataOffset);
                    else
                        pDataBuffer = new IntPtr(pInfoBuffer.ToInt32() + (int)info.DataOffset);

                    outputBuilder.AppendFormat("| {0,-64}| S | L | P | AC | N | CurSize | MaxSize | Changes |\n", "WNF State Name");
                    outputBuilder.AppendLine(new string('-', 118));
                    outputBuilder.Append(Helpers.DumpWnfData(stateName, pDataBuffer, bShowSd, bShowData, false));
                    Console.Write(outputBuilder.ToString());
                }
                else
                {
                    Console.WriteLine("[-] Failed to query registry value (Error = 0x{0}).", ntstatus.ToString("X8"));
                }
            }

            NativeMethods.NtClose(hKey);

            return true;
        }


        public static void DumpWnfNames(bool bShowSd, bool bShowData, bool bUsedOnly)
        {
            var outputBuilder = new StringBuilder();

            Console.WriteLine("[*] OS version is {0}.\n", Globals.OsVersion ?? "unspecified");

            if (!Globals.IsSupported)
            {
                Console.WriteLine("[-] This OS is not supported.");
                return;
            }

            for (var idx = 0; idx < Globals.LifetimeKeyNameKeys.Length; idx++)
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

                for (var nValueIndex = 0u; ntstatus == Win32Consts.STATUS_SUCCESS; nValueIndex++)
                {
                    var nInfoLength = 0x1000u;
                    var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);

                    do
                    {
                        ntstatus = NativeMethods.NtEnumerateValueKey(
                            hKey,
                            nValueIndex,
                            KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation,
                            pInfoBuffer,
                            nInfoLength,
                            out nInfoLength);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                            Marshal.FreeHGlobal(pInfoBuffer);
                    } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        var nNameOffset = Marshal.OffsetOf(typeof(KEY_VALUE_FULL_INFORMATION), "Name").ToInt32();
                        var info = (KEY_VALUE_FULL_INFORMATION)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(KEY_VALUE_FULL_INFORMATION));

                        if (info.NameLength >= 32)
                        {
                            IntPtr pNameBuffer;
                            IntPtr pDataBuffer;

                            if (Environment.Is64BitProcess)
                            {
                                pNameBuffer = new IntPtr(pInfoBuffer.ToInt64() + nNameOffset);
                                pDataBuffer = new IntPtr(pInfoBuffer.ToInt64() + info.DataOffset);
                            }
                            else
                            {
                                pNameBuffer = new IntPtr(pInfoBuffer.ToInt32() + nNameOffset);
                                pDataBuffer = new IntPtr(pInfoBuffer.ToInt32() + (int)info.DataOffset);
                            }

                            try
                            {
                                var nameString = Marshal.PtrToStringUni(pNameBuffer);
                                var stateName = Convert.ToUInt64(nameString, 16);
                                var dataString = Helpers.DumpWnfData(
                                    stateName,
                                    pDataBuffer,
                                    bShowSd,
                                    bShowData,
                                    bUsedOnly);
                                outputBuilder.Append(dataString);
                            }
                            catch { }
                        }

                        Marshal.FreeHGlobal(pInfoBuffer);
                    }
                }

                NativeMethods.NtClose(hKey);
            }

            Console.WriteLine(outputBuilder.ToString());
        }


        public static void OperationRead(ulong stateName)
        {
            string nameString = Helpers.GetWnfName(stateName);

            Console.WriteLine("[*] OS version is {0}.", Globals.OsVersion ?? "unspecified");

            if (!Globals.IsSupported)
            {
                Console.WriteLine("[-] This OS is not supported.");
                return;
            }

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

            Console.WriteLine("[*] OS version is {0}.", Globals.OsVersion ?? "unspecified");

            if (!Globals.IsSupported)
            {
                Console.WriteLine("[-] This OS is not supported.");
                return;
            }

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
