using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Helpers
    {
        public static string GetSymbolPath(IntPtr hProcess, IntPtr pBuffer)
        {
            string symbol = null;
            var mappedFileName = new UNICODE_STRING();
            uint nInfoLength = (uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            var symbolInfo = new SYMBOL_INFO
            {
                SizeOfStruct = (uint)Marshal.SizeOf(typeof(SYMBOL_INFO)) - Win32Consts.MAX_SYM_NAME,
                MaxNameLen = Win32Consts.MAX_SYM_NAME,
                Name = new byte[Win32Consts.MAX_SYM_NAME]
            };
            Marshal.StructureToPtr(mappedFileName, pInfoBuffer, false);

            if (!NativeMethods.SymInitialize(hProcess, null, true))
                return null;

            do
            {
                long nDisplacement = 0L;
                NTSTATUS ntstatus = NativeMethods.NtQueryVirtualMemory(
                    hProcess,
                    pBuffer,
                    MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation,
                    pInfoBuffer,
                    new SIZE_T(nInfoLength),
                    out SIZE_T _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                mappedFileName = (UNICODE_STRING)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(UNICODE_STRING));

                if (string.IsNullOrEmpty(mappedFileName.ToString()))
                    break;

                if (NativeMethods.SymFromAddr(
                    hProcess,
                    pBuffer.ToInt64(),
                    ref nDisplacement,
                    ref symbolInfo))
                {
                    if (nDisplacement > 0)
                    {
                        symbol = string.Format("{0}!{1}+0x{2}",
                            Path.GetFileNameWithoutExtension(mappedFileName.ToString()),
                            Encoding.ASCII.GetString(symbolInfo.Name).Trim('\0'),
                            nDisplacement.ToString("X"));
                    }
                    else
                    {
                        symbol = string.Format("{0}!{1}",
                            Path.GetFileNameWithoutExtension(mappedFileName.ToString()),
                            Encoding.ASCII.GetString(symbolInfo.Name).Trim('\0'));
                    }
                }
                else
                {
                    symbol = Path.GetFileNameWithoutExtension(mappedFileName.ToString());
                }
            } while (false);

            NativeMethods.SymCleanup(hProcess);
            Marshal.FreeHGlobal(pInfoBuffer);

            return symbol;
        }


        public static string GetWnfName(ulong stateName)
        {
            string wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME), stateName);
            var wnfStateName = new WNF_STATE_NAME { Data = stateName };
            var tag = BitConverter.GetBytes(wnfStateName.GetOwnerTag());

            if (string.IsNullOrEmpty(wnfName) && wnfStateName.IsValid())
            {
                if (wnfStateName.GetNameLifeTime() == WNF_STATE_NAME_LIFETIME.WellKnown)
                {
                    wnfName = string.Format("{0}.{1} 0x{2}",
                        Encoding.ASCII.GetString(tag).Trim('\0'),
                        wnfStateName.GetSequenceNumber().ToString("D3"),
                        stateName.ToString("X8"));
                }
                else
                {
                    wnfName = "N/A";
                }
            }

            return wnfName;
        }


        public static bool IsWin11()
        {
            NativeMethods.RtlGetNtVersionNumbers(out int majorVersion, out int _, out int buildNumber);
            buildNumber &= 0xFFFF;

            return ((majorVersion >= 10) && (buildNumber >= 22000));
        }


        public static void PrintProcessInformation(PROCESS_INFORMATION processInfo)
        {
            var outputBuilder = new StringBuilder();
            outputBuilder.AppendFormat("Process Name  : {0}\n", processInfo.ProcessName);
            outputBuilder.AppendFormat("Process ID    : {0}\n", processInfo.ProcessId);
            outputBuilder.AppendFormat("Architecture  : {0}\n", processInfo.Architecture);

            if (!string.IsNullOrEmpty(processInfo.ErrorMessage))
                outputBuilder.AppendFormat("Error Message : {0}\n", processInfo.ErrorMessage);

            Console.WriteLine(outputBuilder.ToString());
        }
    }
}
