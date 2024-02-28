using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    internal class Helpers
    {
        public static string GetSymbolPath(IntPtr hProcess, IntPtr pointer)
        {
            string symbol;
            var pathBuilder = new StringBuilder((int)Win32Consts.MAX_PATH);
            var symbolInfo = new SYMBOL_INFO
            {
                SizeOfStruct = (uint)Marshal.SizeOf(typeof(SYMBOL_INFO)) - Win32Consts.MAX_SYM_NAME,
                MaxNameLen = Win32Consts.MAX_SYM_NAME,
                Name = new byte[Win32Consts.MAX_SYM_NAME]
            };

            NativeMethods.SymInitialize(hProcess, null, true);

            NativeMethods.GetMappedFileName(
                hProcess,
                pointer,
                pathBuilder,
                (uint)pathBuilder.Capacity);

            if (NativeMethods.SymFromAddr(
                hProcess,
                pointer.ToInt64(),
                IntPtr.Zero,
                ref symbolInfo))
            {
                symbol = string.Format(
                    "{0}!{1}",
                    Path.GetFileName(pathBuilder.ToString()),
                    Encoding.ASCII.GetString(symbolInfo.Name).Trim('\0'));
            }
            else
            {
                symbol = Path.GetFileName(pathBuilder.ToString());
            }

            if (string.IsNullOrEmpty(symbol))
                symbol = "N/A";

            NativeMethods.SymCleanup(hProcess);

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
