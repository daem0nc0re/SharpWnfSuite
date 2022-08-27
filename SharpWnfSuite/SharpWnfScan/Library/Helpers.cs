using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using SharpWnfScan.Interop;

namespace SharpWnfScan.Library
{
    internal class Helpers
    {
        private struct WNF_STATE_NAME_DATA
        {
            public ulong Version;
            public ulong NameLifeTime;
            public ulong DataScope;
            public ulong PermanentData;
            public ulong SequenceNumber;
            public ulong OwnerTag;
        }


        private static WNF_STATE_NAME_DATA ConvertFromStateNameToStateData(ulong stateName)
        {
            WNF_STATE_NAME_DATA stateData;
            stateName ^= Win32Consts.WNF_STATE_KEY;
            stateData.Version = (stateName & 0xF);
            stateData.NameLifeTime = ((stateName >> 4) & 0x3);
            stateData.DataScope = ((stateName >> 6) & 0xF);
            stateData.PermanentData = ((stateName >> 10) & 0x1);
            stateData.SequenceNumber = ((stateName >> 11) & 0x1FFFFF);
            stateData.OwnerTag = ((stateName >> 32) & 0xFFFFFFFF);

            return stateData;
        }


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
            {
                symbol = "N/A";
            }

            NativeMethods.SymCleanup(hProcess);

            return symbol;
        }


        public static string GetWnfName(ulong stateName)
        {
            string wnfName;
            WNF_STATE_NAME_DATA data = ConvertFromStateNameToStateData(stateName);
            byte[] tag = BitConverter.GetBytes((uint)data.OwnerTag);
            bool isWellKnown = data.NameLifeTime ==
                (ulong)WNF_STATE_NAME_LIFETIME.WnfWellKnownStateName;

            wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME), stateName);

            if (string.IsNullOrEmpty(wnfName))
            {
                if (isWellKnown)
                {
                    wnfName = string.Format("{0}.{1} 0x{2}",
                        Encoding.ASCII.GetString(tag).Trim('\0'),
                        data.SequenceNumber.ToString("D3"),
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
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;

            NativeMethods.RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            return ((MajorVersion >= 10) && (BuildNumber >= 22000));
        }


        public static void PrintProcessInformation(PROCESS_INFORMATION processInfo)
        {
            if (string.IsNullOrEmpty(processInfo.ErrorMessage))
            {
                Console.WriteLine("Process Name  : {0}", processInfo.ProcessName);
                Console.WriteLine("Process ID    : {0}", processInfo.ProcessId);
                Console.WriteLine("Architecture  : {0}\n", processInfo.Architecture);
            }
            else
            {
                Console.WriteLine("Process Name  : {0}", processInfo.ProcessName);
                Console.WriteLine("Process ID    : {0}", processInfo.ProcessId);
                Console.WriteLine("Architecture  : {0}", processInfo.Architecture);
                Console.WriteLine("Error Message : {0}\n", processInfo.ErrorMessage);
            }
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }


        public static void ZeroMemory(ref byte[] bytes, int size)
        {
            var nullBytes = new byte[size];
            Buffer.BlockCopy(nullBytes, 0, bytes, 0, size);
        }
    }
}
