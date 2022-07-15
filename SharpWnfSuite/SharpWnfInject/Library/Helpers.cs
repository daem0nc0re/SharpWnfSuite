using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfInject.Interop;

namespace SharpWnfInject.Library
{
    class Helpers
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
            stateName ^= Win32Const.WNF_STATE_KEY;
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
            var pathBuilder = new StringBuilder((int)Win32Const.MAX_PATH);
            var symbolInfo = new Win32Struct.SYMBOL_INFO
            {
                SizeOfStruct = (uint)Marshal.SizeOf(typeof(Win32Struct.SYMBOL_INFO)) - Win32Const.MAX_SYM_NAME,
                MaxNameLen = Win32Const.MAX_SYM_NAME,
                Name = new byte[Win32Const.MAX_SYM_NAME]
            };

            Win32Api.SymInitialize(hProcess, null, true);

            Win32Api.GetMappedFileName(
                hProcess,
                pointer,
                pathBuilder,
                (uint)pathBuilder.Capacity);

            if (Win32Api.SymFromAddr(
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

            Win32Api.SymCleanup(hProcess);

            return symbol;
        }


        public static string GetWnfName(ulong stateName)
        {
            string wnfName;
            WNF_STATE_NAME_DATA data = ConvertFromStateNameToStateData(stateName);
            byte[] tag = BitConverter.GetBytes((uint)data.OwnerTag);
            bool isWellKnown = data.NameLifeTime ==
                (ulong)Win32Const.WNF_STATE_NAME_LIFETIME.WnfWellKnownStateName;

            wnfName = Enum.GetName(typeof(Win32Const.WELL_KNOWN_WNF_NAME), stateName);

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


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            Win32Const.FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            IntPtr pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                        break;
                    }
                }

                dwFlags = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                dwFlags = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            nReturnedLength = Win32Api.FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }

        public static bool IsWin11()
        {
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;

            Win32Api.RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            return ((MajorVersion >= 10) && (BuildNumber >= 22000));
        }
    }
}
