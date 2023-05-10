using System;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfDump.Interop;

namespace SharpWnfDump.Library
{
    internal class Helpers
    {
        public static string[] g_LifetimeKeyNames = new string[] {
            "SYSTEM\\CurrentControlSet\\Control\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\VolatileNotifications"
        };

        public enum WNF_DATA_SCOPE_Brief : uint
        {
            System = 0,
            session = 1,
            User = 2,
            Process = 3,
            Machine = 4,
            physicalMachine = 5
        }

        public struct WNF_STATE_NAME_Data
        {
            public ulong Version;
            public ulong NameLifeTime;
            public ulong DataScope;
            public ulong PermanentData;
            public ulong SequenceNumber;
            public ulong OwnerTag;
        }

        public enum WNF_STATE_NAME_LIFETIME_Brief : uint
        {
            WellKnown = 0,
            Permanent = 1,
            Volatile = 2,
            Temporary = 3
        }

        public static ulong ConvertFromStateDataToStateName(WNF_STATE_NAME_Data stateData)
        {
            ulong stateName = 0;
            stateName |= (stateData.Version & 0xF);
            stateName |= ((stateData.NameLifeTime) << 4);
            stateName |= ((stateData.DataScope & 0xF) << 6);
            stateName |= ((stateData.PermanentData & 0x1) << 10);
            stateName |= ((stateData.SequenceNumber & 0x1FFFFF) << 11);
            stateName |= ((stateData.OwnerTag & 0xFFFFFFFF) << 32);
            stateName ^= Win32Consts.WNF_STATE_KEY;

            return stateName;
        }

        public static WNF_STATE_NAME_Data ConvertFromStateNameToStateData(ulong stateName)
        {
            WNF_STATE_NAME_Data stateData;
            stateName ^= Win32Consts.WNF_STATE_KEY;
            stateData.Version = (stateName & 0xF);
            stateData.NameLifeTime = ((stateName >> 4) & 0x3);
            stateData.DataScope = ((stateName >> 6) & 0xF);
            stateData.PermanentData = ((stateName >> 10) & 0x1);
            stateData.SequenceNumber = ((stateName >> 11) & 0x1FFFFF);
            stateData.OwnerTag = ((stateName >> 32) & 0xFFFFFFFF);

            return stateData;
        }

        public static bool DumpWnfData(
            ulong stateName,
            IntPtr pSecurityDescriptor,
            bool showSd,
            bool showData)
        {
            int maxSize = -1;
            int sdSize;

            if (pSecurityDescriptor != IntPtr.Zero)
            {
                if (NativeMethods.IsValidSecurityDescriptor(pSecurityDescriptor))
                {
                    sdSize = NativeMethods.GetSecurityDescriptorLength(pSecurityDescriptor);
                    maxSize = Marshal.ReadInt32(new IntPtr(pSecurityDescriptor.ToInt64() + sdSize));
                }
                else
                {
                    pSecurityDescriptor = IntPtr.Zero;
                    maxSize = 0;
                }
            }

            return PrintWnfRuntimeStatus(
                stateName,
                pSecurityDescriptor,
                showSd,
                maxSize,
                showData);
        }

        public static string GetWnfName(ulong stateName)
        {
            string wnfName;
            WNF_STATE_NAME_Data data = ConvertFromStateNameToStateData(stateName);
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
                    wnfName = string.Format("0x{0}", stateName.ToString("X16"));
                }
            }

            return wnfName;
        }

        public static ulong GetWnfStateName(string name)
        {
            ulong value;

            try
            {
                value = (ulong)Enum.Parse(
                    typeof(WELL_KNOWN_WNF_NAME),
                    name.ToUpper());
            }
            catch
            {
                try
                {
                    value = Convert.ToUInt64(name, 16);
                }
                catch
                {
                    Console.WriteLine("\n[-] Failed to resolve WNF State Name.\n");
                    value = 0;
                }
            }

            return value;
        }

        public static bool IsValidInternalName(ulong stateName)
        {
            WNF_STATE_NAME_Data stateData = ConvertFromStateNameToStateData(stateName);
            uint maxNameLifetime = (uint)(Enum.GetNames(
                typeof(WNF_STATE_NAME_LIFETIME)).Length - 1);
            uint maxDataScope = (uint)(Enum.GetNames(
                typeof(WNF_DATA_SCOPE)).Length - 1);

            if (stateData.NameLifeTime > maxNameLifetime)
                return false;

            if (stateData.DataScope > maxDataScope)
                return false;

            return true;
        }

        public static bool IsWritable(ulong stateName)
        {
            int STATUS_OPERATION_FAILED = Convert.ToInt32("0xC0000001", 16);
            int ntstatus = NativeMethods.NtUpdateWnfStateData(
                in stateName,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                -1,
                1);

            if (ntstatus == STATUS_OPERATION_FAILED)
            {
                return true;
            }

            return false;
        }

        public static bool PrintWnfRuntimeStatus(
            ulong stateName,
            IntPtr pSecurityDescriptor,
            bool showSd,
            int maxSize,
            bool showData)
        {
            long exists = 2;
            int SDDL_REVISION_1 = 1;

            if (!IsValidInternalName(stateName))
            {
                return false;
            }

            bool readable = ReadWnfData(
                stateName,
                out int changeStamp,
                out IntPtr dataBuffer,
                out int bufferSize);

            bool writable = IsWritable(stateName);

            if (writable)
            {
                exists = QueryWnfInfoClass(
                    stateName,
                    WNF_STATE_NAME_INFORMATION.WnfInfoSubscribersPresent);
            }

            WNF_STATE_NAME_Data data = ConvertFromStateNameToStateData(stateName);

            Console.WriteLine(
                "| {0,-64}| {1} | {2} | {3} | {4} | {5} | {6,7} | {7,7} | {8,7} |",
                GetWnfName(stateName),
                Enum.GetName(typeof(WNF_DATA_SCOPE_Brief), data.DataScope)[0],
                Enum.GetName(typeof(WNF_STATE_NAME_LIFETIME_Brief), data.NameLifeTime)[0],
                data.PermanentData != 0 ? 'Y' : 'N',
                readable && writable ? "RW" : (readable ? "RO" : (writable ? "WO" : "NA")),
                exists == 1 ? 'A' : (exists == 2 ? 'U' : 'I'),
                bufferSize,
                maxSize == -1 ? "?" : maxSize.ToString("D"),
                changeStamp);

            if (showSd && pSecurityDescriptor != IntPtr.Zero)
            {
                NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                    pSecurityDescriptor,
                    SDDL_REVISION_1,
                    SECURITY_INFORMATION.DACL_SECURITY_INFORMATION | SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.LABEL_SECURITY_INFORMATION,
                    out StringBuilder StringSecurityDescriptor,
                    IntPtr.Zero);
                Console.WriteLine("\n\t{0}", StringSecurityDescriptor);
            }

            if (showData && readable && bufferSize != 0)
            {
                Console.WriteLine();
                HexDump.Dump(dataBuffer, (uint)bufferSize, 2);
                Console.WriteLine();
            }
            else if (showSd)
            {
                Console.WriteLine();
            }

            NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);

            return true;
        }

        public static int QueryWnfInfoClass(
            ulong stateName,
            WNF_STATE_NAME_INFORMATION nameInfoClass)
        {
            int sizeOfUint = Marshal.SizeOf(typeof(uint));
            int exists = 2;

            int ntstatus = NativeMethods.NtQueryWnfStateNameInformation(
                in stateName,
                nameInfoClass,
                IntPtr.Zero,
                ref exists,
                sizeOfUint);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                return 0;
            }

            return exists;
        }

        public static bool ReadWnfData(
            ulong stateName,
            out int changeStamp,
            out IntPtr dataBuffer,
            out int bufferSize)
        {
            changeStamp = 0;
            bufferSize = 0x1000;

            dataBuffer = NativeMethods.VirtualAlloc(
                IntPtr.Zero,
                bufferSize,
                Win32Consts.MEM_COMMIT,
                Win32Consts.PAGE_READWRITE);

            if (dataBuffer == IntPtr.Zero)
            {
                bufferSize = 0;
                return false;
            }

            int ntstatus = NativeMethods.NtQueryWnfStateData(
                in stateName,
                IntPtr.Zero,
                IntPtr.Zero,
                out changeStamp,
                dataBuffer,
                ref bufferSize);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
                dataBuffer = IntPtr.Zero;
                bufferSize = 0;
                return false;
            }

            if (bufferSize == 0)
            {
                NativeMethods.VirtualFree(dataBuffer, 0, Win32Consts.MEM_RELEASE);
                dataBuffer = IntPtr.Zero;
            }

            return true;
        }

        public static bool WriteWnfData(ulong stateName, IntPtr dataBuffer, int dataSize)
        {
            int ntstatus = NativeMethods.NtUpdateWnfStateData(
                in stateName,
                dataBuffer,
                dataSize,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                return false;
            }

            return true;
        }
    }
}
