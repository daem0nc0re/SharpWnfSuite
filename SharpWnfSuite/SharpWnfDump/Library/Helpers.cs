using System;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfDump.Interop;

namespace SharpWnfDump.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
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
                    maxSize = Marshal.ReadInt32(pSecurityDescriptor, sdSize);
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
            var wnfStateName = new WNF_STATE_NAME { Data = stateName };
            byte[] tag = BitConverter.GetBytes(wnfStateName.GetOwnerTag());
            WNF_STATE_NAME_LIFETIME nameLifeTime = wnfStateName.GetNameLifeTime();
            string wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME), stateName);

            if (string.IsNullOrEmpty(wnfName))
            {
                if (nameLifeTime == WNF_STATE_NAME_LIFETIME.WellKnown)
                {
                    wnfName = string.Format("{0}.{1} 0x{2}",
                        Encoding.ASCII.GetString(tag).Trim('\0'),
                        wnfStateName.GetSequenceNumber().ToString("D3"),
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
                value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME), name.ToUpper());
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


        public static bool IsWritable(ulong stateName)
        {
            NTSTATUS ntstatus = NativeMethods.NtUpdateWnfStateData(
                in stateName,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                -1,
                1);

            return (ntstatus == Win32Consts.STATUS_OPERATION_FAILED);
        }


        public static bool PrintWnfRuntimeStatus(
            ulong stateName,
            IntPtr pSecurityDescriptor,
            bool showSd,
            int maxSize,
            bool showData)
        {
            bool bReadable;
            bool bWritable;
            Char dataScopeTag;
            WNF_DATA_SCOPE dataScope;
            long exists = 2;
            int SDDL_REVISION_1 = 1;
            var wnfStateName = new WNF_STATE_NAME { Data = stateName };


            if (!wnfStateName.IsValid())
                return false;

            dataScope = wnfStateName.GetDataScope();

            if ((dataScope == WNF_DATA_SCOPE.Session) || (dataScope == WNF_DATA_SCOPE.PhysicalMachine))
                dataScopeTag = dataScope.ToString().ToLower()[0];
            else
                dataScopeTag = dataScope.ToString()[0];

            bReadable = ReadWnfData(
                stateName,
                out int changeStamp,
                out IntPtr dataBuffer,
                out uint bufferSize);
            bWritable = IsWritable(stateName);

            if (bWritable)
            {
                exists = QueryWnfInfoClass(
                    stateName,
                    WNF_STATE_NAME_INFORMATION.WnfInfoSubscribersPresent);
            }

            Console.WriteLine(
                "| {0,-64}| {1} | {2} | {3} | {4} | {5} | {6,7} | {7,7} | {8,7} |",
                GetWnfName(stateName),
                dataScopeTag,
                wnfStateName.GetNameLifeTime().ToString()[0],
                (wnfStateName.GetPermanentData() != 0) ? 'Y' : 'N',
                bReadable && bWritable ? "RW" : (bReadable ? "RO" : (bWritable ? "WO" : "NA")),
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

            if (showData && bReadable && bufferSize != 0)
            {
                Console.WriteLine();
                HexDump.Dump(dataBuffer, (uint)bufferSize, 2);
                Console.WriteLine();
            }
            else if (showSd)
            {
                Console.WriteLine();
            }

            if (dataBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(dataBuffer);

            return true;
        }


        public static int QueryWnfInfoClass(
            ulong stateName,
            WNF_STATE_NAME_INFORMATION nameInfoClass)
        {
            int exists = 2;
            NTSTATUS ntstatus = NativeMethods.NtQueryWnfStateNameInformation(
                in stateName,
                nameInfoClass,
                IntPtr.Zero,
                ref exists,
                4);

            return (ntstatus == Win32Consts.STATUS_SUCCESS) ? exists : 0;
        }


        public static bool ReadWnfData(
            ulong stateName,
            out int changeStamp,
            out IntPtr pInfoBuffer,
            out uint nInfoLength)
        {
            NTSTATUS ntstatus;
            nInfoLength = 0x1000u;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryWnfStateData(
                    in stateName,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out changeStamp,
                    pInfoBuffer,
                    ref nInfoLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nInfoLength == 0))
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool WriteWnfData(ulong stateName, IntPtr dataBuffer, int dataSize)
        {
            NTSTATUS ntstatus = NativeMethods.NtUpdateWnfStateData(
                in stateName,
                dataBuffer,
                dataSize,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
