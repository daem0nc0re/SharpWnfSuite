using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfDump.Interop;

namespace SharpWnfDump.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static string DumpWnfData(
            ulong stateName,
            IntPtr pSecurityDescriptor,
            bool bShowSd,
            bool bShowData,
            bool bUsedOnly)
        {
            int nMaxSize = -1;
            var outputBuilder = new StringBuilder();

            if (pSecurityDescriptor != IntPtr.Zero)
            {
                if (NativeMethods.IsValidSecurityDescriptor(pSecurityDescriptor))
                {
                    var nSdSize = NativeMethods.GetSecurityDescriptorLength(pSecurityDescriptor);
                    nMaxSize = Marshal.ReadInt32(pSecurityDescriptor, nSdSize);
                }
                else
                {
                    pSecurityDescriptor = IntPtr.Zero;
                    nMaxSize = 0;
                }
            }

            do
            {
                bool bReadable;
                bool bWritable;
                Char dataScopeTag;
                int nExists = 2;
                var additionalInfoBuilder = new StringBuilder();
                var wnfStateName = new WNF_STATE_NAME { Data = stateName };
                WNF_DATA_SCOPE dataScope = wnfStateName.GetDataScope();

                if (!wnfStateName.IsValid())
                {
                    outputBuilder.Append("[!] WNF State Name is invalid.\n");
                    break;
                }

                if ((dataScope == WNF_DATA_SCOPE.Session) || (dataScope == WNF_DATA_SCOPE.PhysicalMachine))
                    dataScopeTag = dataScope.ToString().ToLower()[0];
                else
                    dataScopeTag = dataScope.ToString()[0];

                bReadable = ReadWnfData(
                    stateName,
                    out int changeStamp,
                    out IntPtr pInfoBuffer,
                    out uint nInfoLength);
                bWritable = IsWritableWnfStateName(stateName);

                if (bWritable)
                    nExists = GetWnfSubscribersPresenceInfo(stateName);

                if (bUsedOnly && (changeStamp == 0))
                    continue;

                outputBuilder.AppendFormat(
                    "| {0,-64}| {1} | {2} | {3} | {4} | {5} | {6,7} | {7,7} | {8,7} |\n",
                    GetWnfName(stateName),
                    dataScopeTag,
                    wnfStateName.GetNameLifeTime().ToString()[0],
                    (wnfStateName.GetPermanentData() != 0) ? 'Y' : 'N',
                    bReadable && bWritable ? "RW" : (bReadable ? "RO" : (bWritable ? "WO" : "NA")),
                    (nExists == 1) ? 'A' : (nExists == 2 ? 'U' : 'I'),
                    nInfoLength,
                    (nMaxSize == -1) ? "?" : nMaxSize.ToString("D"),
                    changeStamp);

                if (bShowSd && pSecurityDescriptor != IntPtr.Zero)
                {
                    NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        pSecurityDescriptor,
                        Win32Consts.SDDL_REVISION_1,
                        SECURITY_INFORMATION.DACL_SECURITY_INFORMATION | SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.LABEL_SECURITY_INFORMATION,
                        out StringBuilder sdString,
                        IntPtr.Zero);
                    additionalInfoBuilder.AppendFormat("\n        {0}\n", sdString);
                }

                if (bShowData && bReadable && (nInfoLength != 0))
                {
                    var hexDump = HexDump.Dump(pInfoBuffer, nInfoLength, 2);
                    additionalInfoBuilder.AppendFormat("\n{0}",
                        string.IsNullOrEmpty(hexDump) ? "Failed to get hexdump.\n" : hexDump);
                }

                if (additionalInfoBuilder.Length > 0)
                    outputBuilder.AppendFormat("{0}\n", additionalInfoBuilder.ToString());

                if (pInfoBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (false);

            return outputBuilder.ToString();
        }


        public static bool GetOsVersionNumbers(out int nMajorVersion, out int nMinorVersion, out int nBuildNumber)
        {
            NTSTATUS ntstatus;
            IntPtr hKey;
            var bSuccess = true;
            var valueNames = new List<string>
            {
                @"CurrentMajorVersionNumber",
                @"CurrentMinorVersionNumber",
                @"CurrentBuildNumber"
            };
            nMajorVersion = 0;
            nMinorVersion = 0;
            nBuildNumber = 0;

            using (var objectAttributes = new OBJECT_ATTRIBUTES(
                   @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                   OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
            {
                ntstatus = NativeMethods.NtOpenKey(
                    out hKey,
                    ACCESS_MASK.KEY_QUERY_VALUE,
                    in objectAttributes);
            }

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return false;

            foreach (var name in valueNames)
            {
                IntPtr pInfoBuffer;
                var nInfoLength = (uint)Marshal.SizeOf(typeof(KEY_VALUE_FULL_INFORMATION));

                using (var valueName = new UNICODE_STRING(name))
                {
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
                        var info = (KEY_VALUE_FULL_INFORMATION)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(KEY_VALUE_FULL_INFORMATION));

                        if (string.Compare(name, @"CurrentMajorVersionNumber", true) == 0)
                        {
                            nMajorVersion = Marshal.ReadInt32(pInfoBuffer, (int)info.DataOffset);
                        }
                        else if (string.Compare(name, @"CurrentMinorVersionNumber", true) == 0)
                        {
                            nMinorVersion = Marshal.ReadInt32(pInfoBuffer, (int)info.DataOffset);
                        }
                        else
                        {
                            IntPtr pStringBuffer;

                            if (Environment.Is64BitProcess)
                                pStringBuffer = new IntPtr(pInfoBuffer.ToInt64() + info.DataOffset);
                            else
                                pStringBuffer = new IntPtr(pInfoBuffer.ToInt32() + (int)info.DataOffset);

                            try
                            {
                                nBuildNumber = Convert.ToInt32(Marshal.PtrToStringUni(pStringBuffer), 10);
                            }
                            catch
                            {
                                bSuccess = false;
                            }
                        }


                        Marshal.FreeHGlobal(pInfoBuffer);
                    }
                    else
                    {
                        bSuccess = false;
                        break;
                    }
                }
            }

            NativeMethods.NtClose(hKey);

            return bSuccess;
        }


        public static string GetOsVersionString(int nMajorVersion, int nMinorVersion, int nBuildNumber)
        {
            string versionString = null;

            if (nMajorVersion == 6)
            {
                if (nMinorVersion == 0)
                    versionString = "Windows Vista";
                else if (nMinorVersion == 1)
                    versionString = "Windows 7 or Windows Server 2008 R2";
                else if (nMinorVersion == 2)
                    versionString = "Windows 8 or Windows Server 2012";
                else if (nMinorVersion == 3)
                    versionString = "Windows 8.1 or Windows Server 2012 R2";
            }
            else if ((nMajorVersion == 10) && (nMinorVersion == 0))
            {
                if (nBuildNumber == 10240)
                    versionString = "Windows 10 Version 1507";
                else if (nBuildNumber == 10586)
                    versionString = "Windows 10 Version 1511";
                else if (nBuildNumber == 14393)
                    versionString = "Windows 10 Version 1607";
                else if (nBuildNumber == 15063)
                    versionString = "Windows 10 Version 1703";
                else if (nBuildNumber == 16299)
                    versionString = "Windows 10 Version 1709";
                else if (nBuildNumber == 17134)
                    versionString = "Windows 10 Version 1803";
                else if (nBuildNumber == 17763)
                    versionString = "Windows 10 Version 1809";
                else if (nBuildNumber == 18362)
                    versionString = "Windows 10 Version 1903";
                else if (nBuildNumber == 18363)
                    versionString = "Windows 10 Version 1909";
                else if (nBuildNumber == 19041)
                    versionString = "Windows 10 Version 2004";
                else if (nBuildNumber == 19042)
                    versionString = "Windows 10 Version 20H2";
                else if (nBuildNumber == 19043)
                    versionString = "Windows 10 Version 21H1";
                else if (nBuildNumber == 19044)
                    versionString = "Windows 10 Version 21H2";
                else if (nBuildNumber == 19045)
                    versionString = "Windows 10 Version 22H2";
                else if (nBuildNumber == 22000)
                    versionString = "Windows 11 Version 21H2";
                else if (nBuildNumber == 22621)
                    versionString = "Windows 11 Version 22H2";
                else if (nBuildNumber == 22631)
                    versionString = "Windows 11 Version 23H2";
                else if (nBuildNumber == 26100)
                    versionString = "Windows 11 Version 24H2";
            }

            return versionString;
        }


        public static string GetWnfName(ulong stateName)
        {
            var wnfStateName = new WNF_STATE_NAME { Data = stateName };
            byte[] tag = BitConverter.GetBytes(wnfStateName.GetOwnerTag());
            WNF_STATE_NAME_LIFETIME nameLifeTime = wnfStateName.GetNameLifeTime();
            string wnfName = null;

            if ((Globals.MajorVersion == 10) && (Globals.MinorVersion == 0))
            {
                if (Globals.BuildNumber == 10240)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1507), stateName);
                else if (Globals.BuildNumber == 10586)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1511), stateName);
                else if (Globals.BuildNumber == 14393)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1607), stateName);
                else if (Globals.BuildNumber == 15063)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1703), stateName);
                else if (Globals.BuildNumber == 16299)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1709), stateName);
                else if (Globals.BuildNumber == 17134)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1803), stateName);
                else if (Globals.BuildNumber == 17763)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1809), stateName);
                else if (Globals.BuildNumber == 18362)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1903_TO_1909), stateName);
                else if (Globals.BuildNumber == 18363)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_1903_TO_1909), stateName);
                else if (Globals.BuildNumber == 19041)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), stateName);
                else if (Globals.BuildNumber == 19042)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), stateName);
                else if (Globals.BuildNumber == 19043)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), stateName);
                else if (Globals.BuildNumber == 19044)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_21H2), stateName);
                else if (Globals.BuildNumber == 19045)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_22H2), stateName);
                else if (Globals.BuildNumber == 22000)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_21H2), stateName);
                else if (Globals.BuildNumber == 22621)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_22H2), stateName);
                else if (Globals.BuildNumber == 22631)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_23H2), stateName);
                else if (Globals.BuildNumber == 26100)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_24H2), stateName);
            }

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
                if (Globals.BuildNumber == 10240)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1507), name.ToUpper());
                else if (Globals.BuildNumber == 10586)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1511), name.ToUpper());
                else if (Globals.BuildNumber == 14393)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1607), name.ToUpper());
                else if (Globals.BuildNumber == 15063)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1703), name.ToUpper());
                else if (Globals.BuildNumber == 16299)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1709), name.ToUpper());
                else if (Globals.BuildNumber == 17134)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1803), name.ToUpper());
                else if (Globals.BuildNumber == 17763)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1809), name.ToUpper());
                else if (Globals.BuildNumber == 18362)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1903_TO_1909), name.ToUpper());
                else if (Globals.BuildNumber == 18363)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1903_TO_1909), name.ToUpper());
                else if (Globals.BuildNumber == 19041)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), name.ToUpper());
                else if (Globals.BuildNumber == 19042)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), name.ToUpper());
                else if (Globals.BuildNumber == 19043)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), name.ToUpper());
                else if (Globals.BuildNumber == 19044)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_21H2), name.ToUpper());
                else if (Globals.BuildNumber == 19045)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_22H2), name.ToUpper());
                else if (Globals.BuildNumber == 22000)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_21H2), name.ToUpper());
                else if (Globals.BuildNumber == 22621)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_22H2), name.ToUpper());
                else if (Globals.BuildNumber == 22631)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_23H2), name.ToUpper());
                else if (Globals.BuildNumber == 26100)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_24H2), name.ToUpper());
                else
                    throw new NotSupportedException();
            }
            catch
            {
                try
                {
                    value = Convert.ToUInt64(name, 16);
                }
                catch
                {
                    value = 0;
                }
            }

            return value;
        }


        public static bool IsWritableWnfStateName(ulong stateName)
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


        public static int GetWnfSubscribersPresenceInfo(ulong stateName)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryWnfStateNameInformation(
                in stateName,
                WNF_STATE_NAME_INFORMATION.WnfInfoSubscribersPresent,
                IntPtr.Zero,
                pInfoBuffer,
                4);
            int nPresent = Marshal.ReadInt32(pInfoBuffer);
            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS) ? nPresent : 0;
        }


        public static bool ReadWnfData(
            ulong stateName,
            out int nChangeStamp,
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
                    out nChangeStamp,
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


        public static bool WriteWnfData(ulong stateName, IntPtr pDataBuffer, int nDataSize)
        {
            NTSTATUS ntstatus = NativeMethods.NtUpdateWnfStateData(
                in stateName,
                pDataBuffer,
                nDataSize,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
