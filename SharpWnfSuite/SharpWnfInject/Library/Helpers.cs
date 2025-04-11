using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using SharpWnfInject.Interop;

namespace SharpWnfInject.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Helpers
    {
        public static Dictionary<string, string> GetDeviceMap()
        {
            var driveLetters = new List<string>();
            var deviceMap = new Dictionary<string, string>();
            var nInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_DEVICEMAP_INFORMATION));
            var pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                new IntPtr(-1),
                PROCESSINFOCLASS.ProcessDeviceMap,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            int nDeviceMap = Marshal.ReadInt32(pInfoBuffer);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                for (int idx = 0; idx < 0x1A; idx++)
                {
                    var nTestBit = (1 << idx);
                    var driveLetterBytes = new byte[] { (byte)(0x41 + idx), 0x3A };

                    if ((nDeviceMap & nTestBit) == nTestBit)
                        driveLetters.Add(Encoding.ASCII.GetString(driveLetterBytes));
                }
            }

            foreach (var letter in driveLetters)
            {
                IntPtr hSymlink;
                var unicodeString = new UNICODE_STRING { MaximumLength = 512 };

                using (var objectAttributes = new OBJECT_ATTRIBUTES(
                    string.Format(@"\GLOBAL??\{0}", letter),
                    OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
                {
                    ntstatus = NativeMethods.NtOpenSymbolicLinkObject(
                        out hSymlink,
                        ACCESS_MASK.SYMBOLIC_LINK_QUERY,
                        in objectAttributes);
                }

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    continue;

                if (Environment.Is64BitProcess)
                    unicodeString.SetBuffer(new IntPtr(pInfoBuffer.ToInt64() + Marshal.SizeOf(typeof(UNICODE_STRING))));
                else
                    unicodeString.SetBuffer(new IntPtr(pInfoBuffer.ToInt32() + Marshal.SizeOf(typeof(UNICODE_STRING))));

                Marshal.StructureToPtr(unicodeString, pInfoBuffer, true);

                ntstatus = NativeMethods.NtQuerySymbolicLinkObject(hSymlink, pInfoBuffer, out uint _);
                NativeMethods.NtClose(hSymlink);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    var target = (UNICODE_STRING)Marshal.PtrToStructure(pInfoBuffer, typeof(UNICODE_STRING));

                    if (target.Length != 0)
                        deviceMap.Add(letter, target.ToString());
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return deviceMap;
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
                    versionString = "Windows Vista or Windows Server 2008";
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
                    versionString = "Windows 10 Version 1607 or Windows Server 2016";
                else if (nBuildNumber == 15063)
                    versionString = "Windows 10 Version 1703";
                else if (nBuildNumber == 16299)
                    versionString = "Windows 10 Version 1709";
                else if (nBuildNumber == 17134)
                    versionString = "Windows 10 Version 1803";
                else if (nBuildNumber == 17763)
                    versionString = "Windows 10 Version 1809 or Windows Server 2019";
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
                else if (nBuildNumber == 20348)
                    versionString = "Windows Server 2022";
                else if (nBuildNumber == 22000)
                    versionString = "Windows 11 Version 21H2";
                else if (nBuildNumber == 22621)
                    versionString = "Windows 11 Version 22H2";
                else if (nBuildNumber == 22631)
                    versionString = "Windows 11 Version 23H2";
                else if (nBuildNumber == 26100)
                    versionString = "Windows 11 Version 24H2 or Windows Server 2025";
            }

            return versionString;
        }


        public static IntPtr GetPebBase(IntPtr hProcess, out IntPtr pPebWow32)
        {
            var pPeb = IntPtr.Zero;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            pPebWow32 = IntPtr.Zero;

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
                pPeb = info.PebBaseAddress;

                if (Environment.Is64BitProcess)
                {
                    ntstatus = NativeMethods.NtQueryInformationProcess(
                        hProcess,
                        PROCESSINFOCLASS.ProcessWow64Information,
                        pInfoBuffer,
                        (uint)IntPtr.Size,
                        out uint _);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                        pPebWow32 = Marshal.ReadIntPtr(pInfoBuffer);
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);
            return pPeb;
        }


        public static IMAGE_FILE_MACHINE GetProcessArchitecture(IntPtr hProcess)
        {
            uint nInfoLength;
            IntPtr pBufferToRead;
            IntPtr pInfoBuffer;
            IntPtr pPeb = GetPebBase(hProcess, out IntPtr pPebWow32);
            var architecture = IMAGE_FILE_MACHINE.UNKNOWN;

            if (pPeb == IntPtr.Zero)
                return IMAGE_FILE_MACHINE.UNKNOWN;

            if (pPebWow32 != IntPtr.Zero)
                pPeb = pPebWow32;

            if (Environment.Is64BitProcess && (pPebWow32 == IntPtr.Zero))
            {
                pBufferToRead = new IntPtr(pPeb.ToInt64() + 0x10);
                nInfoLength = 8u;
            }
            else
            {
                pBufferToRead = new IntPtr(pPeb.ToInt32() + 0x8);
                nInfoLength = 4u;
            }

            pInfoBuffer = Marshal.AllocHGlobal(0x40);

            do
            {
                IntPtr pImageBase;
                NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pBufferToRead,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                if (nInfoLength == 8u)
                    pImageBase = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
                else
                    pImageBase = new IntPtr(Marshal.ReadInt32(pInfoBuffer));

                nInfoLength = 0x40u;
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pImageBase,
                    pInfoBuffer,
                    nInfoLength,
                    out nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                if (Environment.Is64BitProcess && (pPebWow32 == IntPtr.Zero))
                    pBufferToRead = new IntPtr(pImageBase.ToInt64() + Marshal.ReadInt32(pInfoBuffer, 0x3C));
                else
                    pBufferToRead = new IntPtr(pImageBase.ToInt32() + Marshal.ReadInt32(pInfoBuffer, 0x3C));

                nInfoLength = 0x18u;
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pBufferToRead,
                    pInfoBuffer,
                    nInfoLength,
                    out nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                architecture = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pInfoBuffer, 4);
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            return architecture;
        }


        public static string GetProcessImageFileName(IntPtr hProcess)
        {
            var nInfoLength = (uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            string imageFileName = null;
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessImageFileName,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (UNICODE_STRING)Marshal.PtrToStructure(pInfoBuffer, typeof(UNICODE_STRING));
                Dictionary<string, string> deviceMap = GetDeviceMap();
                imageFileName = info.ToString();

                if (info.Length > 0)
                {
                    foreach (var alias in deviceMap)
                    {
                        if (imageFileName.StartsWith(alias.Value, StringComparison.OrdinalIgnoreCase))
                        {
                            imageFileName = Regex.Replace(
                                imageFileName,
                                string.Format(@"^{0}", alias.Value).Replace(@"\", @"\\"),
                                alias.Key,
                                RegexOptions.IgnoreCase);
                            break;
                        }
                    }
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return imageFileName;
        }


        public static Dictionary<string, IntPtr> GetProcessModules(
            IntPtr hProcess,
            out Dictionary<string, IntPtr> wow32Modules)
        {
            NTSTATUS ntstatus;
            IntPtr pLdr;
            IntPtr pInfoBuffer;
            IntPtr pRootInMemoryOrderModuleList;
            IntPtr pInMemoryOrderModuleList;
            uint nInfoLength;
            uint nReturnedLength;
            IntPtr pPeb = GetPebBase(hProcess, out IntPtr pPebWow32);
            var modules = new Dictionary<string, IntPtr>();
            wow32Modules = new Dictionary<string, IntPtr>();

            if (pPeb == IntPtr.Zero)
                return modules;

            pInfoBuffer = Marshal.AllocHGlobal(0x800);

            if (((pPebWow32 != IntPtr.Zero) && Environment.Is64BitProcess) || !Environment.Is64BitProcess)
            {
                do
                {
                    if (!Environment.Is64BitProcess)
                        pPebWow32 = pPeb;

                    nInfoLength = 4u;
                    ntstatus = NativeMethods.NtReadVirtualMemory(
                        hProcess,
                        new IntPtr(pPebWow32.ToInt32() + 0xC),
                        pInfoBuffer,
                        nInfoLength,
                        out nReturnedLength);

                    if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                        break;

                    pLdr = new IntPtr(Marshal.ReadInt32(pInfoBuffer));
                    pRootInMemoryOrderModuleList = new IntPtr(pLdr.ToInt32() + 0x14);
                    ntstatus = NativeMethods.NtReadVirtualMemory(
                        hProcess,
                        pRootInMemoryOrderModuleList,
                        pInfoBuffer,
                        nInfoLength,
                        out nReturnedLength);

                    if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                        break;

                    pInMemoryOrderModuleList = new IntPtr(Marshal.ReadInt32(pInfoBuffer));

                    while (pInMemoryOrderModuleList != pRootInMemoryOrderModuleList)
                    {
                        IntPtr pDllBase;
                        string moduleName;
                        nInfoLength = 0x2Cu;
                        ntstatus = NativeMethods.NtReadVirtualMemory(
                            hProcess,
                            pInMemoryOrderModuleList,
                            pInfoBuffer,
                            nInfoLength,
                            out nReturnedLength);

                        if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                            break;

                        pInMemoryOrderModuleList = new IntPtr(Marshal.ReadInt32(pInfoBuffer));
                        pDllBase = new IntPtr(Marshal.ReadInt32(pInfoBuffer, 0x10));
                        nInfoLength = (uint)Marshal.ReadInt16(pInfoBuffer, 0x24);
                        ntstatus = NativeMethods.NtReadVirtualMemory(
                            hProcess,
                            new IntPtr(Marshal.ReadInt32(pInfoBuffer, 0x28)),
                            pInfoBuffer,
                            nInfoLength,
                            out nReturnedLength);

                        if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                            break;

                        moduleName = Marshal.PtrToStringUni(pInfoBuffer, (int)nInfoLength / 2);

                        if (Environment.Is64BitProcess && !wow32Modules.ContainsKey(moduleName))
                            wow32Modules.Add(moduleName, pDllBase);
                        else if (!Environment.Is64BitProcess && !modules.ContainsKey(moduleName))
                            modules.Add(moduleName, pDllBase);
                    }
                } while (false);
            }

            if (Environment.Is64BitProcess)
            {
                do
                {
                    nInfoLength = 8u;
                    ntstatus = NativeMethods.NtReadVirtualMemory(
                        hProcess,
                        new IntPtr(pPeb.ToInt64() + 0x18),
                        pInfoBuffer,
                        nInfoLength,
                        out nReturnedLength);

                    if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                        break;

                    pLdr = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
                    pRootInMemoryOrderModuleList = new IntPtr(pLdr.ToInt64() + 0x20);
                    ntstatus = NativeMethods.NtReadVirtualMemory(
                        hProcess,
                        pRootInMemoryOrderModuleList,
                        pInfoBuffer,
                        nInfoLength,
                        out nReturnedLength);

                    if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                        break;

                    pInMemoryOrderModuleList = new IntPtr(Marshal.ReadInt64(pInfoBuffer));

                    while (pInMemoryOrderModuleList != pRootInMemoryOrderModuleList)
                    {
                        IntPtr pDllBase;
                        string moduleName;
                        nInfoLength = 0x58u;
                        ntstatus = NativeMethods.NtReadVirtualMemory(
                            hProcess,
                            pInMemoryOrderModuleList,
                            pInfoBuffer,
                            nInfoLength,
                            out nReturnedLength);

                        if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                            break;

                        pInMemoryOrderModuleList = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
                        pDllBase = new IntPtr(Marshal.ReadInt64(pInfoBuffer, 0x20));
                        nInfoLength = (uint)Marshal.ReadInt16(pInfoBuffer, 0x48);
                        ntstatus = NativeMethods.NtReadVirtualMemory(
                            hProcess,
                            new IntPtr(Marshal.ReadInt64(pInfoBuffer, 0x50)),
                            pInfoBuffer,
                            nInfoLength,
                            out nReturnedLength);

                        if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                            break;

                        moduleName = Marshal.PtrToStringUni(pInfoBuffer, (int)nInfoLength / 2);

                        if (!modules.ContainsKey(moduleName))
                            modules.Add(moduleName, pDllBase);
                    }
                } while (false);
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return modules;
        }


        public static Dictionary<string, IMAGE_SECTION_HEADER> GetModuleSectionHeaders(
            IntPtr hProcess,
            IntPtr pModuleBase)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            ushort nNumberOfSections = 0;
            var pSectionHeader = IntPtr.Zero;
            var nInfoLength = 0x40u;
            var headers = new Dictionary<string, IMAGE_SECTION_HEADER>();

            if ((pModuleBase.ToInt64() & 0xFFF) != 0)
                return headers;

            pInfoBuffer = Marshal.AllocHGlobal(0x40);

            do
            {
                IntPtr pNtHeaders;
                ushort nSizeOfOptionalHeader;
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pModuleBase,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                if (Marshal.ReadInt16(pInfoBuffer) != 0x5A4D)
                    break;

                nInfoLength = 0x18u;

                if (Environment.Is64BitProcess)
                    pNtHeaders = new IntPtr(pModuleBase.ToInt64() + Marshal.ReadInt32(pInfoBuffer, 0x3C));
                else
                    pNtHeaders = new IntPtr(pModuleBase.ToInt32() + Marshal.ReadInt32(pInfoBuffer, 0x3C));

                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pNtHeaders,
                    pInfoBuffer,
                    nInfoLength,
                    out nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                nNumberOfSections = (ushort)Marshal.ReadInt16(pInfoBuffer, 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pInfoBuffer, 0x14);

                if (Environment.Is64BitProcess)
                    pSectionHeader = new IntPtr(pNtHeaders.ToInt64() + 0x18 + nSizeOfOptionalHeader);
                else
                    pSectionHeader = new IntPtr(pNtHeaders.ToInt32() + 0x18 + nSizeOfOptionalHeader);
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            if (pSectionHeader != IntPtr.Zero)
            {
                int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
                nInfoLength = (uint)(nSectionHeaderSize * nNumberOfSections);
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pSectionHeader,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nReturnedLength);

                if ((ntstatus == Win32Consts.STATUS_SUCCESS) && (nReturnedLength == nInfoLength))
                {
                    for (var idx = 0; idx < nNumberOfSections; idx++)
                    {
                        if (Environment.Is64BitProcess)
                            pSectionHeader = new IntPtr(pInfoBuffer.ToInt64() + (nSectionHeaderSize * idx));
                        else
                            pSectionHeader = new IntPtr(pInfoBuffer.ToInt32() + (int)(nSectionHeaderSize * idx));

                        var info = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                            pSectionHeader,
                            typeof(IMAGE_SECTION_HEADER));
                        headers.Add(info.Name, info);
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return headers;
        }

        public static string GetSymbolPath(IntPtr hProcess, IntPtr pBuffer)
        {
            IntPtr pInfoBuffer;
            var symbolBuilder = new StringBuilder();
            var mappedFileName = new UNICODE_STRING();
            var nInfoLength = (uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
            var symbolInfo = new SYMBOL_INFO
            {
                SizeOfStruct = (uint)Marshal.SizeOf(typeof(SYMBOL_INFO)) - Win32Consts.MAX_SYM_NAME,
                MaxNameLen = Win32Consts.MAX_SYM_NAME,
                Name = new byte[Win32Consts.MAX_SYM_NAME]
            };
            NativeMethods.SymSetOptions(SYM_OPTIONS.SYMOPT_DEFERRED_LOADS);

            if (!NativeMethods.SymInitialize(hProcess, null, true))
                return null;

            pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            Marshal.StructureToPtr(mappedFileName, pInfoBuffer, false);

            do
            {
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

                symbolBuilder.Append(Path.GetFileNameWithoutExtension(mappedFileName.ToString()));

                if (NativeMethods.SymFromAddr(
                    hProcess,
                    pBuffer.ToInt64(),
                    out long nDisplacement,
                    ref symbolInfo))
                {
                    symbolBuilder.AppendFormat("!{0}", Encoding.ASCII.GetString(symbolInfo.Name).Trim('\0'));

                    if (nDisplacement != 0L)
                        symbolBuilder.AppendFormat("+0x{0}", nDisplacement.ToString("X"));
                }
            } while (false);

            NativeMethods.SymCleanup(hProcess);
            Marshal.FreeHGlobal(pInfoBuffer);

            return (symbolBuilder.Length == 0) ? null : symbolBuilder.ToString();
        }


        public static string GetWellKnownWnfName(ulong stateName)
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
                else if (Globals.BuildNumber == 20348)
                    wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME_2022), stateName);
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
                else if (Globals.BuildNumber == 20348)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2022), name.ToUpper());
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



        public static bool Is32BitProcess(IntPtr hProcess)
        {
            bool b32BitProcess = !Environment.Is64BitOperatingSystem || !Environment.Is64BitProcess;

            if (!b32BitProcess)
            {
                IntPtr pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessWow64Information,
                    pInfoBuffer,
                    (uint)IntPtr.Size,
                    out uint _);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    b32BitProcess = (Marshal.ReadIntPtr(pInfoBuffer) != IntPtr.Zero);

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return b32BitProcess;
        }

        public static bool IsWin11()
        {
            NativeMethods.RtlGetNtVersionNumbers(out int majorVersion, out int _, out int buildNumber);

            return (((majorVersion == 10) && ((buildNumber & 0xFFFF) >= 22000)) || (majorVersion > 10));
        }

        public static bool IsHeapAddress(IntPtr hProcess, IntPtr pBuffer)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryVirtualMemory(
                hProcess,
                pBuffer,
                MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
                pInfoBuffer,
                new SIZE_T(nInfoLength),
                out SIZE_T _);
            bool bIsHeapAddress = false;

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (MEMORY_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(MEMORY_BASIC_INFORMATION));
                bIsHeapAddress = (info.State == MEMORY_ALLOCATION_TYPE.MEM_COMMIT) &&
                    (info.Type == MEMORY_ALLOCATION_TYPE.MEM_PRIVATE) &&
                    (info.Protect == MEMORY_PROTECTION.PAGE_READWRITE);
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return bIsHeapAddress;
        }
    }
}
