using System;
using System.Collections.Generic;
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

            if (((pPebWow32 != IntPtr.Zero) && Environment.Is64BitProcess) ||
                !Environment.Is64BitProcess)
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

                        pInMemoryOrderModuleList = new IntPtr(Marshal.ReadInt32(pInfoBuffer));
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


        public static Dictionary<string, IntPtr> GetModuleSectionBases(
            IntPtr hProcess,
            IntPtr pModuleBase)
        {
            IntPtr pInfoBuffer;
            var nInfoLength = 0x40u;
            var sections = new Dictionary<string, IntPtr>();

            if ((pModuleBase.ToInt64() & 0xFFF) != 0)
                return sections;

            pInfoBuffer = Marshal.AllocHGlobal(0x40);

            do
            {
                int e_lfanew;
                ushort nNumberOfSections;
                ushort nSizeOfOptionalHeader;
                IntPtr pNtHeaders;
                IntPtr pSectionHeader;
                int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
                NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pModuleBase,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                if (Marshal.ReadInt16(pInfoBuffer) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pInfoBuffer, 0x3C);
                nInfoLength = 0x18u;

                if (Environment.Is64BitProcess)
                    pNtHeaders = new IntPtr(pModuleBase.ToInt64() + e_lfanew);
                else
                    pNtHeaders = new IntPtr(pModuleBase.ToInt32() + e_lfanew);

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
                    pSectionHeader = new IntPtr(pModuleBase.ToInt64() + e_lfanew + 0x18 + nSizeOfOptionalHeader);
                else
                    pSectionHeader = new IntPtr(pModuleBase.ToInt32() + e_lfanew + 0x18 + nSizeOfOptionalHeader);

                Marshal.FreeHGlobal(pInfoBuffer);
                nInfoLength = (uint)(nSectionHeaderSize * nNumberOfSections);
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pSectionHeader,
                    pInfoBuffer,
                    nInfoLength,
                    out nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                pSectionHeader = pInfoBuffer;

                for (var idx = 0; idx < nNumberOfSections; idx++)
                {
                    var info = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));

                    if (Environment.Is64BitProcess)
                    {
                        sections.Add(info.Name, new IntPtr(pModuleBase.ToInt64() + info.VirtualAddress));
                        pSectionHeader = new IntPtr(pSectionHeader.ToInt64() + nSectionHeaderSize);
                    }
                    else
                    {
                        sections.Add(info.Name, new IntPtr(pModuleBase.ToInt32() + (int)info.VirtualAddress));
                        pSectionHeader = new IntPtr(pSectionHeader.ToInt32() + nSectionHeaderSize);
                    }
                }
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            return sections;
        }


        public static string GetSymbolPath(IntPtr hProcess, IntPtr pBuffer)
        {
            var symbolBuilder = new StringBuilder();
            var mappedFileName = new UNICODE_STRING();
            var nInfoLength = (uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
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

            return (((majorVersion == 10) && ((buildNumber & 0xFFFF) >= 22000)) || (majorVersion > 10));
        }


        public static bool Is32BitProcess(IntPtr hProcess)
        {
            bool b32BitProcess = false;

            if (Environment.Is64BitOperatingSystem)
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
