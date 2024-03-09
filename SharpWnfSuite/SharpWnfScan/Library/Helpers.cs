﻿using System;
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
