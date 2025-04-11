﻿using System;
using System.Runtime.InteropServices;

namespace SharpWnfInject.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        /*
         * Dbghelp.dll
         */
        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymFromAddr(
            IntPtr hProcess,
            long Address,
            out long Displacement,
            ref SYMBOL_INFO Symbol);

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern SYM_OPTIONS SymSetOptions(
            SYM_OPTIONS SymOptions);

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymInitialize(
            IntPtr hProcess,
            string UserSearchPath,
            bool fInvadeProcess);

        /*
         * ntdll.dll
         * 
         * Reference:
         *   + https://github.com/processhacker/processhacker/blob/master/phnt/include/ntexapi.h
         *
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtAdjustPrivilegesToken(
            IntPtr TokenHandle,
            BOOLEAN DisableAllPrivileges,
            IntPtr /* PTOKEN_PRIVILEGES */ TokenPrivileges,
            uint PreviousPrivilegesLength,
            IntPtr /* PTOKEN_PRIVILEGES */ PreviousPrivileges,
            IntPtr /* out uint */ RequiredLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            SIZE_T ZeroBits,
            ref SIZE_T RegionSize,
            ALLOCATION_TYPE AllocationType,
            MEMORY_PROTECTION Protect);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref SIZE_T RegionSize,
            ALLOCATION_TYPE FreeType);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenKey(
            out IntPtr KeyHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenProcess(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            in CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSymbolicLinkObject(
            out IntPtr LinkHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref uint NumberOfBytesToProtect,
            MEMORY_PROTECTION NewAccessProtection,
            out MEMORY_PROTECTION OldAccessProtection);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySymbolicLinkObject(
            IntPtr LinkHandle,
            IntPtr /* PUNICODE_STRING */ LinkTarget,
            out uint ReturnedLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryValueKey(
            IntPtr KeyHandle,
            in UNICODE_STRING ValueName,
            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
            IntPtr KeyValueInformation,
            uint Length,
            out uint ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            MEMORY_INFORMATION_CLASS MemoryInformationClass,
            IntPtr MemoryInformation,
            SIZE_T MemoryInformationLength,
            out SIZE_T ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            out uint NumberOfBytesReaded);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtUpdateWnfStateData(
            in ulong StateName,
            IntPtr Buffer,
            int Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            int MatchingChangeScope,
            int CheckStamp);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToWrite,
            out uint NumberOfBytesWritten);

        [DllImport("ntdll.dll")]
        public static extern void RtlGetNtVersionNumbers(
            out int MajorVersion,
            out int MinorVersion,
            out int BuildNumber);
    }
}
