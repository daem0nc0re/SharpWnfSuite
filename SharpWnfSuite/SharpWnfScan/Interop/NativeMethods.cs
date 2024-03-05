using System;
using System.Runtime.InteropServices;

namespace SharpWnfScan.Interop
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
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

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
        public static extern NTSTATUS NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            MEMORY_INFORMATION_CLASS MemoryInformationClass,
            IntPtr MemoryInformation,
            SIZE_T MemoryInformationLength,
            out SIZE_T ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern void RtlGetNtVersionNumbers(
            out int MajorVersion,
            out int MinorVersion,
            out int BuildNumber);
    }
}
