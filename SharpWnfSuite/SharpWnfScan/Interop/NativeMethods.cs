using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWnfScan.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        /*
         * Dbghelp.dll
         */
        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymFromAddr(
            IntPtr hProcess,
            long Address,
            IntPtr Displacement,
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
         * Psapi.dll
         */
        [DllImport("Psapi.dll", SetLastError = true)]
        public static extern uint GetMappedFileName(
            IntPtr hProcess,
            IntPtr fileHandle,
            StringBuilder lpFilename,
            uint nSize);

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
        public static extern void RtlGetNtVersionNumbers(
            out int MajorVersion,
            out int MinorVersion,
            out int BuildNumber);
    }
}
