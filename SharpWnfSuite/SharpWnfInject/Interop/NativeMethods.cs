using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWnfInject.Interop
{
    using NTSTATUS = Int32;

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
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MemoryAllocationFlags flAllocationType,
            MemoryProtectionFlags flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MemoryProtectionFlags flNewProtect,
            out MemoryProtectionFlags lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            IntPtr lpNumberOfBytesWritten);

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
        public static extern NTSTATUS NtQueryWnfStateData(
            in ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            IntPtr Buffer,
            ref int BufferSize);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryWnfStateNameInformation(
            in ulong StateName,
            WNF_STATE_NAME_INFORMATION NameInfoClass,
            IntPtr ExplicitScope,
            ref int InfoBuffer,
            int InfoBufferSize);

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
        public static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);
    }
}
