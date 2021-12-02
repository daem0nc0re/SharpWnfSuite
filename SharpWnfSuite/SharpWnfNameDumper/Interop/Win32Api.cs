using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWnfNameDumper.Interop
{
    class Win32Api
    {
        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            int dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            int dwSize,
            uint dwFreeType);
    }
}
