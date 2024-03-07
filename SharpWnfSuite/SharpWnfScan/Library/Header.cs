using System.Runtime.InteropServices;

namespace SharpWnfScan.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public string ProcessName;
        public int ProcessId;
        public string Architecture;
        public string ErrorMessage;
    }
}
