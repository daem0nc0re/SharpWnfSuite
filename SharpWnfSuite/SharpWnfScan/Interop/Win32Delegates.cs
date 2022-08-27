using System;
using System.Runtime.InteropServices;

namespace SharpWnfScan.Interop
{
    internal class Win32Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int WNF_USER_CALLBACK(
            WNF_STATE_NAME StateName,
            uint /* WNF_CHANGE_STAMP */ ChangeStamp,
            IntPtr /* WNF_TYPE_ID */ TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            uint BufferSize);
    }
}
