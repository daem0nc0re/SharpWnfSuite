using System;
using System.Runtime.InteropServices;

namespace SharpWnfScan.Interop
{
    class Win32Delegate
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int WNF_USER_CALLBACK(
            Win32Struct.WNF_STATE_NAME StateName,
            uint /* WNF_CHANGE_STAMP */ ChangeStamp,
            IntPtr /* WNF_TYPE_ID */ TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            uint BufferSize);
    }
}
