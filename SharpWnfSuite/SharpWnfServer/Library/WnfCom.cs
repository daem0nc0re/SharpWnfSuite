using System;
using System.ComponentModel;
using System.Text;
using System.Runtime.InteropServices;
using SharpWnfServer.Interop;

namespace SharpWnfServer.Library
{
    using NTSTATUS = Int32;

    internal class WnfCom : IDisposable
    {
        /*
         * Structs
         */
        private struct NotifyContext
        {
            public bool Destroyed;
            public IntPtr Event;

            public NotifyContext(bool _destroyed, IntPtr _event)
            {
                this.Destroyed = _destroyed;
                this.Event = _event;
            }
        }

        /*
         * Delegate Types
         */
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CallbackDelegate(
            ulong StateName,
            int ChangeStamp,
            IntPtr TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            int BufferSize);

        /*
         * Global Variables
         */
        private WNF_STATE_NAME StateName;
        private readonly IntPtr Callback;
        private readonly IntPtr SecurityDescriptor;
        private IntPtr Dacl;
        private IntPtr Sid;

        /*
         * Constructors
         */
        public WnfCom()
        {
            this.StateName = new WNF_STATE_NAME();
            this.Callback = Marshal.GetFunctionPointerForDelegate(new CallbackDelegate(NotifyCallback));
            this.SecurityDescriptor = GetWorldAllowedSecurityDescriptor();

            if (this.SecurityDescriptor == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to initialize Security Descriptor");
        }


        public WnfCom(string nameString)
        {
            SetStateName(nameString);
            this.Callback = Marshal.GetFunctionPointerForDelegate(new CallbackDelegate(NotifyCallback));
            this.SecurityDescriptor = GetWorldAllowedSecurityDescriptor();

            if (this.SecurityDescriptor == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to initialize Security Descriptor");
        }


        /*
         * Destructor
         */
        public void Dispose()
        {
            Marshal.FreeHGlobal(this.Dacl);
            Marshal.FreeHGlobal(this.Sid);
            Marshal.FreeHGlobal(this.SecurityDescriptor);
        }

        /*
         * Public Methods
         */
        public ulong CreateServer()
        {
            NTSTATUS ntstatus = NativeMethods.NtCreateWnfStateName(
                out this.StateName.Data,
                WNF_STATE_NAME_LIFETIME.Temporary,
                WNF_DATA_SCOPE.Machine,
                false,
                IntPtr.Zero,
                0x1000,
                this.SecurityDescriptor);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("\n[+] New WNF State Name is created successfully : 0x{0}\n", this.StateName.Data.ToString("X16"));
            }
            else
            {
                Console.WriteLine("\n[-] Failed to create a new WNF State Name (NTSTATUS = 0x{0}).\n", ntstatus.ToString("X8"));
                this.StateName.Data = 0UL;
            }

            return this.StateName.Data;
        }


        public bool Listen()
        {
            NTSTATUS ntstatus;
            NotifyContext context;
            IntPtr hEvent = IntPtr.Zero;
            IntPtr pContextBuffer = IntPtr.Zero;
            IntPtr pSubscription = IntPtr.Zero;
            bool status = false;

            do
            {
                if (this.StateName.Data == 0UL)
                {
                    Console.WriteLine("\n[-] Server is not initialized.\n");
                    break;
                }

                hEvent = NativeMethods.CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);

                if (hEvent == IntPtr.Zero)
                {
                    Console.WriteLine("\n[-] Failed to create event.\n");
                    break;
                }

                pContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NotifyContext)));
                context = new NotifyContext(false, hEvent);
                Marshal.StructureToPtr(context, pContextBuffer, true);

                ntstatus = NativeMethods.RtlSubscribeWnfStateChangeNotification(
                    out pSubscription,
                    this.StateName.Data,
                    0,
                    this.Callback,
                    pContextBuffer,
                    IntPtr.Zero,
                    0,
                    0);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                    Console.WriteLine("\n[-] Failed to subscribe WNF (NTSTATUS = 0x{0})\n", ntstatus.ToString("X8"));
            } while (false);

            if (status)
            {
                do
                {
                    try
                    {
                        NativeMethods.WaitForSingleObject(hEvent, 1000);
                        context = (NotifyContext)Marshal.PtrToStructure(pContextBuffer, typeof(NotifyContext));
                    }
                    catch
                    {
                        break;
                    }
                } while (!context.Destroyed);

                NativeMethods.RtlUnsubscribeWnfStateChangeNotification(pSubscription);
            }

            if (hEvent != IntPtr.Zero)
                NativeMethods.CloseHandle(hEvent);

            if (pContextBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pContextBuffer);

            return status;
        }


        public void PrintInternalName()
        {
            var output = new StringBuilder();

            output.AppendFormat("Encoded State Name: 0x{0}, Decoded State Name: 0x{1}\n",
                this.StateName.Data.ToString("X16"),
                (this.StateName.Data ^ 0x41C64E6DA3BC0074UL).ToString("X"));
            output.AppendFormat("    Version: {0}, Lifetime: {1}, Scope: {2}, Permanent: {3}, Sequence Number: 0x{4}, Owner Tag: 0x{5}\n",
                this.StateName.GetVersion(),
                this.StateName.GetNameLifeTime().ToString(),
                this.StateName.GetDataScope().ToString(),
                (this.StateName.GetPermanentData() != 0) ? "YES" : "NO",
                this.StateName.GetSequenceNumber().ToString("X"),
                this.StateName.GetOwnerTag().ToString("X"));

            Console.WriteLine(output.ToString());
        }


        public bool Read(out int nChangeStamp, out IntPtr pDataBuffer, out int nBufferSize)
        {
            NTSTATUS ntstatus;
            bool status = false;
            pDataBuffer = IntPtr.Zero;
            nChangeStamp = 0;
            nBufferSize = 0x1000;

            do
            {
                if (this.StateName.Data == 0UL)
                {
                    Console.WriteLine("\n[-] Server is not initialized.\n");
                    break;
                }

                pDataBuffer = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    nBufferSize,
                    Win32Consts.MEM_COMMIT,
                    Win32Consts.PAGE_READWRITE);

                if (pDataBuffer == IntPtr.Zero)
                    break;

                ntstatus = NativeMethods.NtQueryWnfStateData(
                    in this.StateName.Data,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out nChangeStamp,
                    pDataBuffer,
                    ref nBufferSize);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);
            } while (false);

            if (!status)
            {
                nChangeStamp = 0;
                nBufferSize = 0;

                if (pDataBuffer != IntPtr.Zero)
                {
                    NativeMethods.VirtualFree(pDataBuffer, 0, Win32Consts.MEM_RELEASE);
                    pDataBuffer = IntPtr.Zero;
                }
            }

            return status;
        }


        public bool SetStateName(string name)
        {
            bool status = false;
            ulong tmpName = GetWnfStateName(name);

            if (tmpName != 0)
            {
                this.StateName.Data = tmpName;
                status = true;
            }

            return status;
        }


        public bool Write(byte[] data)
        {
            NTSTATUS ntstatus;
            IntPtr pDataBuffer;

            if (this.StateName.Data == 0UL)
            {
                Console.WriteLine("\n[-] Server is not initialized.\n");
                return false;
            }

            pDataBuffer = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pDataBuffer, data.Length);

            Console.WriteLine("Sending input data to WNF subscriber...\n");

            ntstatus = NativeMethods.NtUpdateWnfStateData(
                in this.StateName.Data,
                pDataBuffer,
                data.Length,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);
            Marshal.FreeHGlobal(pDataBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        /*
         * Private Methods
         */
        private ulong GetWnfStateName(string name)
        {
            ulong value;

            try
            {
                value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME), name.ToUpper());
            }
            catch
            {
                try
                {
                    value = Convert.ToUInt64(name, 16);
                }
                catch
                {
                    Console.WriteLine("\n[-] Failed to resolve WNF State Name.\n");
                    value = 0;
                }
            }

            return value;
        }


        private IntPtr GetWorldAllowedSecurityDescriptor()
        {
            bool status;
            int cbSid = Win32Consts.SECURITY_MAX_SID_SIZE;
            int cbDacl = Marshal.SizeOf(typeof(ACL)) + 
                    Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) -
                    Marshal.SizeOf(typeof(int)) +
                    cbSid;
            var pSecurityDescriptor = IntPtr.Zero;
            this.Dacl = Marshal.AllocHGlobal(cbDacl);
            this.Sid = Marshal.AllocHGlobal(cbSid);

            do
            {
                status = NativeMethods.CreateWellKnownSid(
                    WELL_KNOWN_SID_TYPE.WinWorldSid, 
                    IntPtr.Zero,
                    this.Sid,
                    ref cbSid);

                if (!status)
                    break;

                status = NativeMethods.InitializeAcl(this.Dacl, cbDacl, Win32Consts.ACL_REVISION);

                if (!status)
                    break;

                status = NativeMethods.AddAccessAllowedAce(
                    this.Dacl,
                    Win32Consts.ACL_REVISION,
                    ACCESS_MASK.GENERIC_ALL,
                    this.Sid);

                if (!status)
                    break;

                pSecurityDescriptor = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_DESCRIPTOR)));
                status = NativeMethods.InitializeSecurityDescriptor(
                    pSecurityDescriptor,
                    Win32Consts.SECURITY_DESCRIPTOR_REVISION);

                if (!status)
                    break;

                status = NativeMethods.SetSecurityDescriptorDacl(
                    pSecurityDescriptor,
                    true,
                    this.Dacl,
                    false);
            } while (false);

            if (!status)
            {
                Marshal.FreeHGlobal(pSecurityDescriptor);
                pSecurityDescriptor = IntPtr.Zero;
            }

            return pSecurityDescriptor;
        }


        private int NotifyCallback(
            ulong stateName,
            int nChangeStamp,
            IntPtr pTypeId,
            IntPtr pCallbackContext,
            IntPtr pBuffer,
            int nBufferSize)
        {
            var outputBuilder = new StringBuilder();
            NotifyContext context = (NotifyContext)Marshal.PtrToStructure(pCallbackContext, typeof(NotifyContext));

            if (pBuffer == IntPtr.Zero && nBufferSize == 0 && nChangeStamp == 0)
            {
                outputBuilder.AppendLine();
                outputBuilder.AppendLine("[*] WNF State Name is destroyed.");
                outputBuilder.AppendLine("[*] Shutting down client...\n");
                context.Destroyed = true;
            }
            else
            {
                outputBuilder.AppendLine();
                outputBuilder.AppendLine("[>] Received data from server.");
                outputBuilder.AppendFormat("    [*] Timestamp : {0}\n", nChangeStamp);
                outputBuilder.AppendFormat("    [*] Buffer Size : {0} byte(s)\n", nBufferSize);
                outputBuilder.AppendLine("    [*] Data :\n");
                outputBuilder.AppendLine(HexDump.Dump(pBuffer, (uint)nBufferSize, 2));
            }

            Console.Write(outputBuilder.ToString());
            Marshal.StructureToPtr(context, pCallbackContext, true);

            return Win32Consts.STATUS_SUCCESS;
        }
    }
}
