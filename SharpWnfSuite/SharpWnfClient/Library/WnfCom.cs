using System;
using System.Text;
using System.Runtime.InteropServices;
using SharpWnfClient.Interop;

namespace SharpWnfClient.Library
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

        /*
         * Constructors
         */
        public WnfCom()
        {
            this.StateName = new WNF_STATE_NAME();
            this.Callback = Marshal.GetFunctionPointerForDelegate(new CallbackDelegate(NotifyCallback));
        }


        /*
         * Destructor
         */
        public void Dispose() { }

        /*
         * Public Methods
         */
        public ulong CreateServer()
        {
            IntPtr pSecurityDescriptor = GetWorldAllowedSecurityDescriptor();
            NTSTATUS ntstatus = NativeMethods.NtCreateWnfStateName(
                out this.StateName.Data,
                WNF_STATE_NAME_LIFETIME.Temporary,
                WNF_DATA_SCOPE.Machine,
                false,
                IntPtr.Zero,
                0x1000,
                pSecurityDescriptor);
            Marshal.FreeHGlobal(pSecurityDescriptor);

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
            IntPtr pContextBuffer;
            var context = new NotifyContext { Destroyed = false };

            if (this.StateName.Data == 0UL)
            {
                Console.WriteLine("\n[-] Server is not initialized.\n");
                return false;
            }

            ntstatus = NativeMethods.NtCreateEvent(
                out IntPtr hEvent,
                ACCESS_MASK.EVENT_ALL_ACCESS,
                IntPtr.Zero,
                EVENT_TYPE.SynchronizationEvent,
                BOOLEAN.FALSE);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("\n[-] Failed to create event.\n");
                return false;
            }

            pContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NotifyContext)));
            context.Event = hEvent;
            Marshal.StructureToPtr(context, pContextBuffer, true);

            do
            {
                ntstatus = NativeMethods.RtlSubscribeWnfStateChangeNotification(
                    out IntPtr pSubscription,
                    this.StateName.Data,
                    0,
                    this.Callback,
                    pContextBuffer,
                    IntPtr.Zero,
                    0,
                    0);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("\n[-] Failed to subscribe WNF (NTSTATUS = 0x{0})\n", ntstatus.ToString("X8"));
                    break;
                }

                do
                {
                    try
                    {
                        var timeout = LARGE_INTEGER.FromInt64(-(1000 * 10000)); // 1,000 ms
                        NativeMethods.NtWaitForSingleObject(hEvent, BOOLEAN.FALSE, in timeout);
                        context = (NotifyContext)Marshal.PtrToStructure(pContextBuffer, typeof(NotifyContext));
                    }
                    catch
                    {
                        break;
                    }
                } while (!context.Destroyed);

                NativeMethods.RtlUnsubscribeWnfStateChangeNotification(pSubscription);
            } while (false);
            
            NativeMethods.NtClose(hEvent);
            Marshal.FreeHGlobal(pContextBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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


        public bool Read(out int nChangeStamp, out IntPtr pInfoBuffer, out uint nInfoLength)
        {
            NTSTATUS ntstatus;
            nChangeStamp = 0;
            pInfoBuffer = IntPtr.Zero;
            nInfoLength = 0x1000u;

            if (this.StateName.Data == 0UL)
            {
                Console.WriteLine("\n[-] Server is not initialized.\n");
                nInfoLength = 0;
                return false;
            }

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryWnfStateData(
                    in this.StateName.Data,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out nChangeStamp,
                    pInfoBuffer,
                    ref nInfoLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nInfoLength == 0))
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                nInfoLength = 0u;
                nChangeStamp = 0;
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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


        public bool SetStateName(string stateName)
        {
            this.StateName.Data = GetWnfStateName(stateName);
            return (this.StateName.Data != 0);
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
            IntPtr pDacl;
            IntPtr pAce;
            var nDaclOffset = Marshal.SizeOf(typeof(SECURITY_DESCRIPTOR));
            var nSidStartOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32();
            var everyoneSid = new byte[] { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }; // S-1-1-0
            var nBufferLength = nDaclOffset + Marshal.SizeOf(typeof(ACL)) + nSidStartOffset + everyoneSid.Length;
            var sd = new SECURITY_DESCRIPTOR
            {
                Revision = 1,
                Control = SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT | SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE,
                Dacl = nDaclOffset
            };
            var ace = new ACCESS_ALLOWED_ACE
            {
                Header = new ACE_HEADER
                {
                    AceType = ACE_TYPE.ACCESS_ALLOWED,
                    AceFlags = ACE_FLAGS.NONE,
                    AceSize = (short)(nSidStartOffset + everyoneSid.Length)
                },
                Mask = ACCESS_MASK.GENERIC_ALL
            };
            var aclHeader = new ACL
            {
                AclRevision = ACL_REVISION.ACL_REVISION,
                Sbz1 = 0,
                AclSize = (short)(Marshal.SizeOf(typeof(ACL)) + nSidStartOffset + everyoneSid.Length),
                AceCount = 1,
                Sbz2 = 0
            };
            var pSecurityDescriptor = Marshal.AllocHGlobal(nBufferLength);

            if (Environment.Is64BitProcess)
            {
                pDacl = new IntPtr(pSecurityDescriptor.ToInt64() + nDaclOffset);
                pAce = new IntPtr(pDacl.ToInt64() + Marshal.SizeOf(typeof(ACL)));
            }
            else
            {
                pDacl = new IntPtr(pSecurityDescriptor.ToInt32() + nDaclOffset);
                pAce = new IntPtr(pDacl.ToInt32() + Marshal.SizeOf(typeof(ACL)));
            }

            Marshal.StructureToPtr(sd, pSecurityDescriptor, true);
            Marshal.StructureToPtr(aclHeader, pDacl, true);
            Marshal.StructureToPtr(ace, pAce, true);

            for (var oft = 0; oft < everyoneSid.Length; oft++)
                Marshal.WriteByte(pAce, nSidStartOffset + oft, everyoneSid[oft]);

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
            var context = (NotifyContext)Marshal.PtrToStructure(pCallbackContext, typeof(NotifyContext));

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
