using System;
using System.Text;
using System.Runtime.InteropServices;
using SharpWnfServer.Interop;

namespace SharpWnfServer.Library
{
    class WnfCom
    {
        struct NotifyContext
        {
            public bool Destroyed;
            public IntPtr Event;

            public NotifyContext(bool _destroyed, IntPtr _event)
            {
                this.Destroyed = _destroyed;
                this.Event = _event;
            }
        }

        private struct WNF_STATE_NAME_Data
        {
            public ulong Version;
            public ulong NameLifeTime;
            public ulong DataScope;
            public ulong PermanentData;
            public ulong SequenceNumber;
            public ulong OwnerTag;
        }

        private enum WNF_DATA_SCOPE_Brief
        {
            System = 0,
            Session = 1,
            User = 2,
            Process = 3,
            Machine = 4,
            PhysicalMachine = 5
        }

        private enum WNF_STATE_NAME_LIFETIME_Brief
        {
            WellKnown = 0,
            Permanent = 1,
            Persistent = 2,
            Temporary = 3
        }

        private delegate int CallbackDelegate(
            ulong StateName,
            int ChangeStamp,
            IntPtr TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            int BufferSize);

        private ulong StateName;
        private WNF_STATE_NAME_Data InternalName;
        private readonly IntPtr Callback;
        private readonly IntPtr SecurityDescriptor;

        public ulong CreateServer()
        {
            int ntstatus = Win32Api.NtCreateWnfStateName(
                out this.StateName,
                Win32Const.WNF_STATE_NAME_LIFETIME.WnfTemporaryStateName,
                Win32Const.WNF_DATA_SCOPE.WnfDataScopeMachine,
                false,
                IntPtr.Zero,
                0x1000,
                this.SecurityDescriptor);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
                return 0;

            SetInternalName();

            Console.WriteLine("\n[+] New WNF State Name is created successfully : 0x{0}\n", this.StateName.ToString("X16"));
            return this.StateName;
        }

        private ulong GetWnfStateName(string name)
        {
            ulong value;

            try
            {
                value = (ulong)Enum.Parse(
                    typeof(Win32Const.WELL_KNOWN_WNF_NAME),
                    name.ToUpper());
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

        public bool Listen()
        {
            if (this.StateName == 0)
            {
                Console.WriteLine("\n[-] Server is not initialized.\n");
                return false;
            }

            IntPtr hEvent = Win32Api.CreateEvent(
                IntPtr.Zero,
                false,
                false,
                IntPtr.Zero);

            if (hEvent == IntPtr.Zero)
            {
                Console.WriteLine("\n[-] Failed to create event.\n");
                return false;
            }

            IntPtr contextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NotifyContext)));
            NotifyContext context = new NotifyContext(false, hEvent);
            Marshal.StructureToPtr(context, contextBuffer, true);

            int ntstatus = Win32Api.RtlSubscribeWnfStateChangeNotification(
                out IntPtr subscription,
                this.StateName,
                0,
                this.Callback,
                contextBuffer,
                IntPtr.Zero,
                0,
                0);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                Console.WriteLine("\n[-] Failed to subscribe WNF (NTSTATUS = 0x{0})\n", ntstatus.ToString("X8"));
                return false;
            }

            while (!((NotifyContext)Marshal.PtrToStructure(
                contextBuffer, typeof(NotifyContext))).Destroyed)
            {
                try
                {
                    Win32Api.WaitForSingleObject(hEvent, 1000);
                }
                catch
                {
                    break;
                }
            }

            Console.WriteLine("\n[>] Shutting down client...\n");
            Win32Api.CloseHandle(hEvent);
            Win32Api.RtlUnsubscribeWnfStateChangeNotification(subscription);
            return true;
        }

        private int NotifyCallback(
            ulong stateName,
            int changeStamp,
            IntPtr typeId,
            IntPtr callbackContext,
            IntPtr buffer,
            int bufferSize)
        {
            NotifyContext context = (NotifyContext)Marshal.PtrToStructure(
                callbackContext, typeof(NotifyContext));

            if (buffer == IntPtr.Zero && bufferSize == 0 && changeStamp == 0)
            {
                Console.WriteLine("\n[>] WNF State Name is destroyed.\n");
                context.Destroyed = true;
            }
            else
            {
                Console.WriteLine("\n[>] Received data from server.");
                Console.WriteLine("    |-> Timestamp : {0}", changeStamp);
                Console.WriteLine("    |-> Buffer Size : {0} byte(s)", bufferSize);
                Console.WriteLine("    |-> Data :");

                HexDump.Dump(buffer, bufferSize, 2);
                Console.WriteLine();
            }

            Marshal.StructureToPtr(context, callbackContext, true);

            return Win32Const.STATUS_SUCCESS;
        }

        public void PrintInternalName()
        {
            StringBuilder output = new StringBuilder();

            output.Append("\n");
            output.Append(string.Format(
                "Encoded State Name: 0x{0}, Decoded State Name: 0x{1}\n",
                this.StateName.ToString("X16"),
                (this.StateName ^ Win32Const.WNF_STATE_KEY).ToString("X")));
            output.Append(string.Format(
                "\tVersion: {0}, Lifetime: {1}, Scope: {2}, Permanent: {3}, Sequence Number: 0x{4}, Owner Tag: 0x{5}",
                this.InternalName.Version,
                Enum.GetName(typeof(WNF_STATE_NAME_LIFETIME_Brief), this.InternalName.NameLifeTime),
                Enum.GetName(typeof(WNF_DATA_SCOPE_Brief), this.InternalName.DataScope),
                this.InternalName.PermanentData != 0 ? "YES" : "NO",
                this.InternalName.SequenceNumber.ToString("X"),
                this.InternalName.OwnerTag.ToString("X")));
            output.Append("\n");
            Console.WriteLine(output);
        }

        public bool Read(
            out int changeStamp,
            out IntPtr dataBuffer,
            out int bufferSize)
        {
            changeStamp = 0;
            bufferSize = 0x1000;

            if (this.StateName == 0)
            {
                Console.WriteLine("\n[-] Server is not initialized.\n");
                dataBuffer = IntPtr.Zero;
                bufferSize = 0;
                return false;
            }

            dataBuffer = Win32Api.VirtualAlloc(
                IntPtr.Zero,
                bufferSize,
                Win32Const.MEM_COMMIT,
                Win32Const.PAGE_READWRITE);

            if (dataBuffer == IntPtr.Zero)
            {
                bufferSize = 0;
                return false;
            }

            int ntstatus = Win32Api.NtQueryWnfStateData(
                in this.StateName,
                IntPtr.Zero,
                IntPtr.Zero,
                out changeStamp,
                dataBuffer,
                ref bufferSize);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                Win32Api.VirtualFree(dataBuffer, 0, Win32Const.MEM_RELEASE);
                dataBuffer = IntPtr.Zero;
                bufferSize = 0;
                return false;
            }

            if (bufferSize == 0)
            {
                Win32Api.VirtualFree(dataBuffer, 0, Win32Const.MEM_RELEASE);
                dataBuffer = IntPtr.Zero;
            }

            return true;
        }

        private void SetInternalName()
        {
            ulong stateName = this.StateName ^ Win32Const.WNF_STATE_KEY;
            this.InternalName.Version = (stateName & 0xF);
            this.InternalName.NameLifeTime = ((stateName >> 4) & 0x3);
            this.InternalName.DataScope = ((stateName >> 6) & 0xF);
            this.InternalName.PermanentData = ((stateName >> 10) & 0x1);
            this.InternalName.SequenceNumber = ((stateName >> 11) & 0x1FFFFF);
            this.InternalName.OwnerTag = ((stateName >> 32) & 0xFFFFFFFF);
        }

        public bool SetStateName(string name)
        {
            ulong tmpName = GetWnfStateName(name);

            if (tmpName == 0)
            {
                return false;
            }

            this.StateName = tmpName;
            SetInternalName();

            return true;
        }

        public WnfCom()
        {
            this.StateName = 0UL;
            this.InternalName = new WNF_STATE_NAME_Data();
            this.Callback = Marshal.GetFunctionPointerForDelegate(
                new CallbackDelegate(NotifyCallback));

            int cbSid = Win32Const.SECURITY_MAX_SID_SIZE;
            IntPtr pSid = Marshal.AllocHGlobal(cbSid);

            if (!Win32Api.CreateWellKnownSid(
                Win32Const.WELL_KNOWN_SID_TYPE.WinWorldSid,
                IntPtr.Zero,
                pSid,
                ref cbSid))
            {
                Console.WriteLine("\n[-] Failed to create SID (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            int cbDacl = Marshal.SizeOf(typeof(Win32Struct.ACL)) +
                Marshal.SizeOf(typeof(Win32Struct.ACCESS_ALLOWED_ACE)) -
                Marshal.SizeOf(typeof(int)) +
                cbSid;
            IntPtr pDacl = Marshal.AllocHGlobal(cbDacl);

            if (!Win32Api.InitializeAcl(pDacl, cbDacl, Win32Const.ACL_REVISION))
            {
                Console.WriteLine("\n[-] Failed to initialize ACL (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            if (!Win32Api.AddAccessAllowedAce(
                pDacl,
                Win32Const.ACL_REVISION,
                Win32Const.ACCESS_MASK.GENERIC_ALL,
                pSid))
            {
                Console.WriteLine("\n[-] Failed to add ACL (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            IntPtr pSecurityDescriptor = Marshal.AllocHGlobal(Marshal.SizeOf(
                typeof(Win32Struct.SECURITY_DESCRIPTOR)));

            if (!Win32Api.InitializeSecurityDescriptor(
                pSecurityDescriptor,
                Win32Const.SECURITY_DESCRIPTOR_REVISION))
            {
                Console.WriteLine("\n[-] Failed to initialize security descriptor (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            if (!Win32Api.SetSecurityDescriptorDacl(
                pSecurityDescriptor,
                true,
                pDacl,
                false))
            {
                Console.WriteLine("\n[-] Failed to set security descriptor (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            this.SecurityDescriptor = pSecurityDescriptor;
        }

        public WnfCom(string nameString)
        {
            SetStateName(nameString);
            this.Callback = Marshal.GetFunctionPointerForDelegate(
                new CallbackDelegate(NotifyCallback));

            int cbSid = Win32Const.SECURITY_MAX_SID_SIZE;
            IntPtr pSid = Marshal.AllocHGlobal(cbSid);

            if (!Win32Api.CreateWellKnownSid(
                Win32Const.WELL_KNOWN_SID_TYPE.WinWorldSid,
                IntPtr.Zero,
                pSid,
                ref cbSid))
            {
                Console.WriteLine("\n[-] Failed to create SID (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            int cbDacl = Marshal.SizeOf(typeof(Win32Struct.ACL)) +
                Marshal.SizeOf(typeof(Win32Struct.ACCESS_ALLOWED_ACE)) -
                Marshal.SizeOf(typeof(int)) +
                cbSid;
            IntPtr pDacl = Marshal.AllocHGlobal(cbDacl);

            if (!Win32Api.InitializeAcl(pDacl, cbDacl, Win32Const.ACL_REVISION))
            {
                Console.WriteLine("\n[-] Failed to initialize ACL (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            if (!Win32Api.AddAccessAllowedAce(
                pDacl,
                Win32Const.ACL_REVISION,
                Win32Const.ACCESS_MASK.GENERIC_ALL,
                pSid))
            {
                Console.WriteLine("\n[-] Failed to add ACL (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            IntPtr pSecurityDescriptor = Marshal.AllocHGlobal(Marshal.SizeOf(
                typeof(Win32Struct.SECURITY_DESCRIPTOR)));

            if (!Win32Api.InitializeSecurityDescriptor(
                pSecurityDescriptor,
                Win32Const.SECURITY_DESCRIPTOR_REVISION))
            {
                Console.WriteLine("\n[-] Failed to initialize security descriptor (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            if (!Win32Api.SetSecurityDescriptorDacl(
                pSecurityDescriptor,
                true,
                pDacl,
                false))
            {
                Console.WriteLine("\n[-] Failed to set security descriptor (Error = {0}).\n",
                    Marshal.GetLastWin32Error());
                return;
            }

            this.SecurityDescriptor = pSecurityDescriptor;
        }

        public bool Write(byte[] data)
        {
            if (this.StateName == 0)
            {
                Console.WriteLine("\n[-] Server is not initialized.\n");
                return false;
            }

            IntPtr dataBuffer = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, dataBuffer, data.Length);

            Console.WriteLine("Sending input data to WNF subscriber...\n");

            int ntstatus = Win32Api.NtUpdateWnfStateData(
                in this.StateName,
                dataBuffer,
                data.Length,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);

            Marshal.FreeHGlobal(dataBuffer);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                return false;
            }

            return true;
        }
    }
}
