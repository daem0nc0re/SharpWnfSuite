using System;
using System.Text;
using System.Runtime.InteropServices;
using SharpWnfClient.Interop;
using System.Collections.Generic;

namespace SharpWnfClient.Library
{
    using NTSTATUS = Int32;

    internal class WnfCom : IDisposable
    {
        // 
        // Structs
        // 
        private struct NotifyContext
        {
            public bool Destroyed;
            public IntPtr Event;
        }

        // 
        // Delegate Types
        // 
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CallbackDelegate(
            ulong StateName,
            int ChangeStamp,
            IntPtr TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            int BufferSize);

        // 
        // Global Variables
        // 
        private WNF_STATE_NAME StateName;
        private IntPtr Callback { get; } = IntPtr.Zero;
        private int MajorVersion { get; } = 0;
        private int MinorVersion { get; } = 0;
        private int BuildNumber { get; } = 0;
        private string OsVersion { get; } = null;

        // 
        // Constructors
        // 
        public WnfCom()
        {
            this.StateName = new WNF_STATE_NAME();
            this.Callback = Marshal.GetFunctionPointerForDelegate(new CallbackDelegate(NotifyCallback));
            GetOsVersionNumbers(out int nMajorVersion, out int nMinorVersion, out int nBuildNumber);
            MajorVersion = nMajorVersion;
            MinorVersion = nMinorVersion;
            BuildNumber = nBuildNumber;
            OsVersion = GetOsVersionString(MajorVersion, MinorVersion, BuildNumber);
            Console.WriteLine("[*] OS version is {0}.", OsVersion ?? "unspecified");

            if ((MajorVersion < 10) || string.IsNullOrEmpty(OsVersion))
            {
                Console.WriteLine("[!] Unsupported version.\n");
                Environment.Exit(0);
            }
        }


        // 
        // Destructor
        // 
        public void Dispose() { }

        // 
        // Public Methods
        // 
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


        // 
        // Private Methods
        // 
        private static bool GetOsVersionNumbers(out int nMajorVersion, out int nMinorVersion, out int nBuildNumber)
        {
            NTSTATUS ntstatus;
            IntPtr hKey;
            var bSuccess = true;
            var valueNames = new List<string>
            {
                @"CurrentMajorVersionNumber",
                @"CurrentMinorVersionNumber",
                @"CurrentBuildNumber"
            };
            nMajorVersion = 0;
            nMinorVersion = 0;
            nBuildNumber = 0;

            using (var objectAttributes = new OBJECT_ATTRIBUTES(
                   @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                   OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
            {
                ntstatus = NativeMethods.NtOpenKey(
                    out hKey,
                    ACCESS_MASK.KEY_QUERY_VALUE,
                    in objectAttributes);
            }

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return false;

            foreach (var name in valueNames)
            {
                IntPtr pInfoBuffer;
                var nInfoLength = (uint)Marshal.SizeOf(typeof(KEY_VALUE_FULL_INFORMATION));

                using (var valueName = new UNICODE_STRING(name))
                {
                    do
                    {
                        pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                        ntstatus = NativeMethods.NtQueryValueKey(
                            hKey,
                            in valueName,
                            KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation,
                            pInfoBuffer,
                            nInfoLength,
                            out nInfoLength);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                            Marshal.FreeHGlobal(pInfoBuffer);
                    } while (ntstatus == Win32Consts.STATUS_BUFFER_OVERFLOW);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        var info = (KEY_VALUE_FULL_INFORMATION)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(KEY_VALUE_FULL_INFORMATION));

                        if (string.Compare(name, @"CurrentMajorVersionNumber", true) == 0)
                        {
                            nMajorVersion = Marshal.ReadInt32(pInfoBuffer, (int)info.DataOffset);
                        }
                        else if (string.Compare(name, @"CurrentMinorVersionNumber", true) == 0)
                        {
                            nMinorVersion = Marshal.ReadInt32(pInfoBuffer, (int)info.DataOffset);
                        }
                        else
                        {
                            IntPtr pStringBuffer;

                            if (Environment.Is64BitProcess)
                                pStringBuffer = new IntPtr(pInfoBuffer.ToInt64() + info.DataOffset);
                            else
                                pStringBuffer = new IntPtr(pInfoBuffer.ToInt32() + (int)info.DataOffset);

                            try
                            {
                                nBuildNumber = Convert.ToInt32(Marshal.PtrToStringUni(pStringBuffer), 10);
                            }
                            catch
                            {
                                bSuccess = false;
                            }
                        }


                        Marshal.FreeHGlobal(pInfoBuffer);
                    }
                    else
                    {
                        bSuccess = false;
                        break;
                    }
                }
            }

            NativeMethods.NtClose(hKey);

            return bSuccess;
        }


        private static string GetOsVersionString(int nMajorVersion, int nMinorVersion, int nBuildNumber)
        {
            string versionString = null;

            if (nMajorVersion == 6)
            {
                if (nMinorVersion == 0)
                    versionString = "Windows Vista or Windows Server 2008";
                else if (nMinorVersion == 1)
                    versionString = "Windows 7 or Windows Server 2008 R2";
                else if (nMinorVersion == 2)
                    versionString = "Windows 8 or Windows Server 2012";
                else if (nMinorVersion == 3)
                    versionString = "Windows 8.1 or Windows Server 2012 R2";
            }
            else if ((nMajorVersion == 10) && (nMinorVersion == 0))
            {
                if (nBuildNumber == 10240)
                    versionString = "Windows 10 Version 1507";
                else if (nBuildNumber == 10586)
                    versionString = "Windows 10 Version 1511";
                else if (nBuildNumber == 14393)
                    versionString = "Windows 10 Version 1607 or Windows Server 2016";
                else if (nBuildNumber == 15063)
                    versionString = "Windows 10 Version 1703";
                else if (nBuildNumber == 16299)
                    versionString = "Windows 10 Version 1709";
                else if (nBuildNumber == 17134)
                    versionString = "Windows 10 Version 1803";
                else if (nBuildNumber == 17763)
                    versionString = "Windows 10 Version 1809 or Windows Server 2019";
                else if (nBuildNumber == 18362)
                    versionString = "Windows 10 Version 1903";
                else if (nBuildNumber == 18363)
                    versionString = "Windows 10 Version 1909";
                else if (nBuildNumber == 19041)
                    versionString = "Windows 10 Version 2004";
                else if (nBuildNumber == 19042)
                    versionString = "Windows 10 Version 20H2";
                else if (nBuildNumber == 19043)
                    versionString = "Windows 10 Version 21H1";
                else if (nBuildNumber == 19044)
                    versionString = "Windows 10 Version 21H2";
                else if (nBuildNumber == 19045)
                    versionString = "Windows 10 Version 22H2";
                else if (nBuildNumber == 20348)
                    versionString = "Windows Server 2022";
                else if (nBuildNumber == 22000)
                    versionString = "Windows 11 Version 21H2";
                else if (nBuildNumber == 22621)
                    versionString = "Windows 11 Version 22H2";
                else if (nBuildNumber == 22631)
                    versionString = "Windows 11 Version 23H2";
                else if (nBuildNumber == 26100)
                    versionString = "Windows 11 Version 24H2 or Windows Server 2025";
            }

            return versionString;
        }


        private ulong GetWnfStateName(string name)
        {
            ulong value;

            try
            {
                if (this.BuildNumber == 10240)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1507), name.ToUpper());
                else if (this.BuildNumber == 10586)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1511), name.ToUpper());
                else if (this.BuildNumber == 14393)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1607), name.ToUpper());
                else if (this.BuildNumber == 15063)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1703), name.ToUpper());
                else if (this.BuildNumber == 16299)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1709), name.ToUpper());
                else if (this.BuildNumber == 17134)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1803), name.ToUpper());
                else if (this.BuildNumber == 17763)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1809), name.ToUpper());
                else if (this.BuildNumber == 18362)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1903_TO_1909), name.ToUpper());
                else if (this.BuildNumber == 18363)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_1903_TO_1909), name.ToUpper());
                else if (this.BuildNumber == 19041)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), name.ToUpper());
                else if (this.BuildNumber == 19042)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), name.ToUpper());
                else if (this.BuildNumber == 19043)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2004_TO_21H1), name.ToUpper());
                else if (this.BuildNumber == 19044)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_21H2), name.ToUpper());
                else if (this.BuildNumber == 19045)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_22H2), name.ToUpper());
                else if (this.BuildNumber == 20348)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_2022), name.ToUpper());
                else if (this.BuildNumber == 22000)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_21H2), name.ToUpper());
                else if (this.BuildNumber == 22621)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_22H2), name.ToUpper());
                else if (this.BuildNumber == 22631)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_23H2), name.ToUpper());
                else if (this.BuildNumber == 26100)
                    value = (ulong)Enum.Parse(typeof(WELL_KNOWN_WNF_NAME_24H2), name.ToUpper());
                else
                    throw new NotSupportedException();
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
