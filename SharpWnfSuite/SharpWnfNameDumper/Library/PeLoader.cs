using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfNameDumper.Interop;

namespace SharpWnfNameDumper.Library
{
    class PeLoader
    {
        public readonly IntPtr Buffer;
        private readonly Win32Struct.IMAGE_DOS_HEADER DosHeader;
        private readonly Win32Struct.IMAGE_NT_HEADERS32 NtHeader32;
        private readonly Win32Struct.IMAGE_NT_HEADERS64 NtHeader64;
        private readonly List<Win32Struct.IMAGE_SECTION_HEADER> SectionHeaders;
        private Win32Struct.IMAGE_SECTION_HEADER CurrentSectionHeader;
        private byte[] SectionData;

        public PeLoader(string _filePath)
        {
            this.Buffer = LoadFileData(_filePath);

            if (this.Buffer == IntPtr.Zero)
                throw new InvalidDataException(string.Format(
                    "Failed to load \"{0}\".", _filePath));

            if (!GetDosHeader(out this.DosHeader))
                throw new InvalidDataException(string.Format(
                    "Failed to get DOS Header from \"{0}\".", _filePath));

            string arch = GetArchitecture();
            IntPtr lpNtHeader = new IntPtr(this.Buffer.ToInt64() + this.DosHeader.e_lfanew);

            if (arch == "x64")
            {
                this.NtHeader32 = new Win32Struct.IMAGE_NT_HEADERS32();
                this.NtHeader64 = (Win32Struct.IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    lpNtHeader, typeof(Win32Struct.IMAGE_NT_HEADERS64));
            }
            else if (arch == "x86")
            {
                this.NtHeader32 = (Win32Struct.IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                    lpNtHeader, typeof(Win32Struct.IMAGE_NT_HEADERS32));
                this.NtHeader64 = new Win32Struct.IMAGE_NT_HEADERS64();
            }
            else
            {
                throw new InvalidDataException(string.Format(
                    "Failed to get NT Header from \"{0}\".", _filePath));
            }

            if (!GetSectionHeaders(out this.SectionHeaders))
                throw new InvalidDataException(string.Format(
                    "Failed to get Section Headers from \"{0}\".", _filePath));

            SetSectionData(".rdata");
        }

        public string GetArchitecture()
        {
            ushort arch;

            try
            {
                arch = (ushort)Marshal.ReadInt16(
                    new IntPtr(this.Buffer.ToInt64() + 
                    this.DosHeader.e_lfanew + 
                    Marshal.SizeOf(typeof(int))));
            }
            catch
            {
                return string.Empty;
            }

            if (arch == 0x8664)
            {
                return "x64";
            }
            else if (arch == 0x014C)
            {
                return "x86";
            }
            else if (arch == 0x0200)
            {
                return "ia64";
            }
            else
            {
                return string.Empty;
            }
        }

        private bool GetDosHeader(out Win32Struct.IMAGE_DOS_HEADER _dosHeader)
        {
            try
            {
                _dosHeader = (Win32Struct.IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                    this.Buffer, typeof(Win32Struct.IMAGE_DOS_HEADER));
            }
            catch
            {
                _dosHeader = new Win32Struct.IMAGE_DOS_HEADER();
                return false;
            }

            return _dosHeader.IsValid;
        }

        public IntPtr GetImageBase()
        {
            string arch = GetArchitecture();

            if (arch == "x64")
            {
                return new IntPtr((long)this.NtHeader64.OptionalHeader.ImageBase);
            }
            else if (arch == "x86")
            {
                return new IntPtr((long)this.NtHeader32.OptionalHeader.ImageBase);
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        private bool GetSectionHeaders(out List<Win32Struct.IMAGE_SECTION_HEADER> _sectionHeaders)
        {
            _sectionHeaders = new List<Win32Struct.IMAGE_SECTION_HEADER>();
            IntPtr pFileHeader = new IntPtr(
                this.Buffer.ToInt64() + this.DosHeader.e_lfanew + Marshal.SizeOf(typeof(int)));

            try
            {
                Win32Struct.IMAGE_FILE_HEADER fileHeader = (Win32Struct.IMAGE_FILE_HEADER)Marshal.PtrToStructure(
                    pFileHeader, typeof(Win32Struct.IMAGE_FILE_HEADER));
                ushort nSectionCount = fileHeader.NumberOfSections;
                IntPtr pSectionHeaders = new IntPtr(
                    this.Buffer.ToInt64() + this.DosHeader.e_lfanew + 0x18 + fileHeader.SizeOfOptionalHeader);

                for (var idx = 0; idx < nSectionCount; idx++)
                {
                    _sectionHeaders.Add((Win32Struct.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        new IntPtr(pSectionHeaders.ToInt64() +
                        idx * Marshal.SizeOf(typeof(Win32Struct.IMAGE_SECTION_HEADER))),
                        typeof(Win32Struct.IMAGE_SECTION_HEADER)));
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public int GetSectionSize()
        {
            return (int)this.CurrentSectionHeader.SizeOfRawData;
        }

        public IntPtr GetSectionBufferAddress()
        {
            string arch = GetArchitecture();

            if (arch == "x64")
            {
                return new IntPtr(
                    this.Buffer.ToInt64() +
                    this.CurrentSectionHeader.PointerToRawData);
            }
            else if (arch == "x86")
            {
                return new IntPtr(
                    this.Buffer.ToInt64() +
                    this.CurrentSectionHeader.PointerToRawData);
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        public IntPtr GetSectionVirtualAddress()
        {
            string arch = GetArchitecture();

            if (arch == "x64")
            {
                return new IntPtr(
                    (long)(this.NtHeader64.OptionalHeader.ImageBase + 
                    this.CurrentSectionHeader.VirtualAddress));
            }
            else if (arch == "x86")
            {
                return new IntPtr(
                    this.NtHeader32.OptionalHeader.ImageBase +
                    this.CurrentSectionHeader.VirtualAddress);
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        public string GetUnicodeStringFromSection(IntPtr lpUnicodeString)
        {
            IntPtr lpBuffer = new IntPtr(
                this.Buffer.ToInt64() + 
                this.CurrentSectionHeader.PointerToRawData +
                lpUnicodeString.ToInt64() - 
                GetSectionVirtualAddress().ToInt64());
            IntPtr lpTerminator;
            byte[] bytesString;
            int count = 0;

            try
            {
                while (true)
                {
                    lpTerminator = new IntPtr(lpBuffer.ToInt64() + count);

                    if (Marshal.ReadInt16(lpTerminator) == 0)
                        break;
                    else
                        count++;
                }
                bytesString = new byte[count + 1];
                Marshal.Copy(lpBuffer, bytesString, 0, count + 1);
                return Encoding.Unicode.GetString(bytesString);
            }
            catch
            {
                return string.Empty;
            }
        }

        public string GetUnicodeStringFromSection(int offset)
        {
            IntPtr lpBuffer = new IntPtr(
                this.Buffer.ToInt64() + this.CurrentSectionHeader.PointerToRawData + offset);
            IntPtr lpTerminator;
            byte[] bytesString;
            int count = 0;

            try
            {
                while (true)
                {
                    lpTerminator = new IntPtr(lpBuffer.ToInt64() + count);

                    if (Marshal.ReadInt16(lpTerminator) == 0)
                        break;
                    else
                        count++;
                }
                bytesString = new byte[count + 1];
                Marshal.Copy(lpBuffer, bytesString, 0, count + 1);
                return Encoding.Unicode.GetString(bytesString);
            }
            catch
            {
                return string.Empty;
            }
        }

        private IntPtr LoadFileData(string _filePath)
        {
            string fullFilePath = Path.GetFullPath(_filePath);
            IntPtr buffer = IntPtr.Zero;

            if (!File.Exists(fullFilePath))
                return buffer;

            try
            {
                byte[] data = File.ReadAllBytes(fullFilePath);
                buffer = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, buffer, data.Length);
            }
            catch
            {
                return IntPtr.Zero;
            }

            return buffer;
        }

        public IntPtr ReadPointerFromSection(int offset)
        {
            string arch = GetArchitecture();
            int nSize;

            if (arch == "x64")
            {
                nSize = 8;
            }
            else if (arch == "x86")
            {
                nSize = 4;
            }
            else
            {
                return IntPtr.Zero;
            }

            IntPtr lpBuffer = Marshal.AllocHGlobal(nSize);
            Marshal.Copy(this.SectionData, offset, lpBuffer, nSize);
            IntPtr result = Marshal.ReadIntPtr(lpBuffer);
            Marshal.FreeHGlobal(lpBuffer);
            return result;
        }

        public byte[] ReadSectionWithVirtualAddress(IntPtr address, int nSize)
        {
            int offset = (int)(address.ToInt64() - GetSectionVirtualAddress().ToInt64());
            byte[] result = new byte[nSize];
            IntPtr lpBuffer = new IntPtr(this.Buffer.ToInt64() + this.CurrentSectionHeader.PointerToRawData + offset);
            Marshal.Copy(lpBuffer, result, 0, nSize);
            return result;
        }

        public List<int> SearchBytes(byte[] pattern)
        {
            bool status;
            List<int> indices = new List<int>();

            for (var dataIdx = 0; dataIdx < (this.SectionData.Length - pattern.Length); dataIdx++)
            {
                status = false;

                if (this.SectionData[dataIdx] == pattern[0])
                {
                    for (var patternIdx = 0; patternIdx < pattern.Length; patternIdx++)
                    {
                        status = (this.SectionData[dataIdx + patternIdx] == pattern[patternIdx]);
                        if (!status)
                            break;
                    }

                    if (status)
                        indices.Add(dataIdx);
                }
            }

            return indices;
        }

        public List<int> SearchPointers(IntPtr address)
        {
            string arch = GetArchitecture();
            bool status;
            byte[] pattern;
            List<int> indices = new List<int>();

            if (arch == "x64")
            {
                pattern = BitConverter.GetBytes(address.ToInt64());
            }
            else if (arch == "x86")
            {
                pattern = BitConverter.GetBytes(address.ToInt32());
            }
            else
            {
                return indices;
            }

            for (var dataIdx = 0; dataIdx < (this.SectionData.Length - pattern.Length); dataIdx++)
            {
                status = false;

                if (this.SectionData[dataIdx] == pattern[0])
                {
                    for (var patternIdx = 0; patternIdx < pattern.Length; patternIdx++)
                    {
                        status = (this.SectionData[dataIdx + patternIdx] == pattern[patternIdx]);
                        if (!status)
                            break;
                    }

                    if (status)
                        indices.Add(dataIdx);
                }
            }

            return indices;
        }

        public void SetSectionData(string nameSection)
        {
            IntPtr buffer;

            try
            {
                foreach (var section in this.SectionHeaders)
                {
                    if (section.Name == nameSection)
                    {
                        this.CurrentSectionHeader = section;
                        this.SectionData = new byte[section.SizeOfRawData];
                        buffer = new IntPtr(this.Buffer.ToInt64() + section.PointerToRawData);
                        Marshal.Copy(buffer, this.SectionData, 0, (int)section.SizeOfRawData);
                        return;
                    }
                }
            }
            catch
            {
                this.CurrentSectionHeader = new Win32Struct.IMAGE_SECTION_HEADER();
                this.SectionData = new byte[] { };
                return;
            }

            this.CurrentSectionHeader = new Win32Struct.IMAGE_SECTION_HEADER();
            this.SectionData = new byte[] { };
        }
    }
}
