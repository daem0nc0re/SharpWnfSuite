using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWnfNameDumper.Library
{
    internal class Helpers
    {
        public static bool DumpWellKnownWnfNames(
            IntPtr pRawImageData,
            out Dictionary<string, Dictionary<ulong, string>> stateNames)
        {
            bool bSuccess;
            int nSectionOffset;
            int nSectionVirtualAddress;
            int nSizeOfSection;
            string sectionName = ".rdata";
            long suffix = BitConverter.ToInt64(Encoding.Unicode.GetBytes("WNF_"), 0);
            long nImageBase = GetImageBase(pRawImageData);
            int nSizeOfPointer = GetImagePointerSize(pRawImageData);
            int nUnitSize = nSizeOfPointer * 3;
            Dictionary<string, IMAGE_SECTION_HEADER> sectionHeaders = GetSectionHeaders(pRawImageData);
            var suffixOffsets = new List<int>();
            var nTableBase = 0;
            stateNames = new Dictionary<string, Dictionary<ulong, string>>();

            if (!sectionHeaders.ContainsKey(".rdata") || (nSizeOfPointer == 0) || (nImageBase == 0L))
                return false;

            nSectionOffset = (int)sectionHeaders[sectionName].PointerToRawData;
            nSectionVirtualAddress = (int)sectionHeaders[sectionName].VirtualAddress;
            nSizeOfSection = (int)sectionHeaders[sectionName].SizeOfRawData;

            for (var idx = 0; idx < (nSizeOfSection / nSizeOfPointer); idx++)
            {
                if (Marshal.ReadInt64(pRawImageData, nSectionOffset + (nSizeOfPointer * idx)) == suffix)
                    suffixOffsets.Add(nSectionVirtualAddress + (nSizeOfPointer * idx));
            }

            foreach (var offset in suffixOffsets)
            {
                for (var idx = 0; idx < (nSizeOfSection / nSizeOfPointer); idx++)
                {
                    long nVirtualAddress;
                    var bIsValid = false;
                    nTableBase = nSectionOffset + (nSizeOfPointer * idx) - nSizeOfPointer;

                    if (nSizeOfPointer == 8)
                        nVirtualAddress = Marshal.ReadInt64(pRawImageData, nSectionOffset + (nSizeOfPointer * idx));
                    else
                        nVirtualAddress = (long)Marshal.ReadInt32(pRawImageData, nSectionOffset + (nSizeOfPointer * idx));

                    if (nVirtualAddress == (nImageBase + (long)offset))
                    {
                        int nStateNameOffset;

                        for (int count = 0; count < 3; count++)
                        {
                            if (nSizeOfPointer == 8)
                            {
                                long nSubtructor = nImageBase + nSectionVirtualAddress - nSectionOffset;
                                nStateNameOffset = (int)(Marshal.ReadInt64(pRawImageData, nTableBase + (nUnitSize * count)) - nSubtructor);
                            }
                            else
                            {
                                int nSubtructor = (int)nImageBase + nSectionVirtualAddress - nSectionOffset;
                                nStateNameOffset = Marshal.ReadInt32(pRawImageData, nTableBase + (nUnitSize * count)) - nSubtructor;
                            }

                            var wnfStateName = new WNF_STATE_NAME
                            {
                                Data = (ulong)Marshal.ReadInt64(pRawImageData, nStateNameOffset)
                            };

                            bIsValid = wnfStateName.IsValid() && (wnfStateName.GetNameLifeTime() == WNF_STATE_NAME_LIFETIME.WellKnown);

                            if (!bIsValid)
                            {
                                nTableBase = 0;
                                break;
                            }
                        }
                    }

                    if (bIsValid)
                        break;
                }

                if (nTableBase != 0)
                    break;
            }

            bSuccess = (nTableBase != 0);

            while (bSuccess)
            {
                int nStateNameOffset;
                int nNameOffset;
                int nDescriptionOffset;
                string wellKnownName;
                string description;

                if (Marshal.ReadInt32(pRawImageData, nTableBase) == 0)
                {
                    if (Marshal.ReadInt64(pRawImageData, nTableBase) == 0)
                        break;
                }

                if (nSizeOfPointer == 8)
                {
                    long nSubtructor = nImageBase + nSectionVirtualAddress - nSectionOffset;
                    nStateNameOffset = (int)(Marshal.ReadInt64(pRawImageData, nTableBase) - nSubtructor);
                    nNameOffset = (int)(Marshal.ReadInt64(pRawImageData, nTableBase + nSizeOfPointer) - nSubtructor);
                    nDescriptionOffset = (int)(Marshal.ReadInt64(pRawImageData, nTableBase + (nSizeOfPointer * 2)) - nSubtructor);
                }
                else
                {
                    int nSubtructor = (int)nImageBase + nSectionVirtualAddress - nSectionOffset;
                    nStateNameOffset = Marshal.ReadInt32(pRawImageData, nTableBase) - nSubtructor;
                    nNameOffset = Marshal.ReadInt32(pRawImageData, nTableBase + nSizeOfPointer) - nSubtructor;
                    nDescriptionOffset = Marshal.ReadInt32(pRawImageData, nTableBase + (nSizeOfPointer * 2)) - nSubtructor;
                }

                var wnfStateName = new WNF_STATE_NAME
                {
                    Data = (ulong)Marshal.ReadInt64(pRawImageData, nStateNameOffset)
                };

                if (!wnfStateName.IsValid())
                    break;

                if (wnfStateName.GetNameLifeTime() != WNF_STATE_NAME_LIFETIME.WellKnown)
                    break;

                if (Environment.Is64BitProcess)
                {
                    wellKnownName = Marshal.PtrToStringUni(new IntPtr(pRawImageData.ToInt64() + nNameOffset));
                    description = Marshal.PtrToStringUni(new IntPtr(pRawImageData.ToInt64() + nDescriptionOffset));
                }
                else
                {
                    wellKnownName = Marshal.PtrToStringUni(new IntPtr(pRawImageData.ToInt64() + nNameOffset));
                    description = Marshal.PtrToStringUni(new IntPtr(pRawImageData.ToInt64() + nDescriptionOffset));
                }

                stateNames.Add(
                    wellKnownName,
                    new Dictionary<ulong, string> { { wnfStateName.Data, description } });

                nTableBase += nUnitSize;
            }

            return bSuccess;
        }


        public static long GetImageBase(IntPtr pImageBase)
        {
            short magic;
            long nImageBase = 0L;
            var e_lfanew = Marshal.ReadInt32(pImageBase, 0x3C);

            if (Marshal.ReadInt16(pImageBase) != 0x5A4D)
                return 0;

            if (e_lfanew > 0x800)
                return 0;

            magic = Marshal.ReadInt16(pImageBase, e_lfanew + 0x18);

            if (magic == 0x020B)
                nImageBase = Marshal.ReadInt64(pImageBase, e_lfanew + 0x30);
            else if (magic == 0x010B)
                nImageBase = Marshal.ReadInt32(pImageBase, e_lfanew + 0x34);

            return nImageBase;
        }


        public static int GetImagePointerSize(IntPtr pImageBase)
        {
            short magic;
            int nPointerSize;
            var e_lfanew = Marshal.ReadInt32(pImageBase, 0x3C);

            if (Marshal.ReadInt16(pImageBase) != 0x5A4D)
                return 0;

            if (e_lfanew > 0x800)
                return 0;

            magic = Marshal.ReadInt16(pImageBase, e_lfanew + 0x18);

            if (magic == 0x020B)
                nPointerSize = 8;
            else if (magic == 0x010B)
                nPointerSize = 4;
            else
                nPointerSize = 0;

            return nPointerSize;
        }


        public static Dictionary<string, IMAGE_SECTION_HEADER> GetSectionHeaders(IntPtr pImageBase)
        {
            ushort nNumberOfSections;
            ushort nSizeOfOptionalHeader;
            var sectionHeaders = new Dictionary<string, IMAGE_SECTION_HEADER>();
            var e_lfanew = Marshal.ReadInt32(pImageBase, 0x3C);

            if (Marshal.ReadInt16(pImageBase) != 0x5A4D)
                return sectionHeaders;

            if (e_lfanew > 0x800)
                return sectionHeaders;

            nNumberOfSections = (ushort)Marshal.ReadInt16(pImageBase, e_lfanew + 0x6);
            nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pImageBase, e_lfanew + 0x14);

            for (var idx = 0; idx < nNumberOfSections; idx++)
            {
                IntPtr pSectionHeader;
                int nOffset = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * idx;

                if (Environment.Is64BitProcess)
                    pSectionHeader = new IntPtr(pImageBase.ToInt64() + e_lfanew + 0x18 + nSizeOfOptionalHeader + nOffset);
                else
                    pSectionHeader = new IntPtr(pImageBase.ToInt32() + e_lfanew + 0x18 + nSizeOfOptionalHeader + nOffset);

                var info = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pSectionHeader, typeof(IMAGE_SECTION_HEADER));
                sectionHeaders.Add(info.Name, info);
            }

            return sectionHeaders;
        }
    }
}
