using System;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpWnfNameDumper.Library
{
    internal class Helpers
    {
        [HandleProcessCorruptedStateExceptions]
        public static bool ReadStateData(
            in PeFile peImage,
            uint nPointerOffset,
            out ulong stateName,
            out string stateNameString,
            out string description)
        {
            IntPtr pDataBuffer;
            IntPtr pImageBase = peImage.GetImageBase();
            uint alignment = peImage.Is64Bit ? 8u : 4u;
            string sectionName = ".rdata";
            uint nSectionVirtualAddress = peImage.GetSectionVirtualAddress(sectionName);
            uint nSectionOffset = peImage.GetSectionPointerToRawData(sectionName);
            long nBaseOffset = (long)(nSectionOffset - nSectionVirtualAddress) - pImageBase.ToInt64();

            try
            {
                if (Environment.Is64BitProcess)
                {
                    pDataBuffer = peImage.ReadIntPtr(new IntPtr(nPointerOffset));
                    stateName = (ulong)peImage.ReadInt64(new IntPtr(pDataBuffer.ToInt64() + nBaseOffset));

                    pDataBuffer = peImage.ReadIntPtr(new IntPtr(nPointerOffset + alignment));
                    stateNameString = peImage.ReadUnicodeString(new IntPtr(pDataBuffer.ToInt64() + nBaseOffset));

                    pDataBuffer = peImage.ReadIntPtr(new IntPtr(nPointerOffset + (alignment * 2)));
                    description = peImage.ReadUnicodeString(new IntPtr(pDataBuffer.ToInt64() + nBaseOffset));
                }
                else
                {
                    pDataBuffer = peImage.ReadIntPtr(new IntPtr((int)nPointerOffset));
                    stateName = (ulong)peImage.ReadInt64(new IntPtr(pDataBuffer.ToInt32() + (int)nBaseOffset));

                    pDataBuffer = peImage.ReadIntPtr(new IntPtr((int)(nPointerOffset + alignment)));
                    stateNameString = peImage.ReadUnicodeString(new IntPtr(pDataBuffer.ToInt32() + (int)nBaseOffset));

                    pDataBuffer = peImage.ReadIntPtr(new IntPtr((int)(nPointerOffset + (alignment * 2))));
                    description = peImage.ReadUnicodeString(new IntPtr(pDataBuffer.ToInt32() + (int)nBaseOffset));
                }
            }
            catch (AccessViolationException)
            {
                stateName = 0UL;
                stateNameString = null;
                description = null;

                return false;
            }

            return true;
        }


        public static uint SearchTableOffset(in PeFile peImage)
        {
            IntPtr pTablePointer;
            uint nTableOffset;
            IntPtr pSectionOffset;
            IntPtr[] pCandidates;
            IntPtr pTableOffset;
            byte[] searchBytes;
            string sectionName = ".rdata";
            uint nPointerSize = peImage.Is64Bit ? 8u : 4u;
            IntPtr pImageBase = peImage.GetImageBase();
            uint nSectionVirtualAddress = peImage.GetSectionVirtualAddress(sectionName);
            uint nSectionOffset = peImage.GetSectionPointerToRawData(sectionName);
            uint nSectionSize = peImage.GetSectionSizeOfRawData(sectionName);

            if ((nSectionOffset == 0) || (nSectionSize == 0) || (nSectionVirtualAddress == 0))
                return 0u;

            if (Environment.Is64BitProcess)
                pSectionOffset = new IntPtr((long)nSectionOffset);
            else
                pSectionOffset = new IntPtr((int)nSectionOffset);

            pCandidates = peImage.SearchBytes(pSectionOffset, nSectionSize, Encoding.Unicode.GetBytes("WNF_"));

            if (pCandidates.Length == 0)
                return 0u;

            for (var idx = 0; idx < pCandidates.Length; idx++)
            {
                if (Environment.Is64BitProcess)
                {
                    pTablePointer = new IntPtr(pImageBase.ToInt64() + pCandidates[idx].ToInt64() + (long)(nSectionVirtualAddress - nSectionOffset));
                    searchBytes = BitConverter.GetBytes(pTablePointer.ToInt64());
                }
                else
                {
                    pTablePointer = new IntPtr(pImageBase.ToInt32() + pCandidates[idx].ToInt32() + (int)(nSectionVirtualAddress - nSectionOffset));
                    searchBytes = BitConverter.GetBytes(pTablePointer.ToInt32());
                }

                pTableOffset = peImage.SearchBytesFirst(pSectionOffset, nSectionSize, searchBytes);

                if (pTableOffset != IntPtr.Zero)
                {
                    if (Environment.Is64BitProcess)
                        nTableOffset = (uint)pTableOffset.ToInt64() - nPointerSize;
                    else
                        nTableOffset = (uint)pTableOffset.ToInt32() - nPointerSize;

                    if (VerifyTable(in peImage, nTableOffset))
                        return nTableOffset;
                }
            }

            return 0u;
        }


        public static bool VerifyTable(in PeFile peImage, uint tableOffset)
        {
            IntPtr pDataBuffer;
            IntPtr pDataOffset;
            string sectionName = ".rdata";
            IntPtr pImageBase = peImage.GetImageBase();
            uint nSectionVirtualAddress = peImage.GetSectionVirtualAddress(sectionName);
            uint nSectionOffset = peImage.GetSectionPointerToRawData(sectionName);
            uint baseOffset = tableOffset;
            uint nPointerSize = peImage.Is64Bit ? 8u : 4u;
            var suffix = new Regex(@"^WNF_\S+$");

            for (var count = 0; count < 3; count++)
            {
                if (!ReadStateData(
                    in peImage,
                    baseOffset,
                    out ulong stateName,
                    out string stateNameString,
                    out string description))
                {
                    return false;
                }

                if (stateName == 0)
                    return false;

                if (!suffix.IsMatch(stateNameString))
                    return false;

                if (string.IsNullOrEmpty(description))
                    return false;

                baseOffset += nPointerSize * 3;
            }

            // Verify Top of Table with WNF state name string
            baseOffset = tableOffset - (nPointerSize * 2);
            pDataBuffer = peImage.ReadIntPtr(new IntPtr(baseOffset));

            if (Environment.Is64BitProcess)
                pDataOffset = new IntPtr(pDataBuffer.ToInt64() - pImageBase.ToInt64() - (long)(nSectionVirtualAddress - nSectionOffset));
            else
                pDataOffset = new IntPtr(pDataBuffer.ToInt32() - pImageBase.ToInt32() - (int)(nSectionVirtualAddress - nSectionOffset));

            if (pDataOffset.ToInt64() != 0)
            {
                if (suffix.IsMatch(peImage.ReadUnicodeString(pDataOffset)))
                    return false;
            }

            return true;
        }
    }
}
