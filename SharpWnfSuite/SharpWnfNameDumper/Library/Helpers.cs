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
            uint alignment;
            string archtecture = peImage.GetArchitecture();
            string sectionName = ".rdata";
            IntPtr pDataBuffer;
            IntPtr pImageBase = peImage.GetImageBase();
            uint nSectionVirtualAddress = peImage.GetSectionVirtualAddress(sectionName);
            uint nSectionOffset = peImage.GetSectionPointerToRawData(sectionName);
            long nBaseOffset = (long)(nSectionOffset - nSectionVirtualAddress) - pImageBase.ToInt64();
            
            stateName = 0UL;
            stateNameString = null;
            description = null;

            if (archtecture == "x64")
                alignment = 8u;
            else if (archtecture == "x86")
                alignment = 4u;
            else
                return false;

            try
            {
                pDataBuffer = peImage.ReadIntPtr(new IntPtr(nPointerOffset));
                stateName = (ulong)peImage.ReadInt64(
                    new IntPtr(pDataBuffer.ToInt64() + nBaseOffset));

                pDataBuffer = peImage.ReadIntPtr(new IntPtr(nPointerOffset + alignment));
                stateNameString = peImage.ReadUnicodeString(
                    new IntPtr(pDataBuffer.ToInt64() + nBaseOffset));

                pDataBuffer = peImage.ReadIntPtr(new IntPtr(nPointerOffset + (alignment * 2)));
                description = peImage.ReadUnicodeString(
                    new IntPtr(pDataBuffer.ToInt64() + nBaseOffset));
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
            IntPtr pImageBase;
            IntPtr pTablePointer;
            uint nSectionVirtualAddress;
            uint nSectionOffset;
            uint nSectionSize;
            uint nTableOffset;
            uint nPointerSize;
            IntPtr[] pCandidates;
            IntPtr pTableOffset;
            byte[] searchBytes;
            string architecture = peImage.GetArchitecture();
            string sectionName = ".rdata";

            pImageBase = peImage.GetImageBase();
            nSectionVirtualAddress = peImage.GetSectionVirtualAddress(sectionName);
            nSectionOffset = peImage.GetSectionPointerToRawData(sectionName);
            nSectionSize = peImage.GetSectionSizeOfRawData(sectionName);

            if ((nSectionOffset == 0) || (nSectionSize == 0) || (nSectionVirtualAddress == 0))
                return 0u;

            pCandidates = peImage.SearchBytes(
                new IntPtr((long)nSectionOffset),
                nSectionSize,
                Encoding.Unicode.GetBytes("WNF_"));

            if (pCandidates.Length == 0)
                return 0u;

            for (var idx = 0; idx < pCandidates.Length; idx++)
            {
                pTablePointer = new IntPtr(
                    pImageBase.ToInt64() +
                    (long)nSectionVirtualAddress +
                    pCandidates[idx].ToInt64() -
                    (long)nSectionOffset);

                if (architecture == "x64")
                {
                    nPointerSize = 8u;
                    searchBytes = BitConverter.GetBytes(pTablePointer.ToInt64());
                }
                else if (architecture == "x86")
                {
                    nPointerSize = 4u;
                    searchBytes = BitConverter.GetBytes(pTablePointer.ToInt32());
                }
                else
                {
                    return 0u;
                }

                pTableOffset = peImage.SearchBytesFirst(
                    new IntPtr((long)nSectionOffset),
                    nSectionSize,
                    searchBytes);

                if (pTableOffset != IntPtr.Zero)
                {
                    nTableOffset = (uint)pTableOffset.ToInt64() - nPointerSize;
                    
                    if (VerifyTable(in peImage, nTableOffset))
                        return nTableOffset;
                }
            }

            return 0u;
        }


        public static bool VerifyTable(in PeFile peImage, uint tableOffset)
        {
            uint nPointerSize;
            uint baseOffset;
            IntPtr pImageBase;
            IntPtr pDataBuffer;
            IntPtr pDataOffset;
            ulong stateName;
            string stateNameString;
            string description;
            uint nSectionVirtualAddress;
            uint nSectionOffset;
            string architecture = peImage.GetArchitecture();
            string sectionName = ".rdata";
            var suffix = new Regex(@"^WNF_\S+$");

            if (architecture == "x64")
                nPointerSize = 8u;
            else if (architecture == "x86")
                nPointerSize = 4u;
            else
                return false;

            pImageBase = peImage.GetImageBase();
            nSectionVirtualAddress = peImage.GetSectionVirtualAddress(sectionName);
            nSectionOffset = peImage.GetSectionPointerToRawData(sectionName);
            baseOffset = tableOffset;

            for (var count = 0; count < 3; count++)
            {
                if (!ReadStateData(
                    in peImage,
                    baseOffset,
                    out stateName,
                    out stateNameString,
                    out description))
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
            pDataOffset = new IntPtr(
                pDataBuffer.ToInt64() -
                pImageBase.ToInt64() -
                (long)nSectionVirtualAddress +
                (long)nSectionOffset);

            if (pDataOffset.ToInt64() != 0)
            {
                if (suffix.IsMatch(peImage.ReadUnicodeString(pDataOffset)))
                    return false;
            }

            return true;
        }
    }
}
