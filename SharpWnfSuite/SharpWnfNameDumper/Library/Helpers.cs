using System;
using System.Collections.Generic;
using System.Text;

namespace SharpWnfNameDumper.Library
{
    class Helpers
    {
        public static int SearchTableOffset(in PeLoader binary)
        {
            List<int> nameOffsets = binary.SearchBytes(Encoding.Unicode.GetBytes("WNF_"));
            IntPtr sectionVA = binary.GetSectionVirtualAddress();
            IntPtr pointerSearch;
            int tableOffset;
            string arch = binary.GetArchitecture();
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
                return 0;
            }

            foreach (var nameOffset in nameOffsets)
            {
                pointerSearch = new IntPtr(sectionVA.ToInt64() + nameOffset);
                List<int> tableOffsets = binary.SearchPointers(pointerSearch);
                if (tableOffsets.Count > 0)
                {
                    tableOffset = tableOffsets[0] - nSize;
                    if (VerifyTable(in binary, tableOffset))
                    {
                        return tableOffset;
                    }
                }
            }

            return 0;
        }

        public static bool VerifyTable(in PeLoader binary, int tableOffset)
        {
            string arch = binary.GetArchitecture();
            int nSize;
            int baseOffset;
            IntPtr lpSubject;
            byte[] data;
            IntPtr lpSection = binary.GetSectionVirtualAddress();
            int nSectionSize = binary.GetSectionSize();

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
                return false;
            }

            baseOffset = tableOffset;

            for (var count = 0; count < 3; count++)
            {
                // WNF State Name Value
                lpSubject = binary.ReadPointerFromSection(baseOffset);
                data = binary.ReadSectionWithVirtualAddress(lpSubject, 8);
                
                if (BitConverter.ToInt64(data, 0) == 0)
                    return false;

                // WNF State Name Key
                baseOffset += nSize;
                lpSubject = binary.ReadPointerFromSection(baseOffset);
                data = binary.ReadSectionWithVirtualAddress(lpSubject, 8);

                if (Encoding.Unicode.GetString(data) != "WNF_")
                    return false;

                // WNF State Name Description
                baseOffset += nSize;
                lpSubject = binary.ReadPointerFromSection(baseOffset);
                data = binary.ReadSectionWithVirtualAddress(lpSubject, 8);
                if (BitConverter.ToInt64(data, 0) == 0)
                    return false;

                if (lpSubject.ToInt64() < lpSection.ToInt64() ||
                    lpSubject.ToInt64() >= (lpSection.ToInt64() + nSectionSize - nSize))
                    return false;
                baseOffset += nSize;
            }

            baseOffset = tableOffset - (nSize * 2);
            lpSubject = binary.ReadPointerFromSection(baseOffset);

            if (lpSubject.ToInt64() != 0)
            {
                data = binary.ReadSectionWithVirtualAddress(lpSubject, 8);
                if (Encoding.Unicode.GetString(data) == "WNF_")
                    return false;
            }

            return true;
        }
    }
}
