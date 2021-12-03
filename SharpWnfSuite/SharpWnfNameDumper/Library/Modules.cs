using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpWnfNameDumper.Library
{
    class Modules
    {
        public static bool DumpWellKnownWnfNames(
            string filePath, 
            out Dictionary<string, Dictionary<ulong, string>> stateNames)
        {
            PeLoader binary;
            stateNames= new Dictionary<string, Dictionary<ulong, string>>();

            try
            {
                binary = new PeLoader(filePath);
            }
            catch (InvalidDataException ex)
            {
                Console.WriteLine("\n[!] {0}\n", ex.Message);
                return false;
            }

            int tableOffset = Helpers.SearchTableOffset(in binary);

            if (tableOffset == 0)
            {
                return false;
            }

            int offset = tableOffset;
            IntPtr lpSubject = binary.ReadPointerFromSection(offset);
            byte[] data;
            string key;
            ulong value;
            string description;
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
                return false;
            }

            while (lpSubject.ToInt64() != 0)
            {
                data = binary.ReadSectionWithVirtualAddress(lpSubject, 8);
                value = BitConverter.ToUInt64(data, 0);
                
                offset += nSize;
                lpSubject = binary.ReadPointerFromSection(offset);
                
                if (lpSubject.ToInt64() == 0)
                    return false;

                key = binary.GetUnicodeStringFromSection(lpSubject);
                offset += nSize;
                lpSubject = binary.ReadPointerFromSection(offset);

                if (lpSubject.ToInt64() == 0)
                    return false;

                description = binary.GetUnicodeStringFromSection(lpSubject);
                stateNames.Add(key, new Dictionary<ulong, string> { { value, description } });
                offset += nSize;
                lpSubject = binary.ReadPointerFromSection(offset);
            }

            return true;
        }

        public static void DiffTables(
            Dictionary<string, Dictionary<ulong, string>> oldNames,
            Dictionary<string, Dictionary<ulong, string>> newNames,
            out Dictionary<string, Dictionary<ulong, string>> added,
            out Dictionary<string, Dictionary<ulong, string>> deleted,
            out Dictionary<string, Dictionary<ulong, string>> modified)
        {
            added = new Dictionary<string, Dictionary<ulong, string>>();
            deleted = new Dictionary<string, Dictionary<ulong, string>>();
            modified = new Dictionary<string, Dictionary<ulong, string>>();
            bool exists;
            bool modifies;

            foreach (var oldName in oldNames)
            {
                exists = false;
                modifies = false;

                foreach (var newName in newNames)
                {
                    if (newName.Key == oldName.Key)
                    {
                        exists = true;
                        
                        foreach (var oldValue in oldName.Value)
                        {
                            foreach (var newValue in newName.Value)
                            {
                                if (oldValue.Key != newValue.Key)
                                {
                                    modifies = true;
                                }
                            }
                        }
                    }
                }

                if (!exists)
                {
                    foreach (var oldValue in oldName.Value)
                    {
                        deleted.Add(oldName.Key, new Dictionary<ulong, string> { { oldValue.Key, oldValue.Value } });
                    }
                }
                else if (exists && modifies)
                {
                    foreach (var oldValue in oldName.Value)
                    {
                        modified.Add(oldName.Key, new Dictionary<ulong, string> { { oldValue.Key, oldValue.Value } });
                    }
                }
            }

            foreach (var newName in newNames)
            {
                exists = false;
                modifies = false;

                foreach (var oldName in oldNames)
                {
                    if (oldName.Key == newName.Key)
                    {
                        exists = true;
                        break;
                    }
                }

                if (!exists)
                {
                    foreach (var newValue in newName.Value)
                    {
                        added.Add(newName.Key, new Dictionary<ulong, string> { { newValue.Key, newValue.Value } });
                    }
                }
            }
        }

        public static void PrintDiff(
            Dictionary<string, Dictionary<ulong, string>> added,
            Dictionary<string, Dictionary<ulong, string>> deleted,
            Dictionary<string, Dictionary<ulong, string>> modified,
            string filename,
            bool verbose,
            string format)
        {
            StringBuilder output = new StringBuilder();
            StringBuilder headerAdded = new StringBuilder();
            StringBuilder headerDeleted = new StringBuilder();
            StringBuilder headerModified = new StringBuilder();

            string fullPath = string.Empty;
            string dirPath;

            if (filename != string.Empty)
            {
                fullPath = Path.GetFullPath(filename);
                dirPath = Path.GetDirectoryName(fullPath);

                if (!Directory.Exists(dirPath))
                {
                    Console.WriteLine("\n[!] Target directory does not exist.\n");
                    fullPath = string.Empty;
                }
            }

            headerAdded.Append("################################################\n");
            headerAdded.Append("#                   NEW KEYS                   #\n");
            headerAdded.Append("################################################\n\n");

            headerDeleted.Append("################################################\n");
            headerDeleted.Append("#                 DELETED KEYS                 #\n");
            headerDeleted.Append("################################################\n\n");

            headerModified.Append("################################################\n");
            headerModified.Append("#                 MODIFIED KEYS                #\n");
            headerModified.Append("################################################\n\n");

            if (fullPath != string.Empty)
            {
                File.WriteAllText(fullPath, string.Empty);
            }

            if (added.Count > 0)
            {
                output.Append(headerAdded);

                if (fullPath != string.Empty)
                {
                    File.WriteAllText(fullPath, output.ToString());
                    WriteWnfNamesToFile(added, fullPath, true, verbose, format);
                    File.AppendAllText(fullPath, "\n");
                }
                else
                {
                    Console.WriteLine(output);
                    WriteWnfNamesToFile(added, string.Empty, true, verbose, format);
                    Console.WriteLine("\n");
                }
            }

            output.Clear();

            if (deleted.Count > 0)
            {
                output.Append(headerDeleted);

                if (fullPath != string.Empty)
                {
                    File.AppendAllText(fullPath, output.ToString());
                    WriteWnfNamesToFile(deleted, fullPath, true, verbose, format);
                    File.AppendAllText(fullPath, "\n");
                }
                else
                {
                    Console.WriteLine(output);
                    WriteWnfNamesToFile(deleted, string.Empty, true, verbose, format);
                    Console.WriteLine("\n");
                }
            }

            output.Clear();

            if (modified.Count > 0)
            {
                output.Append(headerModified);

                if (fullPath != string.Empty)
                {
                    File.AppendAllText(fullPath, output.ToString());
                    WriteWnfNamesToFile(modified, fullPath, true, verbose, format);
                    File.AppendAllText(fullPath, "\n\n");
                }
                else
                {
                    Console.WriteLine(output);
                    WriteWnfNamesToFile(modified, string.Empty, true, verbose, format);
                    Console.WriteLine("\n\n");
                }
            }
        }

        public static void WriteWnfNamesToFile(
            Dictionary<string, Dictionary<ulong, string>> stateNames,
            string filename,
            bool append,
            bool verbose,
            string format)
        {
            StringBuilder output = new StringBuilder();
            string key;
            ulong value;
            string desctiption;
            string formatterHeader;
            string formatComment;
            string formatterLine;
            string delimiter;
            string formatterFooter;
            int count = 0;
            int sizeStateNames = stateNames.Count;
            string fullPath = string.Empty;
            string dirPath;

            if (filename != string.Empty)
            {
                fullPath = Path.GetFullPath(filename);
                dirPath = Path.GetDirectoryName(fullPath);

                if (!Directory.Exists(dirPath))
                {
                    Console.WriteLine("\n[!] Target directory does not exist.\n");
                    fullPath = string.Empty;
                }
            }

            if (format == "c")
            {
                output.Append("typedef struct _WNF_NAME");
                output.Append("{\n");
                output.Append("    PCHAR Name;\n");
                output.Append("    ULONG64 Value;\n");
                output.Append("} WNF_NAME, *PWNF_NAME;\n\n");

                formatterHeader = "WNF_NAME g_WellKnownWnfNames[] =\n{\n";
                formatComment = "    // {0}\n";
                formatterLine = "    {{\"{0}\", 0x{1}}}";
                delimiter = ",\n";
                formatterFooter = "\n};";
            }
            else if (format == "py")
            {
                formatterHeader = "g_WellKnownWnfNames = {\n";
                formatComment = "    # {0}\n";
                formatterLine = "    \"{0}\": 0x{1}";
                delimiter = ",\n";
                formatterFooter = "\n}";
            }
            else
            {
                formatterHeader = "public enum WELL_KNOWN_WNF_NAME : ulong\n{\n";
                formatComment = "    // {0}\n";
                formatterLine = "    {0} = 0x{1}UL";
                delimiter = ",\n";
                formatterFooter = "\n}";
            }

            output.Append(formatterHeader);

            foreach (var stateName in stateNames.OrderBy(sn => sn.Key))
            {
                key = stateName.Key;

                foreach (var valAndDesc in stateName.Value)
                {
                    value = valAndDesc.Key;
                    desctiption = valAndDesc.Value;

                    if (verbose)
                    {
                        output.Append(string.Format(formatComment, desctiption));
                    }

                    output.Append(string.Format(formatterLine, key, value.ToString("X16")));
                }

                if (count < sizeStateNames - 1)
                {
                    output.Append(delimiter);
                }

                count++;
            }

            output.Append(formatterFooter);

            if ((fullPath != string.Empty) && !append)
            {
                File.WriteAllText(fullPath, output.ToString());
            }
            else if ((fullPath != string.Empty) && append)
            {
                File.AppendAllText(fullPath, output.ToString());
            }
            else
            {
                Console.WriteLine(output);
            }
        }
    }
}
