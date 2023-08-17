using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpWnfNameDumper.Library
{
    internal class Modules
    {
        public static bool DumpWellKnownWnfNames(
            string filePath, 
            out Dictionary<string, Dictionary<ulong, string>> stateNames)
        {
            uint nTableOffset;
            uint nPointerSize;
            stateNames= new Dictionary<string, Dictionary<ulong, string>>();

            try
            {
                using (var peImage = new PeFile(filePath))
                {
                    nPointerSize = peImage.Is64Bit ? 8u : 4u;
                    nTableOffset = Helpers.SearchTableOffset(in peImage);

                    if (nTableOffset == 0)
                        return false;

                    while (Helpers.ReadStateData(
                        in peImage,
                        nTableOffset,
                        out ulong stateName,
                        out string stateNameString,
                        out string description))
                    {
                        stateNames.Add(
                            stateNameString, 
                            new Dictionary<ulong, string> { { stateName, description } });
                        nTableOffset += (nPointerSize * 3);
                    }
                }
            }
            catch (InvalidDataException ex)
            {
                Console.WriteLine("[!] {0}", ex.Message);

                return false;
            }
            catch
            {
                Console.WriteLine("[!] Unexpected exception.");
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
            bool exists;
            bool modifies;
            added = new Dictionary<string, Dictionary<ulong, string>>();
            deleted = new Dictionary<string, Dictionary<ulong, string>>();
            modified = new Dictionary<string, Dictionary<ulong, string>>();

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
            string dirPath;
            string fullPath = null;
            var output = new StringBuilder();
            var headerAdded = new StringBuilder();
            var headerDeleted = new StringBuilder();
            var headerModified = new StringBuilder();

            if (!string.IsNullOrEmpty(filename))
            {
                fullPath = Path.GetFullPath(filename);
                dirPath = Path.GetDirectoryName(fullPath);

                if (!Directory.Exists(dirPath))
                {
                    Console.WriteLine("\n[!] Target directory does not exist.\n");
                    fullPath = null;
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

            if (!string.IsNullOrEmpty(fullPath))
            {
                File.WriteAllText(fullPath, null);
            }

            if (added.Count > 0)
            {
                output.Append(headerAdded);

                if (!string.IsNullOrEmpty(fullPath))
                {
                    File.WriteAllText(fullPath, output.ToString());
                    WriteWnfNamesToFile(added, fullPath, true, verbose, format);
                    File.AppendAllText(fullPath, "\n");
                }
                else
                {
                    Console.WriteLine(output);
                    WriteWnfNamesToFile(added, null, true, verbose, format);
                    Console.WriteLine("\n");
                }
            }

            output.Clear();

            if (deleted.Count > 0)
            {
                output.Append(headerDeleted);

                if (!string.IsNullOrEmpty(fullPath))
                {
                    File.AppendAllText(fullPath, output.ToString());
                    WriteWnfNamesToFile(deleted, fullPath, true, verbose, format);
                    File.AppendAllText(fullPath, "\n");
                }
                else
                {
                    Console.WriteLine(output);
                    WriteWnfNamesToFile(deleted, null, true, verbose, format);
                    Console.WriteLine("\n");
                }
            }

            output.Clear();

            if (modified.Count > 0)
            {
                output.Append(headerModified);

                if (!string.IsNullOrEmpty(fullPath))
                {
                    File.AppendAllText(fullPath, output.ToString());
                    WriteWnfNamesToFile(modified, fullPath, true, verbose, format);
                    File.AppendAllText(fullPath, "\n\n");
                }
                else
                {
                    Console.WriteLine(output);
                    WriteWnfNamesToFile(modified, null, true, verbose, format);
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
            string key;
            ulong value;
            string desctiption;
            string formatterHeader;
            string formatComment;
            string formatterLine;
            string delimiter;
            string formatterFooter;
            string dirPath;
            int count = 0;
            int sizeStateNames = stateNames.Count;
            string fullPath = null;
            var output = new StringBuilder();

            if (!string.IsNullOrEmpty(filename))
            {
                fullPath = Path.GetFullPath(filename);
                dirPath = Path.GetDirectoryName(fullPath);

                if (!Directory.Exists(dirPath))
                {
                    Console.WriteLine("\n[!] Target directory does not exist.\n");
                    fullPath = null;
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
                        output.AppendFormat(formatComment, desctiption);
                    }

                    output.AppendFormat(formatterLine, key, value.ToString("X16"));
                }

                if (count < sizeStateNames - 1)
                {
                    output.Append(delimiter);
                }

                count++;
            }

            output.Append(formatterFooter);

            if (!string.IsNullOrEmpty(fullPath) && !append)
                File.WriteAllText(fullPath, output.ToString());
            else if (!string.IsNullOrEmpty(fullPath) && append)
                File.AppendAllText(fullPath, output.ToString());
            else
                Console.WriteLine(output);
        }
    }
}
