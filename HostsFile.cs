using System;
using System.Collections.Generic;
using System.IO;

namespace HostsToWindowsFirewall
{
    public class HostsFile
    {
        public static List<HostsFileEntry> ParseFile(string filePath)
        {
            List<HostsFileEntry> hostEntries = new List<HostsFileEntry>();
            if (filePath == null)
                throw new ArgumentNullException(nameof(filePath));

            IEnumerable<string> lines = File.ReadLines(filePath);
            foreach (string line in lines)
            {
                if (line.Trim().Length == 0 || line.StartsWith("#"))
                    continue;

                string[] split = line.Trim().Split(new[] { ' ', '\t' });
                if (split.Length < 2)
                    continue;

                HostsFileEntry hostEntry = new HostsFileEntry(split[1], split[0]);
                hostEntries.Add(hostEntry);
            }
            return hostEntries;
        }
    }
}