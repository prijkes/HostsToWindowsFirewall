using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallAPIv2.Rules;

namespace HostsToWindowsFirewall
{
    class Program
    {
        static string[] localIPRanges = {
            "0.",
            "10.",
            "127.",
            "169.254.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
            "255.255.255.255"
        };
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                string exec = Path.GetFileName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                Console.WriteLine("Usage: {0} <hosts file path> <firewall rule name>", exec);
                return;
            }
            string hostsFile = args[0];

            if (!File.Exists(hostsFile))
            {
                Console.WriteLine("[-] File {0} does not exists", hostsFile);
                return;
            }
            Console.WriteLine("[+] Parsing hosts file {0}", hostsFile);

            List<HostsFileEntry> hostEntries = HostsFile.ParseFile(hostsFile);
            if (hostEntries.Count == 0)
            {
                Console.WriteLine("[-] Found no host entries in host file {0}", hostsFile);
                return;
            }
            Console.WriteLine("[+] Found {0} host entries in host file {1}", hostEntries.Count, hostsFile);

            string ruleName = args[1];
            IFirewall activateFirewall = FirewallManager.Instance;

            HashSet<string> hashSet = new HashSet<string>();
            List<IAddress> remoteAddresses = new List<IAddress>(hostEntries.Count);
            for (int count = 0, max = hostEntries.Count; count < max; count++)
            {
                HostsFileEntry hostEntry = hostEntries[count];
                try
                {
                    IPAddress[] addresses = Dns.GetHostAddresses(hostEntry.Hostname);
                    for (int ipCount = 0, ips = addresses.Length; ipCount < ips; ipCount++)
                    {
                        IPAddress address = addresses[ipCount];
                        string ip = address.ToString();
                        if (IsLocalIP(ip))
                        {
                            Console.WriteLine("[*][{0}/{1}] Skipping local IP of host {2} -> {3} ({4}/{5})",
                                count + 1, max, hostEntry.Hostname, ip, ipCount + 1, addresses.Length);
                            continue;
                        }

                        if (hashSet.Contains(ip))
                        {
                            Console.WriteLine("[*][{0}/{1}] Skipping already added IP of host {2} -> {3} ({4}/{5})",
                                count + 1, max, hostEntry.Hostname, ip, ipCount + 1, addresses.Length);
                            continue;
                        }

                        hashSet.Add(ip);
                        SingleIP singleIp = SingleIP.FromIPAddress(address);
                        if (address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            remoteAddresses.Add(singleIp);
                            Console.WriteLine("[+][{0}/{1}] Found IP of host {2} -> {3} ({4}/{5})",
                                count + 1, max, hostEntry.Hostname, ip, ipCount + 1, addresses.Length);
                        }
                        else
                        {
                            Console.WriteLine("[*][{0}/{1}] Skipped non-IPv4 IP of host {2} -> {3} ({4}/{5})",
                                count + 1, max, hostEntry.Hostname, ip, ipCount + 1, addresses.Length);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-][{0}/{1}] Failed to get IPs for host {2}", count+1, max, hostEntry.Hostname, e.ToString());
                }
            }

            // Max addresses for a rule is 1000
            const int addressesPerRule = 1000;
            IAddress[] sortedAddresses = remoteAddresses.Where(x => x is SingleIP).OrderBy(x => Version.Parse(x.ToString())).Select(x => x as SingleIP).ToArray();
            int ruleCount = (int)Math.Ceiling((double)sortedAddresses.Length / addressesPerRule);
            int extraLength = ruleCount.ToString().Length;
            string extraLengthFormat = "".PadLeft(extraLength, '0');
            for (int i = 0; i < ruleCount; i++)
            {
                string name = String.Format("{0} ({1:" + extraLengthFormat + "})", ruleName, i+1);
                StandardRule rule = new StandardRule(name, 80, FirewallAction.Block, FirewallDirection.Outbound, FirewallProfiles.Private)
                {
                    Protocol = FirewallProtocol.TCP,
                    RemotePorts = new ushort[] { 80, 443 },
                    RemoteAddresses = sortedAddresses.Skip(i * addressesPerRule).Take(addressesPerRule).ToArray()
                };
                activateFirewall.Rules.Add(rule);
                Console.WriteLine("[+] Added rule {0} blocking {1} IPs", name, rule.RemoteAddresses.Length);
            }
            Console.WriteLine("[+] Added {0} rules with {1} IPs", ruleCount, remoteAddresses.Count);
        }

        private static bool IsLocalIP(string ip)
        {
            foreach (string localIPRange in localIPRanges)
            {
                if (ip.StartsWith(localIPRange))
                    return true;
            }
            return false;
        }
    }
}
