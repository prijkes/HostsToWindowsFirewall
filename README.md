# Windows Hosts Firewall Tool

## Description

Windows Hosts Firewall Tool is a utility designed to add the contents of the Windows Hosts file as rules to Windows Firewall. It excludes local IP addresses to prevent unintentional self-blocking.

## Features

- Parses the contents of the Windows Hosts file
- Creates a single firewall rule with up to 1000 entries
- Creates a new rule after the maximum of 1000 entries
- Skips adding local IP addresses (from the local area network ranges)

## Prerequisites

To compile and use this project, you will need:

- Microsoft Visual Studio
- .NET Framework

## Installation

1. Clone the repository to your local machine using `git clone https://github.com/prijkes/HostsToWindowsFirewall.git`
2. Open the project in Visual Studio.
3. Ensure that the WindowsFirewallHelper NuGet package is installed. If not, install it via the NuGet Package Manager.
4. Build the project by selecting `Build > Build Solution` from the menu.

## Acknowledgements

Uses the WindowsFirewallHelper package by [falahati](https://github.com/falahati/WindowsFirewallHelper)
