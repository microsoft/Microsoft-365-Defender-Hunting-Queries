# Detect Base64-encoded PowerShell process and network creation commands

This query was originally published in the threat analytics report, *Hunting for PowerShell Empire*

[PowerShell Empire](https://www.powershellempire.com/) is a modular toolkit used both by penetration testers and malicious actors. It offers a wide range of attack techniques, and has been observed in numerous attacks.

The following query detects Base64-encoded PowerShell commands that are either process creation or network events. This can identify common techniques, such as [Kerberoasting](https://attack.mitre.org/techniques/T1558/003/).

More queries related to PowerShell Empire are listed under the [See also](#see-also) section below.

## Query

```Kusto
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(1d)
// Pivot on PowerShell processes
| where InitiatingProcessFileName  in~("powershell.exe", "powershell_ise.exe")
// Look for -encodedcommands, which can be 
// abbreviated all the way down to just -e
| where InitiatingProcessCommandLine hasprefix "-e"
// Split the commands on spaces
| extend SplitString = split(InitiatingProcessCommandLine, " ")
// Move the results into an array
| mvexpand SS = SplitString 
// Look for Base64 based on regex pattern
| where SS matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
// Decode Base64 and removing nul character
| extend DecodeString = replace("\\0", "", base64_decodestring(tostring(SS)))
// Check decoded string for Invoke or IEX
| where DecodeString has_any("iex", "invoke")
// Check for specific tokens or combinations 
// - update this for querying other tokens of interest in your environment
| where DecodeString has_any(
"locklogging", // ScriptBlock logging command often observed
".php") // Specified C2 domain, usually PHP 
or DecodeString has "join" and DecodeString has "char[]"
or DecodeString has "kerberoast"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
| Credential Access | v |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Detect PowerShell Empire modules](../Execution/powershell-empire-modules.md)
* [Return alerts for PowerShell Empire](../Protection%20events/powershell-empire-alerts.md)
* [Detect obfuscated PowerShell commands](../Defense%20evasion/obfuscated-powershell-commands.md)
* [Detect PowerShell commands to connect to remote hosts](../General%20queries/powershell-remote-connection.md)
* [Detect PowerShell commands executed from remote host](../Execution/powershell-execution-from-repo.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
