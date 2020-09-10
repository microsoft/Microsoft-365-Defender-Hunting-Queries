# Detect PowerShell commands to connect to remote hosts

This query was originally published in the threat analytics report, *Hunting for PowerShell Empire*

[PowerShell Empire](https://www.powershellempire.com/) is a modular toolkit used both by penetration testers and malicious actors. It offers a wide range of attack techniques, and has been observed in numerous attacks.

The following query detects obfuscated or indirect PowerShell commands to connect to remote hosts.

More queries related to PowerShell Empire are listed under the [See also](#see-also) section below.

## Query

```Kusto
​// Look for PowerShell commands that connect to remote hosts
DeviceProcessEvents
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
| where DecodeString has "proxy" and DecodeString 
has_any("webclient", "downloadfile", "downloadstring", "webrequest")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement | v |  |
| Collection |  |  |
| Command and control | v |  |
| Exfiltration | v |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Return alerts for PowerShell Empire](../Protection%20events/powershell-empire-alerts.md)
* [Detect PowerShell Empire modules](../Execution/powershell-empire-modules.md)
* [Detect Base64-encoded PowerShell process and network creation commands](../Defense%20evasion/base64-encoded-powershell-commands.md)
* [Detect obfuscated PowerShell commands](../Defense%20evasion/obfuscated-powershell-commands.md)
* [Detect PowerShell commands executed from remote host](../Execution/powershell-execution-from-repo.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
