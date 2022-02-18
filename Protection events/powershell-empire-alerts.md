# Return alerts for PowerShell Empire

This query was originally published in the threat analytics report, *Hunting for PowerShell Empire*

[PowerShell Empire](https://www.powershellempire.com/) is a modular toolkit used both by penetration testers and malicious actors. It offers a wide range of attack techniques, and has been observed in numerous attacks.

The following query returns alerts that are commonly associated with PowerShell Empire activity.

More queries related to PowerShell Empire are listed under the [See also](#see-also) section below.

## Query

```Kusto
DeviceAlertEvents
// Find specific alerts that might relate to Empire usage
| where Title in~("Suspicious Power Shell command line",
"Suspicious connection to legitimate web service",
"Possible Antimalware Scan Interface (AMSI) tampering",
"Suspicious WMI process creation",
"Attempt to disable PowerShell logging",
"A malicious PowerShell Cmdlet was invoked on the machine",
"Suspicious decoded content")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component | v |  |

## See also

* [Detect PowerShell Empire modules](../Execution/powershell-empire-modules.md)
* [Detect Base64-encoded PowerShell process and network creation commands](../Defense%20evasion/base64-encoded-powershell-commands.md)
* [Detect obfuscated PowerShell commands](../Defense%20evasion/obfuscated-powershell-commands.md)
* [Detect PowerShell commands to connect to remote hosts](../General%20queries/powershell-remote-connection.md)
* [Detect PowerShell commands executed from remote host](../Execution/powershell-execution-from-repo.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
