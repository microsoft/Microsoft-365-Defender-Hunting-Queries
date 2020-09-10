# Detect PowerShell commands executed from remote host

This query was originally published in the threat analytics report, *Hunting for PowerShell Empire*

[PowerShell Empire](https://www.powershellempire.com/) is a modular toolkit used both by penetration testers and malicious actors. It offers a wide range of attack techniques, and has been observed in numerous attacks.

The following query detects attempts to call certain PowerShell Empire modules directly from a remote project repository.

More queries related to PowerShell Empire are listed under the [See also](#see-also) section below.

## Query

```Kusto
​// Look for PowerShell commands that connect to remote hosts
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(1d)
// Pivot on PowerShell processes
| where InitiatingProcessFileName  in~("powershell.exe", "powershell_ise.exe")
| where InitiatingProcessCommandLine has "empireproject" 
and InitiatingProcessCommandLine has "webclient"
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
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Return alerts for PowerShell Empire](../Protection%20events/powershell-empire-alerts.md)
* [Detect PowerShell Empire modules](../Execution/powershell-empire-modules.md)
* [Detect Base64-encoded PowerShell process and network creation commands](../Defense%20evasion/base64-encoded-powershell-commands.md)
* [Detect obfuscated PowerShell commands](../Defense%20evasion/obfuscated-powershell-commands.md)
* [Detect PowerShell commands to connect to remote hosts](../General%20queries/powershell-remote-connection.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
