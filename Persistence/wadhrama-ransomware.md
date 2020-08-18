# Find RDP persistance attempts related to Wadhrama ransomware

This query was originally published in the threat analytics report, *RDP ransomware persists as Wadhrama*.

The ransomware known as [Wadhrama](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Wadhrama) has been used in human-operated attacks that follow a particular pattern. The attackers often use Remote Desktop Protocol (RDP) to gain initial access to a device or network, exfiltrate credentials, and maintain persistance.

The following query checks for possible Wadhrama-related activity, by searching for attempts to establish RDP persistance via the registry.

Other techniques used by the group associated with Wadhrama are listed under [See also](#see-also).

## Query

```Kusto
// Find attempts to establish RDP persistence via the registry
let Allow = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "reg.exe"
| where ProcessCommandLine has "AllowTSConnections"
| extend AllowReport = Timestamp ;
//
let Deny = DeviceProcessEvents 
| where Timestamp > ago(7d)
| where FileName == "reg.exe"
| where ProcessCommandLine has "fDenyTSConnections"
| extend DenyReport = Timestamp;
// 
let Special = DeviceProcessEvents  
| where Timestamp > ago(7d)
| where FileName == "reg.exe"
| where ProcessCommandLine has "SpecialAccounts"
| extend SpecialReport = Timestamp;
//
Special | join kind=inner (Deny | join kind=inner Allow on DeviceId) on DeviceId 
| where AllowReport < Timestamp +10s and AllowReport > Timestamp -10s
| where DenyReport < Timestamp +10s and DenyReport > Timestamp -10s
| where SpecialReport < Timestamp +10s and SpecialReport > Timestamp -10s
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution |  |  |
| Persistence | v |  |
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

* [Find data destruction related to Wadhrama ransomware](../Impact/wadhrama-data-destruction.md)
* [Image File Execution Options and .bat file usage in association with Wadhrama ransomware](../Credential%20Access/wadhrama-credential-dump.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
