# Image File Execution Options and .bat file usage in association with Wadhrama ransomware

This query was originally published in the threat analytics report, *RDP ransomware persists as Wadhrama*.

The ransomware known as [Wadhrama](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Wadhrama) has been used in human-operated attacks that follow a particular pattern. The attackers often use Remote Desktop Protocol (RDP) to gain initial access to a device or network, exfiltrate credentials, and maintain persistance.

The following query checks for possible Wadhrama-related activity, by detecting the technique these attackers have used in the past to dump credentials.

Other techniques used by the group associated with Wadhrama are listed under [See also](#see-also).

## Query

```Kusto
// Find use of Image File Execution Options (IFEO) in conjunction 
// with a .bat file to dump credentials
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has "sethc" or RegistryKey has "utilman"
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
| Credential Access | v |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact | v |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Find data destruction related to Wadhrama ransomware](../Impact/wadhrama-data-destruction.md)
* [Find RDP persistance attempts related to Wadhrama ransomware](../Persistence/wadhrama-ransomware.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
