# Detect attempts to turn off System Restore

This query was originally published in the threat analytics report, *Ransomware continues to hit healthcare, critical services*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/).

In April of 2020, security researchers observed multiple ransomware campaigns using the same set of techniques.

The following query detects attempts to stop System Restore, which would prevent the user from recovering data by going back to a restore point.

The [See also](#see=also) section below lists more queries related to techniques shared by these campaigns.

## Query

```Kusto
​DeviceProcessEvents  
| where Timestamp > ago(7d)  
//Pivoting for rundll32  
and InitiatingProcessFileName =~ 'rundll32.exe'   
//Looking for empty command line   
and InitiatingProcessCommandLine !contains " " and InitiatingProcessCommandLine != ""  
//Looking for schtasks.exe as the created process  
and FileName in~ ('schtasks.exe')  
//Disabling system restore   
and ProcessCommandLine has 'Change' and ProcessCommandLine has 'SystemRestore' 
and ProcessCommandLine has 'disable'
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
| Credential Access |  |  |
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

[Return backup files deletion events](./backup-deletion.md)
[Detect use of Alternate Data Streams](../Defense%20evasion/alt-data-streams.md)
[Detect cipher.exe deleting data](../Defense%20evasion/deleting-data-w-cipher-tool.md)
[Detect clearing of system logs](../Defense%20evasion/clear-system-logs.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team