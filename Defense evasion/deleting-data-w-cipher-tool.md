# Detect cipher.exe deleting data

This query was originally published in the threat analytics report, *Ransomware continues to hit healthcare, critical services*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/).

In April of 2020, security researchers observed multiple ransomware campaigns using the same set of techniques.

The following query detects the use of the tool *cipher.exe* to delete indicators of malicious activity right before encrypting a drive.

The [See also](#see=also) section below lists more queries related to techniques shared by these campaigns.

## Query

```Kusto
​DeviceProcessEvents 
| where Timestamp > ago(7d)  
| where FileName =~ "cipher.exe"  
// Looking for /w flag for deleting  
| where ProcessCommandLine has "/w"  
| summarize CommandCount = dcount(ProcessCommandLine), 
make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 1m)  
// Looking for multiple drives in a short timeframe  
| where CommandCount > 1
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
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

[Return backup files deletion events](../Impact/backup-deletion.md)
[Detect use of Alternate Data Streams](./alt-data-streams.md)
[Detect attempts to turn off System Restore](./turn-off-system-restore.md)
[Detect clearing of system logs](./clear-system-logs.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team