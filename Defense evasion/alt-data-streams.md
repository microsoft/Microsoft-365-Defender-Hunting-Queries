# Detect use of Alternate Data Streams

This query was originally published in the threat analytics report, *Ransomware continues to hit healthcare, critical services*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/).

In April of 2020, security researchers observed multiple ransomware campaigns using the same set of techniques.

The following query detects suspicious use of [Alternate Data Streams](https://docs.microsoft.com/sysinternals/downloads/streams) (ADS), which may indicate an attempt to mask malicious activity. These campaigns have been known to deploy ransomware in-memory and exploit ADS.

The [See also](#see=also) section below lists more queries related to techniques shared by these campaigns.

## Query

```Kusto
// Alternate Data Streams execution 
DeviceProcessEvents 
| where Timestamp > ago(7d) 
// Command lines used 
| where ProcessCommandLine startswith "-q -s" and ProcessCommandLine hasprefix "-p" 
// Removing IDE processes 
and not(FolderPath has_any("visual studio", "ide")) 
| summarize make_set(ProcessCommandLine), make_set(FolderPath), 
make_set(InitiatingProcessCommandLine) by DeviceId, bin(Timestamp, 1h)
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
[Detect attempts to turn off System Restore](./turn-off-system-restore.md)
[Detect cipher.exe deleting data](./deleting-data-w-cipher-tool.md)
[Detect clearing of system logs](./clear-system-logs.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team