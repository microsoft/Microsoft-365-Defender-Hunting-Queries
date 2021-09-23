# Malicious .bat file in suspicious Oracle Java SE folder path
ZLoader was delivered in a campaign in late summer 2021. This campaign was tweeted by @MsftSecIntel on twitter. 

## Query
This query looks for the suspicious .bat file placed in the folder using a specific naming convention purporting to be Java-related.
```
DeviceFileEvents
| where FileName endswith '.bat'
    and FolderPath has @'Program Files (x86)\Sun Technology Network\Oracle Java SE'
```


## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
