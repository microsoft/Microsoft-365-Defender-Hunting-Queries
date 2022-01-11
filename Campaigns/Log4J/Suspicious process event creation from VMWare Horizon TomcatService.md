# Suspicious process event creation from VMWare Horizon TomcatService
Microsoft has observed attackers who have gained entry to an environment via the Log4J vulnerability utilizing the ws_TomcatService.exe process to launch malicious processes. 

## Query
This query identifies anomalous child processes from the ws_TomcatService.exe process associated with the exploitation of the Log4j vulnerability in VMWare Horizon installations. These events warrant further investigation to determine if they are in fact related to a vulnerable Log4j application. 
```
DeviceProcessEvents
| where InitiatingProcessFileName has "ws_TomcatService.exe"
| where FileName != "repadmin.exe"
```


## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
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
| Vulnerability | v |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
