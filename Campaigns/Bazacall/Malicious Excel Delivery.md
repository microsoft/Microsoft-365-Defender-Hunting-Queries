# Bazacall Malicious Excel Delivery
Bazacall uses malicious Excel files to execute payloads on affected devices. 

## Query
This query looks for files that are downloaded from URL paths known to be associated with the Bazacall threat. 
```
DeviceFileEvents
| where FileOriginUrl has "/cancel.php" and FileOriginReferrerUrl has "/account"
  or FileOriginUrl has "/download.php" and FileOriginReferrerUrl has "/case"
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
