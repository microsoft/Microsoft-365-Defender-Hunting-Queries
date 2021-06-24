# Bazacall NTDS.dit Theft
Microsoft has observed compromises related to Bazacall resulting in theft of the Active Directory database using ntdsutil.exe. 

## Query
This query looks for copies of NTDS created in specific file paths known to be associated with the Bazacall threat. 
```
DeviceProcessEvents
| where FileName =~ "ntdsutil.exe"
| where ProcessCommandLine has_any("full", "fu")
| where ProcessCommandLine has_any ("temp", "perflogs", "programdata")
// Exclusion
| where ProcessCommandLine !contains @"Backup"
```


## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
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
| Exfiltration | v |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
