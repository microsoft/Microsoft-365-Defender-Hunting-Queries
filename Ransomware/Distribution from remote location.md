# Distribution from remote location

This query checks for alerts related to file drop and remote execution where the file name matches PsExec and similar tools used for distribution

## Query
```
AlertInfo
| where Title == "File dropped and launched from remote location"
| join AlertEvidence on $left.AlertId == $right.AlertId
// Looking for tools involved in potential distribution of ransomware
| where FileName hasprefix "psexe" or (FileName matches regex @"^([a-z0-9]){7}\.exe$" and FileName matches regex "[0-9]{1,5}")
or ProcessCommandLine has "accepteula"

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
| Ransomware |V |  |


## Contributor info
**Contributor:** Microsoft 365 Defender
