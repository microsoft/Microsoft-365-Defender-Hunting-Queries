# Bazacall Cobalt Strike Lateral Movement
Microsoft has observed Bazacall using Cobalt Strike in order to move laterally to other machines on the network. 

## Query
This query looks for alerts related to Cobalt Strike and its built-in PSExec used for lateral movement. 
```
AlertInfo
| where Title in("File dropped and launched from remote location", "Suspicious transfer of an executable file")
// Joining in instances where Cobalt Strike's built-in PsExec is used for lateral movement
| join AlertEvidence on $left.AlertId == $right.AlertId
| where FileName matches regex @"^([a-z0-9]){7}\.exe$" and FileName matches regex "[0-9]{1,5}"
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
| Lateral movement | v |  |
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
