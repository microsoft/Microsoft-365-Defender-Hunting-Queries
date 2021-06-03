# Gootkit File Delivery

This query surfaces alerts related to Gootkit and enriches with command and control information, which has been observed delivering ransomware.

## Query
```
AlertInfo | where Title =~ "Suspected delivery of Gootkit malware" 
// Below section is to surface active follow-on Command and Control as a result of the above behavior. Comment out the below joins to see 
// only file create events where the malware may be present but has not yet been executed. 
//// 
// Get alert evidence 
| join AlertEvidence on $left.AlertId == $right.AlertId 
// Look for C2 
| join DeviceNetworkEvents on $left.DeviceId == $right.DeviceId 
| where InitiatingProcessFileName =~ "wscript.exe" and InitiatingProcessCommandLine has ".zip" and InitiatingProcessCommandLine has ".js" 
| summarize by RemoteUrl, RemoteIP , DeviceId, InitiatingProcessCommandLine, Timestamp, InitiatingProcessFileName, AlertId, Title, AccountName

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
