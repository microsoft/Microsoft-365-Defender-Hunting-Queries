# Discovery for highly-privileged accounts

Use this query to locate commands related to discovering highly privileged users in an environment, sometimes a precursor to ransomware

## Query
```
DeviceProcessEvents
| where FileName == "net.exe"
// Create a set for the command lines
| summarize makeset(ProcessCommandLine) by InitiatingProcessFileName, AccountName, DeviceId, bin(Timestamp, 5m)
// Other process launches by Net in that same timeframe
| where (set_ProcessCommandLine has "admin" 
and set_ProcessCommandLine has_any("domain", "enterprise", "backup operators"))
and set_ProcessCommandLine has "group" and set_ProcessCommandLine contains "/do"
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
| Discovery |V  |  | 
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
