# LaZagne Credential Theft

Use this query to locate processes executing credential theft activity, often LaZagne in ransomware compromises.

## Query
```
DeviceProcessEvents 
| where FileName =~ 'reg.exe'
| where ProcessCommandLine has_all('save','hklm','sam')
| project DeviceId, Timestamp, InitiatingProcessId, InitiatingProcessFileName, ProcessId, FileName, ProcessCommandLine

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
