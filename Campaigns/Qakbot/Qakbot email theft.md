# Qakbot email theft


## Query
Use this query to find email stealing activities ran by Qakbot that will use “ping.exe -t 127.0.0.1” to obfuscate subsequent actions. Email theft that occurs might be exfiltrated to operators and indicates that the malware completed a large portion of its automated activity without interruption. 

Generic:
```
DeviceFileEvents
| where InitiatingProcessFileName =~ 'ping.exe'
| where FileName endswith '.eml'
```
Specific:
```
DeviceFileEvents
| where InitiatingProcessFileName =~ 'ping.exe' and InitiatingProcessCommandLine == 'ping.exe -t 127.0.0.1'
    and InitiatingProcessParentFileName in~('msra.exe', 'mobsync.exe') and FolderPath endswith ".eml"
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
| Collection | v |  |
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
