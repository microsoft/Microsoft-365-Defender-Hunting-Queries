# Qakbot reconnaissance activities


## Query
Use this query to find reconnaissance and beaconing activities after code injection occurs. Reconnaissance commands are consistent with the current version of Qakbot and occur automatically to exfiltrate system information. This data, once exfiltrated, will be used to prioritize human operated actions. 
```
DeviceProcessEvents
| where InitiatingProcessFileName == InitiatingProcessCommandLine
| where ProcessCommandLine has_any (
"whoami /all","cmd /c set","arp -a","ipconfig /all","net view /all","nslookup -querytype=ALL -timeout=10",
"net share","route print","netstat -nao","net localgroup")
| summarize dcount(FileName), make_set(ProcessCommandLine) by DeviceId,bin(Timestamp, 1d), InitiatingProcessFileName, InitiatingProcessCommandLine
| where dcount_FileName >= 8

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
| Discovery | v |  |
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
