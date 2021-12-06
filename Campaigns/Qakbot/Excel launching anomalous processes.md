# Excel launching anomalous processes


## Query
Use this query to find Excel launching anomalous processes congruent with Qakbot payloads which contain additional markers from recent Qakbot executions. The presence of such anomalous processes indicate that the payload was delivered and executed, though reconnaissance and successful implantation hasn’t been completed yet. 
```
DeviceProcessEvents
| where InitiatingProcessParentFileName has "excel.exe" or InitiatingProcessFileName =~ "excel.exe"
| where InitiatingProcessFileName in~ ("excel.exe","regsvr32.exe")
| where FileName in~ ("regsvr32.exe", "rundll32.exe")| where ProcessCommandLine has @"..\"
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
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
