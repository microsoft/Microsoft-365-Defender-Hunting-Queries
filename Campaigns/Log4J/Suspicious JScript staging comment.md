# Suspicious JScript staging comment
Microsoft has observed attackers who have gained entry to an environment via the Log4J vulnerability utilizing identifiable strings in PowerShell commands.

## Query
This query identifies a unique string present in malicious PowerShell commands attributed to threat actors exploiting vulnerable Log4j applications. These events warrant further investigation to determine if they are in fact related to a vulnerable Log4j application. 
```
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "VMBlastSG"
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
| Vulnerability | v |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
