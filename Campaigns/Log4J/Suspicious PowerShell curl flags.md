# Suspicious PowerShell curl flags
Microsoft has observed attackers who have gained entry to an environment via the Log4J vulnerability utilizing uncommon PowerShell flags to communicate to command-and-control infrastructure. 

## Query
This query identifies unique, uncommon PowerShell flags used by curl to post the results of an attacker-executed command back to the command-and-control infrastructure. If the event is a true positive, the contents of the “Body” argument are Base64-encoded results from an attacker-issued comment. These events warrant further investigation to determine if they are in fact related to a vulnerable Log4j application. 
```
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all("-met", "POST", "-Body")
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
