# Tim.exe payload delivery
ZLoader was delivered in a campaign in summer 2021 via malvertising. This campaign was tweeted about by @MsftSecIntel on twitter.

## Query
This query looks for delivery of the malicious payload, Tim.exe. 
```
DeviceNetworkEvents
| where InitiatingProcessFileName =~ 'powershell.exe'
    and InitiatingProcessCommandLine has('Invoke-WebRequest') and InitiatingProcessCommandLine endswith '-OutFile tim.EXE'
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
