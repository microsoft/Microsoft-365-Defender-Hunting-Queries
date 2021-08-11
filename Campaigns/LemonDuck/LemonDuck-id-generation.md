# LemonDuck command-and-control ID generation
LemonDuck is an actively updated and robust malware primarily known for its botnet and cryptocurrency mining objectives. First discovered in 2019, LemonDuck has since adopted more sophisticated behavior and escalated its operations in 2021. Today, beyond using resources for its traditional bot and mining activities, LemonDuck steals credentials, removes security controls, spreads via emails, moves laterally, and ultimately drops more tools for human-operated activity.

## Query
This query checks for the current method of exfiltrating basic component information to LemonDuck command and control servers. In previous iterations other methods were used and currently this logic is included at the end of callout to the server to identify the client. 
```
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine endswith "(@($env:COMPUTERNAME,$env:USERNAME,(get-wmiobject Win32_ComputerSystemProduct).UUID,(random))-join'*'))"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |   |  |
| Execution |   |  |
| Persistence |   |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement | v |  |
| Collection |  |  |
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |   |  |
| Vulnerability |   |  |
| Exploit |   |  |
| Misconfiguration |  |  |
| Malware, component |   |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
