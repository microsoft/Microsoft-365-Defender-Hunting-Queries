# LemonDuck command-and-control contact structure
LemonDuck is an actively updated and robust malware primarily known for its botnet and cryptocurrency mining objectives. First discovered in 2019, LemonDuck has since adopted more sophisticated behavior and escalated its operations in 2021. Today, beyond using resources for its traditional bot and mining activities, LemonDuck steals credentials, removes security controls, spreads via emails, moves laterally, and ultimately drops more tools for human-operated activity.

## Query
This query looks for the unique method of contacting the command-and-control (C2) infrastructure for LemonDuck in order to register updates from the bot client or exfiltrate data. This structure has changed over time and this most recent iteration is active as of this report and from June-July 2021.
```
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_all("Exponent=","FromBase64String","$url+")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |   |  |
| Execution |   |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |   |  |
| Collection |  |  |
| Command and control | v |  |
| Exfiltration | v |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
