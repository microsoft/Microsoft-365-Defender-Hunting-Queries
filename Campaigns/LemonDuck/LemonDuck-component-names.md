# LemonDuck common external component names
LemonDuck is an actively updated and robust malware primarily known for its botnet and cryptocurrency mining objectives. First discovered in 2019, LemonDuck has since adopted more sophisticated behavior and escalated its operations in 2021. Today, beyond using resources for its traditional bot and mining activities, LemonDuck steals credentials, removes security controls, spreads via emails, moves laterally, and ultimately drops more tools for human-operated activity.

## Query
This query looks for instances of the callback actions which attempt to obfuscate detection while downloading supporting scripts such as those that enable the “Killer” and “Infection” functions for the malware as well as the mining components and potential secondary functions. This query only encompasses the most common component names.
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "cmd.exe"
| where InitiatingProcessCommandLine has_any("kr.bin","if.bin","m6.bin")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |   |  |
| Execution | v |  |
| Persistence | v |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement | v |  |
| Collection |  |  |
| Command and control |   |  |
| Exfiltration |  |  |
| Impact | v |  |
| Vulnerability | v |  |
| Exploit |   |  |
| Misconfiguration |  |  |
| Malware, component | v |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
