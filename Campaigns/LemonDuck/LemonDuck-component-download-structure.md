# LemonDuck component download structure
LemonDuck is an actively updated and robust malware primarily known for its botnet and cryptocurrency mining objectives. First discovered in 2019, LemonDuck has since adopted more sophisticated behavior and escalated its operations in 2021. Today, beyond using resources for its traditional bot and mining activities, LemonDuck steals credentials, removes security controls, spreads via emails, moves laterally, and ultimately drops more tools for human-operated activity.

## Query
This query looks for any instance of the current version of the LemonDuck component collection commands, even if the component names changes. This structure has and may continue to change over time in order to obfuscate detection. This will surface behavior that will collect mining, secondary malware and lateral movement executables from external sites. This query will typically return downloads of files such as "if.bin" or "kr.bin" or additional mining components.
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "cmd.exe"
| where InitiatingProcessCommandLine has_all("echo","tmp+",".bin","gmd5","downloaddata","down_url")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |   |  |
| Execution |   |  |
| Persistence |   |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |   |  |
| Collection |  |  |
| Command and control | v  |  |
| Exfiltration |  |  |
| Impact | v |  |
| Vulnerability |   |  |
| Exploit |   |  |
| Misconfiguration |  |  |
| Malware, component | v |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
