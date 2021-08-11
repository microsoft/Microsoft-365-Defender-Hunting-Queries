# LemonDuck Microsoft Defender drive exclusion tampering
LemonDuck is an actively updated and robust malware primarily known for its botnet and cryptocurrency mining objectives. First discovered in 2019, LemonDuck has since adopted more sophisticated behavior and escalated its operations in 2021. Today, beyond using resources for its traditional bot and mining activities, LemonDuck steals credentials, removes security controls, spreads via emails, moves laterally, and ultimately drops more tools for human-operated activity.

## Query
This query looks for a command line event where LemonDuck or other like malware might attempt to modify Defender by disabling real-time monitoring functionality or adding entire drive letters to the exclusion criteria. The exclusion additions will often succeed even if tamper protection is enabled due to the design of the application. Custom alerts could be created in an environment for particular drive letters common in the environment. 
```
DeviceProcessEvents  
| where InitiatingProcessCommandLine has_all ("Set-MpPreference", "DisableRealtimeMonitoring", "Add-MpPreference", "ExclusionProcess")  
| project ProcessCommandLine, InitiatingProcessCommandLine, DeviceId, Timestamp  
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
| Command and control |   |  |
| Exfiltration |  |  |
| Impact |   |  |
| Vulnerability |   |  |
| Exploit |   |  |
| Misconfiguration |  |  |
| Malware, component |   |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
