# LemonDuck competition killer script execution
LemonDuck is an actively updated and robust malware primarily known for its botnet and cryptocurrency mining objectives. First discovered in 2019, LemonDuck has since adopted more sophisticated behavior and escalated its operations in 2021. Today, beyond using resources for its traditional bot and mining activities, LemonDuck steals credentials, removes security controls, spreads via emails, moves laterally, and ultimately drops more tools for human-operated activity.

## Query
This query looks for instances of the LemonDuck component KR.Bin, which is intended to kill competition prior to making the installation and persistence of the malware concrete. The killer script used is based off historical versions from 2018 and earlier, which has grown over time to include scheduled task and service names of various botnets, malware, and other competing services. The version currently in use by LemonDuck has approximately 40-60 scheduled task names. The upper maximum in this query can be modified and adjusted to include time bounding. 
```
DeviceProcessEvents
| where ProcessCommandLine has_all("schtasks.exe","/Delete","/TN","/F")
| summarize make_set(ProcessCommandLine) by DeviceId
| extend DeleteVolume = array_length(set_ProcessCommandLine)
| where set_ProcessCommandLine has_any("Mysa","Sorry","Oracle Java Update","ok")
| where DeleteVolume >= 40 and DeleteVolume <= 80
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |   |  |
| Execution | v |  |
| Persistence | v |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |   |  |
| Collection |  |  |
| Command and control |   |  |
| Exfiltration |  |  |
| Impact | v |  |
| Vulnerability |   |  |
| Exploit |   |  |
| Misconfiguration |  |  |
| Malware, component | v |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
