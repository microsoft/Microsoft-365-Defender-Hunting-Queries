# AppArmor service stopped

This query was originally published in the threat analytics report, *Sysrv botnet evolution*.

Sysrv is a Go-based botnet that targets both Windows and Linux servers, and steals resources to mine cryptocurrency.

The following query finds instances of the attacker attempting to stop the AppArmor network security service on devices running Linux.

## Query

```kusto
DeviceProcessEvents
| where InitiatingProcessCommandLine  has "/bin/bash /tmp/" and ProcessCommandLine has "service apparmor stop"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

Technique, tactic, or state | Covered? (v=yes) | Notes
-|-|-
Initial access |  |  
Execution | v |  
Persistence |  |  
Privilege escalation |  |  
Defense evasion |  |  
Credential Access |  |  
Discovery |  |  
Lateral movement |  |  
Collection |  |  
Command and control |  |  
Exfiltration |  |  
Impact |  |  
Vulnerability |  |  
Exploit |  |  
Misconfiguration |  |  
Malware, component | v |  
Ransomware |  |  

## Contributor info

**Contributor:** Microsoft Threat Protection team
