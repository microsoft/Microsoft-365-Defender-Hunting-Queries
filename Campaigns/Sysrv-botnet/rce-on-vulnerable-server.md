# Remote code execution on vulnerable server

This query was originally published in the threat analytics report, *Sysrv botnet evolution*.

Sysrv is a Go-based botnet that targets both Windows and Linux servers, and steals resources to mine cryptocurrency.

The following query finds instances of remote code execution on a vulnerable Linux server.

## Query

```kusto
DeviceProcessEvents
| where InitiatingProcessCommandLine has "php-cgi.exe"
| where ProcessCommandLine has_all ('curl -fsSL', '/ldr.sh', 'wget -q -O')
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
