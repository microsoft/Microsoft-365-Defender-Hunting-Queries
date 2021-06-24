# Oracle WebLogic process wlsvcX64.exe exploitation and execution of PowerShell script to download payloads

This query was originally published in the threat analytics report, *Sysrv botnet evolution*.

Sysrv is a Go-based botnet that targets both Windows and Linux servers, and steals resources to mine cryptocurrency.

The following query finds instances of Oracle WebLogic being exploited to run a PowerShell script that downloads payloads.

## Query

```kusto
union DeviceProcessEvents, DeviceFileEvents
| where InitiatingProcessParentFileName =~ 'wlsvcX64.exe' and InitiatingProcessFileName =~ 'powershell.exe'
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

Technique, tactic, or state | Covered? (v=yes) | Notes
-|-|-
Initial access |  |  
Execution | v |  
Persistence |  |  
Privilege escalation |  |  
Defense evasion | v |  
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
Malware, component |  |  
Ransomware |  |  

## Contributor info

**Contributor:** Microsoft Threat Protection team
