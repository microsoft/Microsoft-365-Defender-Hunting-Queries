# Tomcat 8 process executing PowerShell command line to perform data exploitation activities and setting up scheduler tasks.

This query was originally published in the threat analytics report, *Sysrv botnet evolution*.

Sysrv is a Go-based botnet that targets both Windows and Linux servers, and steals resources to mine cryptocurrency.

The following query finds instances of Apache Tomcat 8 being exploited to execute encoded PowerShell commands.

## Query

```kusto
DeviceProcessEvents
| where InitiatingProcessParentFileName startswith 'tomcat'
| where InitiatingProcessFileName in~("cmd.exe", "powershell.exe") and InitiatingProcessCommandLine hasprefix '-enc '
and ProcessCommandLine has_any ('cmd.exe','powershell.exe','sc.exe','schtasks.exe','WMIC.exe')
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
