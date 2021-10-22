# Macaw Ransomware - Use of MSBuild.exe as a LOLBin
Prior to deploying Macaw ransomware in an organization, the adversary frequently uses MSBuild.exe as a LOLBin to communicate with the C2. 

## Query
This query looks for instances of MSBuild.exe being used as a LOLBin.
```
DeviceProcessEvents 
| where InitiatingProcessFileName =~ "wmiprvse.exe" 
| where FileName =~ "msbuild.exe" and ProcessCommandLine has "programdata"
```


## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
