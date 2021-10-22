# Macaw ransomware - Disable Controlled Folders 
Prior to deploying Macaw ransomware in an organization, the adversary will disable all controlled folders, which will enable them to be encrypted once the ransomware payload is deployed. 

## Query
This query looks for instances where the attacker has disabled the use of controlled folders.
```
DeviceProcessEvents 
| where InitiatingProcessFileName =~ 'cmd.exe' 
| where FileName =~ 'powershell.exe' and ProcessCommandLine has('powershell.exe  -command "Set-MpPreference -EnableControlledFolderAccess Disabled"') 
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
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware | v |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
