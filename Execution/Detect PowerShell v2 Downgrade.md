# Detect PowerShell Downgrade
This query looks for processes that load an older version of the system.management.automation libraries. While not inherently malicious, downgrading to PowerShell version 2 
can enable an attacker to bypass some of the protections afforded by modern PowerShell. It is worth noting that some tools and scripts perform this to enable 
backwards compatibility, so the technique is not inherently malicious. You will likely need to filter the processes within your environment that legitimately use this
capability for this to be effective.

## Query
```
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ 'powershell.exe'
    and FileName in~ ('system.management.automation.ni.dll','System.Management.Automation.dll')
    and FolderPath matches regex @"[12]\.(\d)+\.(\d)+\.(\d)+"

```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
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
| Ransomware |  |  |


## Contributor info
**Contributor:** Michael Melone
**GitHub alias:** mjmelone
**Organization:** Microsoft
**Contact info:** @PowershellPoet
