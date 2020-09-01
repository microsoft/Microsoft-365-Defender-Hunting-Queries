# WastedLocker Downloader

This query identifies the launch pattern associated with wastedlocker ransomware.
Reference writeup: https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/wastedlocker-ransomware-us

## Query

```
DeviceProcessEvents
| where InitiatingProcessFileName =~ 'wscript.exe' and FileName =~ 'powershell.exe' and InitiatingProcessCommandLine matches regex @"(?i)\\chrome\.update\..+?\.js"
```
## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |v|  |
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
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
