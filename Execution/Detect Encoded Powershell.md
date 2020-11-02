# Detect Encoded PowerShell

This query will detect encoded powershell based on the parameters passed during process creation. This query will also work if the PowerShell executable is renamed or tampered with since detection is based solely on a regex of the launch string.

## Query
```
DeviceProcessEvents
| where ProcessCommandLine matches regex @'(\s+-((?i)encod?e?d?c?o?m?m?a?n?d?|e|en|enc|ec)\s).*([A-Za-z0-9+/]{50,}[=]{0,2})'
| extend DecodedCommand = replace(@'\x00','', base64_decode_tostring(extract("[A-Za-z0-9+/]{50,}[=]{0,2}",0 , ProcessCommandLine)))
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
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
**Contributor:** Michael Melone
**GitHub alias:** mjmelone
**Organization:** Microsoft
**Contact info:** @PowershellPoet
