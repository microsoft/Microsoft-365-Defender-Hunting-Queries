# Processes Created from Files with Non-ASCII Characters

This query searches for processes that were created based on files that contain non-ASCII characters. Use of non-ASCII characters is a common obfuscation technique used to trick users into trusting malicious files. You can also change the DeviceProcessEvents table for DeviceFileEvents to look for file writes, or EmailAttachmentInfo to look for e-mail attachments if desired.

## Query
```

DeviceProcessEvents
| where FileName matches regex @"[^\x00-\xFF]" 

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
