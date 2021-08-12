## JNLP File Attachments
JNLP file extensions are an uncommon file type often used to deliver malware. 

## Query
This query looks for email attachment name ending with a JNLP file extension.
```
EmailAttachmentInfo
| where FileName endswith ".jnlp"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |   |  |
| Collection |  |  |
| Command and control |   |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |   |  |
| Exploit |   |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
