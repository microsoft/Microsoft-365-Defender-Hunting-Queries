# Suspicious Google Doc Links

Use this query to find emails with message IDs that resemble IDs used in known attack emails and contain a link a document in Google Docs. These behaviors have
been observed leading to ransomware attacks.

## Query
```
EmailUrlInfo 
| where Url startswith "https://docs.google.com/document/" 
| join (EmailEvents 
| where EmailDirection == "Inbound" 
| where InternetMessageId matches regex "\\<\\w{ 38,42} \\@") on NetworkMessageId 

```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |V  |  |
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
| Ransomware |V |  |


## Contributor info
**Contributor:** Microsoft 365 Defender
