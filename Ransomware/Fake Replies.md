# Fake replies

Use this query to find spoofed reply emails that contain certain keywords in the subject. The emails are also checked for a link to a document in Google Docs.
These attacks have been observed leading to ransomware

## Query
```
let SubjectTerms = pack_array('onus','equired','all','urvey','eb', 'eport','you','nation','me','itting','book','ocument','ill'); 
EmailEvents 
| where EmailDirection == "Inbound" 
| where Subject startswith "RE:" 
| where Subject has_any(SubjectTerms) 
| join EmailUrlInfo on $left.NetworkMessageId == $right.NetworkMessageId 
| where Url startswith "https://docs.google.com/document/" 
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |V |  |
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
