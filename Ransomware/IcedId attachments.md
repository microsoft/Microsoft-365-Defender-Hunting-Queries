# IcedId attachments

Use this query to locate emails with subject indicators of a reply or forward, and the attachment is a .doc, or a .zip containing a .doc. Review results for suspicious emails.
IcedId can lead to ransomware

## Query
```
// Identify a reply or forward via subject line 
let SubjectTerms = pack_array("RE:","FW:","FWD:","AW:","WG:"); 
EmailEvents 
| where Subject has_any(SubjectTerms) 
| where EmailDirection == "Inbound" // Join on those emails by file type (doc or zip>doc) 
| join EmailAttachmentInfo on $left.NetworkMessageId == $right.NetworkMessageId 
| where AttachmentCount == 1 
| where FileType has 'WordStorage' or FileType has 'WordStorage;Zip'
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
| Ransomware |V |  |


## Contributor info
**Contributor:** Microsoft 365 Defender
