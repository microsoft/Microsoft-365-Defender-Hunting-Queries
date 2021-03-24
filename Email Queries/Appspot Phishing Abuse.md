# Appspot Phishing Abuse
This query helps surface phishing campaigns associated with Appspot abuse. These emails frequently contain phishing links that utilize the recipients' own email address as a unique identifier in the URI.

This campaign was published on Twitter by [@MsftSecIntel](https://twitter.com/MsftSecIntel) at this link: https://twitter.com/MsftSecIntel/status/1374148156301004800  
## Query
```
EmailUrlInfo
// Detect URLs with a subdomain on appspot.com
| where UrlDomain matches regex @'\b[\w\-]+-dot-[\w\-\.]+\.appspot\.com\b'
// Enrich results with sender and recipient data
| join kind=inner EmailEvents on $left.NetworkMessageId==$right.NetworkMessageId
// Phishing attempts from Appspot related campaigns typically contain the recipient's email address in the URI
// Example 1: https://example-dot-example.appspot.com/#recipient@domain.com
// Example 2: https://example-dot-example.appspot.com/index.html?user=recipient@domain.com
| where Url has RecipientEmailAddress
    // Some phishing campaigns pass recipient email as a Base64 encoded string in the URI
    or Url has base64_encode_tostring(RecipientEmailAddress)
| project-away Timestamp1, NetworkMessageId1, ReportId1 
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v | Credential phishing |
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
| Ransomware |  |  |


## Contributor info
**Contributor:** Microsoft 365 Defender team
