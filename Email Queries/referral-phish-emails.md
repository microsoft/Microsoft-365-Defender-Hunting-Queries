# Referral infrastructure credential phishing emails
The "Referral" infrastructure is a point-in-time set of infrastructure direclty associated with spoofed emails that imitate SharePoint and other legitimate products in order to conduct crednetial phishing. The operator is also known to use legitimate URL infrastructure such as Google, Microsoft and Digital Ocean to host their phishing pages.
## Query
This query looks for instances where known malicious original senders that are approximately close to the word "Referral" associated with multiple phishing campaigns in multiple months in 2021. These mails also attempt to bypass protections and gain access to inboxes by spoofing the recipient domain in the displayed email address. This query will match instances where the displayed email address matches the recipient's domain and join to the email URL data for easy hunting on potential malicious credential theft sites. 
```
let EmailAddresses = pack_array
('zreffertalt.com.com','zreffesral.com.com','kzreffertal.com.com',
'wzreffertal.com.com','refferal.comq','refferal.net','zreffertal.com.com',
'zrefferal.com.com','refferasl.com.com','zreffesral.com','zrefsfertal.com.com',
'irefferal.com','refferasl.co','zrefferal.com');
EmailEvents
| where SenderMailFromDomain in (EmailAddresses)
| extend RecipientDomain = extract("[^@]+$", 0, RecipientEmailAddress)
| where SenderFromDomain == RecipientDomain
| join EmailUrlInfo on $left.NetworkMessageId == $right.NetworkMessageId
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
| Credential Access | v |  |
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
