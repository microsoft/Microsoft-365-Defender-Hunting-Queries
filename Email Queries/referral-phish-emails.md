# Referral infrastructure credential phishing emails
The "Referral" infrastructure is a point-in-time set of infrastructure associated with spoofed emails that imitate SharePoint and other legitimate products to conduct credential phishing. The operator is also known to use legitimate URL infrastructure such as Google, Microsoft, and Digital Ocean to host their phishing pages.
## Query
Use this query to search for instances of malicious senders associated with multiple phishing campaigns for a few months in 2021, with subjects approximately similar to "Referral". These mails also attempt to bypass protections and access inboxes by spoofing the recipient domain in the displayed email address. This query will match instances where the displayed email address matches the recipient's domain and join to the email URL data for easy hunting on potential malicious credential theft sites.
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

Use this query to detect the following attack techniques and tactics (see MITRE ATT&CK framework) or security configuration states.
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
