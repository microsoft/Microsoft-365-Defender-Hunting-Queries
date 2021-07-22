# Bazacall emails
Bazacall malware uses emails that contain a phone number for the user to call in order to cancel a fake subscription. These emails contain no links or attachments, and use automatic payment lures to trick users into contacting the number included in the email.

## Query
This query looks for the subject lines associated with known Bazacall emails, using a regex to match on the fake account number pattern and a few keywords that are frequently used in these subjects. NOTE: Some emails contain the fake account number in the body of the email rather than the subject. In these instances, searching on keyword alone may surface related emails. Verify maliciousness by matching the regex for the account number in the body of the email if possible. 
```
EmailEvents
| where Subject matches regex @"[A-Z]{1,3}\d{9,15}"
    and Subject has_any('trial', 'free', 'demo', 'membership', 'premium', 'gold', 'notification', 'notice', 'claim', 'order', 'license', 'licenses')
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
