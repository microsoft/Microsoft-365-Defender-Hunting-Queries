# LemonDuck Email Subjects
LemonDuck is an actively updated and robust malware primarily known for its botnet and cryptocurrency mining objectives. First discovered in 2019, LemonDuck has since adopted more sophisticated behavior and escalated its operations in 2021. Today, beyond using resources for its traditional bot and mining activities, LemonDuck steals credentials, removes security controls, spreads via emails, moves laterally, and ultimately drops more tools for human-operated activity.

## Query
This query looks for subject lines that are present from 2020 to 2021 in dropped scripts that attach malicious LemonDuck samples to emails and mail it to contacts of the mailboxes on impacted machines. Additionally, checks if Attachments are present in the mailbox. General attachment types to check for at present are .doc, .zip or .js, though this could be subject to change as well as the subjects themselves.
```
EmailEvents
| where Subject in ('The Truth of COVID-19','COVID-19 nCov Special info WHO','HALTH ADVISORY:CORONA VIRUS',
'WTF','What the fcuk','good bye','farewell letter','broken file','This is your order?')
| where AttachmentCount >= 1
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
| Lateral movement | v |  |
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
