
# Identify potential missed phishing email campaigns

// Identify emails that were send from an address external to your company and where email was send to more then 50 distinct corporate users
// Update corporatedomain.com to your corporate domain to have it excluded
// Update 50 if you want to adjust the distinct user count

## Query

EmailEvents
| where SenderFromDomain != "corporatedomain.com"
| summarize dcount(RecipientEmailAddress) by SenderFromAddress, NetworkMessageId, AttachmentCount, SendTime = Timestamp 
| where dcount_RecipientEmailAddress > 50

## Category

This query can be used the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | X |  |
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
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** < Milad Aslaner >

**GitHub alias:** < https://github.com/MiladMSFT >

**Organization:** < Microsoft >

**Contact info:** < Twitter: MiladMSFT >
