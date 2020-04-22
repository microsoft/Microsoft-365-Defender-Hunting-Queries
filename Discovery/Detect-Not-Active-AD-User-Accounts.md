
# Detect not active AD user accounts

// Detect Active Directory service accounts that are not active because their last logon was more than 14 days ago
// Replace XXX on line 4 with the naming convention start of your Active Directory service accounts

## Query

```
IdentityLogonEvents 
| project Timestamp, AccountName, DeviceName, LogonType
| where AccountName startswith "XXX" 
| summarize LastLogon = max(Timestamp) by AccountName, LogonType, DeviceName
| where LastLogon < ago(14d)

```
## Category

This query can be used the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access | X |  | 
| Discovery | X |  | 
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
