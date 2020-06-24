# Detect LDAP queries for sensitive objects

Detect Active Directory LDAP queries that search for sensitive objects in the organization

This LDAP query cover BloodHound tool

## Query

```
let SensitiveObjects = "[\"Administrators\", \"Domain Controllers\", \"Domain Admins\", \"Account Operators\", \"Backup Operators\", \"DnsAdmin\", \"Enterprise Admins\", \"Group Policy Creator Owners\"]";
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where SensitiveObjects contains QueryTarget or SearchFilter contains "admincount=1"

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
| Credential Access |  |  | 
| Discovery | X |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |



## Contributors info

**Contributor:** Mor Rubin

**GitHub alias:** https://github.com/morRubin

**Organization:** Microsoft

**Contact info:** Twitter: MorRubin

**Contributor:** Oz Soprin

**GitHub alias:** https://github.com/ozSoprin

**Organization:** Microsoft

**Contact info:** Twitter: ozSoprin
