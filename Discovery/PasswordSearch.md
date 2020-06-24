# Detect LDAP queries that search for user password in description or comment

Detect Active Directory LDAP queries that search for users with comment or description that contains the string "pass" that might suggest for the user password

This LDAP query cover MetaSploit - enum_ad_user_comments tool

## Query

```
let PersonObject = "objectCategory=person";
let UserClass = "objectClass=user";
let SamAccountUser = "samAccountType=805306368";
let Description = "description=*pass*";
let Comment = "comment=*pass*";
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where (SearchFilter contains Description or SearchFilter contains Comment) and
(SearchFilter contains PersonObject or SearchFilter contains UserClass or SearchFilter contains SamAccountUser)

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
