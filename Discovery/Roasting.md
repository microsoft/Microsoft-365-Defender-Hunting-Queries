# Detect LDAP queries that search for accounts vulnerable for roasting attacks

// Detect Active Directory LDAP queries that search for Kerberoasting (SPNs) or accounts with Kerberos preauthentication not required
// This LDAP query cover Rubeus, Kerberoast, BloodHound tools

## Query

```
let UserClass = "objectClass=user";
let SamAccountUser = "samAccountType=805306368";
let ASREP_ROASTING = "userAccountControl:1.2.840.113556.1.4.803:=4194304";
let ASREP_ROASTING1 = "userAccountControl|4194304";
let ASREP_ROASTING2 = "userAccountControl&4194304";
let KERBEROASTING = "serviceprincipalname=*";
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where SearchFilter contains ASREP_ROASTING or
SearchFilter contains ASREP_ROASTING1 or
SearchFilter contains ASREP_ROASTING2 or
 (SearchFilter contains KERBEROASTING and SearchFilter contains UserClass or SearchFilter contains SamAccountUser)

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

**Contributor:** < Mor Rubin >

**GitHub alias:** < https://github.com/morRubin >

**Organization:** < Microsoft >

**Contact info:** < Twitter: MorRubin >

**Contributor:** < Oz Soprin >

**GitHub alias:** < https://github.com/ozSoprin >

**Organization:** < Microsoft >

**Contact info:** < Twitter: ozSoprin >