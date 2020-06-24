# Detect multiple sensitive LDAP queries

Detect multiple sensitive Active Directory LDAP queries made in bin time

Sensitive queries defined as Roasting or sensitive objects queries

Replace 10 on line 6 with your desired thershold

Replace 1m on line 7 with your desired bin time

This LDAP query cover Rubeus, Kerberoast, BloodHound tools

## Query

```
let SensitiveObjects = "[\"Administrators\", \"Domain Controllers\", \"Domain Admins\", \"Account Operators\", \"Backup Operators\", \"DnsAdmin\", \"Enterprise Admins\", \"Group Policy Creator Owners\"]";
let ASREP_ROASTING = "userAccountControl:1.2.840.113556.1.4.803:=4194304";
let ASREP_ROASTING1 = "userAccountControl|4194304";
let ASREP_ROASTING2 = "userAccountControl&4194304";
let KERBEROASTING = "serviceprincipalname=*";
let Thershold = 10;
let BinTime = 1m;
let SensitiveQueries = (
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where SensitiveObjects contains QueryTarget or SearchFilter contains "admincount=1");
let Roasting = (
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where SearchFilter contains ASREP_ROASTING or
SearchFilter contains ASREP_ROASTING1 or
SearchFilter contains ASREP_ROASTING2 or
SearchFilter contains KERBEROASTING);
union SensitiveQueries, Roasting
| summarize NumberOfLdapQueries = count(), NumberOfDistinctLdapQueries = dcount(SearchFilter) by DeviceName, bin(Timestamp, BinTime)
| where NumberOfDistinctLdapQueries > Thershold 

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
