# Detect multiple LDAP queries

Detect multiple Active Directory LDAP queries made in bin time

Replace 10 on line 1 with your desired thershold

Replace 1m on line 2 with your desired bin time

## Query

```
let Thershold = 10;
let BinTime = 1m;
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
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
