# Detect LDAP queries that search for computer operating system

Detect Active Directory LDAP queries that try to find operating systems that are vulnerable to specific vulnerabilities

This LDAP query cover MetaSploit - enum_ad_computers tool

## Query

```
let ComputerObject = "objectCategory=computer";
let ComputerClass = "objectClass=computer";
let SamAccountComputer = "sAMAccountType=805306369";
let OperatingSystem = "operatingSystem=";
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where (SearchFilter contains ComputerObject or SearchFilter contains ComputerClass or SearchFilter contains SamAccountComputer) and
 SearchFilter contains OperatingSystem

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
