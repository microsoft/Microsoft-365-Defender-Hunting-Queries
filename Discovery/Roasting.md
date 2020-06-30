# Detect LDAP queries that search for accounts vulnerable for roasting attacks

Detect Active Directory LDAP queries that search for Kerberoasting (SPNs) or accounts with Kerberos preauthentication not required from Azure ATP, and try to get the process initiated the LDAP query from MDATP.

Replace 389 on line 5 with LDAP port in your environment

Replace true on line 6 to false if you want to include Nt Authority process

This LDAP query cover Rubeus, Kerberoast, BloodHound tools

## Query

```
let ASREP_ROASTING = "userAccountControl:1.2.840.113556.1.4.803:=4194304";
let ASREP_ROASTING1 = "userAccountControl|4194304";
let ASREP_ROASTING2 = "userAccountControl&4194304";
let KERBEROASTING = "serviceprincipalname=*";
let LDAP_PORT = 389;
let ExcludeNtAuthorityProcess = true;
let AzureAtpLdap = (
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where SearchFilter contains ASREP_ROASTING or
SearchFilter contains ASREP_ROASTING1 or
SearchFilter contains ASREP_ROASTING2 or
SearchFilter contains KERBEROASTING
| extend Time = bin(Timestamp, 1s)
| extend DeviceNameWithoutDomain = tolower(tostring(split(DeviceName, '.')[0])));
let MDAtpNetworkToProcess = (
DeviceNetworkEvents
| extend DeviceNameWithoutDomain = tolower(tostring(split(DeviceName, '.')[0]))
| where RemotePort == LDAP_PORT
| extend Time = bin(Timestamp, 1s)
| extend isExclude = iff( ExcludeNtAuthorityProcess and InitiatingProcessAccountDomain == "nt authority" , true, false));
AzureAtpLdap
| join kind=leftouter (
MDAtpNetworkToProcess ) on DeviceNameWithoutDomain, Time 
| where isExclude == false or isnull(isExclude)

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
