# AddedCredentialFromContryXAndSigninFromCountryY
Added credential from country X and Signed-In from country Y in a pecific time window:
This query tries to find all applications that credentials were added to them from country X while the application's identity Signed-In from country Y in a specific time window. 

## Query
```
let timewindow = 1d;
let addedApps = (
CloudAppEvents
| where Application == "Office 365"
| where ActionType in ("Add service principal credentials.", "Update application – Certificates and secrets management ")
| project AddedTimestamp = Timestamp , AppName = tostring(RawEventData.Target[3].ID), CountryCode );
AADSpnSignInEventsBeta
| join addedApps on $left.ServicePrincipalName == $right.AppName
| where CountryCode != Country and AddedTimestamp + timewindow > Timestamp

```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |   |  |
| Execution |  |  |
| Persistence | V |  | 
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
**Organization:** Microsoft 365 Defender
