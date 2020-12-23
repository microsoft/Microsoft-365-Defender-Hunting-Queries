# ServicePrincipalAddedToRole [Solorigate]

One of the IOC's in the attack was that unexpected service principals have been added to privileged roles. 
This query is looking for service principals that have been added to any role. 

https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610

## Query
```
let queryTime = 1d;
CloudAppEvents
| where Timestamp > ago(queryTime)
| where Application == "Office 365"
| where ActionType == "Add member to role."
| extend EntityType = RawEventData.Target[2].ID, RoleName = RawEventData.ModifiedProperties[1].NewValue, RoleId = RawEventData.ModifiedProperties[2].NewValue
| where EntityType == "ServicePrincipal"
| project Timestamp , ActionType, ServicePrincipalName = RawEventData.Target[3].ID, ServicePrincipalId = RawEventData.Target[1].ID, RoleName, RoleId, ActorId = AccountObjectId , ActorDisplayName = AccountDisplayName 
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation | V |  |
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
**Contributor:** Dor Edry
**GitHub alias:** doredry
**Organization:** Microsoft 365 Defender
**Contact info:** dor.edry@microsoft.com
