# Add uncommon credential type to application [Solorigate] 
The query is looking for users or service principals that attached uncommon credential type to application. 

As part of the attack, the attacker added credential to already exist application and used the application permissions to extract the users mails.

 https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal

## Query
```
CloudAppEvents
| where Application == "Office 365"
| where ActionType in ("Add service principal credentials.", "Update application – Certificates and secrets management ")
| project Timestamp, RawEventData, AccountDisplayName, ActionType, AccountObjectId
| extend ModifiedProperties = parse_json(RawEventData["ModifiedProperties"])
| mvexpand ModifiedProperties
| evaluate bag_unpack(ModifiedProperties)
| where Name has "KeyDescription"
| project Timestamp, AccountDisplayName, ActionType, NewValue, OldValue, RawEventData, AccountObjectId
| where (NewValue has "KeyType=Password" and OldValue !has "KeyType=Password" and OldValue has "AsymmetricX509Cert") or (NewValue has "AsymmetricX509Cert" and OldValue !has "AsymmetricX509Cert" and OldValue has "KeyType=Password")
| extend NewSecret = set_difference(todynamic(parse_json(tostring(NewValue))), todynamic(parse_json(OldValue)))
| project Timestamp,ActionType,ActorType = RawEventData.Actor[-1].ID, ObjectId = RawEventData.Actor[-2].ID, AccountDisplayName, AccountObjectId,  AppnName = RawEventData.Target[3].ID, AppObjectId = RawEventData.Target[1].ID, NewSecret = NewSecret[0], RawEventData 
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
