# Admin promotion after Role Management Application Permission Grant

This rule looks for a service principal being granted the Microsoft Graph RoleManagement.ReadWrite.Directory (application) permission before being used to add an Azure AD object or user account to an Admin directory role (i.e. Global Administrators). 
* https://docs.microsoft.com/en-us/graph/permissions-reference#role-management-permissions
* https://docs.microsoft.com/en-us/graph/api/directoryrole-post-members?view=graph-rest-1.0&tabs=http

## Query

```kusto
let queryTime = 3d;
CloudAppEvents
| where Timestamp > ago(queryTime)
| where Application == "Office 365"
| where ActionType =~ "Add app role assignment to service principal."
| extend RawEventData = parse_json(RawEventData)
| where RawEventData.ResultStatus =~ "success"
| extend UserAgent = parse_json(replace('-','',tostring(RawEventData.ExtendedPRoperties[0].Value))).UserAgent
| mv-expand RawEventData.ModifiedProperties
| extend PropertyName_ = tostring(RawEventData_ModifiedProperties.Name)
| extend PropertyNewValue_ = tostring(RawEventData_ModifiedProperties.NewValue)
| where PropertyName_ =~ "AppRole.Value"
| where PropertyNewValue_ contains "RoleManagement.ReadWrite.Directory"
| extend Initiator = AccountDisplayName, InitiatorId = AccountId,
  Target = tostring(RawEventData.ModifiedProperties[4].NewValue),
  TargetId = tostring(RawEventData.ModifiedProperties[3].NewValue)
| project Timestamp, Initiator, InitiatorId, Target, TargetId
| join (
  CloudAppEvents
  | where Timestamp > ago(queryTime)
  | where Application == "Office 365"
  | where ActionType == "Add member to role."
  | where ObjectType == "Office 365 Admin Role"
  | where ActivityType == "Assignprivilege"
  | where AccountType == "Application"
  | extend Initiator = tostring(RawEventData.Actor[0].ID), InitiatorId = tostring(RawEventData.Actor[3].ID),
    Target = tostring(RawEventData.Target[3].ID), TargetId = tostring(RawEventData.Target[1].ID),
    TargetType = tostring(RawEventData.Target[2].ID), RoleName = ObjectName, RoleId = ObjectId
  | project Timestamp, Initiator, InitiatorId, Target, TargetId, TargetType, RoleName, RoleId
) on $left.TargetId == $right.InitiatorId
| extend TimeRoleMgGrant = Timestamp, TimeAdminPromo = Timestamp1, ServicePrincipal = Initiator1, ServicePrincipalId = InitiatorId1,
  TargetObject = Target1, TargetObjectId = TargetId1, TargetObjectType = TargetType
| where TimeRoleMgGrant < TimeAdminPromo
| project TimeRoleMgGrant, TimeAdminPromo, RoleName, ServicePrincipal, ServicePrincipalId, TargetObject, TargetObjectId, TargetObjectType
| extend timestamp = TimeRoleMgGrant, AccountCustomEntity = TargetObject
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

## See also

## Contributor info

**Contributor:** Roberto Rodriguez
**GitHub alias:** @Cyb3rWard0g
**Organization:** Microsoft Threat Intelligence Center (MSTIC) R&D
