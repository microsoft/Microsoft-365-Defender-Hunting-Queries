# Azure AD Role Management Permission Grant

Identifies when the Microsoft Graph RoleManagement.ReadWrite.Directory (Delegated or Application) permission is granted to a service principal. This permission allows an application to read and manage the role-based access control (RBAC) settings for your company's directory. An adversary could use this permission to add an Azure AD object to an Admin directory role.
* https://docs.microsoft.com/en-us/graph/permissions-reference#role-management-permissions
* https://docs.microsoft.com/en-us/graph/api/directoryrole-post-members?view=graph-rest-1.0&tabs=http'

## Query

```kusto
let queryTime = 3d;
CloudAppEvents
| where Timestamp > ago(queryTime)
| where Application == "Office 365"
| where ActionType has_any ("Add delegated permission grant.","Add app role assignment to service principal.")
| extend RawEventData = parse_json(RawEventData)
| where RawEventData.ResultStatus =~ "success"
| extend UserAgent = parse_json(replace('-','',tostring(RawEventData.ExtendedPRoperties[0].Value))).UserAgent
| mv-expand RawEventData.ModifiedProperties
| extend PropertyName_ = tostring(RawEventData_ModifiedProperties.Name)
| extend PropertyNewValue_ = tostring(RawEventData_ModifiedProperties.NewValue)
| where PropertyName_ has_any ("AppRole.Value","DelegatedPermissionGrant.Scope")
| where PropertyNewValue_ contains "RoleManagement.ReadWrite.Directory"
| extend Initiator = AccountDisplayName, InitiatorId = AccountId,
  Target = tostring(RawEventData.ModifiedProperties[4].NewValue),
  TargetId = iif(PropertyName_ =~ 'DelegatedPermissionGrant.Scope',
    tostring(RawEventData.ModifiedProperties[2].NewValue),
    tostring(RawEventData.ModifiedProperties[3].NewValue))
| project Timestamp, Initiator, InitiatorId, Target, TargetId, ActionType
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
