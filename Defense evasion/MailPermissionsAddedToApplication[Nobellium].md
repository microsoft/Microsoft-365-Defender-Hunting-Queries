# Mail.Read or Mail.ReadWrite permissions added to OAuth application
This query will find applications that have been granted Mail.Read or Mail.ReadWrite permissions in which the corresponding user recently consented to. It can help identify applications that have been abused to gain access to user email.

Solorigate - The actor was observed modifying existing tenant application permissions to allow them to read user email through the Microsoft Graph API. https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/

Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MailPermissionsAddedToApplication.yaml
## Query
```
let auditLookback = 1d;
CloudAppEvents
| where Timestamp > ago(auditLookback)
| where ActionType == "Add delegated permission grant."
| extend RawEventData = parse_json(RawEventData)
| where RawEventData.ResultStatus =~ "success"
| extend UserId = tostring(RawEventData.UserId)
| extend UserAgent = parse_json(replace('-','',tostring(RawEventData.ExtendedPRoperties[0].Value))).UserAgent
| extend properties = RawEventData.ModifiedProperties
| mvexpand properties
| extend Permissions = properties.NewValue
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite")
| extend PermissionsAddedTo = tostring(RawEventData.Target[3].ID) // Get target of permissions
| project-away properties, RawEventData
| join kind=leftouter (CloudAppEvents
    | where Timestamp > ago(auditLookback)
    | where ActionType == "Consent to application."
    | where isnotempty(AccountDisplayName)
    | extend RawEventData = parse_json(RawEventData)
    | extend UserId = tostring(RawEventData.UserId)
    | extend targetInfo = RawEventData.Target
    | extend AppName = tostring(targetInfo[3].ID) // Find app name
    | extend AppId = tostring(targetInfo[4].ID) // Find appId
    | project ConsentTimestamp=Timestamp, UserId, AccountDisplayName, AppName, AppId
) on UserId
| extend ConsentTimestamp = todatetime(format_datetime(ConsentTimestamp, 'MM/dd/yyyy HH:mm')) // Ensure app consent happend close to the same time as the permissions were granted
| extend PermsTimestamp = todatetime(format_datetime(Timestamp, 'MM/dd/yyyy HH:mm'))
| where PermsTimestamp -2m <= ConsentTimestamp // ensure consent happened near permissions grant
| where PermsTimestamp +2m >= ConsentTimestamp
| project Timestamp, ActionType, InitiatingUser=AccountDisplayName, UserId, InitiatingIP=IPAddress, UserAgent, PermissionsAddedTo, AppName, AppId
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion | V |  | 
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
**Contributor:** Blake Strom
**GitHub alias:** @bstrom
**Organization:** Microsoft 365 Defender
**Contact info:** blstrom@microsoft.com