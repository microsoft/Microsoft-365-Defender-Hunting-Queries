# Security Token Service (STS) refresh token modifications
This will show Active Directory Security Token Service (STS) refresh token modifications by Service Principals and Applications other than DirectorySync. Refresh tokens are used to validate identification and obtain access tokens. This event is most often generated when legitimate administrators troubleshoot frequent AAD user sign-ins but may also be generated as a result of malicious token extensions. Confirm that the activity is related to an administrator legitimately modifying STS refresh tokens and check the new token validation time period for high values.

Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/StsRefreshTokenModification.yaml
## Query
```
CloudAppEvents 
| where ActionType == "Update StsRefreshTokenValidFrom Timestamp."
| where RawEventData !has "Directorysync"
| extend displayName = RawEventData.ModifiedProperties[0].Name  
| where displayName == "StsRefreshTokensValidFrom"
| extend oldValue = RawEventData.ModifiedProperties[0].OldValue
| extend newValue = RawEventData.ModifiedProperties[0].NewValue
| extend oldStsRefreshValidFrom = todatetime(parse_json(tostring(oldValue))[0])
| extend newStsRefreshValidFrom = todatetime(parse_json(tostring(newValue))[0])
| extend tokenMinutesAdded = datetime_diff('minute',newStsRefreshValidFrom,oldStsRefreshValidFrom)
| extend tokenMinutesRemaining = datetime_diff('minute',Timestamp,newStsRefreshValidFrom)
| extend Role = parse_json(RawEventData.Actor[-1]).ID
| distinct AccountObjectId, AccountDisplayName, tostring(Role), IPAddress, IsAnonymousProxy, ISP, tokenMinutesAdded, tokenMinutesRemaining
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
**Contributor:** Stefan Sellmer
**GitHub alias:** @stesell
**Organization:** Microsoft 365 Defender
**Contact info:** stesell@microsoft.com