# OAuth Apps reading mail both via GraphAPI and directly [Nobelium]

As described in (previous guidance)[https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/], Nobelium may re-purpose legitimate existing OAuth Applications in the environment to their own ends. However, malicious activity patterns may be discernable from  legitimate ones.

The following query returns OAuth Applications that access mail both directly and via Graph, allowing review of whether such dual access methods follow expected use patterns.

## Query

```kusto
// Look for OAuth Apps reading mail both via GraphAPI, and directly (not via GraphAPI) 
// (one method may be legitimate and one suspect?) 
let appsReadingMailDirectly = CloudAppEvents 
| where Timestamp >= ago(1h) 
| where ActionType == "MailItemsAccessed" 
| where RawEventData has "AppId" 
| extend rawData = parse_json(RawEventData) 
| extend AppId = tostring(parse_json(rawData.AppId)) 
| where AppId != "00000003-0000-0000-c000-000000000000" 
| summarize by AppId 
| project-rename OAuthAppId = AppId; 
let appsReadingMailViaGraphAPI = CloudAppEvents 
| where Timestamp >= ago(1h) 
| where ActionType == "MailItemsAccessed" 
| where RawEventData has "ClientAppId" 
| where RawEventData has "00000003-0000-0000-c000-000000000000" // performance check 
| extend rawData = parse_json(RawEventData) 
| extend AppId = tostring(parse_json(rawData.AppId)) 
| extend OAuthAppId = tostring(parse_json(rawData.ClientAppId)) // extract OAuthAppId 
| where AppId == "00000003-0000-0000-c000-000000000000" 
| summarize by OAuthAppId; 
// Applications reading mail both directly and via GraphAPI  
// (one method may be legitimate and one suspect?) 
appsReadingMailDirectly 
| join kind = inner appsReadingMailViaGraphAPI 
on OAuthAppId 
| project OAuthAppId 
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration | V |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
