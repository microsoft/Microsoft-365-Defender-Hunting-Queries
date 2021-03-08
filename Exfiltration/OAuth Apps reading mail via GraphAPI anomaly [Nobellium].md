# OAuth Apps reading mail via GraphAPI anomaly [Solorigate]
Review OAuth Applications whose behaviour changed versus a prior baseline period. 
The following query returns OAuth Applications accessing user mail via Graph that did not do so in the preceding week.

## Query
```
//Look for OAuth App reading mail via GraphAPI -- that did not read mail via graph API in prior week 
let appMailReadActivity = (timeframeStart:datetime, timeframeEnd:datetime) { 
CloudAppEvents 
| where Timestamp between (timeframeStart .. timeframeEnd) 
| where ActionType == "MailItemsAccessed" 
| where RawEventData has "00000003-0000-0000-c000-000000000000" // performance check 
| extend rawData = parse_json(RawEventData) 
| extend AppId = tostring(parse_json(rawData.AppId)) 
| extend OAuthAppId = tostring(parse_json(rawData.ClientAppId)) // extract OAuthAppId 
| summarize by OAuthAppId 
}; 
appMailReadActivity(ago(1d),now())                           // detection period 
| join kind = leftanti appMailReadActivity(ago(7d),ago(2d))  // baseline period 
on OAuthAppId 
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
