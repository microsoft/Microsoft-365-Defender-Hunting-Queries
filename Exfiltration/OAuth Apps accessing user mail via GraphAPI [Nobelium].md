# OAuth Apps accessing user mail via GraphAPI [Nobelium]

This query helps you review all OAuth Applications accessing user mail via Graph. It could return a significant number of results depending on how many applications are deployed in the environment.

## Query

```kusto
CloudAppEvents 
| where Timestamp >= ago(1h) 
| where ActionType == "MailItemsAccessed" 
| where RawEventData has "00000003-0000-0000-c000-000000000000" // performance 
| where RawEventData has "ClientAppId" 
| extend rawData = parse_json(RawEventData) 
| extend AppId = tostring(parse_json(rawData.AppId)) 
| where AppId == "00000003-0000-0000-c000-000000000000"         // graph API 
| extend OAuthAppId = tostring(parse_json(rawData.ClientAppId)) // extract OAuthAppId 
| summarize by OAuthAppId 
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence | |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration | V |  |
| Impact | |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component | |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
