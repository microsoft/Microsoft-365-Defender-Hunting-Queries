# Device uptime calculation  
This query calculates device uptime based on periodic DeviceInfo which is recorded every 15 minutes regardless of device’s network connectivity and uploaded once device gets online. If its interval is over 15 minutes, we can consider device is tuned off.　So calculated uptime may include up to 30 minutes discrepancy, devices may be tuned on up to 15 minutes early than the “timestamp”, and may be turned off up to 15 minutes later than the “Lasttimestamp”.　So

## Query
```
DeviceInfo 
| partition by DeviceId
(order by Timestamp desc
| extend NewerTimestamp = prev(Timestamp,1,now(1d))
| extend OlderTimestamp = next(Timestamp,1,0)
| extend StartSignal = Timestamp - OlderTimestamp > 16m
| extend FinalSignal = NewerTimestamp - Timestamp > 16m
| where FinalSignal or StartSignal
| extend ParsedFields=parse_json(LoggedOnUsers)[0]
| extend LastTimeStamp=iff(FinalSignal,Timestamp,prev(Timestamp,1))
| where StartSignal
| extend DurationAtLeast= format_timespan(LastTimeStamp-Timestamp,'dd.hh:mm:ss')
| project Timestamp,LastTimeStamp,DurationAtLeast,DeviceName,DomainName=ParsedFields.DomainName,UserName=ParsedFields.UserName
)
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
| Exfiltration | v |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
Contributor: Yoshihiro Ichinose  
GitHub alias: YoshihiroIchinose  
Organization: Microsoft Japan Co., Ltd.  
Contact info: yoshi@microsoft.com  
