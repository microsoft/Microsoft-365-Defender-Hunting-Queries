# Device uptime calculation  
This query calculates device uptime based on periodic DeviceInfo which is recorded every 15 minutes regardless of device’s network connectivity and uploaded once device gets online. If its interval is over 16 minutes, we can consider device is tuned off.　Calculated uptime may include up to 30 minutes gap. Devices may be tuned on up to 15 minutes earlier than the “timestamp”, and may be turned off up to 15 minutes later than the “LastTimestamp”.  When the sigle independent DeviceInfo without any sequential DeviceInfo within 16 minutes before or after is recorded, “DurationAtLeast” will be displayed as “00.00:00:00”.

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
| extend LastTimestamp=iff(FinalSignal,Timestamp,prev(Timestamp,1))
| where StartSignal
| extend ParsedFields=parse_json(LoggedOnUsers)[0]
| extend DurationAtLeast= format_timespan(LastTimestamp-Timestamp,'dd.hh:mm:ss')
| project Timestamp,LastTimestamp,DurationAtLeast,DeviceName,DomainName=ParsedFields.DomainName,UserName=ParsedFields.UserName
)
```
## Sample output  
| Timestamp | LastTimestamp | DurationAtLeast | DeviceName | DomainName | UserName |
|:---------------:|:---------------:|:-------:|:-------:|:-------:|:-------:|
| 11/4/2020 0:35:08 | 11/4/2020 0:35:08 | 00.00:00:00 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 10/29/2020 14:04:11 | 10/29/2020 15:49:11 | 00.01:45:00 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 10/29/2020 07:57:47 | 10/29/2020 08:42:47 | 00.00:45:00 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 10/28/2020 12:57:07 | 10/28/2020 16:27:06 | 00.03:29:58 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 10/28/2020 12:11:03 | 10/28/2020 12:41:03 | 00.00:30:00 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 11/2/2020 05:05:28 | 11/2/2020 07:00:13 | 00.01:54:45 | vpc1 | AzureAD | User01 |

## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution |  |  |
| Persistence | v |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control | v |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
Contributor: Yoshihiro Ichinose  
GitHub alias: YoshihiroIchinose  
Organization: Microsoft Japan Co., Ltd.  
Contact info: yoshi@microsoft.com  
