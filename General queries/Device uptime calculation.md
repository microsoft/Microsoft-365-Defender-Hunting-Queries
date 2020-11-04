# Device uptime calculation  
This query calculates device uptime based on periodic DeviceInfo which is recorded every 15 minutes regardless of device’s network connectivity and uploaded once device gets online. If its interval is over 15 minutes, we can consider device is tuned off.　Calculated uptime may include up to 30 minutes gap. Devices may be tuned on up to 15 minutes earlier than the “timestamp”, and may be turned off up to 15 minutes later than the “Lasttimestamp”.  

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
## Sample output  
Table.
| table | tabel|
| a | b |

| Timestamp | LastTimeStamp | DurationAtLeast | DeviceName | DomainName | UserName |
| 2020-10-29T14:04:11.8370236Z | 2020-10-29T15:49:11.8373325Z | 00.01:45:00 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 2020-10-29T07:57:47.1895022Z | 2020-10-29T08:42:47.1966788Z | 00.00:45:00 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 2020-10-28T12:57:07.6546625Z | 2020-10-28T16:27:06.5093301Z | 00.03:29:58 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 2020-10-28T12:11:03.4177443Z | 2020-10-28T12:41:03.4202037Z | 00.00:30:00 | desktop-pc1 | DESKTOP-PC1 | localuser1 |
| 2020-11-02T05:05:28.8783299Z | 2020-11-02T07:00:13.985568Z | 00.01:54:45 | desktop-pc1 | AzureAD | User01 |

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
| Command and control |  |  | 
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
