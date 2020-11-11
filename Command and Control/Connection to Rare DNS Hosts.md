# Connection to Rare DNS Hosts

This query will break down hostnames into their second and third level domain parts and analyze the volume of connections made to the destination to look for low count entries. Note that this query is likely to be rather noisy in many organziations and may benefit from analysis over time, anomaly detection, or perhaps machine learning.

## Query
```
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty( RemoteUrl) and RemoteUrl contains "."
| extend RemoteDomain = iff(RemoteUrl matches regex @'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', tolower(RemoteUrl), tostring(parse_url(RemoteUrl).Host))
| extend DomainArray = split(RemoteDomain, '.')
| extend SecondLevelDomain = strcat(tostring(DomainArray[-2]),'.', tostring(DomainArray[-1])), ThirdLevelDomain = strcat(tostring(DomainArray[-3]), '.', tostring(DomainArray[-2]),'.', tostring(DomainArray[-1]))
| summarize ConnectionCount = count(), DistinctDevices = dcount(DeviceId) by SecondLevelDomain, ThirdLevelDomain, RemoteDomain
| top 10000 by DistinctDevices asc
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
| Command and control | v |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
