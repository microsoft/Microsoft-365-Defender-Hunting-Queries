# Detect Tor Relay Connectivity
This advanced hunting query detects processes communicating with known Tor relay IP addresses.
The public URL in the query is updated daily at 12PM and 12AM UTC.
CSV source is the Tor Project API, obtained with: https://github.com/Dylan-J/Tor-Project-Statistics
## Query
```
let TorRelayData = (
    externaldata (Nickname:string,Fingerprint:string,EntryAddress:string,IPv4Address:string,IPv4Port:string,IPv6Address:string,AddressType:string,Hostname:string,CountryCode:string,IsRunning:bool,RelayPublishDate:string,LastChangedIPData:string)
    [h@'https://msde.blob.core.windows.net/public/TorRelayIPs.csv'] with (ignoreFirstRecord=true,format="csv")
    | where AddressType == "IPv4"
);
TorRelayData
| join kind=inner DeviceNetworkEvents on $left.IPv4Address == $right.RemoteIP
| join kind=inner (DeviceInfo | distinct DeviceId, PublicIP) on DeviceId
| project Timestamp, DeviceId, LocalPublicIP = PublicIP, LocalIP, RemoteIP, TorIP = IPv4Address, Hostname, CountryCode, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath
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
| Discovery | V |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control | V |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
**Contributor:** Dylan Jones
**GitHub alias:** Dylan-J
**Organization:** Microsoft
**Contact info:** Twitter - @dylface2
