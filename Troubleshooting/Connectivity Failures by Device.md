# Connectivity Failures by Device

This query checks for network connection failures to Microsoft Defender for Endpoint URLs.
The output includes any device with 1+ connectivity failures, a list of the domains they
failed to connect to (including the number of failures), as well as the overall number of
failures in the time period. Results are sorted by the total number of connection failures
by the device.

## Query

```
let TargetURLs = dynamic(['winatp-gw-cus.microsoft.com', 'winatp-gw-eus.microsoft.com', 'winatp-gw-weu.microsoft.com',
    'winatp-gw-neu.microsoft.com', 'winatp-gw-uks.microsoft.com', 'winatp-gw-ukw.microsoft.com', 'winatp-gw-usgv.microsoft.com',
    'winatp-gw-usgt.microsoft.com', 'eu.vortex-win.data.microsoft.com', 'us.vortex-win.data.microsoft.com',
    'uk.vortex-win.data.microsoft.com', 'events.data.microsoft.com', 'settings-win.data.microsoft.com', 'eu-v20.events.data.microsoft.com',
    'uk-v20.events.data.microsoft.com', 'us-v20.events.data.microsoft.com', 'us4-v20.events.data.microsoft.com',
    'us5-v20.events.data.microsoft.com', 'ctldl.windowsupdate.com']);
DeviceNetworkEvents
| where isnotempty(RemoteUrl) and ActionType == 'ConnectionFailed'
| extend Domain = case(RemoteUrl contains "//", parse_url(RemoteUrl).Host, RemoteUrl)
| where Domain in(TargetURLs)
| summarize arg_max(Timestamp, DeviceName), ConnectionFailures = count() by DeviceId, Domain
| extend DomainDetails = pack(Domain, ConnectionFailures)
| summarize DomainDetails = make_list(DomainDetails), LastConnectionFailure = any(Timestamp), DeviceName = any(DeviceName), TotalConnectionFailures = sum(ConnectionFailures) by DeviceId
| order by TotalConnectionFailures desc
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
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration | v |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** Michael Melone, with special thanks to Jesse Esquivel

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
