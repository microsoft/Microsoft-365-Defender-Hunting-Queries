# Connectivity Failures by Domain

This query is designed to help troubleshoot connectivity issues to Microsoft Defender for Endpoint URLs. 
It provides a summary of the number of failures which occurred, the number of distinct machines that failed
to connect to the URL, and sorts them by the sum of the overall number of failures recorded.

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
| summarize (LastConnectionFailure, DeviceName) = arg_max(Timestamp, DeviceName), ConnectionFailures = count(), DistinctMachines = dcount(DeviceId) by Domain
| order by DistinctMachines desc
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
| Misconfiguration |  |  |
| Malware, component | v |  |


## Contributor info

**Contributor:** Michael Melone, with special thanks to Jessie Esquivel

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
