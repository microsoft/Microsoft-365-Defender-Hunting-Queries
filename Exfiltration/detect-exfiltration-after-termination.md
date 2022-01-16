# Detect Exfiltration after Termination

This query can be used to explore any instances where a terminated individual (i.e. one who has an impending termination date but has not left the company) downloads a large number of files from a non-Domain network address.

## Query

```
// Look for any activity for terminated employee creating a DeviceNetworkEvents after they announced termination or resignation
let TermAccount = 'departing.employee'; //Enter the departing employee's username
let ReleaseTime = datetime("01/16/2022 00:00:00"); //Enter the date the resignation or termination was announced
DeviceNetworkEvents
| where InitiatingProcessAccountName =~ TermAccount
| where Timestamp  > ReleaseTime
//| project Timestamp , DeviceName, InitiatingProcessAccountName
| sort by Timestamp  desc
| join 
DeviceFileEvents on InitiatingProcessAccountName
| where FileName endswith ".docx" or FileName endswith ".pptx" or FileName endswith ".xlsx" or FileName endswith ".pdf"
| join DeviceNetworkInfo on DeviceId
| where ConnectedNetworks !contains '"Category":"Domain"'  //Looking for remote, non-domain networks
| summarize TotalFiles=count() by bin(5Minutebin=Timestamp, 5m), InitiatingProcessAccountName
|where TotalFiles >1000 // adjust accordingly
| project TotalFiles,5Minutebin,InitiatingProcessAccountName
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

**Contributor:** SEI National Insider Threat Center

**GitHub alias:** sei-nitc

**Organization:** Carnegie Mellon University Software Engineering Institute

**Contact info:** insider-threat-feedback@cert.org

&copy; Carnegie Mellon University, 2020. All rights reserved
