# Remote code execution with CVE-2019-1181 and CVE-2019-1182

This query was originally published in the threat analytics report, *August 2019 RDP update advisory*.

Remote Desktop Services (RDS) allows a host to run remote client sessions. In 2019, two vulnerabilities were discovered in RDS, allowing an unauthenticated user to connect to a target and run code: [CVE-2019-1181](https://nvd.nist.gov/vuln/detail/CVE-2019-1181) and [CVE-2019-1182](https://nvd.nist.gov/vuln/detail/CVE-2019-1182).

These vulnerabilities have since been addressed.

* [Updates and mitigations](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1181) for CVE-2019-1181
* [Updates and mitigations](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1182) for CVE-2019-1182

The following query finds processes that have suspicious connections to port TCP/3389. This port is commonly used by [Remote Desktop Protocol](https://support.microsoft.com/help/186607/understanding-the-remote-desktop-protocol-rdp) (RDP), the protocol RDS uses, to connect host and client. Because this port is frequently used by legitimate software, the query filters out common RDP software and scanning tools. It also returns the name and IP address of the devices that are connected.

## Query

```Kusto
// Find unusual processes with outbound connections to TCP port 3389 
DeviceNetworkEvents 
| where RemotePort == 3389 
| where ActionType == "ConnectionSuccess" and Protocol == "Tcp"
| where InitiatingProcessFileName !in~ //Remove common RDP programs
("mstsc.exe","RTSApp.exe", "RTS2App.exe","RDCMan.exe","ws_TunnelService.exe", 
"RSSensor.exe","RemoteDesktopManagerFree.exe","RemoteDesktopManager.exe", 
"RemoteDesktopManager64.exe","mRemoteNG.exe","mRemote.exe","Terminals.exe", 
"spiceworks-finder.exe","FSDiscovery.exe","FSAssessment.exe", "chrome.exe", 
"microsodeedgecp.exe", "LTSVC.exe", "Hyper-RemoteDesktop.exe", "", 
"RetinaEngine.exe", "Microsoft.Tri.Sensor.exe" ) 
and InitiatingProcessFolderPath  !has "program files" 
and InitiatingProcessFolderPath !has "winsxs" 
and InitiatingProcessFolderPath !contains "windows\\sys"
| where RemoteIP !in("127.0.0.1", "::1")
| summarize DeviceNames = make_set(DeviceName), 
ListofMachines = make_set(DeviceId), 
make_set(Timestamp), 
ConnectionCount = dcount(RemoteIP) by InitiatingProcessFileName, 
InitiatingProcessSHA1, bin(Timestamp, 1d)
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access | v |  |
| Execution | v |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement | v |  |
| Collection | v |  |
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability | v |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team