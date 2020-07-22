# Detect suspicious RDP activity related to BlueKeep

This query was originally published in the threat analytics report, *Exploitation of CVE-2019-0708 (BlueKeep)*.

[CVE-2019-0708](https://nvd.nist.gov/vuln/detail/CVE-2019-0708), also known as BlueKeep, is a critical remote code execution vulnerability involving RDP. Soon after its disclosure, the NSA issued a rare [advisory](https://www.nsa.gov/News-Features/News-Stories/Article-View/Article/1865726/nsa-cybersecurity-advisory-patch-remote-desktop-services-on-legacy-versions-of/) about this vulnerability, out of concern that it could be used to quickly spread malware. Attackers have since used this vulnerability to [install cryptocurrency miners](https://www.wired.com/story/bluekeep-hacking-cryptocurrency-mining/) on targets.

Microsoft has issued [updates](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708) for this vulnerability, as well as [guidance](https://support.microsoft.com/en-us/help/4500705/customer-guidance-for-cve-2019-0708) for protecting operating systems that we no longer support. Microsoft Defender ATP also contains [behavioral detections](https://www.microsoft.com/security/blog/2019/11/07/the-new-cve-2019-0708-rdp-exploit-attacks-explained/) for defending against this threat.

The following query locates Windows 7 or Windows Server 2008 machines initiating outbound connections to internal or public IP addresses on TCP port 3389. It filters out common RDP programs and scanning tools and shows the number of connections per machine. It can identify machines with relatively intense outbound network activity on the common RDP port (TCP/3389). You can use it to find processes that might be scanning for possible targets or exhibiting worm-like behavior.

## Query

```Kusto
// Find unusual processes on Windows 7 or Windows Server 2008 machines with
// outbound connections to TCP port 3389
let listMachines = DeviceInfo
| where OSVersion == "6.1" //Win7 and Srv2008
| distinct DeviceId;
DeviceNetworkEvents
| where RemotePort == 3389
| where Protocol == "Tcp" and ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~  //filter some legit programs
("mstsc.exe","RTSApp.exe", "RTS2App.exe","RDCMan.exe","ws_TunnelService.exe","RSSensor.exe"
"RemoteDesktopManagerFree.exe","RemoteDesktopManager.exe","RemoteDesktopManager64.exe",
"mRemoteNG.exe","mRemote.exe","Terminals.exe","spiceworks-finder.exe",
"FSDiscovery.exe","FSAssessment.exe")
| join listMachines on DeviceId
| project Timestamp, DeviceId, DeviceName, RemoteIP, InitiatingProcessFileName, 
InitiatingProcessFolderPath, InitiatingProcessSHA1
| summarize conn=count() by DeviceId, InitiatingProcessFileName, bin(Timestamp, 1d)
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery | v |  |
| Lateral movement | v |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Detect BlueKeep-related mining](../Execution/detect-bluekeep-related-mining.md)
* [Detect command-and-control communication related to BlueKeep cryptomining](../Command%20and%20Control/c2-bluekeep.md)
* [Detect BlueKeep exploitation attempts](../Initial%20access/detect-bluekeep-exploitation-attempts.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
