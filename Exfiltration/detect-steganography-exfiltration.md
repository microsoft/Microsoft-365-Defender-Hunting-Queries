# Detect Steganography Exfiltration

This query can be used to detect instances of malicious users who attempt to create steganographic images and then immediately browse to a webmail URL.  This query would require additional investigation to determine whether the co-occurrance of generating a steganographic image and browsing to a webmail URL is an indication of a malicious event.

## Query

```
let stegProcesses= view() {
let stegnames = pack_array ("camouflage","crypture", "hidensend", "openpuff","picsel","slienteye","steg","xiao");
let ProcessQuery = view()
{
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (stegnames)
};
let FileQuery = view(){
DeviceFileEvents
| where FileName has_any (stegnames)
};
union ProcessQuery, FileQuery
| project StegProcessTimestamp=Timestamp, DeviceName, InitiatingProcessAccountName, FileName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine};
let WebMailUsage=view(){
// This query finds network communication to specific webmail URL
let webmailURLs = pack_array ("mail.google.com", "mail.yahoo.com", "mail.protonmail.com"); // Change or append additional webmail URLs
DeviceNetworkEvents 
| where Timestamp > ago(30d)
and RemoteUrl contains webmailURLs};
WebMailUsage
| join stegProcesses on DeviceName
| where (Timestamp - StegProcessTimestamp) between (0min..30min)
|project StegProcessTimestamp,Timestamp,RemoteUrl,DeviceName,InitiatingProcessAccountName,FileName
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