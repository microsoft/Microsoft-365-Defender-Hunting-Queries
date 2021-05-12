# Detect Snip3 associated communication protocols

Snip3 is a family of related remote access trojans. Although the malware in this family contain numerous small variations, they all exhibit similar behaviors and techniques.

The following query looks for network connections using any protocols associated with recent RevengeRAT, AsyncRAT, and other malware campaigns targeting the aviation industry.

This activity is often followed by connections to copy-and-paste sites such as pastebin.com, stikked.ch, academia.edu, and archive.org. Many of these connections will occur on non-standard ports.

## Query

```kusto
DeviceNetworkEvents 
| where RemoteUrl in ("mail.alamdarhardware.com","kexa600200.ddns.net","h0pe1759.ddns.net","n0ahark2021.ddns.net"," kimjoy007.dyndns.org"," kimjoy.ddns.net"," asin8988.ddns.net"," asin8989.ddns.net", "asin8990.ddns.net")
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
| Exfiltration | v |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
