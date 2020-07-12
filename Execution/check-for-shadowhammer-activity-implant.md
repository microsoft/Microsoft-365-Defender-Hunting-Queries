# Check for ShadowHammer-related implant or container activity

This query was originally published in the threat analytics report, *ShadowHammer supply chain attack*

[Operation ShadowHammer](https://www.vice.com/en_us/article/pan9wn/hackers-hijacked-asus-software-updates-to-install-backdoors-on-thousands-of-computers) was an attack against ASUS computer hardware, using the company's own update infrastructure to deliver malware to the company's products. The campaign ran from June to November, 2018. ASUS has since [responded](https://www.asus.com/News/hqfgVUyZ6uyAyJe1) with updates that protect their Live Update system, and diagnostic tools to check affected systems.

The following query checks for activity associated with the ShadowHammer implant or container over the past 30 days.

## Query

```
​// Event types that may be associated with the implant or container
union DeviceProcessEvents , DeviceNetworkEvents , DeviceFileEvents , DeviceImageLoadEvents 
| where Timestamp > ago(30d)
// File SHAs for implant and container
| where InitiatingProcessSHA1 in("e01c1047001206c52c87b8197d772db2a1d3b7b4",
"e005c58331eb7db04782fdf9089111979ce1406f", "69c08086c164e58a6d0398b0ffdcb957930b4cf2")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v |  |
| Persistence | v |  |
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

**Contributor:** Microsoft Threat Protection team
