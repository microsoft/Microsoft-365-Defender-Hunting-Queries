# Detect network connection events on a device impacted by the Dudear campaign

This query was originally published in the threat analytics report, *The expansion of Dudear (TA505)*.

The [Dudear](https://www.msn.com/en/news/technology/microsoft-detects-new-evil-corp-malware-attacks/ar-BBZxkRs) campaign spreads commodity malware for profit. Other security researchers have given the name *TA505* to a group performing similar or related malicious activity.

The Dudear campaign targets financial services or healthcare. They involve several kinds of malware implants, including a family of trojan droppers also known as [Dudear](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanDropper:O97M/Dudear.A!dha&threatId=-2147217587). Dudear campaign operators often use Remote Access Trojans (RATs) for command-and-control, lateral movement, and credential dumping.

The following query finds network connection events on a device that has connected to a Dudear IP address. To find these devices, see [Detect devices connected to Dudear campaign IPs](dudear.ip.md).

## Query

```Kusto
// All network connection spawned by malicious actions on impacted machine
DeviceNetworkEvents 
| where InitiatingProcessFileName in ("rundll32.exe", "winless.exe", "reduce1.exe", "64.exe", "excel.exe", "wsus.exe")
| where Timestamp >= datetime(2019-12-06)
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access | v |  |
| Discovery |  |  |
| Lateral movement | v |  |
| Collection | v |  |
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
