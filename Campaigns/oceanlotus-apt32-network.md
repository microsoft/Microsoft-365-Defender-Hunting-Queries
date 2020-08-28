# Detect malicious network activity associated with group known as "OceanLotus"

This query was originally published in a threat analytics report about the group known to other security researchers as *APT32* or *OceanLotus*

This tracked activity group uses a wide array of malicious documents to conduct attacks. Some of their favored techniques include sideloading dynamic link libraries,  and disguising payloads as image files.

The following query detects network activity that may indicate an attack by this group.

See [Detect malicious documents associated with group known as "OceanLotus"](oceanlotus-apt32-files.md) for another query related to this group's activity.

## Query

```Kusto
//Network activities 
DeviceNetworkEvents 
| where Timestamp > ago(30d) 
| where RemoteUrl in ( 
//'Malicious URL Indicators for OceanLotus Activities 2019', 
'open.betaoffice.net', 
'outlook.updateoffices.net', 
'load.newappssystems.com', 
'syn.servebbs.com', 
//'C2 Indicators for OceanLotus Activities 2019', 
'cortanazone.com', 
'cortanasyn.com', 
'ristineho.com', 
'syn.servebbs.com') 
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
| Credential Access |  |  |
| Discovery | v |  |
| Lateral movement | v |  |
| Collection |  |  |
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
