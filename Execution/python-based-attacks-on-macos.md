# Python-based attacks on macOS

This query was originally published in the threat analytics report, *Python abuse on macOS*

[Operation ShadowHammer](https://www.vice.com/en_us/article/pan9wn/hackers-hijacked-asus-software-updates-to-install-backdoors-on-thousands-of-computers) was an attack against ASUS computer hardware, using the company's own update infrastructure to deliver malware to the company's products. The campaign ran from June to November, 2018. ASUS has since [responded](https://www.asus.com/News/hqfgVUyZ6uyAyJe1) with updates that protect their Live Update system, and diagnostic tools to check affected systems.

The following query checks for Microsoft Office documents that run Python scripts.

## Query

```Kusto
DeviceProcessEvents
| where InitiatingProcessParentFileName in ("Microsoft Word", "Microsoft Excel")
| where FileName =~ "Python"
| where ProcessCommandLine matches regex "[A-Za-z0-9]{50}"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v |  |
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
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
