# Detect Snip3 loader-encoded PowerShell command

Snip3 is a family of related remote access trojans. Although the malware in this family contain numerous small variations, they all exhibit similar behaviors and techniques.

The following query looks for the method that Snip3 malware use to obfuscate PowerShell commands with UTF8 encoding. This technique is intended to evade detection from security products, and avoids the more standard switches used for encoding in malware such as Emotet.

At present, this method of encoding is much more rare, being seen largely with loader installation of RevengeRAT, AsyncRAT and other RATs used in campaigns targeting the aviation industry.

## Query

```kusto
DeviceFileEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_all ("IEX","Text.Encoding","UTF8.GetString(@")
| where InitiatingProcessCommandLine has_any ("Unrestricted","Hidden")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
