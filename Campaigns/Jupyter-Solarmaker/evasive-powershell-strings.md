# Evasive PowerShell with uncommon read strings 

This query searches for a string pattern detected in evasive PowerShell usage. Jupyter or SolarMarker will iterate on this pattern multiple times to read data and call additional processes. This query is not fully specific to Jupyter or SolarMarker, and will also return other malicious malware, but is unlikely to return false positives.

## Query
```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_all("-ep bypass","-command","get-content","remove-item","iex")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
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
