# BazaCall dropping payload via certutil.exe

BazaCall is a campaign that manipulate users into calling a customer support center, where they are instructed to download an Excel file to unsubscribe from a phony service. When the user opens the Excel file, they are prompted to enable a malicious macro that infects their device with BazaLoader.

This query hunts for an attacker-created copy of *certutil.exe*, a legitimate process, which the macro uses to download BazaLoader.

## Query

```kusto
DeviceFileEvents
| where InitiatingProcessFileName !~ "certutil.exe"
| where InitiatingProcessFileName !~ "cmd.exe"
| where InitiatingProcessCommandLine has_all("-urlcache", "split", "http")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
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

**Contributor:**  Microsoft 365 Defender team
