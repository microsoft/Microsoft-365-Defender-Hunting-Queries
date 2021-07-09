# BazaCall Excel file download domain pattern

BazaCall is a campaign that manipulate users into calling a customer support center, where they are instructed to download an Excel file to unsubscribe from a phony service. When the user opens the Excel file, they are prompted to enable a malicious macro that infects their device with BazaLoader.

This query surfaces connections to the distinctive *.xyz* domains that the BazaCall campaign uses to host malicious Excel files.

## Query

```kusto
DeviceNetworkEvents
| where RemoteUrl matches regex @".{14}\.xyz/config\.php"
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
