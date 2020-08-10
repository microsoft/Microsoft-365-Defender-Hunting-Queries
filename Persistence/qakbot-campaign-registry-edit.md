# Registry edits by campaigns using Qakbot malware

This query was originally published in the threat analytics report, *Qakbot blight lingers, seeds ransomware*

[Qakbot](https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/) is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under [See also](#See-also).

The following query detects registry entries that may indicate that an operator is trying to establish persistence for the Qakbot binary.

## Query

```Kusto
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "explorer.exe"
| where RegistryValueData has @"AppData\Roaming\Microsoft" and
RegistryValueData has "$windowsupdate"
| where RegistryKey has @"CurrentVersion\Run"
| project RegistryKey, RegistryValueData, DeviceId, Timestamp
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution |  |  |
| Persistence | v |  |
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

## See also

* [Self-deletion by Qakbot malware](..\Defense&#32;evasion\qakbot-campaign-self-deletion.md)
* [Process injection by Qakbot malware](..\Defense&#32;evasion\qakbot-campaign-process-injection.md)
* [Browser cookie theft by campaigns using Qakbot malware](..\Discovery\qakbot-campaign-esentutl.md)
* [Outlook email access by campaigns using Qakbot malware](..\Discovery\qakbot-campaign-outlook.md)
* [Javascript use by Qakbot malware](..\Execution\qakbot-campaign-suspicious-javascript.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
