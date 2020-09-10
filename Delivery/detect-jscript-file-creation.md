# Detect .jse file creation events

This query was originally published in the threat analytics report, *Emulation-evading JavaScripts*.

Attackers in several ransomware campaigns have employed heavily obfuscated JavaScript code, in order to implant malware or execute malicious commands. The obfuscation is intended to help the code evade security systems and potentially escape sandbox environments.

The following query detects the creation of files with a *.jse* extension. Certain ransomware campaigns, such as [Emotet](https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/), are known to employ encrypted JavaScript code that is saved to the target as *.jse* files.

See [Detect potentially malicious .jse launch by File Explorer or Word](../Execution/jse-launched-by-word.md) for a similar technique.

## Query

```Kusto
​// Creation of any .jse file, including legitimate and malicious ones 
DeviceFileEvents 
| where Timestamp > ago(7d)
| where FileName endswith ".jse"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
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
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
