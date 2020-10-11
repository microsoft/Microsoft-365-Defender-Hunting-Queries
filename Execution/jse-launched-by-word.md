# Detect potentially malicious .jse launch by File Explorer or Word

This query was originally published in the threat analytics report, *Emulation-evading JavaScripts*.

Attackers in several ransomware campaigns have employed heavily obfuscated JavaScript code, in order to implant malware or execute malicious commands. The obfuscation is intended to help the code evade security systems and potentially escape sandbox environments.

The following query detects when Word or File Explorer have launched files with a *.jse* extension. Attackers involved in various [human-operated campaigns](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/) have been known to embed a heavily obfuscated JavaScript file in malicious Word docs. The loader is used to download and install the banking trojan, Trickbot.

See [Detect .jse file creation events](../Delivery/detect-jscript-file-creation.md) for a similar technique.

## Query

```Kusto
// Find potentially malicious .jse launch by File Explorer or Word 
DeviceProcessEvents 
| where Timestamp > ago(7d) 
| where InitiatingProcessFileName in~ ("explorer.exe","winword.exe") 
and FileName =~ "wscript.exe"
and ProcessCommandLine contains ".jse"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access | v |  |
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
