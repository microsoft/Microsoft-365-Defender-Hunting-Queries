# Office applications launching wscript.exe to run JScript

This query was originally published in the threat analytics report, *Trickbot: Pervasive & underestimated*.

[Trickbot](https://attack.mitre.org/software/S0266/) is a very prevalent piece of malware with an array of malicious capabilities. Originally designed to steal banking credentials, it has since evolved into a modular trojan that can deploy other malware, disable security software, and perform command-and-control (C2) operations.

Trickbot is frequently spread through email. An attacker will send a target a message with an attachment containing a malicious macro. If the target enables the macro, it will write a JScript Encoded (JSE) file to disk (JScript is a Microsoft dialect of ECMAScript). The JSE file will then be launched using *[wscript.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wscript)* to perform a variety of malicious tasks, particularly reconnaissance.

The following query detects when Office applications have launched wscript.exe to run a JSE file.

See [Detect rundll.exe being used for reconnaissance and command-and-control](../Command%20and%20Control/recon-with-rundll.md) for another query related to Trickbot activity.

## Query

```Kusto
DeviceProcessEvents 
| where InitiatingProcessFileName in~('winword.exe', 'excel.exe', 'outlook.exe') 
| where FileName =~ "wscript.exe" and ProcessCommandLine has ".jse" 
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
