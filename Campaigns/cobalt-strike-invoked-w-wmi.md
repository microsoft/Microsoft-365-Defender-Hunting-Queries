# Detect Cobalt Strike invoked via WMI

This query was originally published in the threat analytics report, *Ryuk ransomware*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/).

[Ryuk](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Ryuk&threatId=-2147232689) is human-operated ransomware. Much like [DoppelPaymer](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/) ransomware, Ryuk is spread manually, often on networks that are already infected with Trickbot.

During the earliest stages of a Ryuk infection, an operator downloads [Cobalt Strike](https://www.cobaltstrike.com/), a penetration testing kit that is also used by malicious actors. Cobalt Strike is used by Ryuk operators to explore the network before deploying the Ryuk payload. This malicious behavior is often obscured by Base64 encoding and other tricks.

The following query detects possible invocation of Cobalt Strike using [Windows Management Instrumentation](https://docs.microsoft.com/windows/win32/wmisdk/wmi-start-page) (WMI).

The [See also](#See-also) section below lists links to other queries associated with Ryuk ransomware.

## Query

```Kusto
// Find use of Base64 encoded PowerShell
// Indicating possible Cobalt Strike 
DeviceProcessEvents
| where Timestamp > ago(7d)
// Only WMI-initiated instances, remove to broaden scope
| where InitiatingProcessFileName =~ 'wmiprvse.exe'
| where FileName =~ 'powershell.exe'
 and (ProcessCommandLine hasprefix '-e' or 
 ProcessCommandLine contains 'frombase64')
// Check for Base64 with regex
| where ProcessCommandLine matches regex '[A-Za-z0-9+/]{50,}[=]{0,2}'
// Exclusions: The above regex may trigger false positive on legitimate SCCM activities. 
// Remove this exclusion to search more broadly.
| where ProcessCommandLine !has 'Windows\\CCM\\'
| project DeviceId, Timestamp, InitiatingProcessId, 
InitiatingProcessFileName, ProcessId, FileName, ProcessCommandLine
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

## See also

* [Detect PsExec being used to spread files](../Lateral%20Movement/remote-file-creation-with-psexec.md)
* [Detect credential theft via SAM database export by LaZagne](../Credential%20Access/lazagne.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
