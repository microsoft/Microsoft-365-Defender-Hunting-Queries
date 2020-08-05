# Defense evasion by campaigns using Qakbot malware

This query was originally published in the threat analytics report, *Qakbot blight lingers, seeds ransomware*

Qakbot is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under [#see-also].

The following query detects if an instance of Qakbot has attempted to overwrite its original binary.

## Query

```Kusto
DeviceProcessEvents 
| where FileName =~ "ping.exe"
| where InitiatingProcessFileName =~ "cmd.exe"
| where InitiatingProcessCommandLine has "calc.exe" and
InitiatingProcessCommandLine has "-n 6" 
and InitiatingProcessCommandLine has "127.0.0.1"
| project ProcessCommandLine, InitiatingProcessCommandLine,
InitiatingProcessParentFileName, DeviceId, Timestamp
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
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
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also



## Contributor info

**Contributor:** Microsoft Threat Protection team
