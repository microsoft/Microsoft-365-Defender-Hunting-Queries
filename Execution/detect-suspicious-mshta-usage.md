# Detect suspicious Mshta usage

This query was originally published in the threat analytics report, *Ursnif (Gozi) continues to evolve*.

[Microsoft HTML Applications](https://docs.microsoft.com/previous-versions/ms536496(v=vs.85)), or *HTAs*, are executable files that use the same technologies and models as Internet Explorer, but do not run inside of a web browser.

*[Mshta.exe](https://docs.microsoft.com/en-us/previous-versions/windows/embedded/aa940701(v%3dwinembedded.5))* is a Windows utility that provides a host for HTA files to run in. Although it has legitimate uses, attackers can use mshta.exe to run malicious Javascript or VBScript commands. The MITRE ATT&CK framework includes [Mshta](https://attack.mitre.org/techniques/T1170/) among its list of enterprise attack techniques.

The following query detects when mshta.exe has been run, which might include illegitimate usage by attackers.

## Query

```Kusto
// mshta.exe script launching processes
DeviceProcessEvents 
| where Timestamp > ago(7d)
and InitiatingProcessFileName =~ 'mshta.exe'
and InitiatingProcessCommandLine contains '<script>'
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v |   |  |
| Execution | v | The query will detect whenever mshta.exe has been run over the past seven days. This sort of activity, although suspicious, is not by itself actively harmful. Administrators should investigate further to determine if the event was  malicious. |
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

## Contributor info

**Contributor:** Microsoft Threat Protection team
