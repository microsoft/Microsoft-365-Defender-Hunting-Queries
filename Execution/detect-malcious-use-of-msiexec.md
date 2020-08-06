# Detect malicious use of Msiexec

This query was originally published in the threat analytics report, *Msiexec abuse*.

*[Msiexec.exe](https://docs.microsoft.com/windows-server/administration/windows-commands/msiexec)* is a Windows component that installs files with the *.msi* extension. These kinds of files are Windows installer packages, and are used by a wide array of legitimate software. However, malicious actors can re-purpose msiexec.exe for living-off-the-land attacks, where they use legitimate system binaries on the compromised device to perform attacks.

The following query detects activity associated with misuse of msiexec.exe, particularly alongside [mimikatz](https://www.varonis.com/blog/what-is-mimikatz/), a common credential dumper and privilege escalation tool.

## Query

```Kusto
//Find possible download and execution using Msiexec
DeviceProcessEvents
| where Timestamp > ago(7d)
//MSIExec
| where FileName =~ "msiexec.exe" and 
//With domain in command line
(ProcessCommandLine has "http" and ProcessCommandLine has "return")//Find PowerShell running files from the temp folder

DeviceProcessEvents
| where Timestamp > ago(7d)
//Looking for PowerShell
| where FileName =~ "powershell.exe"
//Looking for %temp% in the command line indicating deployment 
and ProcessCommandLine contains "%temp%"//Find credential theft attempts using Msiexec to run Mimikatz commands

DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "msiexec.exe"
//Mimikatz commands
and (ProcessCommandLine contains "privilege::" 
or ProcessCommandLine has "sekurlsa" 
or ProcessCommandLine contains "token::") 
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
| Persistence |  |  |
| Privilege escalation | v |  |
| Defense evasion |  |  |
| Credential Access | v |  |
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
