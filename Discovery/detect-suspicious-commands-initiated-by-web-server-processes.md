# Detect suspicious commands initiated by web server processes

This query was originally published in the threat analytics report, *Operation Soft Cell*.

[Operation Soft Cell](https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers) is a series of campaigns targeting users' call logs at telecommunications providers throughout the world. These attacks date from as early as 2012.

Operation Soft Cell operators sometimes use legitimate web server processes to launch commands, especially for network discovery and user/owner discovery. The following query detects activity of this kind.

## Query

```Kusto
// Suspicious commands launched by web server processes
DeviceProcessEvents 
| where Timestamp > ago(7d)
// Pivoting on parents or grand parents
and (((InitiatingProcessParentFileName in("w3wp.exe", "beasvc.exe",
"httpd.exe") or InitiatingProcessParentFileName startswith "tomcat")
or InitiatingProcessFileName in("w3wp.exe", "beasvc.exe", "httpd.exe") or
InitiatingProcessFileName startswith "tomcat"))
    and FileName in~('cmd.exe','powershell.exe')
| where ProcessCommandLine contains '%temp%'
    or ProcessCommandLine has 'wget'
    or ProcessCommandLine has 'whoami'
    or ProcessCommandLine has 'certutil'
    or ProcessCommandLine has 'systeminfo'
    or ProcessCommandLine has 'ping'
    or ProcessCommandLine has 'ipconfig'
    or ProcessCommandLine has 'timeout'
| summarize any(Timestamp), any(Timestamp), any(FileName),
makeset(ProcessCommandLine), any(InitiatingProcessFileName),
any(InitiatingProcessParentFileName) by DeviceId
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v | This query detects whenever, over the past seven days, a web server process launched a CLI command. This sort of activity, although suspicious, is not by itself actively harmful. Administrators should investigate further to determine if the event was malicious or associated with Operation Soft Cell. |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
| Credential Access |  |  |
| Discovery | v |  |
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
