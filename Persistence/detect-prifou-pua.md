# Detect potentially unwanted activity from ironSource bundlers

This query was originally published in the threat analytics report, *ironSource PUA & unwanted apps impact millions*.

IronSource provides software bundling tools for many popular legitimate apps, such as FileZilla. However, some of ironSource's bundling tools are considered PUA, because they exhibit potentially unwanted behavior. One component of these tools, detected by Microsoft as *Prifou*, silently transmits system information from the user. It also installs an outdated version of Chromium browser with various browser extensions, resets the user's home page, changes their search engine settings, and forces Chromium and itself to launch at startup.

The following query can be used to locate unique command-line strings used by ironSource bundlers to launch Prifou, as well as commands used by Prifou to install Chromium.

## Query

```Kusto
union DeviceFileEvents, DeviceProcessEvents 
| where Timestamp > ago(7d)
// Prifou launched by ironSource bundler
| where ProcessCommandLine has "/mhp " and ProcessCommandLine has "/mnt " 
and ProcessCommandLine has "/mds "
// InstallCore launch commands
or (ProcessCommandLine has "/mnl" and ProcessCommandLine has "rsf")
// Chromium installation
or ProcessCommandLine has "bundlename=chromium"
or FileName == "prefjsonfn.txt"
| project SHA1, ProcessCommandLine, FileName, InitiatingProcessFileName,
InitiatingProcessCommandLine, InitiatingProcessSHA1
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
| Malware, component | v |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
