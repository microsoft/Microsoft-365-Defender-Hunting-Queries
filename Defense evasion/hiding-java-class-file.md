# Hiding a Java class file

This query was originally published in the threat analytics report, *Adwind utilizes Java for cross-platform impact*.

Adwind is a remote access tool (RAT) that takes advantage of the cross-platform capabilities of the Java framework. It can check which operating system a target is running and adapt accordingly, allowing it to successfully compromise both Windows and macOS devices.

The query below checks for attempts to disguise Java class files (i.e., complied code with a *.class* extension). Although the behavior detected by this query is typical of attacks that use Adwind malware, unrelated attacks may use the same or similar defense evasion techniques.

See [Detecting a JAR attachment](../Initial%20access/jar-attachments.md) for an additional query that detects behavior associated with Adwind attacks.

## Query

```kusto
union DeviceFileEvents, DeviceProcessEvents
| where ProcessCommandLine has "attrib +h +s +r " 
and ProcessCommandLine contains ".class"
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

## Contributor info

**Contributor:** Microsoft Threat Protection team
