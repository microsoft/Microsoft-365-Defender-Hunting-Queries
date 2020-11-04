# Detecting a JAR attachment

This query was originally published in the threat analytics report, *Adwind utilizes Java for cross-platform impact*.

Adwind is a remote access tool (RAT) that takes advantage of the cross-platform capabilities of the Java framework. It can check which operating system a target is running and adapt accordingly, allowing it to successfully compromise both Windows and macOS devices.

The query below must be run in Microsoft 365 Defender. This query detects events where a single Java archive, or JAR file, was attached to an incoming email. Since Adwind is distributed as a JAR file, this can help detect the initial access stage of a Adwind attack. Note that, although the behavior detected by this query is typical of attacks that use Adwind malware, unrelated attacks may use the same or similar techniques. Also note that JAR attachments are not necessarily or even often malware, and that further research will be needed to determine if query results are associated with malicious behavior.

See [Hiding a Java class file](../Defense%20evasion/hiding-java-class-file.md) for an additional query that detects behavior associated with Adwind attacks.

## Query

```kusto
let mailsHTML = EmailAttachmentInfo
| where FileType startswith "Jar"
| distinct NetworkMessageId;
EmailEvents
| where NetworkMessageId in (mailsHTML) and AttachmentCount > 0
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access | v | Microsoft 365 Defender exclusive |
| Execution |  |  |
| Persistence |  |  |
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
