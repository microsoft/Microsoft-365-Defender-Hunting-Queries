# Detect DoublePulsar execution

This query was originally published in the threat analytics report, *Motivated miners*.

[Doublepulsar](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/DoublePulsar&threatId=-2147239036) is a backdoor developed by the National Security Agency (NSA). First [disclosed in 2017](https://www.scmagazine.com/home/security-news/cybercrime/doublepulsar-malware-spreading-rapidly-in-the-wild-following-shadow-brokers-dump/), it is now used by many malicious actors. Software [patches](https://support.microsoft.com/en-us/help/4013389/title) are available.

The following query detects possible DoublePulsar execution events.

See [Detect web server exploitation by DoublePulsar](detect-web-server-exploit-doublepulsar.md) for a query that detects behaviors associated with campaigns that use DoublePulsar.

## Query

```Kusto
//DoublePulsar execution
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA1 == "be855cd1bfc1e1446a3390c693f29e2a3007c04e" or
(ProcessCommandLine contains "targetport" and ProcessCommandLine contains "targetip" and 
(ProcessCommandLine contains "payload" or ProcessCommandLine contains "verifybackdoor"))
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v |  |
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
