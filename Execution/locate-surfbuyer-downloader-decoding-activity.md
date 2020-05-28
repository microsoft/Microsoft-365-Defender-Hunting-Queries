# Locate SurfBuyer downloader decoding activity

This query was originally published in the threat analytics report, *OSX/SurfBuyer adware campaign*.

It will return results if a shell script has furtively attempted to decode and save a file to a */tmp* folder.

If discovered on your system, this kind of activity might be associated with SurfBuyer, which is adware that installs a browser extension to take control of several major web browsers, including Safari, Google Chrome, and Firefox.

## Query

```
// Find SurfBuyer command to decode a file and save it into a /tmp folder using a certain file name
DeviceProcessEvents
// Check for activity over the past 7 days
| where Timestamp > ago(7d)
| where ProcessCommandLine has "base64" and ProcessCommandLine has "/tmp/e_"
```

## Category

This query can be used the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

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
