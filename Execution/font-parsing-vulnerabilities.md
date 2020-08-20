# Font parsing vulnerability associated with remote execution

This query was originally published in the threat analytics report, *Type 1 font-parsing 0-day vulnerabilities*.

In March of 2020, Microsoft released a [security advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006) about vulnerabilities related to how Microsoft Windows interacts with Adobe Type Manager Library: [CVE-2020-1020](https://nvd.nist.gov/vuln/detail/CVE-2020-1020) and [CVE-2020-0938](https://nvd.nist.gov/vuln/detail/CVE-2020-0938).

These vulnerabilities can be exploited by an attacker to remotely execute code. They are caused by a flaw in handling [Adobe Type 1 PostScript](https://www.adobe.com/products/postscript.html) fonts.

Initially reported while still a zero-day, updates and mitigations are now available.

* Windows update for [CVE-2020-1020](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1020).
* Windows update for [CVE-2020-0938](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0938).
* [Mitigations and workarounds](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006) for systems that cannot be updated.

The following query locates suspicious processes launched by the vulnerable font parser. This activity may indicate an attack that is exploiting the two vulnerabilities above.

## Query

```Kusto
​// Surfaces suspicious processes created by the font parser (fontdrvhost.exe)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "fontdrvhost.exe"
| where FileName !in~("WerFault.exe", "conhost.exe", "wermgr.exe", 
"wsqmcons.exe", "taskhostw.exe", "csrss.exe" )
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
