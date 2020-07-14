# Locate Shlayer payload decryption activity

This query was originally published in the threat analytics report, *OSX/Shlayer sustains adware push*.

[Shlayer](https://www.intego.com/mac-security-blog/osxshlayer-new-mac-malware-comes-out-of-its-shell/) is adware that spies on users' search terms, and redirects network traffic to serve the user attacker-controlled search results containing ads.

The following query locates activity associated with the Shlayer payload decrypter.

## Query

```Kusto
// Find use of the Shlayer OpenSSL command to decode and decrypt a payload
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "openssl"
and ProcessCommandLine has "-base64" and
ProcessCommandLine has "-out"  and
ProcessCommandLine has "-nosalt"
and ProcessCommandLine has_any("-aes256", "-aes-256")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution | v | Our tests indicate that this query might return a few rare matches to normal activity. |
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