# Phishing email URL redirection

This query was originally published on Twitter, by [@MsftSecIntel](https://twitter.com/MsftSecIntel).

The query helps detect emails associated with a campaign that has used open redirector URLs. The campaign's URLs begin with the distinct pattern, *hxxps://t[.]domain[.]tld/r/?*. Attackers use URL redirection to manipulate users into visiting a malicious website or to evade detection.

## Query

```
EmailUrlInfo
| where Url matches regex @"s?\:\/\/(?:www\.)?t\.(?:[\w\-\.]+\/+)+(?:r|redirect)\/?\?"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
