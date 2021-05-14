# Phishing email URL redirection

This query was originally published on Twitter, by [@MsftSecIntel](https://twitter.com/MsftSecIntel).

The query helps detect emails associated with the open redirector URL campaign. The campaign's URLs begin with the distinct pattern, hxxps://t[.]domain[.]tld/r/?. Attackers use URL redirection to manipulate users into visiting a malicious website or to evade detection.

## Query
Generic regex for all emails containing base "t-dot" redirector pattern:
```
EmailUrlInfo
| where Url matches regex @"s?\:\/\/(?:www\.)?t\.(?:[\w\-\.]+\/+)+(?:r|redirect)\/?\?"
```
Specific regex for campaigns containing known malicious infrastructure as observed from late 2020 until at least April 2021:
```
EmailUrlInfo
//This regex identifies emails containing the "T-Dot" redirector pattern in the URL
| where Url matches regex @"s?\:\/\/(?:www\.)?t\.(?:[\w\-\.]+\/+)+(?:r|redirect)\/?\?" 
    //This regex narrows in on emails that contain the known malicious domain pattern in the URL from the most recent campaigns
    and Url matches regex @"[a-zA-Z]\-[a-zA-Z]{2}\.(xyz|club|shop)"
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
