# Detect Exfiltration to Competitor Organization

This query can be used to detect instances of a malicious insider creating a file archive and then emailing that archive to an external "competitor" organization.

## Query

```
EmailEvents
| where RecipientEmailAddress contains "competitor"
and AttachmentCount >=1
| join (
EmailAttachmentInfo
//| where isnotempty(SHA256)
)on NetworkMessageId
| join (
DeviceFileEvents
| where InitiatingProcessFileName in ("7z.exe", "7zG.exe", "AxCrypt.exe", "BitLocker.exe", "Diskcryptor.exe", "GNUPrivacyGuard.exe", "GPG4Win.exe", "PeaZip.exe", "VeraCrypt.exe", "WinRAR.exe", "WinZip.exe")
| project FileName, SHA256
) on FileName
```
## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration | v |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** SEI National Insider Threat Center

**GitHub alias:** sei-nitc

**Organization:** Carnegie Mellon University Software Engineering Institute

**Contact info:** insider-threat-feedback@cert.org

&copy; Carnegie Mellon University, 2020. All rights reserved