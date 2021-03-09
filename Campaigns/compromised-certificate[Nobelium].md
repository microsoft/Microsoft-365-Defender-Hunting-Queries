# Compromised certificate [Nobelium]

Search for the files that are using the compromised certificate.

You can remove the comments to:

* get the list of the Devices where there is at least a file signed with the certificate
* get the list of the Files signed with the certificate
* get the list of the Files signed with the certificate group by Devices

## Query

```Kusto
DeviceFileCertificateInfo
| where Signer == 'Solarwinds Worldwide, LLC' and SignerHash == '47d92d49e6f7f296260da1af355f941eb25360c4'
| join DeviceFileEvents on SHA1
| distinct DeviceName, FileName, FolderPath, SHA1, SHA256, IsTrusted, IsRootSignerMicrosoft, SignerHash
//| distinct DeviceName
//| distinct FileName
//| summarize mylist = make_list(FileName) by DeviceName
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation | v |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability | v |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Dario Brambilla
**GitHub alias:** darioongit
**Organization:** Microsoft 365 Defender
