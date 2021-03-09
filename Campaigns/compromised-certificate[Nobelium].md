# Compromised certificate [Nobelium]

Search for the files that are using a compromised certificate associated with the Nobelium campaign.

You can remove the comments to:

* get the list of devices where there is at least one file signed with the certificate
* get the list of files signed with the certificate
* get the list of files signed with the certificate group by Devices

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

## See also

* [Locate Nobelium implant receiving DNS response](./c2-lookup-from-nonbrowser[Nobelium].md)
* [Locate Nobelium implant receiving DNS response](./c2-lookup-response[Nobelium].md)
* [FireEye Red Team tool CVEs [Nobelium]](./fireeye-red-team-tools-CVEs%20[Nobelium].md)
* [FireEye Red Team tool HASHs [Nobelium]](./fireeye-red-team-tools-HASHs%20[Nobelium].md)
* [View data on software identified as affected by Nobelium campaign](./known-affected-software-orion[Nobelium].md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](./launching-base64-powershell[Nobelium].md)
* [Locate SolarWinds processes launching command prompt with the echo command](./launching-cmd-echo[Nobelium].md)
* [Locate Nobelium-related malicious DLLs created in the system or locally](./locate-dll-created-locally[Nobelium].md)
* [Locate Nobelium-related malicious DLLs loaded in memory](./locate-dll-loaded-in-memory[Nobelium].md)
* [Get an inventory of SolarWinds Orion software possibly affected by Nobelium](./possible-affected-software-orion[Nobelium].md)
* [Anomalous use of MailItemAccess on other users' mailboxes [Nobelium]](../Collection/Anomaly%20of%20MailItemAccess%20by%20Other%20Users%20Mailbox%20[Nobelium].md)
* [Nobelium campaign DNS pattern](../Command%20and%20Control/DNSPattern%20[Nobelium].md)
* [Nobelium encoded domain in URL](../Command%20and%20Control/EncodedDomainURL%20[Nobelium].md)
* [Domain federation trust settings modified](../Defense%20evasion/ADFSDomainTrustMods[Nobelium].md)
* [Discovering potentially tampered devices [Nobelium]](../Defense%20evasion/Discovering%20potentially%20tampered%20devices%20[Nobelium].md)
* [Mail.Read or Mail.ReadWrite permissions added to OAuth application](../Defense%20evasion/MailPermissionsAddedToApplication[Nobelium].md)
* [Suspicious enumeration using Adfind tool](../Discovery/SuspiciousEnumerationUsingAdfind[Nobelium].md)
* [Anomalous use of MailItemAccess by GraphAPI [Nobelium]](../Exfiltration/Anomaly%20of%20MailItemAccess%20by%20GraphAPI%20[Nobelium].md)
* [MailItemsAccessed throttling [Nobelium]](../Exfiltration/MailItemsAccessed%20Throttling%20[Nobelium].md)
* [OAuth apps accessing user mail via GraphAPI [Nobelium]](../Exfiltration/OAuth%20Apps%20accessing%20user%20mail%20via%20GraphAPI%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI and directly [Nobelium]](../Exfiltration/OAuth%20Apps%20reading%20mail%20both%20via%20GraphAPI%20and%20directly%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI anomaly [Nobelium]](../Exfiltration/OAuth%20Apps%20reading%20mail%20via%20GraphAPI%20anomaly%20[Nobelium].md)
* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Nobelium]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Nobelium].md)
* [New access credential added to application or service principal](../Persistence/NewAppOrServicePrincipalCredential[Nobelium].md)
* [Add uncommon credential type to application [Nobelium]](../Privilege%20escalation/Add%20uncommon%20credential%20type%20to%20application%20[Nobelium].md)
* [ServicePrincipalAddedToRole [Nobelium]](../Privilege%20escalation/ServicePrincipalAddedToRole%20[Nobelium].md)

## Contributor info

**Contributor:** Dario Brambilla
**GitHub alias:** darioongit
**Organization:** Microsoft 365 Defender
