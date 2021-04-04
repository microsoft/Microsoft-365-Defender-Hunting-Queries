# FireEye Red Team tool CVEs [Nobelium]

Search for the CVEs that should be prioritized and resolved to reduce the success of the FireEye Red Team tools compromised by the Nobelium activity group.
See [red_team_tool_countermeasures](https://github.com/fireeye/red_team_tool_countermeasures/blob/master/CVEs_red_team_tools.md) on the [official FireEye repo](https://github.com/fireeye).

## Query

```Kusto
let FireEyeCVE= dynamic(
[
"CVE-2019-11510", //pre-auth arbitrary file reading from Pulse Secure SSL VPNs - CVSS 10.0
"CVE-2020-1472", //Microsoft Active Directory escalation of privileges - CVSS 10.0
"CVE-2018-13379", //pre-auth arbitrary file reading from Fortinet Fortigate SSL VPN - CVSS 9.8 //no find CVE
"CVE-2018-15961", //RCE via Adobe ColdFusion (arbitrary file upload that can be used to upload a JSP web shell) - CVSS 9.8
"CVE-2019-0604", //RCE for Microsoft Sharepoint - CVSS 9.8
"CVE-2019-0708", //RCE of Windows Remote Desktop Services (RDS) - CVSS 9.8
"CVE-2019-11580", //Atlassian Crowd Remote Code Execution - CVSS 9.8
"CVE-2019-19781", //RCE of Citrix Application Delivery Controller and Citrix Gateway - CVSS 9.8  //no find CVE
"CVE-2020-10189", //RCE for ZoHo ManageEngine Desktop Central - CVSS 9.8
"CVE-2014-1812", //Windows Local Privilege Escalation - CVSS 9.0
"CVE-2019-3398", //Confluence Authenticated Remote Code Execution - CVSS 8.8
"CVE-2020-0688", //Remote Command Execution in Microsoft Exchange - CVSS 8.8
"CVE-2016-0167", //local privilege escalation on older versions of Microsoft Windows - CVSS 7.8
"CVE-2017-11774", //RCE in Microsoft Outlook via crafted document execution (phishing) - CVSS 7.8
"CVE-2018-8581", //Microsoft Exchange Server escalation of privileges - CVSS 7.4
"CVE-2019-8394" //arbitrary pre-auth file upload to ZoHo ManageEngine ServiceDesk Plus - CVSS 6.5
]
);
DeviceTvmSoftwareVulnerabilitiesKB
| where CveId in(FireEyeCVE)
| join DeviceTvmSoftwareVulnerabilities on CveId
| project-away CveId1, VulnerabilitySeverityLevel1, AffectedSoftware
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
* [Compromised certificate [Nobelium]](./compromised-certificate[Nobelium].md)
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
