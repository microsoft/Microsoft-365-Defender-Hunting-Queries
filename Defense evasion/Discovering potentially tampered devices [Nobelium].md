# Discovering potentially tampered devices [Nobelium]

To evade security software and analyst tools, Nobelium malware enumerates the target system looking for certain running processes, loaded drivers, and registry keys, with the goal of disabling them.

The Microsoft Defender for Endpoint sensor is one of the processes the malware attempts to disable.

Microsoft Defender for Endpoint has built-in protections against many techniques attackers use to disable endpoint sensors ranging from hardened OS protection, anti-tampering policies, and detections for a variety of tampering attempts, including "Attempt to stop Microsoft Defender for Endpoint sensor", "Tampering with Microsoft Defender for Endpoint sensor settings", or "Possible sensor tampering in memory".

Successfully disabling Microsoft Defender for Endpoint can prevent the system from reporting observed activities.

However, the multitude of signals reported into Microsoft 365 Defender provides a unique opportunity to hunt for systems where the tampering technique used might have been successful.

The following advanced hunting query can be used to locate devices that should be reporting but aren’t:

## Query

```Kusto
// Times to be modified as appropriate
let timeAgo=1d;
let silenceTime=8h;
// Get all silent devices and IPs from network events
let allNetwork=materialize(DeviceNetworkEvents
| where Timestamp > ago(timeAgo)
and isnotempty(LocalIP)
and isnotempty(RemoteIP)
and ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
and LocalIP !in ("127.0.0.1", "::1")
| project DeviceId, Timestamp, LocalIP, RemoteIP, ReportId);
let nonSilentDevices=allNetwork
| where Timestamp > ago(silenceTime)
| union (DeviceProcessEvents | where Timestamp > ago(silenceTime))
| summarize by DeviceId;
let nonSilentIPs=allNetwork
| where Timestamp > ago(silenceTime)
| summarize by LocalIP;
let silentDevices=allNetwork
| where DeviceId !in (nonSilentDevices)
and LocalIP !in (nonSilentIPs)
| project DeviceId, LocalIP, Timestamp, ReportId;
// Get all remote IPs that were recently active
let addressesDuringSilence=allNetwork
| where Timestamp > ago(silenceTime)
| summarize by RemoteIP;
// Potentially disconnected devices were connected but are silent
silentDevices
| where LocalIP in (addressesDuringSilence)
| summarize ReportId=arg_max(Timestamp, ReportId), Timestamp=max(Timestamp), LocalIP=arg_max(Timestamp, LocalIP) by DeviceId
| project DeviceId, ReportId=ReportId1, Timestamp, LocalIP=LocalIP1
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | V |  |
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

## See also

* [Locate Nobelium implant receiving DNS response](../Campaigns/c2-lookup-from-nonbrowser[Nobelium].md)
* [Locate Nobelium implant receiving DNS response](../Campaigns/c2-lookup-response[Nobelium].md)
* [Compromised certificate [Nobelium]](../Campaigns/compromised-certificate[Nobelium].md)
* [FireEye Red Team tool CVEs [Nobelium]](../Campaigns/fireeye-red-team-tools-CVEs%20[Nobelium].md)
* [FireEye Red Team tool HASHs [Nobelium]](../Campaigns/fireeye-red-team-tools-HASHs%20[Nobelium].md)
* [View data on software identified as affected by Nobelium campaign](../Campaigns/known-affected-software-orion[Nobelium].md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](../Campaigns/launching-base64-powershell[Nobelium].md)
* [Locate SolarWinds processes launching command prompt with the echo command](../Campaigns/launching-cmd-echo[Nobelium].md)
* [Locate Nobelium-related malicious DLLs created in the system or locally](../Campaigns/locate-dll-created-locally[Nobelium].md)
* [Locate Nobelium-related malicious DLLs loaded in memory](../Campaigns/locate-dll-loaded-in-memory[Nobelium].md)
* [Get an inventory of SolarWinds Orion software possibly affected by Nobelium](../Campaigns/possible-affected-software-orion[Nobelium].md)
* [Anomalous use of MailItemAccess on other users' mailboxes [Nobelium]](../Collection/Anomaly%20of%20MailItemAccess%20by%20Other%20Users%20Mailbox%20[Nobelium].md)
* [Nobelium campaign DNS pattern](../Command%20and%20Control/DNSPattern%20[Nobelium].md)
* [Nobelium encoded domain in URL](../Command%20and%20Control/EncodedDomainURL%20[Nobelium].md)
* [Domain federation trust settings modified](./ADFSDomainTrustMods[Nobelium].md)
* [Mail.Read or Mail.ReadWrite permissions added to OAuth application](./MailPermissionsAddedToApplication[Nobelium].md)
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

**Contributor:** Microsoft 365 Defender
