# Locate Nobelium-related malicious DLLs created in the system or locally

This query was originally published in the threat analytics report, *Solorigate supply chain attack*. Please note that these attacks are currently known as the *Nobelium campaign*.

Microsoft detects the [2020 SolarWinds supply chain attack](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) implant and its other components as part of a campaign by the Nobelium activity group. Nobelium is the threat actor behind the attack against SolarWinds, which was previously referred to as [*Solorigate*](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/).

 Nobelium silently added malicious code to legitimate software updates for Orion, which is IT monitoring software provided by SolarWinds. In this way, malicious dynamic link libraries (DLLs) were distributed to SolarWinds customers.

The following query locates malicious Nobelium-associated DLLs that have been created in the system or locally.

More Nobelium-related queries can be found listed under the [See also](#see-also) section of this document.

## Query

```kusto
DeviceFileEvents 
| where SHA1 in ("76640508b1e7759e548771a5359eaed353bf1eec","d130bd75645c2433f88ac03e73395fba172ef676","1acf3108bf1e376c8848fbb25dc87424f2c2a39c","e257236206e99f5a5c62035c9c59c57206728b28","6fdd82b7ca1c1f0ec67c05b36d14c9517065353b","2f1a5a7411d015d01aaee4535835400191645023","bcb5a4dcbc60d26a5f619518f2cfc1b4bb4e4387","16505d0b929d80ad1680f993c02954cfd3772207","d8938528d68aabe1e31df485eb3f75c8a925b5d9","395da6d4f3c890295f7584132ea73d759bd9d094","c8b7f28230ea8fbf441c64fdd3feeba88607069e","2841391dfbffa02341333dd34f5298071730366a","2546b0e82aecfe987c318c7ad1d00f9fa11cd305","2dafddbfb0981c5aa31f27a298b9c804e553c7bc","e2152737bed988c0939c900037890d1244d9a30e","fd15760abfc0b2537b89adc65b1ff3f072e7e31c") or SHA256 in ("32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77","ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6","dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b","eb6fab5a2964c5817fb239a7a5079cabca0a00464fb3e07155f28b0a57a2c0ed","ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c","019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134","c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77","0f5d7e6dfdd62c83eb096ba193b5ae394001bac036745495674156ead6557589","e0b9eda35f01c1540134aba9195e7e6393286dde3e001fce36fb661cc346b91d","20e35055113dac104d2bb02d4e7e33413fae0e5a426e0eea0dfd2c1dce692fd9","2b3445e42d64c85a5475bdbc88a50ba8c013febb53ea97119a11604b7595e53d","a3efbc07068606ba1c19a7ef21f4de15d15b41ef680832d7bcba485143668f2d","92bd1c3d2a11fc4aba2735d9547bd0261560fb20f36a0e7ca2f2d451f1b62690","a58d02465e26bdd3a839fd90e4b317eece431d28cab203bbdde569e11247d9e2","b8a05cc492f70ffa4adcd446b693d5aa2b71dc4fa2bf5022bf60d7b13884f666","cc082d21b9e880ceb6c96db1c48a0375aaf06a5f444cb0144b70e01dc69048e6","ffdbdd460420972fd2926a7f460c198523480bc6279dd6cca177230db18748e8")
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence | v |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact | v |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component | v |  |

## See also

* [Locate Nobelium implant receiving DNS response](./c2-lookup-from-nonbrowser[Nobelium].md)
* [Locate Nobelium implant receiving DNS response](./c2-lookup-response[Nobelium].md)
* [Compromised certificate [Nobelium]](./compromised-certificate[Nobelium].md)
* [FireEye Red Team tool CVEs [Nobelium]](./fireeye-red-team-tools-CVEs%20[Nobelium].md)
* [FireEye Red Team tool HASHs [Nobelium]](./fireeye-red-team-tools-HASHs%20[Nobelium].md)
* [View data on software identified as affected by Nobelium campaign](./known-affected-software-orion[Nobelium].md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](./launching-base64-powershell[Nobelium].md)
* [Locate SolarWinds processes launching command prompt with the echo command](./launching-cmd-echo[Nobelium].md)
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

**Contributor:** Microsoft Threat Protection team
