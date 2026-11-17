# ola-radio-audit
Independent Network Behaviour, Infrastructure and Privacy Investigation
# OLA RADIO
## Independent Network Behaviour, Infrastructure and Privacy Investigation

**Version:** 2.0  
**Date:** 17 November 2026  
**Platform investigated:** Android  
**Monitoring tool:** PCAPdroid  
**Investigation status:** Open — independent testing and community contributions welcome

**Repository:** https://github.com/700-glitch/ola-radio-audit

---

## Important notice

This is an independent, observational investigation based on network activity reported during testing of the Ola Radio Android application.

It is not a formal penetration test, forensic examination, or proof of malware infection.

Some original PCAPdroid captures and connection-history records were deleted before this report was consolidated. Consequently, several findings are historical observations that have not yet been independently reproduced.

The purpose of this project is to document those observations accurately, identify unanswered technical questions, and invite other people to repeat the tests.

**No confirmed malware infection, data theft, unauthorised access or malicious activity by Ola Radio has been established.**

---

# 1. Executive summary

This report documents an independent investigation into network activity observed while using the Ola Radio Android application.

The investigation was carried out using an Android tablet which the investigator reports was brand new and factory-reset before testing.

PCAPdroid was used to observe network connections and DNS activity during normal application use and while exploring different application functions. Testing was reported on both home Wi-Fi and a cellular mobile-data connection.

The main subject of this investigation is a group of unusual domain names following this pattern:

`[five-character prefix]2940637fafa.com`

Examples previously reported include:

- `wqswl2940637fafa.com`
- `ldyfg2940637fafa.com`
- `kcxru2940637fafa.com`
- `ukjwb2940637fafa.com`
- `jpkhj2940637fafa.com`
- `jzldt2940637fafa.com`
- `icpvn2940637fafa.com`
- `wmdww2940637fafa.com`
- `lvgjo2940637fafa.com`
- `nplvy2940637fafa.com`
- `brecy2940637fafa.com`
- `lxneq2940637fafa.com`
- `eeaak2940637fafa.com`

Earlier PCAPdroid observations reportedly associated some of these domains with TCP port `55530`.

FAFA-related activity was also reported during cellular mobile-data testing, not only on the home Wi-Fi connection.

A particularly interesting observation involved the application's **Connect to Devices** function. The investigator reported seeing FAFA-associated activity after pressing **Stop** during device discovery, without successfully pairing another device.

These observations raise reasonable technical questions about the origin and purpose of the network traffic.

There is also a relevant public threat-intelligence correlation: cybersecurity research published in 2025 documented a Vo1d botnet domain-generation seed containing the same `2940637fafa` suffix.

This similarity warrants investigation. It does not establish that Ola Radio contains malware or that the tablet is infected.

The original PCAPdroid captures have been deleted, so the observations need to be reproduced with fresh captures before stronger conclusions can be reached.

This project is now inviting other Ola Radio users, Android owners, developers and cybersecurity researchers to repeat the tests and share their results.

**The objective is to establish what is happening through independent, repeatable testing — not to make accusations without evidence.**

---

# 2. Investigation background

The investigation began after unusual network activity was noticed while using Ola Radio on Android.

The investigator used PCAPdroid to examine:

- DNS requests.
- Domain names.
- Outbound network connections.
- TCP ports.
- Connection status.
- Reported data-transfer sizes.
- Application and system-level attribution.

Different application functions were explored, including normal use, device discovery, stopping device discovery and viewing the firmware-update section.

Testing was also carried out using different network connections.

The observations in this report are separated into three categories:

**Reported observations:** Things the investigator remembers seeing in PCAPdroid or during testing.

**Public research:** Information documented by external cybersecurity researchers.

**Unconfirmed explanations:** Possible reasons for the observations that still require evidence.

This distinction is important. A domain appearing in a network monitor does not, by itself, reveal who initiated the request or what information was transmitted.

---

# 3. Device and testing environment

The investigator reports that the Android tablet was brand new and factory-reset before testing began.

This is relevant because it reduces the likelihood that previously installed user applications or accumulated user settings explain the observations.

However, a factory reset does not rule out:

- Preinstalled manufacturer applications.
- Android operating-system services.
- Firmware components.
- Built-in device-management software.
- Services installed or activated after setup.
- Other device-specific software.

The same tablet was used for the reported Wi-Fi and cellular comparisons.

This means that the network comparisons provide useful information about the home network, but do not independently identify the software component responsible for the activity.

## 3.1 PCAPdroid monitoring

PCAPdroid was used as the network-monitoring application.

The Android key or VPN indicator shown during monitoring was understood by the investigator to represent PCAPdroid's local Android VPN-based capture mechanism.

The presence of that indicator should not be interpreted as proof that a separate commercial or external VPN service was being used.

PCAPdroid observations can help identify network activity, but process attribution and connection metadata must be interpreted carefully.

In particular, a DNS request attributed to `Root` or `System` does not automatically establish that the originating application was Ola Radio.

---

# 4. FAFA domain family

## 4.1 Observed domain pattern

The reported domain structure is:

`[five-character prefix]2940637fafa.com`

Examples include:

| Reported domain | Prefix |
|---|---|
| `wqswl2940637fafa.com` | wqswl |
| `ldyfg2940637fafa.com` | ldyfg |
| `kcxru2940637fafa.com` | kcxru |
| `ukjwb2940637fafa.com` | ukjwb |
| `jpkhj2940637fafa.com` | jpkhj |
| `jzldt2940637fafa.com` | jzldt |
| `icpvn2940637fafa.com` | icpvn |
| `wmdww2940637fafa.com` | wmdww |
| `lvgjo2940637fafa.com` | lvgjo |
| `nplvy2940637fafa.com` | nplvy |
| `brecy2940637fafa.com` | brecy |
| `lxneq2940637fafa.com` | lxneq |
| `eeaak2940637fafa.com` | eeaak |

The repeated five-character prefix and common suffix indicate a structured naming pattern.

Possible explanations include:

- Algorithmically generated domain names.
- Dynamically selected network endpoints.
- Third-party service infrastructure.
- Session or connection-related domains.
- A proprietary application or device-management system.

These are possible explanations, not established facts.

The domain owner, operator and intended purpose have not been confirmed.

## 4.2 TCP port 55530

Earlier PCAPdroid observations reportedly associated some FAFA-domain activity with TCP port:

`55530`

The investigator recalls seeing small connection exchanges, approximately 100–340 bytes in some observations.

These figures are historical recollections and have not been independently checked against the original capture files.

TCP port 55530 is within the IANA dynamic/private port range of 49152–65535.

The port number alone does not indicate malware or malicious activity.

Possible explanations for a connection on this port include:

- Application signalling.
- Device discovery.
- Connection-state reporting.
- Session management.
- A third-party service.
- Another proprietary network protocol.

The actual function remains unknown.

**Important:** The presence of a DNS request, a TCP connection attempt and a successful TCP connection are three different observations. They must not be treated as interchangeable.

---

# 5. Public threat-intelligence research: Vo1d

One of the most important research leads concerns the Android Vo1d botnet.

A paper presented at Virus Bulletin 2025, titled:

*Vo1d rising: inside the botnet controlling 1.68 M+ Android TVs worldwide*

documents a Vo1d domain-generation seed containing:

`2940637fafa`

The research describes a five-character component followed by this suffix.

The paper includes the example:

`fjsjf2940637fafa.com`

This is a significant similarity to the domain pattern reported during the Ola Radio investigation.

### Why this matters

It establishes that the suffix is not merely an arbitrary pattern invented for this report: it appears in published research into Vo1d-related domain generation.

However, a matching domain pattern is not sufficient to establish that the observed traffic is malicious.

It does not prove:

- That the tablet is infected with Vo1d.
- That Ola Radio contains Vo1d malware.
- That the observed domains are currently controlled by a botnet.
- That Ola Radio communicates with a Vo1d command-and-control server.
- That any personal information has been stolen.
- That the application operator is connected to the Vo1d operation.

### TCP port comparison

A separate Darktrace article about Vo1d describes observed outbound connections involving TCP ports `55520` and `55521`.

Those are not the same ports as the `55530` reported in this investigation.

The port difference is important.

This report does not claim that TCP 55530 is a known Vo1d port or that the observed traffic is part of the same malicious infrastructure.

The domain-pattern similarity is a lead for further investigation, not a malware diagnosis.

### Published references

1. Virus Bulletin 2025 — *Vo1d rising: inside the botnet controlling 1.68 M+ Android TVs worldwide*  
   https://www.virusbulletin.com/conference/vb2025/abstracts/vo1d-rising-inside-botnet-controlling-168-m-android-tvs-worldwide/

2. Virus Bulletin research paper (PDF)  
   https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Vo1d-rising-inside-the-botnet-controlling-168M-Android-TVs-worldwide.pdf

3. Darktrace — *Vo1d Botnet Exposed: How Darktrace Detected a Global Android Threat*  
   https://www.darktrace.com/blog/unmasking-vo1d-inside-darktraces-botnet-detection

---

# 6. Historical ShadowServer nameserver observation

An earlier investigation reportedly identified the following nameservers for:

`kizvn2940637fafa.com`

- `SINKHOLE-00.SHADOWSERVER.ORG`
- `SINKHOLE-01.SHADOWSERVER.ORG`
- `SINKHOLE-02.SHADOWSERVER.ORG`
- `SINKHOLE-03.SHADOWSERVER.ORG`

These nameservers appear to be associated with ShadowServer Foundation infrastructure.

However, the original WHOIS or DNS records were not preserved.

This observation therefore requires independent revalidation.

Possible explanations include historical DNS configuration, sinkhole activity, domain changes or other infrastructure events.

None of these explanations has been confirmed for this domain.

The observation does not establish that ShadowServer operates Ola Radio's backend, receives Ola Radio user information or has any direct relationship with the application.

It must not be assumed that every domain in the FAFA family has the same nameservers.

---

# 7. Other reported network endpoints

Earlier PCAPdroid observations identified communications involving the following hostnames.

## 7.1 Ola Radio-related hostnames

`international.olaradio.top`

`euweb2c.olaradio.top`

Previously reported connection details included:

| Hostname | Reported protocol | Reported port |
|---|---|---:|
| `international.olaradio.top` | TCP / HTTPS | 443 |
| `euweb2c.olaradio.top` | TCP / TLS | 7002 |

The investigator also recalled approximately 356.9 KB of traffic associated with `international.olaradio.top`.

These are historical observations. The original captures are no longer available for independent verification.

The actual purpose of each endpoint has not been established.

They may be involved in normal application services, but the application operator would need to confirm their functions.

## 7.2 Google advertising-related hostnames

The following domains were also reported:

- `googleads.g.doubleclick.net`
- `static.doubleclick.net`

These are associated with Google advertising or measurement infrastructure.

Their presence indicates that advertising-related network activity was observed.

It does not establish which identifiers, if any, were transmitted or what information was processed.

## 7.3 MapLibre

The following hostname was reported:

`demotiles.maplibre.org`

This is associated with mapping and map-tile infrastructure.

Its presence alone does not prove that precise GPS coordinates were transmitted.

Further evidence would be needed to establish whether the application accesses location information, whether coordinates are sent to a remote service and what information is retained.

---

# 8. Device discovery and the Stop action

One of the most interesting reported observations involved the Ola Radio **Connect to Devices** functionality.

The investigator reported the following sequence:

1. Open the device-connection or discovery function.
2. Allow the discovery process to run.
3. Press **Stop**.
4. Observe FAFA-associated network activity.
5. No successful pairing with another device takes place.

The investigator believed the FAFA-related activity appeared when stopping the discovery process.

This observation is important because it suggests a possible relationship between an application action and the network activity.

However, the original captures have been deleted and the sequence has not yet been independently reproduced.

## 8.1 Possible explanations

Possible explanations include:

- The application sends a final discovery-status message.
- A connection-management component performs a cleanup operation.
- The application reports a change in connection state.
- A third-party SDK makes a network request.
- The traffic is unrelated to the Stop action and occurs at approximately the same time.

No explanation has been confirmed.

## 8.2 What needs to be tested

A proper comparison should include:

- Opening device discovery and leaving it running.
- Opening discovery and pressing Stop.
- Repeating the Stop action several times.
- Comparing the timestamps of network requests.
- Recording DNS queries separately from TCP connection attempts.
- Recording which process PCAPdroid attributes the traffic to.

The goal is to determine whether the activity consistently follows the Stop action.

---

# 9. Wi-Fi and cellular comparison

The investigator reported FAFA-associated activity during both home Wi-Fi and cellular mobile-data testing.

The cellular test reportedly included a DNS observation involving:

`lxneq2940637fafa.com`

The PCAPdroid screen was described as showing:

- DNS port 53.
- Root/System attribution.
- Unreachable status.
- Zero bytes.

This is an important distinction.

A DNS request or attempted lookup is not proof that a successful connection to the destination was established.

Likewise, Root/System attribution does not establish that Ola Radio itself initiated the original request.

The investigator also reported that Ola Radio continued working normally over cellular data.

### What the comparison tells us

The reported observations make an explanation limited exclusively to the home Wi-Fi router or broadband connection less likely.

However, because the same tablet was used on both networks, the activity could still originate from:

- Ola Radio.
- A third-party library used by the application.
- Android system software.
- A manufacturer service.
- Another component on the tablet.

Further tests using different Android devices and independent networks would help narrow this down.

---

# 10. Background activity

The investigator changed an Android background-activity setting and subsequently reported that FAFA-associated traffic appeared to stop.

The exact setting, its scope and the conditions of the test were not preserved.

This is therefore an observation requiring further testing, not a confirmed cause-and-effect relationship.

Background network activity can be generated by legitimate functions such as:

- Synchronisation.
- Periodic server checks.
- Reconnection.
- Notifications.
- Session management.
- Analytics.
- Device discovery.

The investigation needs controlled comparisons with the setting enabled and disabled.

---

# 11. Current evidence assessment

The following table distinguishes reported observations from unresolved questions.

| Subject | Current status |
|---|---|
| FAFA domain family | Previously reported; original captures deleted |
| Five-character prefix pattern | Matches the pattern described in public Vo1d research |
| TCP port 55530 | Previously reported; purpose unknown |
| Small connection exchanges | Historically reported; not independently rechecked |
| Cellular DNS observation | Reported; successful connection not established |
| Wi-Fi observations | Reported; original captures unavailable |
| Connect to Devices — Stop | Reported possible relationship; needs reproduction |
| Firmware-update section | Explored; no confirmed update-related behaviour |
| Background activity | Possible relationship reported; not confirmed |
| ShadowServer nameservers | Previously reported; requires revalidation |
| Ola Radio-related endpoints | Previously reported; functions unconfirmed |
| Google advertising-related endpoints | Previously reported |
| MapLibre endpoint | Previously reported |
| Malware infection | Not established |
| Data theft | Not established |
| Malicious command-and-control | Not established |
| Application vulnerability | Not established |

## 11.1 What this investigation has not proved

This investigation has not proved:

- That Ola Radio contains malware.
- That the Android tablet is infected.
- That the FAFA domains are malicious in every context.
- That TCP port 55530 is a malicious communication channel.
- That personal information was stolen.
- That precise GPS coordinates were transmitted.
- That ShadowServer has a relationship with Ola Radio.
- That the application operator is responsible for the FAFA domains.
- That the observed traffic contains commands or instructions.

These questions require additional evidence.

---

# 12. Questions for the Ola Radio operator

The following questions are submitted in the interest of technical transparency.

1. Does Ola Radio use or communicate with domains following the pattern `[five-character prefix]2940637fafa.com`?
2. If so, what is the purpose of these domains?
3. What is the purpose of TCP port 55530 in the reported observations?
4. Is this infrastructure operated by Ola Radio or a third-party provider?
5. Does the Connect to Devices function send a network request when the user presses Stop?
6. Does the device-discovery function use a third-party SDK or service?
7. Does the firmware-update function use separate infrastructure?
8. What are the purposes of `international.olaradio.top` and `euweb2c.olaradio.top`?
9. What information is exchanged with the application's backend services?
10. Which advertising, analytics and mapping services are integrated?
11. Does the application transmit device identifiers or account identifiers to third parties?
12. What information is retained, and for how long?
13. Where is application data processed and stored?
14. Is any application data transferred outside the user's country?
15. Can the operator provide a technical explanation of the FAFA domain pattern and its relationship, if any, to the pattern documented in public Vo1d research?

The purpose of these questions is to obtain clarification, not to presume wrongdoing.

---

# 13. Recommended further investigation

Future tests should preserve the original evidence.

The original PCAPdroid captures and connection history from the earlier investigation were deleted. New testing should therefore begin with fresh captures and careful record keeping.

Recommended evidence includes:

- Original PCAPdroid capture files.
- Screenshots showing the full hostname.
- DNS query and response information.
- Connection timestamps.
- Destination IP addresses.
- Destination ports.
- Connection status.
- Data-transfer sizes.
- Process attribution.
- Ola Radio version.
- Android version.
- Device model.
- Network type.
- The exact application action being performed.

## 13.1 Repeatable test procedure

### Test A — Normal application use

1. Start PCAPdroid.
2. Record the time.
3. Open Ola Radio.
4. Use the application normally.
5. Record any FAFA-related DNS requests or connections.
6. Save the capture.

### Test B — Device discovery

1. Start a fresh capture.
2. Open Connect to Devices.
3. Allow discovery to run.
4. Record network activity.
5. Press Stop without pairing another device.
6. Record activity immediately after pressing Stop.
7. Repeat the test.

### Test C — Firmware-update section

1. Start a fresh capture.
2. Open the firmware-update section.
3. Record any network activity.
4. Do not install unverified firmware.
5. Do not initiate an update unless it is safe and intended.

### Test D — Background activity

1. Observe Ola Radio while open.
2. Repeat while the application is in the background.
3. Repeat with the relevant Android background-activity setting changed.
4. Record the setting and results precisely.

### Test E — Different network

1. Repeat the same tests using Wi-Fi.
2. Repeat using cellular mobile data if available.
3. Record whether the same domains and ports appear.

### Test F — Different Android device

If possible, repeat the same procedure on another Android device.

This will help establish whether the behaviour is specific to one tablet or occurs across different devices.

## 13.2 Safety during testing

Please do not:

- Attempt to connect to unknown devices.
- Install unverified firmware.
- Disable Android security protections.
- Install unknown applications or APK files.
- Visit suspicious domains directly.
- Share account credentials or authentication tokens.
- Interfere with systems or networks you do not own or have permission to test.

Passive observation of your own device's network activity is sufficient for the initial investigation.

---

# 14. Community testing — help us compare results

## We want other Ola Radio users to repeat these tests

This project should not depend on one person's observations.

We are inviting Ola Radio users, Android owners, developers, network analysts and cybersecurity researchers to repeat the tests and report what they find.

**The more independent people who participate, the better we can compare results.**

We welcome results that match the original observations and results that do not.

A test that finds no FAFA-related activity is just as useful as one that does.

## 14.1 What we would like people to check

Please investigate:

1. Do FAFA-related domains appear during normal Ola Radio use?
2. Does TCP port 55530 appear?
3. Does activity occur when opening Connect to Devices?
4. Does activity occur specifically after pressing Stop?
5. Does the same behaviour occur without successfully pairing a device?
6. Does anything unusual happen when opening the firmware-update section?
7. Does the traffic continue when Ola Radio is in the background?
8. Does the same behaviour occur over Wi-Fi?
9. Does the same behaviour occur over cellular mobile data?
10. Does the behaviour occur on other Android phones or tablets?

## 14.2 Information to include with your results

Please record:

| Information | Example |
|---|---|
| Device manufacturer | Samsung, Lenovo, etc. |
| Device model | Exact model if known |
| Android version | Android version number |
| Ola Radio version | Version shown in the app |
| PCAPdroid version | Version installed |
| Test date | Date of observation |
| Network | Wi-Fi or cellular |
| Application action | Normal use, Stop, firmware screen, etc. |
| FAFA domain observed? | Yes / No |
| TCP 55530 observed? | Yes / No |
| DNS request or TCP connection? | Specify which |
| Connection result | Successful, failed, unreachable or unknown |
| Process attribution | Ola Radio, Root/System, another process or unknown |
| Repeatable? | Yes / No / Not tested |

Please distinguish between a DNS request and an established network connection.

A domain appearing in DNS records does not prove that a successful connection followed.

## 14.3 How we will compare results

Community findings will be grouped into four categories.

**Confirmed by repeat testing**

The observation was reproduced with supporting evidence.

**Not observed**

The test was completed, but the behaviour did not appear.

**Different result**

Traffic appeared, but the domains, ports or circumstances were different.

**Inconclusive**

There was insufficient evidence to reach a conclusion.

We will not treat a single person's result as proof that all Android devices behave the same way.

## 14.4 Submit your findings

Please use the public GitHub repository:

https://github.com/700-glitch/ola-radio-audit

You can:

- Open a GitHub Issue describing your results.
- Submit screenshots.
- Attach appropriately redacted PCAP files.
- Submit a pull request containing additional research.
- Correct technical errors.
- Provide independent explanations.

Suggested GitHub Issue title:

`Community Test Results — Ola Radio Network Behaviour — [Device Model]`

Please include your Android version, Ola Radio version, network type and the exact steps you performed.

## 14.5 Protect your privacy

Before sharing screenshots or capture files, remove or obscure:

- Public or private IP addresses where appropriate.
- Account names.
- Email addresses.
- Authentication tokens.
- Passwords.
- Device serial numbers.
- Telephone numbers.
- Private communications.
- Personal identifiers.

Do not upload unredacted account information or credentials.

Only share information you are comfortable making public.

## 14.6 Why independent testing matters





ola-radio-audit/
├── README.md
├── evidence/
│   ├── 01-device-information/
│   ├── 02-original-pcap/
│   ├── 03-dns-observations/
│   ├── 04-tls-certificates/
│   ├── 05-application-analysis/
│   ├── 06-screenshots/
│   └── 07-test-results/
├── research/
│   ├── fa-fa-domains.md
│   ├── vo1d-research.md
│   └── infrastructure.md
├── methodology/
│   └── repeatable-tests.md
└── CHANGELOG.md



If several people reproduce the same behaviour using different Android devices and different internet connections, the finding becomes more useful.

If other people cannot reproduce it, that is also valuable.

Differences may help identify:

- Device-specific behaviour.
- Android-version differences.
- Application-version differences.
- Network-provider differences.
- Third-party services.
- Background system activity.

The purpose is to develop an evidence base that other people can examine and challenge.

**Please test independently. Please report honestly. Please share results whether they support or contradict the original observations.**

---

# 15. Responsible disclosure and communication

This project is intended to encourage technical transparency and constructive discussion.

It does not accuse Ola Radio's developers of knowingly distributing malware or conducting malicious activity.

The application operator should have the opportunity to respond to the technical questions in this report.

If the operator provides an explanation or technical documentation, it should be reviewed and incorporated into a future revision where appropriate.

If independent researchers identify an error in this report, corrections are welcome.

The quality of the investigation depends on evidence, not on whether the findings support an initial suspicion.

---

# 16. Limitations

The following limitations must be considered when interpreting this report:

- The investigation primarily involved one Android tablet.
- The investigator reports that the tablet was brand new and factory-reset before testing.
- The original PCAPdroid captures and connection history were deleted.
- Some findings are based on historical observations and recollection.
- The original packet contents cannot currently be re-examined.
- Encrypted payloads were not decrypted.
- The Ola Radio application was not reverse-engineered.
- Private application backend systems were not inspected.
- Domain ownership has not been independently established for every reported domain.
- The ShadowServer nameserver observation requires revalidation.
- The device-discovery Stop observation requires controlled reproduction.
- The background-activity observation requires controlled reproduction.
- The reported cellular DNS request does not establish a successful connection.
- No formal penetration test was performed.

This document should therefore be treated as an independent observational investigation and a request for further research, not a formally accredited security audit.

---

# 17. Conclusion

The investigation has identified several network observations that warrant further technical clarification.

The most significant is the reported FAFA domain family following the pattern:

`[five-character prefix]2940637fafa.com`

The same suffix appears in public 2025 research concerning the Vo1d Android botnet's domain-generation activity.

That is a meaningful threat-intelligence correlation, but it is not proof that Ola Radio or the Android tablet is infected.

Earlier PCAPdroid observations reportedly associated some FAFA-related activity with TCP port 55530. This port must not be confused with TCP ports 55520 and 55521 discussed in separate Vo1d research.

The investigator also reported FAFA-related activity on both Wi-Fi and cellular mobile data.

The reported association with pressing Stop during device discovery is another important lead, but it needs to be reproduced using fresh captures.

The original PCAPdroid evidence has been deleted. Consequently, the observations must remain historical and provisional until they can be independently reproduced.

At present, the origin and purpose of the FAFA-related traffic remain unknown.

The central questions are:

- Which application or system component generates the requests?
- What is the purpose of the FAFA domain family?
- Why was TCP port 55530 observed?
- Does the device-discovery Stop action trigger the activity?
- Does the behaviour occur on other Android devices?
- What information, if any, is exchanged?
- What explanation can the application operator provide?

**The findings justify further investigation and a request for technical clarification. They do not establish malware infection, data theft or malicious intent.**

This project remains open to independent testing, corrections and community contributions.

The goal is simple:

**Observe the traffic. Preserve the evidence. Repeat the tests. Compare the results. Establish the facts.**

---

# END OF REPORT

**OLA RADIO — INDEPENDENT NETWORK BEHAVIOUR, INFRASTRUCTURE AND PRIVACY INVESTIGATION**

**Version 2.0 — 17 November 2026**

**Independent research. Evidence-led conclusions. Community testing welcome.**
