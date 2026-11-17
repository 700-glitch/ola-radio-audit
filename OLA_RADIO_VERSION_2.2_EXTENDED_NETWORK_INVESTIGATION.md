# OLA RADIO — VERSION 2.2
## Extended Network Investigation: Repeated Connections, DNS Activity and Infrastructure Analysis

**Investigation type:** Independent Android application network investigation  
**Application:** Ola Radio  
**Android package:** `com.aewt.app.friends`  
**Application version observed:** 2.5.9  
**Investigation date:** 17 November 2026  
**Report version:** 2.2  
**Status:** Ongoing investigation  
**Repository:** https://github.com/700-glitch/ola-radio-audit

---

## 1. Executive Summary

This report extends the earlier independent investigation into the network behaviour of the Android application Ola Radio.

The investigation examined network activity captured from an Android tablet using PCAPdroid, with supporting analysis conducted on Kali Linux.

The most significant finding in this phase is a repeated pattern of application-attributed TCP connections to external IP addresses on destination port `55530`. These connections were associated by PCAPdroid with a changing series of hostnames ending in:

`2940637fafa.com`

The relevant TCP connection records identify:

- Application: Ola Radio
- Android package: `com.aewt.app.friends`
- Android UID: `10070`
- Destination port: `55530`

The capture includes multiple connections to different IP addresses, with DNS hostname information associated with the TCP records.

A further notable finding is that three of the destination IP addresses belong to a network allocation registered to The Shadowserver Foundation.

The evidence establishes that the application-attributed connections were attempted. It does not establish the purpose of those connections, the identity of the operator behind the domain, or whether the activity is malicious.

The investigation also identified ordinary application infrastructure, including connections associated with Ola Radio's own domains, Cloudflare-hosted services, and MapLibre map-tile infrastructure.

The purpose of this report is to document the observed behaviour accurately, preserve the technical evidence, and provide a foundation for further independent examination.

## 2. Scope and Objectives

This phase focused on:

1. Identifying network connections attributed to Ola Radio.
2. Examining repeated DNS activity involving the `2940637fafa.com` hostname family.
3. Identifying destination IP addresses and network ownership.
4. Comparing unusual traffic with the application's ordinary network infrastructure.
5. Preserving the captured evidence and its file integrity.
6. Identifying what can and cannot reasonably be concluded from the available data.

This is an independent investigation, not a formal penetration test, commissioned security audit, or certification exercise.

No claim of complete application coverage is made.

## 3. Test Environment and Tools

### Android device

- Android tablet
- Wi-Fi network connection
- USB connection to Kali Linux for ADB access
- No SIM card or mobile-data connection used during the investigation

### Analysis workstation

- Kali Linux
- Android Debug Bridge (ADB)
- PCAPdroid
- `dig`
- `whois`
- `sha256sum`
- Standard Linux command-line analysis tools

### Network capture

PCAPdroid was configured to monitor Ola Radio's traffic.

The application-specific connection records were associated with:

- UID: `10070`
- Package: `com.aewt.app.friends`

The package name and UID were also examined through Android debugging.

This provides a useful attribution mechanism for the captured TCP connections.

An important distinction applies to DNS records: the DNS entries in the supplied PCAPdroid CSV are labelled UID 0 (Root). They represent Android resolver activity, rather than direct proof that the application process itself emitted the DNS packets.

The TCP connection records, by contrast, explicitly identify the Ola Radio UID and package.

## 4. Application Identification

The application examined was identified as:

| Property | Observed value |
|---|---|
| Application name | Ola Radio |
| Package | `com.aewt.app.friends` |
| Version name | 2.5.9 |
| Version code | 49 |
| Target SDK | 36 |
| Minimum SDK | 24 |
| Android UID | 10070 |

The application uses the main activity:

`com.aewt.app.aewt.MainActivity`

The package and UID information provides the basis for interpreting the application-attributed traffic in the captures.

## 5. Principal Finding: Repeated Connections to the 2940637fafa.com Hostname Family

### 5.1 Overview

The investigation identified repeated connections associated with hostnames ending in:

`2940637fafa.com`

The hostnames use changing five-character prefixes.

Examples observed include:

- `eeaak2940637fafa.com`
- `xrpsq2940637fafa.com`
- `icpvn2940637fafa.com`
- `wmdww2940637fafa.com`
- `lvgjo2940637fafa.com`
- `nplvy2940637fafa.com`
- `brecy2940637fafa.com`
- `wqswl2940637fafa.com`
- `ldvgf2940637fafa.com`
- `kcxru2940637fafa.com`
- `ukjwb2940637fafa.com`
- `jpkhj2940637fafa.com`
- `jzldt2940637fafa.com`
- `fpiml2940637fafa.com`
- `kakig2940637fafa.com`

The changing prefixes and repeated structure are unusual enough to warrant further investigation.

The pattern is compatible with dynamically generated or algorithmically varied hostnames, but the available evidence does not establish that a domain-generation algorithm is being used.

### 5.2 Application attribution

The latest PCAPdroid CSV contains TCP connection records identifying:

- UID `10070`
- Application `Ola Radio`
- Package `com.aewt.app.friends`

The connections were made to external IP addresses on TCP port `55530`.

The `Info` field associates the relevant TCP records with the unusual hostname family.

This is important because the finding is not based solely on DNS queries appearing at approximately the same time as application activity.

The TCP records themselves provide application attribution and hostname association.

### 5.3 Latest capture: 17 November 2026

The principal capture examined in this phase was:

`PCAPdroid_17_Nov_20_56_10.csv`

The following connections were present:

| Approximate UTC time | Hostname | Destination IP | Port | PCAPdroid status |
|---|---|---|---:|---|
| 20:52:20 | eeaak2940637fafa.com | 3.250.92.156 | 55530 | Closed |
| 20:52:50 | xrpsq2940637fafa.com | 47.76.118.67 | 55530 | Closed |
| 20:52:56 | nplvy2940637fafa.com | 162.249.71.240 | 55530 | Error |
| 20:52:56 | brecy2940637fafa.com | 162.249.71.239 | 55530 | Error |
| 20:52:56 | wqswl2940637fafa.com | 85.17.155.52 | 55530 | Closed |
| 20:53:26 | ldvgf2940637fafa.com | 162.249.71.238 | 55530 | Error |
| 20:53:27 | kcxru2940637fafa.com | 85.17.155.52 | 55530 | Closed |
| 20:53:57 | ukjwb2940637fafa.com | 85.17.70.16 | 55530 | Closed |
| 20:54:27 | jpkhj2940637fafa.com | 178.162.202.97 | 55530 | Closed |
| 20:54:58 | jzldt2940637fafa.com | 85.17.155.52 | 55530 | Closed |
| 20:55:28 | fpiml2940637fafa.com | 178.162.202.96 | 55530 | Active at export |
| 20:55:58 | kakig2940637fafa.com | 178.162.202.97 | 55530 | Active at export |

All listed TCP records were attributed by PCAPdroid to UID `10070`, Ola Radio, package `com.aewt.app.friends`.

There were also DNS entries for several additional hostnames in the same family for which no corresponding TCP record appeared in this particular excerpt.

### 5.4 Connection behaviour

The captured connections show variation in the amount of data transferred.

Examples include:

- Some connections transferred approximately 300 bytes outbound and 40 bytes inbound.
- Some transferred 224 bytes outbound and 168 bytes inbound.
- Three connections to the Shadowserver-registered addresses showed 60 bytes outbound and 40 bytes inbound.
- Two connections were still marked Active when the CSV was exported, with 300 bytes sent and no received bytes recorded at that point.

The repeated use of port `55530` is a notable characteristic of this traffic.

The connection status values must be interpreted carefully:

- `Closed` means the connection was closed when recorded.
- `Error` indicates a connection error.
- `Active` means the connection was still active at the time of export.

These statuses do not, by themselves, identify the application-layer protocol or the purpose of the communication.

### 5.5 Timing pattern

Earlier captures also showed repeated DNS activity involving different hostnames from the same family.

In one earlier capture, DNS queries occurred at approximately 40-second intervals, with a second query to `8.8.8.8` approximately five seconds after the initial resolver query.

The later capture contains application-attributed TCP connections to the same hostname family.

Taken together, these observations provide evidence of recurring network activity associated with the application.

Further packet-level examination is required to determine what the connections actually communicate.

## 6. Shadowserver Foundation Network Addresses

Three destination addresses in the latest capture were examined:

- `162.249.71.238`
- `162.249.71.239`
- `162.249.71.240`

WHOIS lookups identified these addresses as belonging to a network allocation registered to:

**The Shadowserver Foundation**

The relevant registration information included:

- Network allocation: `162.249.68.0 – 162.249.71.255`
- Network name: `THESH-162-249-68-0`
- Organisation: The Shadowserver Foundation
- Country registration: United States
- Origin ASN: `AS22168`

The three application-attributed TCP connection records to these addresses were all marked `Error`.

Each showed:

- 60 bytes sent
- 40 bytes received
- One packet sent
- One packet received
- Destination port `55530`

### Interpretation

The observed connections establish that Ola Radio-attributed TCP connection attempts were made to addresses within a network allocation registered to The Shadowserver Foundation.

This is a noteworthy finding.

However, it does not establish:

- Why the application contacted these addresses.
- Whether the Foundation itself operated the specific destination service.
- Whether the addresses were being used for research, scanning, monitoring, sinkholing, or another purpose.
- Whether any successful application-level exchange took place.
- Whether the activity was initiated intentionally by the application's developers.

The Foundation's network registration is evidence of allocation and organisational association, not evidence of the purpose of the traffic.

This finding should be investigated further rather than presented as proof of malicious behaviour or an investigation into the device.

## 7. DNS Resolution and Supporting Evidence

### 7.1 Earlier DNS capture

An earlier file was examined:

`PCAPdroid_17_Nov_20_34_37.csv`

This capture contained DNS records for several unusual hostnames, including:

- `xrpsq2940637fafa.com`
- `wmdww2940637fafa.com`
- `icpvn2940637fafa.com`
- `lvgjo2940637fafa.com`

The DNS records in that file were labelled UID 0.

This capture therefore provides evidence of DNS resolution activity but does not, by itself, attribute the queries to the Ola Radio process.

### 7.2 Independent DNS lookup

A subsequent DNS lookup was performed for:

`xrpsq2940637fafa.com`

The lookup returned:

`47.76.118.67`

This matched the destination address shown in the later PCAPdroid TCP record for that hostname.

This provides an additional consistency check between DNS resolution and the destination recorded in the application-attributed TCP connection.

A current DNS lookup does not independently prove what DNS answer was returned at an earlier capture time. The PCAPdroid connection record is the relevant historical evidence.

### 7.3 Earlier raw DNS packet examination

A small raw DNS packet extract was also examined.

The query contained:

`kwbcx2940637fafa.com`

A corresponding response contained:

- Matching DNS transaction ID
- Successful DNS response status
- One A record
- TTL of 430 seconds
- Returned IPv4 address: `3.132.75.97`

This demonstrates that the hostname was resolved to an IPv4 address in that packet exchange.

The raw files examined were small packet extracts, not complete PCAP or PCAPNG capture files. They should not be represented as complete network captures.

## 8. Historical Research Correlation

During earlier research, a possible correlation was identified between the suffix:

`2940637fafa`

and a hostname/IP combination discussed in publicly available XLab research concerning the Vo1d malware family.

The IP address `3.132.75.97` was also observed in the earlier DNS packet examination.

This correlation is worth recording because it provides a possible avenue for further research.

However, a shared domain suffix or IP address does not establish:

- That the tablet is infected with Vo1d.
- That Ola Radio contains Vo1d malware.
- That the same operator controls the observed infrastructure.
- That the observed traffic has the same purpose as traffic described in the earlier research.

No malware infection conclusion is made in this report.

The correlation is a research lead, not a confirmed attribution.

## 9. Ordinary Application Infrastructure

The investigation also observed connections to domains associated with Ola Radio's normal operation.

These included:

### 9.1 `international.olaradio.top`

Observed DNS addresses included:

- `172.67.157.1`
- `104.21.48.239`

The application made HTTPS connections to these addresses.

The IP ownership information identified Cloudflare infrastructure.

One observed connection transferred approximately:

- 10,238 bytes sent
- 17,845 bytes received

This is consistent with a substantially larger application communication session than the short connections observed on port `55530`.

### 9.2 `euweb2c.olaradio.top`

Observed server addresses included:

- `139.95.12.59`
- `139.95.12.172`

The application made TCP connections to port `7002`.

A connection to `139.95.12.172` was identified as TLS and transferred approximately:

- 2,757 bytes sent
- 7,721 bytes received

WHOIS information associated this server address with Alibaba Cloud.

The network path observed during traceroute included multiple international routing points. Traceroute does not establish the physical location of the server.

### 9.3 `demotiles.maplibre.org`

DNS and HTTPS connections associated with this hostname were observed.

The traffic is consistent with map-tile infrastructure.

The presence of map-tile traffic does not establish that the application transmitted precise device-location coordinates. That would require examination of the actual data exchanged.

## 10. TLS and Certificate Observations

Earlier examination identified a TLS certificate with:

- Common Name: `olaradio.top`
- Certificate authority: Google Trust Services
- Issuer: WE1
- Validity period observed: 21 September 2026 to 20 December 2026
- Subject Alternative Names including `olaradio.top` and `*.olaradio.top`

The certificate establishes that the relevant TLS endpoint presented a certificate covering the domain names listed.

It does not establish the trustworthiness of every service using the domain, the identity of the application's operator, or the content of encrypted communications.

## 11. Android Permissions and Application Capabilities

Earlier manifest examination identified permissions relating to:

- Internet access
- Audio and media functions
- Foreground services
- Camera access
- Bluetooth scanning and connection
- Fine and coarse location
- Boot completion
- Wake locks

These permissions describe capabilities available to the application under Android's permission model.

A permission declaration does not prove that the application exercised that capability.

The investigation also observed Bluetooth Low Energy scan activity around one period of unusual network activity.

The timing is worth recording, but the available logs did not establish a Bluetooth connection, pairing event, or causal relationship between Bluetooth activity and the unusual network connections.

Similarly, screen-state changes and network events were observed close together in some earlier logs. Timing alone does not establish causation.

## 12. App Attribution and Evidence Strength

The strongest attribution evidence in this phase comes from the PCAPdroid TCP connection records.

The relevant records identify:

- UID `10070`
- Application `Ola Radio`
- Package `com.aewt.app.friends`
- Destination IP
- Destination port
- Connection status
- Byte and packet counts
- Hostname information in the connection details

The Android package and UID were independently examined through ADB.

This supports the conclusion that the captured TCP connections were attributed to the Ola Radio application.

There are still important distinctions:

1. UID attribution identifies the Android application identity associated with a connection.
2. Hostname information associates a name with the connection record.
3. A destination IP identifies the network endpoint recorded by the capture.
4. None of these alone reveals the exact application-layer content or the purpose of the communication.

The evidence is sufficient to document the observed network behaviour and justify further investigation.

It is not sufficient to assign malicious intent or identify the responsible operator.

## 13. Evidence Integrity

The latest principal CSV file was preserved and hashed using SHA-256.

**Evidence filename:**

`PCAPdroid_17_Nov_20_56_10.csv`

**SHA-256:**

`5a13537f285b20e2eb48370ae10d2ca2bad823dc1b6b207b079152f2b2f0e5a0`

This checksum can be used to verify that a later copy of the file is byte-for-byte identical to the file that was hashed.

The checksum does not independently establish the capture's origin, date, or completeness.

The original file should remain unchanged. Any further processing should be performed on a separate working copy.

## 14. Findings Summary

| Finding | Evidence | Assessment |
|---|---|---|
| Repeated unusual hostname family | DNS records and TCP connection details | Observed |
| TCP connections on port 55530 | PCAPdroid connection records | Confirmed in capture |
| Ola Radio UID attribution | UID 10070 and package name in TCP records | Strong application attribution |
| Multiple changing destination IPs | PCAPdroid records | Observed |
| Three Shadowserver-registered destinations | WHOIS records and PCAPdroid connections | Confirmed network registration and connection attempts |
| Matching DNS result and TCP destination | DNS lookup and connection record | Consistent |
| Cloudflare application infrastructure | DNS, TCP and WHOIS observations | Observed |
| Alibaba Cloud-associated application server | WHOIS and connection observations | Observed |
| MapLibre-related traffic | DNS and HTTPS connection observations | Observed |
| Malware infection | No direct forensic proof | Not established |
| Malicious intent | No payload or operator attribution | Not established |
| Exact purpose of port 55530 traffic | No application-layer payload analysis | Unknown |

## 15. Limitations

The following limitations apply to this phase:

- The principal evidence examined is based on PCAPdroid CSV exports.
- The CSV connection records provide metadata rather than full application-layer payloads.
- DNS rows are attributed to UID 0, not directly to the application process.
- The raw DNS files examined are packet extracts rather than complete capture files.
- TLS-encrypted traffic cannot be interpreted fully from connection metadata alone.
- The purpose of the port `55530` communications has not been established.
- WHOIS registration does not establish who operated a particular service at the time of the connection.
- No independent laboratory reproduction has yet been completed.
- No formal reverse engineering of the complete application binary has been completed in this phase.
- The investigation does not constitute an exhaustive security audit.

These limitations do not invalidate the recorded connection observations. They define the boundaries of what can responsibly be concluded.

## 16. Recommended Further Investigation

The following work would strengthen the investigation.

### 16.1 Full packet capture

Obtain complete PCAP or PCAPNG captures covering the unusual connections.

The objective is to examine:

- TCP handshake behaviour
- Connection establishment and termination
- Application-layer protocol identification
- TLS negotiation, if applicable
- Server responses
- Any available unencrypted payload data

### 16.2 Controlled repeat testing

Repeat observations under documented conditions:

- Application installed but not running
- Application running in the foreground
- Application running in the background
- Device idle with screen off
- Application force-stopped

Record the precise time, capture settings, and device state for each test.

### 16.3 Domain and infrastructure research

Further investigate:

- Historical DNS records
- Domain registration information
- Certificate transparency records
- Historical IP associations
- Autonomous system and hosting information
- Whether the unusual hostname family appears in independent threat-intelligence research

### 16.4 Application examination

Where legally and technically appropriate, examine:

- Application package contents
- Embedded libraries
- Network configuration
- Background services
- Scheduled tasks and receivers
- Hard-coded hostnames and IP addresses
- Code paths responsible for network connections

### 16.5 Independent review

Provide the relevant evidence and methodology to independent Android security researchers for review.

Independent replication would materially strengthen the findings.

## 17. OWASP Mobile Security Framework Mapping

The investigation can be developed further using the OWASP Mobile Application Security Verification Standard (MASVS) and Mobile Application Security Testing Guide (MASTG) as reference frameworks.

Relevant areas include:

- Network communication security
- Data storage and privacy
- Platform interaction
- Code quality and application configuration
- Resilience and runtime behaviour
- Privacy-sensitive permission use

This report does not claim MASVS compliance or certification.

A future assessment should map each relevant control to:

- Test performed
- Evidence collected
- Result
- Limitations
- Not tested / not applicable status

## 18. Overall Assessment

The most significant result of this investigation phase is the repeated, application-attributed network activity involving the `2940637fafa.com` hostname family and TCP port `55530`.

The PCAPdroid records identify the connections with Ola Radio's Android UID and package.

Three of the recorded destinations fall within a network allocation registered to The Shadowserver Foundation. Those three connection records were marked as errors.

These are concrete observations that warrant further technical examination.

The investigation has not established that the application is malicious, that the device is infected, or that the traffic has a particular operational purpose.

Equally, the unusual network activity should not be dismissed merely because its purpose is currently unknown.

The appropriate conclusion is that the application exhibits recurring network behaviour that deserves explanation and further independent analysis.

## 19. Responsible Disclosure and Right of Reply

The findings are published for transparency, technical discussion, and independent scrutiny.

The application developer should be given a reasonable opportunity to explain the observed network behaviour and identify the purpose of the relevant domains, destination addresses, and port.

Any response or technical clarification received should be documented fairly.

If subsequent evidence changes the interpretation of these findings, this report should be updated accordingly.

No allegation of wrongdoing is made in this document.

## 20. Conclusion

This phase has advanced the investigation beyond DNS observations alone.

The latest PCAPdroid capture provides application-attributed TCP connection records linking Ola Radio with repeated communications involving a distinctive hostname family and destination port `55530`.

The identification of three destinations registered to The Shadowserver Foundation adds a further point requiring explanation.

The evidence has been preserved with a SHA-256 checksum, and the findings have been separated from hypotheses and unresolved questions.

The investigation remains open.

The next priority is to obtain fuller packet-level evidence, repeat the observations under controlled conditions, and seek independent technical review.

**The objective is not to accuse. It is to establish what the application does, document the evidence, and make the findings available for informed scrutiny.**

---

**Report status:** Version 2.2 — Supplementary investigation  
**Date:** 17 November 2026  
**Project:** Independent Ola Radio Network Investigation  
**Repository:** https://github.com/700-glitch/ola-radio-audit

*This report records observations from the investigation to date. It may be revised as additional evidence becomes available.*
