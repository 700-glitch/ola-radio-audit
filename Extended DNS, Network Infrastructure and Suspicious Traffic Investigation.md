# OLA RADIO
## Extended DNS, Network Infrastructure and Suspicious Traffic Investigation 

**Investigation version:** 2.2  
**Date:** 17 November 2026  
**Status:** Open investigation — additional evidence recorded  
**Investigation type:** Independent observational network and privacy investigation  
**Relationship to Version 2.0:** Supplementary extension. Version 2.0 remains unchanged.

---

# 1. Executive summary

This report documents additional network observations involving the Ola Radio Android application.

The investigation examined two distinct areas:

1. Suspicious DNS and TCP activity involving hostnames matching the pattern `*.2940637fafa.com`.
2. Infrastructure and routing associated with `international.olaradio.top` and `euweb2c.olaradio.top`.

The FAFA-pattern investigation identified several unusual hostnames, DNS lookups and TCP connections attributed to Ola Radio by PCAPdroid. Three recorded TCP destination addresses were subsequently found in a fresh DNS lookup of `bxrkf2940637fafa.com`.

The infrastructure investigation identified Cloudflare-associated addresses for the international hostname and an Alibaba Cloud-registered network allocation for the EU hostname. TCP traceroutes showed different network paths, including a route through Singapore towards the EU hostname's destination IP.

The observations warrant further investigation. They do not independently prove malware infection, command-and-control activity, personal-data exfiltration or malicious intent.

# 2. Scope and methodology

The following tools and sources were used during the investigation:

- Android tablet running Ola Radio.
- PCAPdroid for connection metadata.
- Kali Linux for DNS, hexadecimal and network analysis.
- `dig` for DNS queries.
- `xxd` for inspection of binary data.
- `traceroute` for TCP network-path observations.
- `whois` for IP network registration information.
- OpenSSL for TLS certificate inspection.
- Previously collected Android logcat observations.

The investigation combines direct device observations with independent network queries.

A distinction is maintained between:
- Observed application connections.
- DNS query and response evidence.
- Independent tests conducted from Kali Linux.
- External research correlations.
- Hypotheses requiring further verification.

# 3. Suspicious DNS activity: `2940637fafa.com`

## 3.1 Observed domain pattern

Several hostnames were observed following this general pattern:

`[five characters]2940637fafa.com`

The following hostnames were reported during the investigation:

| Hostname | Observation |
|---|---|
| `bxrkf2940637fafa.com` | DNS query and response evidence |
| `eibrt2940637fafa.com` | PCAPdroid TCP connection |
| `govel2940637fafa.com` | PCAPdroid TCP connection |
| `yapwk2940637fafa.com` | PCAPdroid TCP connection |
| `fpiml2940637fafa.com` | DNS lookup observed in logcat |
| `lbjzh2940637fafa.com` | DNS lookup observed in logcat |

The repeated hostname structure is unusual and merits investigation.

## 3.2 Historical DNS query: `bxrkf2940637fafa.com`

Evidence file:

`PCAPdroid_17_Nov_15_10_36.txt`

The file was examined using:

```bash
xxd -g 1 ~/Downloads/PCAPdroid_17_Nov_15_10_36.txt
```

The readable DNS structure identified:

- Query hostname: `bxrkf2940637fafa.com`
- Record type: A
- Record class: IN
- Question count: 1
- Answer records in the query: 0

The first two DNS transaction-ID bytes were not reliably recoverable because the file contained UTF-8 replacement sequences (`ef bf bd`).

The evidence supports the presence of a DNS A-record query for the hostname.

## 3.3 Historical DNS response

Evidence file:

`PCAPdroid_17_Nov_15_10_48.txt`

The file was examined using:

```bash
xxd -g 1 ~/Downloads/PCAPdroid_17_Nov_15_10_48.txt
```

The readable structure indicated:

- Matching hostname: `bxrkf2940637fafa.com`
- Record type: A
- Record class: IN
- Question count: 1
- Answer count: 10
- Answer record length: 4 bytes
- TTL represented in the answer records: 59 seconds

The file contained repeated UTF-8 replacement sequences. This indicates that some original binary data was converted or corrupted during text handling.

Consequently, the historical response's ten IP addresses cannot be reliably reconstructed from this copy.

The existence of ten answer records can be identified from the readable structure, but their original address values must not be guessed.

## 3.4 Fresh DNS lookup

A new DNS query was performed in Kali Linux:

```bash
dig bxrkf2940637fafa.com A +noall +answer
```

The returned records were:

| No. | IPv4 address | TTL |
|---:|---|---:|
| 1 | `178.162.202.96` | 60 |
| 2 | `64.62.203.97` | 60 |
| 3 | `85.17.70.16` | 60 |
| 4 | `46.165.199.9` | 60 |
| 5 | `46.165.199.7` | 60 |
| 6 | `85.17.155.53` | 60 |
| 7 | `85.17.70.38` | 60 |
| 8 | `178.162.202.97` | 60 |
| 9 | `85.17.155.52` | 60 |
| 10 | `64.62.203.98` | 60 |

The current lookup returned ten IPv4 A records.

This is consistent with the ten-answer structure identified in the historical response, although it does not prove that the historical and current address lists were identical.

DNS answers can change over time.

## 3.5 Correlation between DNS addresses and PCAPdroid connections

An important additional observation is that three addresses from the fresh DNS lookup match destination IPs recorded in earlier PCAPdroid connections involving FAFA-pattern hostnames.

| PCAPdroid hostname | Recorded destination IP | Present in fresh DNS results? |
|---|---|---|
| `eibrt2940637fafa.com` | `178.162.202.97` | Yes |
| `govel2940637fafa.com` | `85.17.155.52` | Yes |
| `yapwk2940637fafa.com` | `64.62.203.98` | Yes |

All three recorded connections used destination TCP port `55530`.

This is a meaningful correlation between the currently returned DNS address pool and previously observed application connection destinations.

However, the fresh DNS lookup does not prove that these were the exact addresses returned in each historical DNS response. Nor does it prove that all three connections used the same DNS response or occurred at the same time as the current lookup.

## 3.6 PCAPdroid connection observations

The following connection records were previously reported.

### Connection 1: `eibrt2940637fafa.com`

- Application attribution: Ola Radio
- Protocol: TCP
- SNI/hostname: `eibrt2940637fafa.com`
- Destination: `178.162.202.97:55530`
- Status: Closed
- Received: approximately 40 bytes
- Sent: approximately 300 bytes
- Packets: 1 received, 5 sent
- Duration: approximately one minute, based on the earlier description

### Connection 2: `govel2940637fafa.com`

- Application attribution: Ola Radio
- Protocol: TCP
- SNI/hostname: `govel2940637fafa.com`
- Destination: `85.17.155.52:55530`
- Status: Closed
- Received: approximately 40 bytes
- Sent: approximately 300 bytes
- Packets: 1 received, 5 sent

### Connection 3: `yapwk2940637fafa.com`

- Application attribution: Ola Radio
- Protocol: TCP
- SNI/hostname: `yapwk2940637fafa.com`
- Destination: `64.62.203.98:55530`
- Status: Active at the time of observation
- Received: approximately 128 bytes
- Sent: approximately 184 bytes
- Packets: 3 received, 4 sent
- Reported payload: approximately 4 bytes
- Duration: approximately 30 seconds at the time described

The byte and duration figures are based on previously reported PCAPdroid details and should be checked against original records before being treated as exact published measurements.

The connections establish that PCAPdroid attributed TCP activity to Ola Radio involving these hostnames and destinations.

They do not establish the meaning of the transmitted data.

The relatively small traffic volumes are not sufficient to determine whether the connections carried telemetry, control messages, routine service checks or another type of communication.

# 4. External research correlation

A 2025 Virus Bulletin conference paper on the Vo1d botnet documented a domain-generation pattern involving five-character prefixes followed by:

`2940637fafa.com`

The research described generated domains, command-and-control infrastructure and DNS-based correlations associated with the Vo1d malware family.

The observed Ola Radio hostname pattern is therefore consistent with a pattern documented in malware research.

This is a significant investigative lead.

However, pattern similarity alone does not establish:

- That the Android tablet is infected with Vo1d.
- That Ola Radio contains Vo1d malware.
- That the application developer controls the observed domains.
- That the observed connections are command-and-control communications.
- That the traffic contains personal information.
- That the observed infrastructure is malicious in this particular context.

The research correlation should be treated as a reason for deeper examination, not as proof of attribution.

# 5. Contextual Android observations

Additional logcat observations previously recorded include:

- A Bluetooth LE scan started at approximately 14:26:09.
- A lookup for `fpiml2940637fafa.com` occurred at approximately 14:26:14.
- No Bluetooth pairing or completed connection was established in the reviewed excerpt.
- A lookup for `lbjzh2940637fafa.com` occurred at approximately 14:32:47 while the tablet was being used in an idle/screen-wake observation.
- The app was left running during these observations.

These timings are noteworthy because they show DNS activity around Bluetooth scanning and periods when the application was not being actively navigated.

They do not establish that the Bluetooth scan caused the DNS query or that Bluetooth information was transmitted.

Further correlated packet captures and application-level analysis would be needed to establish causation.

# 6. EU hostname infrastructure: `euweb2c.olaradio.top`

## 6.1 DNS resolution

The following query was performed:

```bash
dig euweb2c.olaradio.top A +noall +answer
```

Returned addresses:

- `139.95.12.59`
- `139.95.12.172`

Both records had a reported TTL of 300 seconds.

An earlier raw DNS response also contained these two addresses.

## 6.2 PCAPdroid connection

The reported PCAPdroid record contained:

- Application: Ola Radio
- Hostname/SNI: `euweb2c.olaradio.top`
- Protocol: TCP/TLS
- Destination IP: `139.95.12.172`
- Destination port: reported as `702`
- Status: Closed
- Duration: approximately 9 seconds
- Received traffic: approximately 6.5 KB
- Sent traffic: approximately 2.1 KB

The destination address matches one of the DNS answers.

The port number should be checked against the original PCAPdroid record before publication.

## 6.3 TLS ClientHello

A 257-byte binary payload was inspected.

It contained a TLS ClientHello with:

- SNI: `euweb2c.olaradio.top`
- TLS 1.3 offered
- Cipher suite `13 01` among the offered cipher suites

This supports the identification of TLS communication with the EU hostname.

The inspected file was a raw payload, not a complete PCAP capture.

## 6.4 WHOIS information

WHOIS results for both destination addresses identified the allocation:

- NetRange: `139.95.0.0 - 139.95.255.255`
- CIDR: `139.95.0.0/16`
- NetName: `AL-3`
- Organisation: Alibaba Cloud LLC (AL-3)
- Registry: ARIN

This identifies the registered network allocation, not the exact service operator or physical server location.

# 7. International hostname infrastructure: `international.olaradio.top`

## 7.1 DNS resolution

The query:

```bash
dig international.olaradio.top A +noall +answer
```

returned:

- `172.67.157.1`
- `104.21.48.239`

Both addresses are associated with Cloudflare's network.

## 7.2 PCAPdroid connection

The reported record showed:

- Application: Ola Radio
- Hostname/SNI: `international.olaradio.top`
- Protocol: HTTPS over TCP
- Destination: `104.21.48.239:443`
- Status: Closed
- Duration: approximately 14 seconds
- Received: approximately 17.2 KB
- Sent: approximately 9.1 KB

The destination matches one of the DNS A records.

## 7.3 WHOIS information

The WHOIS result for `104.21.48.239` identified:

- NetRange: `104.16.0.0 - 104.31.255.255`
- CIDR: `104.16.0.0/12`
- NetName: `CLOUDFLARENET`
- Organisation: Cloudflare, Inc.

This identifies the registered network allocation, not the physical origin server.

## 7.4 Authoritative DNS

The domain's name-server query returned:

- `nelly.ns.cloudflare.com`
- `nolan.ns.cloudflare.com`

This identifies Cloudflare as the authoritative DNS provider for `olaradio.top`.

It does not prove that all application services are hosted directly by Cloudflare.

# 8. TLS certificate findings

OpenSSL inspection of `international.olaradio.top` returned:

- Subject: `CN=olaradio.top`
- Issuer: Google Trust Services, WE1
- Valid from: 21 September 2026
- Valid until: 20 December 2026

The Subject Alternative Name extension contained:

- `DNS:olaradio.top`
- `DNS:*.olaradio.top`

The wildcard certificate covers the two investigated subdomains:

- `international.olaradio.top`
- `euweb2c.olaradio.top`

This demonstrates a shared certificate identity across the two hostnames.

It does not prove that the services use the same server, backend or hosting provider.

Google Trust Services is the certificate authority, not proof of Google hosting.

# 9. Network routing investigation

TCP traceroutes were conducted from Kali Linux.

## 9.1 Cloudflare destination

Command:

```bash
sudo traceroute -T -p 443 104.21.48.239
```

The trace completed in nine hops.

Notable results:

- Hop 1: local router `192.168.1.1`
- Hop 2: `lon.the.boxbb.uk`
- Hops 6–8: Cloudflare-associated `141.101.71.x` addresses
- Hop 9: `104.21.48.239`

Final-hop response times were approximately 8–14 milliseconds.

No visible US or Singapore network leg appeared in the trace.

## 9.2 Alibaba Cloud-allocated destination — TCP port 443

Command:

```bash
sudo traceroute -T -p 443 139.95.12.172
```

The route showed:

- London
- Amsterdam
- Vienna
- Singapore
- Further responding network hops

The NTT router names included:

- `londen12.uk`
- `amstnl07.nl`
- `vienat02.at`
- `sngpsi07.sg`

The Singapore-associated hops responded at approximately 177–193 milliseconds.

The destination did not respond within the 30-hop limit.

## 9.3 Alibaba Cloud-allocated destination — TCP port 702

Command:

```bash
sudo traceroute -T -p 702 139.95.12.172
```

This test reproduced the same identifiable route:

- London
- Amsterdam
- Vienna
- Singapore
- Further responding hops

The Singapore-associated hops again responded at approximately 179–191 milliseconds.

The destination did not respond within the 30-hop limit.

This is particularly relevant because port 702 was the destination port reported in the PCAPdroid record for `euweb2c.olaradio.top`.

It remains an independent Kali-originated route test rather than a direct reconstruction of the tablet's original traffic.

# 10. Geographic interpretation and correction

An earlier working hypothesis considered a possible UK–USA–Singapore route.

The traceroute evidence collected does not support presenting that route as established.

The corrected interpretation is:

**Cloudflare destination:**

The tested route reached the Cloudflare-associated destination through the local network and Cloudflare-associated hops. No visible US or Singapore leg appeared.

**EU hostname destination:**

The tested route to `139.95.12.172` passed through London, Amsterdam, Vienna and Singapore before continuing through further network hops.

No visible US leg appeared in either supplied traceroute.

This is an important distinction:

- Corporate registration does not establish physical server location.
- IP allocation does not establish the physical location of the server.
- A Cloudflare IP registered to a US organisation does not prove that traffic physically travelled through the United States.
- A route through Singapore does not prove that the destination server is physically located in Singapore.

The most defensible finding is that the tested network path to the EU hostname's destination traversed Singapore-associated network infrastructure.

# 11. Evidence assessment

## 11.1 Established observations

The investigation has recorded:

1. DNS queries for multiple FAFA-pattern hostnames.
2. A historical DNS response structure containing ten A-record answers for `bxrkf2940637fafa.com`.
3. A fresh DNS lookup returning ten IPv4 addresses for that hostname.
4. Three current DNS results matching previously observed PCAPdroid TCP destination IPs.
5. Three reported PCAPdroid TCP connections to FAFA-pattern hostnames on port 55530.
6. Additional FAFA-pattern DNS lookups around Bluetooth scanning and idle observations.
7. DNS resolution and PCAPdroid connection evidence for `euweb2c.olaradio.top`.
8. DNS resolution and PCAPdroid connection evidence for `international.olaradio.top`.
9. Cloudflare authoritative DNS and network allocation information.
10. Alibaba Cloud network allocation information for the EU hostname's destination IPs.
11. A wildcard TLS certificate covering both investigated subdomains.
12. A repeatable route through Singapore to `139.95.12.172` using TCP ports 443 and 702.

## 11.2 Investigative concerns

The repeated five-character-plus-`2940637fafa.com` hostname pattern is noteworthy because it resembles a domain-generation pattern documented in Vo1d botnet research.

The PCAPdroid connection records make this more significant than a hostname-pattern observation alone.

The correspondence between three current DNS addresses and three previously recorded TCP destinations is an additional investigative lead.

The relationship between the FAFA-pattern traffic, Ola Radio, any included SDKs and the documented malware family remains unresolved.

## 11.3 What has not been proven

This investigation has not established:

- That the tablet is infected with Vo1d.
- That Ola Radio is malware.
- That the FAFA-pattern traffic is command-and-control communication.
- That personal data was transmitted.
- That the application transmitted location or Bluetooth information.
- That the destination servers are physically located in Singapore.
- That the app's developers own or control the identified infrastructure.
- That the encrypted TLS payload contains malicious instructions or sensitive information.

These remain open questions.

# 12. OWASP-aligned follow-up work

The next technical phase should use relevant OWASP Mobile Application Security Verification Standard (MASVS) and Mobile Application Security Testing Guide (MASTG) principles.

Potential follow-up work includes:

- Network communication and TLS configuration review.
- Identification of all application network destinations.
- Correlation of DNS requests with individual TCP connections.
- Full PCAP/PCAPNG capture and packet-level analysis.
- Investigation of third-party SDK network behaviour.
- Runtime observation of Bluetooth and location-related activity.
- Examination of application permissions and their actual runtime use.
- Verification of whether any sensitive information appears in network payloads.

This is an OWASP-aligned investigation, not a completed MASVS assessment or certification.

# 13. Evidence preservation

The following evidence should be retained in its original form:

### FAFA DNS evidence

- `PCAPdroid_17_Nov_15_10_36.txt`
- `PCAPdroid_17_Nov_15_10_48.txt`
- Fresh `dig` output for `bxrkf2940637fafa.com`

### EU hostname evidence

- Raw DNS query and response payloads.
- TLS ClientHello binary payload.
- PCAPdroid connection record.
- DNS output.
- WHOIS output.
- TCP traceroute outputs for ports 443 and 702.

### International hostname evidence

- PCAPdroid connection record.
- DNS output.
- WHOIS output.
- OpenSSL certificate and SAN outputs.
- TCP traceroute output for port 443.

### Contextual Android evidence

- Relevant logcat excerpts.
- Bluetooth scanning observations.
- Timestamped FAFA hostname lookup observations.

Original files should remain unchanged. Redacted or converted copies should be kept separately.

# 14. Overall conclusion

This supplementary investigation has identified a recurring group of unusual DNS hostnames associated with the Ola Radio testing environment, together with PCAPdroid TCP connection records involving three of those hostnames.

The fresh DNS lookup for `bxrkf2940637fafa.com` returned ten IPv4 addresses, three of which matched destination addresses from the previously observed FAFA-pattern TCP connections.

This provides an additional correlation that warrants continued examination.

Separately, the network infrastructure investigation identified Cloudflare-associated international service addresses and an Alibaba Cloud-registered allocation associated with the EU hostname.

TCP traceroutes showed that the tested route to the EU destination traversed London, Amsterdam, Vienna and Singapore. The same identifiable route was observed using TCP port 702, matching the reported PCAPdroid destination port.

The earlier suggestion of a demonstrated US network leg has been corrected because the supplied traceroutes did not show one.

The combined evidence supports continued independent investigation of Ola Radio's network behaviour and infrastructure. It does not yet establish malicious activity, malware attribution or personal-data exfiltration.

**Final assessment: Open investigation. Significant additional network and DNS evidence recorded. Further packet-level and application-level verification required.**

---

*This document is an independent observational investigation record. It is not a formal penetration test, security certification, or completed OWASP MASVS assessment.*
