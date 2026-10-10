# Phishing-Email-Analysis
# Phishing Email Analysis Report

> **Case ID:** PHISH-2026-001  
> **Investigation type:** Email security triage / SOC Analyst Level 1  
> **Disposition:** **Likely phishing — high confidence based on the supplied evidence**  
> **Evidence source:** Screenshots of the raw email headers and VirusTotal results supplied for this analysis  
> **Sample email date:** 8 September 2023 (as shown in the captured headers)  
> **Analysis package prepared:** 10 October 2026

## 1. Executive Summary

The email impersonates a Microsoft account security notification with the subject **“Microsoft account unusual sign in activity.”** Several independent indicators make the message suspicious:

- The display name claims to be **Microsoft account team**, but the visible sender address uses `access-accsecurity[.]com` rather than an obviously Microsoft-owned domain.
- The `Reply-To` address is a Gmail address and differs from both the visible sender and the envelope/return-path domain.
- The captured authentication results show **SPF: none**, **DKIM: none**, and **DMARC: permerror**. These results do not establish that the email is authenticated as a legitimate Microsoft message.
- The supplied VirusTotal screenshot shows the linked URL with **9/92 detections**, with multiple vendors classifying it as phishing or malicious.
- In contrast, the supplied VirusTotal screenshot shows the sender IP `89.144.44.2` with **0/92 detections**. A clean IP reputation result does **not** make the email or its URL safe.
- The message HTML includes a hidden 1×1 image loaded from the same tracking path shown in the URL evidence. This is consistent with tracking, although a tracking pixel alone is not proof of malicious intent.

**Assessment:** Treat this message as a likely phishing email and do not follow its link. The strongest evidence is the URL reputation result combined with the identity mismatches and lack of successful email-authentication results. The available screenshots do not prove whether a recipient clicked the link or whether credentials were captured.

## 2. Email Snapshot

| Field | Observed value |
|---|---|
| Subject | `Microsoft account unusual sign in activity` |
| Display name | `Microsoft account team` |
| From address | `no-reply@access-accsecurity[.]com` |
| Reply-To | `sotrecongizd@gmail[.]com` (as displayed in the supplied header screenshot) |
| Return-Path | `bounce@thcultarfdes[.]co[.]uk` |
| Envelope / SMTP sender domain | `thcultarfdes[.]co[.]uk` |
| Sender IP reported in headers | `89.144.44.2` |
| Sample timestamp | `Fri, 8 Sep 2023 05:47:04 +0000` |
| URL host | `thebandalisty[.]com` |

*Defanging note:* Domains and URLs in this report use `[.]` and `hxxp` notation to reduce the chance of accidentally opening the suspected link. Values were transcribed from the supplied screenshots; confirm them against the original `.eml` file before using them in a production incident record.

## 3. Sender and Identity Analysis

### 3.1 Display name does not establish legitimacy

The display name is **Microsoft account team**, but the `From` address uses `access-accsecurity[.]com`. A display name can be chosen by the sender and is not proof that the message originated from Microsoft. The sender domain should therefore be treated as unverified.

### 3.2 Multiple identity fields do not align

The visible `From` domain (`access-accsecurity[.]com`), `Reply-To` domain (`gmail[.]com`), and `Return-Path` / SMTP sender domain (`thcultarfdes[.]co[.]uk`) are different. Different domains can occur in legitimate mail systems, so this is not conclusive by itself; in a message claiming to be an account-security alert, however, the discrepancy is a significant triage indicator.

![Full email header overview](screenshots/01-email-headers-overview.png)

**Evidence:** The header overview shows the subject, visible sender, authentication results, return path, and reply-to information.

### 3.3 Reply-To discrepancy

The captured `Reply-To` field points to a Gmail address rather than an address aligned with the claimed Microsoft identity. If a recipient replied, the response could go to a different party than the one implied by the display name.

![Reply-To address in raw headers](screenshots/05-reply-to-address.png)

## 4. Email Authentication and Header Review

The supplied raw headers show the following results:

| Check / field | Evidence shown | Interpretation |
|---|---|---|
| SPF | `spf=none`; `Received-SPF: None` | No successful SPF pass is shown. The header text says the SMTP sender domain does not designate the observed host as a permitted sender. |
| DKIM | `dkim=none` / message not signed | No DKIM signature is shown for the message. |
| DMARC | `dmarc=permerror` | DMARC evaluation encountered a permanent error; this is not a pass. The screenshot does not show a successful DMARC result. |
| Header From | `access-accsecurity[.]com` | Does not align visibly with the claimed Microsoft display name. |
| SMTP / envelope sender | `thcultarfdes[.]co[.]uk` | Different from the visible `From` domain. |
| Reply-To | Gmail address | Different from both the visible `From` and envelope sender domains. |

![Authentication results from the raw email header](screenshots/04-authentication-results.png)

The header’s `Authentication-Results` line explicitly includes `spf=none`, `dkim=none`, and `dmarc=permerror`. These results should not be described as a successful authentication pass. They increase suspicion but do not, on their own, prove phishing; they are assessed together with the URL and identity evidence.

![Additional raw header fields](screenshots/06-full-header-fields.png)

### 4.1 Received-path context

The sample contains `Received` lines showing delivery through Microsoft / Outlook mail infrastructure and a hop from `thcultarfdes[.]co[.]uk` associated with `89.144.44.2`. `Received` fields should be read in order and interpreted cautiously: mail infrastructure in the path does not imply that Microsoft authored or endorsed the message.

<details>
<summary>Additional received-header evidence</summary>

![Received header evidence — first hop](screenshots/02-received-header-hop-a.png)

![Received header evidence — second hop](screenshots/03-received-header-hop-b.png)

![X-Sender-IP header evidence](screenshots/10-x-sender-ip-header.png)

</details>

## 5. Sender IP Reputation — VirusTotal

The supplied VirusTotal screenshot for `89.144.44.2` shows:

- **Community / detection result:** `0/92` at the time captured.
- **Additional context:** the page reports two detected files communicating with the IP address.
- **Displayed network information:** `89.144.44.0/24`, ASN `201132` (shown as “MSCode”), and country indicator `PL`.

![VirusTotal analysis of sender IP 89.144.44.2](screenshots/09-virustotal-ip-analysis.png)

### Interpretation

The IP had no vendor detections in this particular screenshot. That result is limited to the vendors and analysis state shown at capture time. Infrastructure can be shared, changed, or have a low reputation history, so **0/92 is not proof of safety** and does not override the malicious URL result or the email-header anomalies. The location displayed by a reputation site is also not sufficient to identify the person who sent a message.

## 6. URL Reputation — VirusTotal

The URL shown in the evidence is defanged below:

`hxxp://thebandalisty[.]com/track/043062rdzGz18708448Gdrw1821750fYo33632dSjh176`

The supplied VirusTotal screenshot shows **9/92 detections**. Several visible vendors classify the URL as **Phishing** or **Malicious**, and at least one visible result is marked **Suspicious**.

![VirusTotal URL analysis showing 9/92 detections](screenshots/08-virustotal-url-analysis.png)

### Interpretation

This is the strongest indicator in the submitted evidence. Multiple vendor detections support treating the URL as unsafe. Reputation results are not infallible and can change over time, but the combined results warrant handling the message as likely phishing. The URL has been defanged in this report; do not visit it directly from a normal workstation.

## 7. HTML / Tracking Indicator

A screenshot of the email HTML shows an image element whose `src` points to the same tracking path and whose dimensions are `1px` by `1px`, with hidden visibility.

![Hidden 1×1 image reference in the email HTML](screenshots/07-hidden-tracking-pixel.png)

A hidden tracking pixel can be used to record message opens or recipient activity. Such pixels also exist in legitimate marketing email, so this is **supporting context rather than standalone proof** of maliciousness. In this case, it adds context to the URL reputation and sender inconsistencies.

## 8. Indicators of Compromise (IOCs)

| Type | Defanged / recorded indicator | Assessment |
|---|---|---|
| Sender IP | `89.144.44.2` | 0/92 in the supplied VirusTotal capture; do not treat as proof of safety. |
| URL | `hxxp://thebandalisty[.]com/track/043062rdzGz18708448Gdrw1821750fYo33632dSjh176` | 9/92 in the supplied VirusTotal capture; multiple phishing/malicious classifications. |
| URL domain | `thebandalisty[.]com` | Associated with the URL flagged by multiple vendors in the captured result. |
| Visible From | `no-reply@access-accsecurity[.]com` | Domain does not substantiate the claimed Microsoft identity. |
| Reply-To | `sotrecongizd@gmail[.]com` | Separate Gmail address; identity mismatch. |
| Return-Path / SMTP sender domain | `thcultarfdes[.]co[.]uk` | Does not match the visible From domain. |
| Subject | `Microsoft account unusual sign in activity` | Account-security theme may be used to prompt recipient action. |

**Handling note:** IOCs are included for defensive search and correlation. Defanging is intentional. Before importing them into a block list or threat-intelligence platform, validate the values against the original message and follow organizational change-control procedures.

## 9. SOC L1 Investigation Workflow

1. **Preserve the evidence.** Save the original `.eml`, record its SHA-256 hash, retain full headers, and keep screenshots or scanner reports with their capture times.
2. **Triage the message.** Compare the display name, `From`, `Reply-To`, `Return-Path`, subject, and sending infrastructure. Do not rely on the display name alone.
3. **Review authentication.** Record SPF, DKIM, and DMARC outcomes exactly as reported. In this case, none of the captured results establishes a successful pass.
4. **Reputation-check safely.** Look up the URL and IP using approved reputation tools without navigating to the live URL. Save the scan timestamp and detection count because results may change.
5. **Determine exposure.** Search mail-gateway logs for other recipients, then review proxy, DNS, browser, and endpoint telemetry for connections to the URL/domain. Check click events where available.
6. **Contain according to policy.** If confirmed by the organization’s process, quarantine or remove matching messages and block the URL/domain. Avoid broad IP blocking solely because it appears in a message; first check whether the IP is shared infrastructure and confirm with threat intelligence.
7. **Escalate if interaction occurred.** If a user clicked the link or entered credentials, notify the incident-response/identity team and follow the organization’s playbook for account review, session revocation, password reset, and MFA checks.
8. **Document the disposition.** Record the evidence, scope, user impact, actions performed, and whether the incident was confirmed, contained, or escalated.

## 10. Final Verdict

**Disposition: Likely phishing — high confidence from the supplied evidence.**

The message combines a Microsoft-themed display name with inconsistent sender identities, no SPF or DKIM pass shown, a DMARC permanent error, and a URL receiving multiple phishing/malicious detections in VirusTotal. The IP’s `0/92` result is not sufficient to establish legitimacy and does not outweigh the URL evidence.

**Limitations:** This conclusion is based on screenshots, not a fresh live scan or a complete forensic examination of the original `.eml`. The evidence supplied does not establish whether the link was clicked, whether a credential-harvesting page was served to a recipient, whether credentials were entered, or whether an endpoint was compromised. Those questions require mail, network, identity, and endpoint telemetry.

## 11. GitHub Evidence Files

All supplied screenshots used in this report are included in the `screenshots/` folder with descriptive filenames. Keep the files and this Markdown report in the same directory structure so the embedded images render on GitHub.

Suggested repository structure:

```text
Phishing_Email_Analysis.md
screenshots/
├── 01-email-headers-overview.png
├── 02-received-header-hop-a.png
├── 03-received-header-hop-b.png
├── 04-authentication-results.png
├── 05-reply-to-address.png
├── 06-full-header-fields.png
├── 07-hidden-tracking-pixel.png
├── 08-virustotal-url-analysis.png
├── 09-virustotal-ip-analysis.png
└── 10-x-sender-ip-header.png
```

If your main lab repository already has a `README.md`, you can link to this report from it with:

```markdown
## Investigation Reports

- [Phishing Email Analysis](Phishing_Email_Analysis.md)
```

---

*Prepared for defensive security learning and SOC Analyst L1 portfolio demonstration. This report documents analysis of a supplied sample and does not imply that any live URL was visited.*
