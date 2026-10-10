# Enrichment Providers

TalonHound includes built-in enrichment providers for reputation, network, registration, and blocklist data. Some providers work immediately, while others require an API key or token obtained directly from the provider.

TalonHound does **not** supply third-party API keys. When a provider requires authentication, register with the provider and configure the credential yourself in **Administration → Enrichment Providers**. Never paste API keys or tokens into documentation, logs, screenshots, issue trackers, or source control.

Provider credentials and security-sensitive settings require the **admin** role. Other signed-in users can view provider status only.

## Summary

| Provider | Credential | Primary Purpose | Test Connection |
|----------|------------|-----------------|-----------------|
| VirusTotal | API key required | File, URL, and domain reputation lookup | Yes |
| IPinfo Lite | API token required | On-demand IP enrichment (ASN, country, continent) | Yes |
| AbuseIPDB | API key required | Public IP reputation checks (check endpoint only) | Yes |
| urlscan.io | API key required | Passive historical website scan search (Search + Result APIs only) | Yes |
| RDAP / WHOIS | No credentials required | Domain registration data via public RDAP | Yes |
| Spamhaus DROP | No credentials required | Periodic CIDR blocklist dataset sync; local IP lookup | No — use **Run sync now** |

On a fresh install, **VirusTotal** and **RDAP / WHOIS** are enabled by default. **IPinfo Lite**, **AbuseIPDB**, **urlscan.io**, and **Spamhaus DROP** are disabled until you turn them on in the provider card. Credential-protected providers still need a saved key or token before enrichment works, even when enabled.

## Configuring credentials

Open **Administration → Enrichment Providers**, expand the provider card, enter the credential, and click **Save Changes**. Use **Test Connection** where available to verify access before relying on the provider in **IOC Details → Intelligence**.

Server administrators can also set environment-variable fallbacks where supported (see [`.env.example`](../.env.example) for VirusTotal and IPinfo Lite). The Enrichment Providers UI is the preferred place to configure credentials.

### VirusTotal

1. Create or sign in to a [VirusTotal](https://www.virustotal.com/) account.
2. Open your [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) page and copy the key.
3. In TalonHound, open **Administration → Enrichment Providers → VirusTotal**.
4. Paste the key into **API Key**.
5. Click **Save Changes**.
6. Click **Test Connection**.

VirusTotal enrichment applies to hash, URL, domain, and IP observables from **IOC Details → Intelligence**.

### IPinfo Lite

1. Create or sign in to an [IPinfo](https://ipinfo.io/) account.
2. Copy your token from the [IPinfo account token page](https://ipinfo.io/account/token).
3. In TalonHound, open **Administration → Enrichment Providers → IPinfo Lite**.
4. Turn **Enabled** on if you are activating the provider for the first time.
5. Paste the token into **API Token**.
6. Click **Save Changes** (TalonHound prompts for an audit reason).
7. Click **Test Connection**.

IPinfo Lite enriches IP observables (and IP hosts extracted from URL IOCs). The **Base URL** is fixed to the official IPinfo Lite endpoint.

### AbuseIPDB

1. Create or sign in to an [AbuseIPDB](https://www.abuseipdb.com/) account.
2. Generate or copy your API key from the [AbuseIPDB account dashboard](https://www.abuseipdb.com/account) (see the [AbuseIPDB API documentation](https://docs.abuseipdb.com/) for details).
3. In TalonHound, open **Administration → Enrichment Providers → AbuseIPDB**.
4. Turn **Enabled** on.
5. Paste the key into **API Key**.
6. Click **Save Changes** (TalonHound prompts for an audit reason).
7. Click **Test Connection**. Optionally set **Test IP (optional, public IPv4/IPv6)** before testing (defaults to `8.8.8.8`).

AbuseIPDB enriches public IP observables (and IP hosts extracted from URL IOCs).

### urlscan.io

1. Create or sign in to a [urlscan.io](https://urlscan.io/) account.
2. Create an API key from your urlscan.io account settings / API page.
3. In TalonHound, open **Administration → Enrichment Providers → urlscan.io**.
4. Turn **Enabled** on.
5. Paste the key into **API Key**.
6. Click **Save Changes** (TalonHound prompts for an audit reason).
7. Click **Test Connection**.

urlscan.io enrichment is **strictly read-only**: TalonHound searches historical scans and may retrieve bounded Result API details. It **never** submits URLs for scanning (`POST /api/v1/scan` is forbidden by the provider client). Applies to domain and URL observables only, from **IOC Details → Intelligence**; for IP, hash, and other IOC types urlscan.io is not applicable and is not shown, queried, or listed in provider coverage.

Absence of historical scans is reported as **No results**, not clean/safe. urlscan scores are provider observations and are not TalonHound confidence.

Each enrichment costs one Search request plus at most **Detail limit** Result requests (default 3). From the best direct-match scan the card shows:

- **Classification** from urlscan's overall verdict only: *Malicious*, *Benign verdict* (negative score), or *Unclassified*. A score of 0 without a verdict is *Unclassified*, never clean. An ML engine flag that the overall verdict does not adopt is shown as an observation and makes the sample assessment *Insufficient evidence*.
- **Visibility observations**, for example *Limited page visibility — HTTP 403* when the scanner only received an error page, failed navigation, challenge pages, off-domain redirects, downloads, and unusual TLS certificates.
- **Page & hosting**, **network activity** (counts only), **redirect chain**, **TLS certificate**, and **detected technologies**.
- **Related observables** with their relationship and origin field. Response-body SHA256 values are labelled as page/resource bodies, not malware samples. Nothing is added to TalonHound or enriched automatically.
- **Scan history**, comparing IP, ASN, title, status, and TLS issuer across the retrieved search sample only.

Results stored before this format show the page facts that were kept and ask for **Refresh** to load the rest. Cookies, headers, response bodies, DOM content, and screenshots are never stored or loaded. Signed URL tokens are masked.

## Providers that work without credentials

### RDAP / WHOIS

Uses public RDAP services for domain registration lookups on **domain** and **URL** observables. No API key is required — the provider card shows **Auth: No API key**.

RDAP is enabled by default and has no enable/disable toggle in the UI. Use **Test Connection** to run a real lookup against `example.com` and verify outbound HTTPS connectivity.

Lookups run on demand from **IOC Details → Intelligence**.

### Spamhaus DROP

Syncs the public Spamhaus DROP IPv4/IPv6 CIDR datasets (`drop_v4.json` / `drop_v6.json`) into TalonHound for local IP lookup. No user-supplied API key is required.

1. Open **Administration → Enrichment Providers → Spamhaus DROP**.
2. Turn **Enabled** on.
3. Choose **Sync interval (hours)** and click **Save Changes**.
4. Click **Run sync now** to queue an immediate sync.

Health reflects sync success rather than a live **Test Connection** probe. After the first successful sync, IP observables can be checked locally without per-IP external calls.

## Troubleshooting

On **Administration → Enrichment Providers**, check each provider card’s **Status** (for example **Healthy**, **Degraded**, or **Unhealthy**) and **Enabled** state.

- Confirm the provider is **Enabled** when you expect enrichment to run.
- For VirusTotal, IPinfo Lite, AbuseIPDB, and urlscan.io, verify the **API Key** or **API Token** was saved and use **Test Connection**.
- For Spamhaus DROP, confirm a sync has completed successfully (**Run sync now** or wait for the scheduled interval).
- Review error messages shown on the provider card and check whether the provider account quota or rate limit may be exhausted.
- Ensure TalonHound has outbound HTTPS access to the provider endpoints.

## Related documentation

- [Built-in Threat Intelligence Feeds](built-in-threat-feeds.md)
