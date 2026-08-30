# Built-in Threat Intelligence Feeds

TalonHound includes several built-in threat intelligence feeds. Some feeds work immediately after installation, while others require credentials obtained directly from the feed provider.

TalonHound does **not** supply third-party API keys. When a feed requires authentication, you must register with the provider and configure the credential yourself. Enter credentials in **Threat Intelligence → Feeds** (open a feed and choose **Edit**). Never paste API keys into documentation, logs, screenshots, issue trackers, or source control.

## Summary

| Feed | Included by Default | API/Auth Key | Credential Source | Primary Data |
|------|---------------------|--------------|-------------------|--------------|
| Emerging Threats Blockrules | Yes | No | — | IPv4 blocklist IPs |
| Siber Güvenlik Başkanlığı / USOM | Yes | No | — | Domains, URLs, IPv4, IPv6 |
| CERT.PL Dangerous Websites | Yes | No | — | Active warning-list domains |
| PhishTank online-valid | No[^phishtank] | No | — | Verified phishing URLs |
| URLhaus abuse.ch | Yes | Yes | [abuse.ch Auth-Key](https://auth.abuse.ch/) | Malicious URLs |
| MalwareBazaar abuse.ch | Yes | Yes | [abuse.ch Auth-Key](https://auth.abuse.ch/) | Malware file hashes (SHA256) |
| ThreatFox abuse.ch | Yes | Yes | [abuse.ch Auth-Key](https://auth.abuse.ch/) | Recent IOCs (IPs, domains, URLs, hashes) |
| AlienVault OTX | Yes | Yes | [OTX account settings](https://otx.alienvault.com/) | IOCs from your subscribed pulses |

[^phishtank]: The PhishTank importer is built into TalonHound and uses the public [`online-valid.csv`](https://data.phishtank.com/data/online-valid.csv) feed without an API key. It is not pre-seeded in the Feeds list on a fresh install; only the seven other built-in feeds appear there by default.

## Configuring credentials

Open **Threat Intelligence → Feeds**, click **Edit** on the feed, scroll to the credential section, enter the key, click **Save Auth Key**, then **Test Connection** when that button is available.

For URLhaus, MalwareBazaar, and ThreatFox, abuse.ch issues **one Auth-Key per account** that works across their community APIs. TalonHound stores credentials **separately for each feed**, so paste the same Auth-Key into each abuse.ch feed you enable.

Server administrators can also set environment-variable fallbacks (see [`.env.example`](../.env.example) for URLhaus, MalwareBazaar, and ThreatFox). The Integrations UI is the preferred place to configure credentials.

### URLhaus abuse.ch

1. Sign in at the [abuse.ch authentication portal](https://auth.abuse.ch/) and create an Auth-Key (see the [URLhaus API documentation](https://urlhaus.abuse.ch/api/) for details).
2. In TalonHound, open **Threat Intelligence → Feeds → URLhaus abuse.ch → Edit**.
3. Enter the **URLHaus Auth-Key** and click **Save Auth Key**.
4. Click **Test Connection** to verify access.

### MalwareBazaar abuse.ch

1. Use the same [abuse.ch Auth-Key](https://auth.abuse.ch/) as for URLhaus and ThreatFox.
2. Open **Threat Intelligence → Feeds → MalwareBazaar abuse.ch → Edit**.
3. Enter the **MalwareBazaar Auth-Key** and click **Save Auth Key**.
4. Click **Test Connection** to verify access.

### ThreatFox abuse.ch

1. Use the same [abuse.ch Auth-Key](https://auth.abuse.ch/) as for URLhaus and MalwareBazaar.
2. Open **Threat Intelligence → Feeds → ThreatFox abuse.ch → Edit**.
3. Enter the **ThreatFox Auth-Key**. Optionally adjust **Recent days (1–7)** (default lookback is 3 days).
4. Click **Save Auth Key**, then **Test Connection**.

### AlienVault OTX

1. Create or sign in to an [OTX](https://otx.alienvault.com/) account and copy your API key from account settings (used as the `X-OTX-API-KEY` header).
2. Open **Threat Intelligence → Feeds → AlienVault OTX → Edit**.
3. Enter the **AlienVault OTX API Key** and click **Save Auth Key**.
4. Click **Test Connection** to verify access.

OTX imports IOCs from **pulses you subscribe to** in OTX. Subscribe to relevant pulses in OTX before expecting data in TalonHound.

## Feeds that work without credentials

These built-in feeds can synchronize after installation without API key configuration:

- **Emerging Threats Blockrules** — public blocklist rules over HTTP
- **Siber Güvenlik Başkanlığı / USOM** — official public TR-CERT API (no API key). USOM also offers **Run Incremental** and **Full Reconciliation** actions on the Feeds page and in feed settings.
- **CERT.PL Dangerous Websites** — official public CERT.PL JSON warning list (no API key)
- **PhishTank online-valid** — public CSV at `https://data.phishtank.com/data/online-valid.csv`; no PhishTank application or API key is used by TalonHound

Ensure each feed is **Enabled** (State shows **Enabled**) so scheduled runs proceed.

## Troubleshooting

On **Threat Intelligence → Feeds**, check each feed’s **State**, **Health**, and **Last Result** columns.

- Confirm the feed is **Enabled** (**Edit → Enable feed**).
- For credential-protected feeds, verify the Auth-Key or API key is saved and use **Test Connection** in feed settings.
- Review **Last Result** for error messages (for example, missing Auth-Key or authentication failures).
- For USOM, check the **USOM Reconciliation** section in feed settings if incremental or full sync looks stale.
- TalonHound manages provider source URLs internally; do not change endpoints unless your deployment documentation explicitly supports it.

For queue-level job status, open **Threat Intelligence → Queue**.

## Related documentation

- [Enrichment Providers](enrichment-providers.md)
