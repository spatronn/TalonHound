# Threat Classifications

TalonHound Threat Classifications describe the **primary threat or activity category** associated with an IOC. They answer:

> What kind of threat / activity does this IOC represent?

They are used for IOC triage, filtering, analyst understanding, reporting, feed normalization, and export.

Threat Classifications are **not**:

- a complete MITRE ATT&CK technique catalog
- a Threat Actor taxonomy
- a malware-family taxonomy
- a free-form tagging system (use Tags for operational metadata)
- a campaign database

## Built-in taxonomy

Fresh installations and upgrades reconcile **18 built-in classifications** from `backend/seeds/threat-classifications.json`:

| Name | Slug | MITRE ATT&CK (optional) |
| --- | --- | --- |
| Unknown | `unknown` | — |
| Phishing | `phishing` | T1566 |
| Credential Theft | `credential_theft` | TA0006 |
| Malware | `malware` | — |
| Ransomware | `ransomware` | T1486 |
| Command and Control (C2) | `command_and_control` | TA0011 |
| Botnet | `botnet` | — |
| Exploit | `exploit` | T1190 |
| Scanner / Reconnaissance | `scanner_recon` | TA0043 |
| Suspicious Infrastructure | `suspicious_infrastructure` | — |
| Spam / Abuse | `spam_abuse` | — |
| Dropper / Downloader | `dropper_downloader` | T1105 |
| Payload Hosting | `payload_hosting` | T1105 |
| Data Exfiltration | `data_exfiltration` | TA0010 |
| Cryptomining | `cryptomining` | T1496 |
| Fraud / Scam | `fraud_scam` | — |
| Typosquatting / Impersonation | `typosquatting_impersonation` | T1583.001 |
| Benign / Test | `benign_test` | — |

Each built-in has a concise analyst-facing description. Broad categories such as **Malware** or **Suspicious Infrastructure** intentionally have **no** MITRE mapping when a single ATT&CK reference would be misleading.

## MITRE ATT&CK mapping layer

MITRE ATT&CK is a **separate optional reference layer** stored in `threat_classification_mitre_mappings`.

- TalonHound does **not** import the full ATT&CK catalog as classifications.
- A built-in classification may have zero, one, or multiple curated mappings.
- Mappings are validated against the bundled snapshot `backend/data/mitre-attack-reference.json`.
- Official ATT&CK URLs are stored for admin display links.

**Runtime does not contact MITRE.** Fresh install, upgrade, and normal operation work offline.

Maintainers can validate bundled mappings locally:

```bash
cd backend
npm run threat-classifications:validate-mitre
npm run threat-classifications:validate-mitre -- --dry-run
```

### MITRE attribution

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. TalonHound bundles a minimal ATT&CK reference subset for classification mappings only. See the [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/) for upstream terms.

## Custom classifications

Administrators may create custom classifications through **Administration → Threat Classifications**. Custom rows:

- keep stable IDs, names, slugs, descriptions, active state, and sort order
- are never deleted or overwritten by bundled reconciliation
- do not receive curated MITRE mappings in beta (built-in mappings are read-only in the admin UI)

## Unknown sentinel

`Unknown` (`unknown`) is the system fallback:

- always present, active, first in order, and built-in
- cannot be disabled or deleted
- used when classification input is missing or unrecognized

## Fresh install

During `npm run migrate`, TalonHound:

1. applies SQL migrations (including `014_threat_classification_taxonomy_mitre.sql`)
2. seeds core dictionary rows from `001_core.sql`
3. reconciles bundled descriptions and MITRE mappings from `backend/seeds/threat-classifications.json`

No network access is required.

## Upgrade reconciliation

Upgrades run the same bundled reconciliation at the end of `npm run migrate`. Reconciliation:

- preserves classification IDs and IOC foreign keys
- preserves custom classifications
- preserves administrator `active = false` choices
- preserves local sort order (does not reset `sort_order` on existing rows)
- fills empty built-in descriptions from bundled data
- idempotently upserts curated MITRE mappings for built-in rows only

It never deletes classifications referenced by IOCs or removes custom classifications.

## Feed / import normalization

Import-time mapping lives in `backend/lib/iocClassificationMapping.js`. Display-time feed evidence normalization lives in `backend/lib/feedTagNormalization.js`. Legacy slug aliases are normalized in `backend/lib/threatClassification.js` (for example `c2` → `command_and_control`, `malware_download` → `dropper_downloader`).

Normalization is **explicit and reviewed** — ambiguous strings are not fuzzy-matched.

## API

Existing Threat Classification API fields are unchanged. When mappings exist, responses add:

```json
"mitre_attack": [
  { "id": "T1566", "name": "Phishing", "type": "technique", "url": "https://attack.mitre.org/techniques/T1566/" }
]
```

IOC UX continues to show classification **names** (for example `Phishing`), not ATT&CK IDs, in lists and pickers.

## Exports

JSON, TXT, and STIX exports keep existing Threat Classification semantics. MITRE mappings are available through TalonHound API/admin metadata rather than being forced into STIX objects in beta.
