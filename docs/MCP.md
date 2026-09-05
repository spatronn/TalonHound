# TalonHound MCP Server

TalonHound exposes a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server so AI clients (Cursor, Claude Desktop, custom agents, and similar tools) can look up and import indicators of compromise (IOCs) against your live TalonHound inventory.

This guide matches the **v0.1** MCP implementation shipped with TalonHound `0.1.1-beta.4` and later.

## What MCP integration is

MCP is a standard way for AI assistants to call structured **tools** on a remote server. TalonHound’s MCP server is not a separate product or second backend: it is an authenticated HTTP endpoint on the same application process that already serves the GUI and REST API.

Through MCP, a client can:

- Look up whether an observable already exists
- Search and page through IOC inventory
- Read analyst context (and stored enrichment when permitted)
- Bulk-check extracted IOCs from a threat report
- List selectable IOC Sources
- Import missing IOCs into an **existing** IOC Source (with optional dry-run)

There are **no** MCP tools to delete IOCs, manage feeds, administer users, or trigger paid enrichment.

## Architecture

```text
┌─────────────────────┐
│  MCP client         │
│  (Cursor / agent)   │
└─────────┬───────────┘
          │ HTTPS + Bearer th_mcp_…
          │ Streamable HTTP POST /mcp
          ▼
┌─────────────────────────────────────────┐
│  TalonHound backend (same process)      │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ /mcp routes │───▶│ MCP tools      │  │
│  │ auth + RL   │    │ (mcpTools)     │  │
│  └─────────────┘    └───────┬────────┘  │
│                             │           │
│         ┌───────────────────▼────────┐  │
│         │ Shared domain services     │  │
│         │ · IOC normalize / search   │  │
│         │ · manual IOC create        │  │
│         │ · IOC Source lifecycle     │  │
│         │ · audit logging            │  │
│         │ · PostgreSQL               │  │
│         └────────────────────────────┘  │
└─────────────────────────────────────────┘
```

Key points:

- MCP reuses the same PostgreSQL schema, IOC normalization, manual create path, and audit pipeline as the GUI/API.
- Effective rights are never higher than the **owner user** attached to the MCP API key.
- Disable the whole surface with `MCP_ENABLED=false` (default is enabled).

## Transport

| Item | Value |
|------|--------|
| Endpoint | `https://<host>/mcp` |
| Protocol | MCP **Streamable HTTP** (stateless; JSON responses enabled) |
| Auth | `Authorization: Bearer <mcp_api_key>` |
| Health probe | `GET /mcp/health` (same Bearer auth; returns limits) |

Session IDs are not used; each request authenticates independently.

## Authentication

MCP credentials are API keys stored in `published_feed_access_keys`, using dedicated access profiles:

| Profile id | Label | Key prefix | Typical use |
|------------|--------|------------|-------------|
| `mcp_read` | MCP Read | `th_mcp_` | Lookup / search / context / bulk / list sources |
| `mcp_analyst` | MCP Analyst | `th_mcp_` | Same reads **plus** `import_iocs` |

Both profiles **require an owner user**. The owner’s TalonHound role is loaded on every request.

**Effective permission = token scopes ∩ owner RBAC ∩ tool policy.**

Examples:

- An `mcp_analyst` key owned by a **readonly** user can read (if the role allows MCP read) but **cannot** import — create is denied by RBAC even when `mcp:ioc:create` is on the token.
- An `mcp_read` key never gets import, regardless of owner role.
- A non-MCP API key without MCP scopes is rejected at `/mcp`.

Create keys in the TalonHound UI under API key management (same place as published-feed / IOC API keys), choosing **MCP Read** or **MCP Analyst** and selecting the owner user. The plaintext key is shown **once** at creation.

## Scopes

| Scope | Grants |
|-------|--------|
| `mcp:ioc:read` | `lookup_ioc`, `search_iocs`, `get_ioc_context`, `bulk_lookup_iocs` |
| `mcp:ioc:create` | `import_iocs` (also needs owner analyst/admin) |
| `mcp:enrichment:read` | Include stored enrichment rows in `get_ioc_context` |
| `mcp:sources:read` | `list_ioc_sources` |

Profile presets:

- **mcp_read:** `mcp:ioc:read`, `mcp:sources:read`, `mcp:enrichment:read`
- **mcp_analyst:** all four MCP scopes above

## Tools

| Tool | Required scope(s) | Read-only | Description |
|------|-------------------|-----------|-------------|
| `lookup_ioc` | `mcp:ioc:read` | Yes | Exact lookup of one observable. Type optional (auto-detect + normalize). |
| `search_iocs` | `mcp:ioc:read` | Yes | Search inventory by DSL or plain-text `query` and/or `type` / `classification` / `source` filters (AND-combined); cursor pagination; bounded page size. See [search semantics](#search_iocs-query-semantics). |
| `get_ioc_context` | `mcp:ioc:read` | Yes | Analyst context by value or id. Enrichment included only with `mcp:enrichment:read`. Does **not** trigger new enrichment. |
| `bulk_lookup_iocs` | `mcp:ioc:read` | Yes | Batch existence check → `existing` / `missing` / `invalid` (max batch size configurable). |
| `list_ioc_sources` | `mcp:sources:read` | Yes | Active, selectable IOC Sources usable as `import_iocs` targets. |
| `import_iocs` | `mcp:ioc:create` | No | Import into an existing source via the same manual ingestion path as the GUI. Supports `dry_run`. |

There are no delete, update-admin, feed, or user-management tools.

### Common input shapes

IOC values may be plain strings or `{ "value": "...", "type": "ip"|"domain"|"url"|"hash" }`.

`import_iocs` arguments:

- `source_id` (required) — from `list_ioc_sources`
- `iocs` (required) — array, max = import batch limit
- `dry_run` (optional boolean)
- `note` (optional string, applied to newly created IOCs)

### `search_iocs` query semantics

`search_iocs` accepts a free-form `query` and/or the structured filters `type`, `classification`, and `source`. At least one of them is required; when several are given they are combined with `AND`.

**`query`** is interpreted one of two ways:

- **TalonHound Search DSL** — the same engine as the GUI Advanced Search. Syntax is `field operator "value"` with `AND` / `OR` / `NOT` and parentheses. Every value (even enum values) must be double-quoted.
  - Fields: `ioc` (alias `value`), `type`, `source`, `tag`, `threat_actor`, `classification`, `status`, `confidence`, `first_seen`, `created_at` (plus exact hash fields `md5` / `sha1` / `sha256`).
  - Operators: `contains`, `equals`, `not_equals`, `starts_with`, `ends_with`, `not_contains`, `in` / `not_in` (list), and `before` / `after` / `between` (dates).
- **Plain text** — anything that is not valid DSL is treated as a bounded IOC-value search, i.e. `ioc contains "<text>"`. (A string that clearly *attempts* DSL — a known field next to a known operator — but is malformed returns a DSL validation error instead of silently searching.)

**Structured filters** map to DSL as: `type` → `type equals "domain"` (and `hash` → `type in ("md5","sha1","sha256")`, `ip` → `type in ("ip","ipv6")`), `classification` → `classification equals "<value>"`, `source` → `source equals "<name>"`.

Results are bounded by the server-enforced maximum page size; use `cursor` for pagination. `search_iocs` is not an export mechanism.

**Examples**

| Goal | Arguments |
|------|-----------|
| Plain-text value search | `{ "query": "evil.com" }` |
| Explicit DSL | `{ "query": "ioc contains \"evil\" AND confidence equals \"high\"" }` |
| All domains | `{ "type": "domain" }` |
| One classification | `{ "classification": "malware" }` |
| From a source | `{ "source": "Threat Hunting" }` |
| Combined | `{ "query": "evil.com", "type": "domain", "source": "Threat Hunting" }` |

## IOC Sources behavior

MCP does **not** create a special “MCP” or “AI” source.

- Imports always target an **existing** IOC Source (`source_id`).
- `list_ioc_sources` returns only sources that are **selectable**: active (not disabled/archived) and not the internal system REST provenance source.
- Prefer a real operational source such as **Threat Hunting** (or whatever your team uses for manual triage).

## Read-only setup

1. Create an API key with profile **MCP Read** (`mcp_read`), bound to an active owner user.
2. Store the `th_mcp_…` secret in the MCP client (not in git or tickets).
3. Point the client at `https://<host>/mcp` with the Bearer header.
4. Confirm with `lookup_ioc` or `GET /mcp/health`.

The client can list sources and read IOCs but cannot call `import_iocs`.

For an owner who must never write even with a mis-issued analyst key, use a **readonly** TalonHound role: RBAC still blocks create.

## Threat-report import workflow

Recommended sequence when an agent extracts IOCs from a report:

1. **`list_ioc_sources`** — pick a real source id (for example Threat Hunting).
2. **`bulk_lookup_iocs`** — split the extract into already-known vs missing.
3. **`import_iocs` with `dry_run: true`** — validate normalization and membership plan without writing.
4. **`import_iocs` with `dry_run: false`** (or omit) — commit only the missing / membership-needed set you intend to add.

Keep batches within the configured import maximum. Prefer importing only the `missing` bucket from the bulk lookup unless you intentionally want source membership on already-known observables.

## Dry-run

When `import_iocs` is called with `dry_run: true`:

- Values are detected, typed, and normalized
- Existing membership in the target source is checked
- The response reports what **would** be created / membership-added / invalid
- **No** IOC rows are written

Use dry-run before committing large or untrusted extracts from LLM output.

## Rate limits and batch sizes

Defaults from `backend/lib/mcpConfig.js` (overridable via environment):

| Limit | Default | Env |
|-------|---------|-----|
| Overall MCP requests / minute / key | **120** | `MCP_RATE_LIMIT_PER_MIN` |
| `import_iocs` / minute | **30** | `MCP_RATE_LIMIT_IMPORT_PER_MIN` |
| `search_iocs` / minute | **60** | `MCP_RATE_LIMIT_SEARCH_PER_MIN` |
| `bulk_lookup_iocs` / minute | **60** | `MCP_RATE_LIMIT_BULK_PER_MIN` |
| Bulk lookup / import batch max | **100** | `MCP_BULK_LOOKUP_MAX` / `MCP_IMPORT_MAX` |
| Search page max | **50** | `MCP_SEARCH_PAGE_MAX` |
| Max value length (chars) | **2048** | `MCP_VALUE_MAX_CHARS` |

Exceeding limits returns HTTP **429**. Disable MCP entirely with `MCP_ENABLED=false`.

## Audit

Successful (and many failed) MCP operations are written through the shared audit log:

| Field | Value |
|-------|--------|
| `source` | `mcp` |
| Metadata `channel` | `mcp` |
| Tool calls (non-import) | action `mcp.tool_call` |
| Imports (including dry-run) | action `mcp.ioc_import` |

Audit metadata typically includes API key id/name, access profile, owner user id, tool name, and import counters (`submitted`, `created` / `would_create`, `invalid`, etc.).

## Security model and prompt-injection boundary

- **Least privilege:** prefer `mcp_read` unless import is required.
- **Owner binding:** every MCP key must have an accountable user; rights cannot exceed that user.
- **No elevation:** token scopes alone never grant GUI-level admin powers.
- **No delete tools:** agents cannot remove IOCs or sources via MCP.
- **No feed/admin tools:** published feeds, users, and system settings are out of scope.
- **Prompt injection:** treat model-proposed imports as untrusted. Always dry-run, review `source_id`, and prefer human confirmation before write. IOC **values** and optional `note` strings may originate from hostile documents — they are stored as data, not executed as code, but they can pollute inventory if imported blindly.
- **Secrets:** never paste live `th_mcp_` keys into chats, tickets, or documentation. Revoke compromised keys immediately.

## TLS trust for MCP clients

Certificate trust and MCP authentication are separate:

- **Auth** always uses a TalonHound MCP API key (`Authorization: Bearer th_mcp_…`).
- **TLS** is the same HTTPS certificate that protects the TalonHound web UI and API (`https://<host>/mcp`).

### Case 1 — certificate already trusted by the client OS/runtime

Connect directly:

`https://<talonhound-host>/mcp`

with the MCP API key. No extra TLS configuration is required.

### Case 2 — TalonHound self-signed certificate

1. Open **Settings → TLS Certificate** (Administration) in the TalonHound UI.
2. Click **Download Public Certificate** (`talonhound-certificate.pem`). The private key is never downloadable.
3. Configure the MCP client/runtime to trust that public certificate.
4. Connect directly to `https://<talonhound-host>/mcp`.
5. Authenticate with the existing MCP API key.

Example for Node-based clients (including Claude Code toolchains that honor Node CA settings):

```bash
export NODE_EXTRA_CA_CERTS=/path/to/talonhound-certificate.pem
```

Do **not** disable TLS verification:

- `NODE_TLS_REJECT_UNAUTHORIZED=0`
- `curl -k` / `--insecure`
- localhost TLS bypass proxies

Only the System Administrator can **replace** the active certificate. Admins can view status and download the public certificate.

## Client configuration

Placeholders only — replace host and token with your values. Do not commit real keys.

### Generic HTTP client

```http
POST /mcp HTTP/1.1
Host: talonhound.example.com
Authorization: Bearer th_mcp_REPLACE_ME
Content-Type: application/json
```

### Cursor (`mcp.json` style)

```json
{
  "mcpServers": {
    "talonhound": {
      "url": "https://<host>/mcp",
      "headers": {
        "Authorization": "Bearer th_mcp_REPLACE_ME"
      }
    }
  }
}
```

Exact client schema may vary by Cursor version; the server expects Streamable HTTP at `/mcp` with a Bearer MCP key.

## Troubleshooting

| Symptom | Likely cause | What to check |
|---------|--------------|---------------|
| 401 Missing/invalid Bearer | No or wrong header | `Authorization: Bearer th_mcp_…` |
| 401 Invalid API key | Wrong/revoked/deleted key | Recreate key; confirm not deleted |
| 403 API key disabled / expired | Key toggled off or past `expires_at` | Re-enable or issue a new key |
| 403 not authorized for MCP | Non-MCP profile / missing MCP scopes | Use `mcp_read` or `mcp_analyst` |
| 403 no accountable owner | Key created without owner | Recreate with owner user |
| 403 / tool `RBAC_DENIED` on import | Owner is readonly or not analyst/admin | Change owner or use a read-only workflow |
| Tool `MISSING_SCOPE` | Profile lacks required scope | Use analyst profile for import |
| 429 rate limit | Burst over defaults | Back off; raise env limits only if needed |
| 503 MCP is disabled | `MCP_ENABLED=false` | Set to true / unset and restart backend |
| Import rejects `source_id` | Inactive, archived, or system source | Call `list_ioc_sources` again |
| Enrichment missing in context | No `mcp:enrichment:read` or nothing stored | Scope + prior GUI enrichment; MCP never triggers fetch |

Health check: authenticated `GET /mcp/health` returns `{ ok, mcp, enabled, transport, limits }`.

## Token revocation

To revoke MCP access:

1. **Disable** the API key in the UI (immediate 403 for that credential), or
2. **Delete** the API key (treated as invalid / 401).

Also disable or remove the owner user if the entire identity should lose access. Rotating means creating a new key and updating every MCP client configuration.

## Limitations (v0.1)

- No delete / suppress / bulk-admin tools
- No feed administration or published-feed operations via MCP
- No automatic enrichment trigger (reads stored enrichment only)
- No threat-report file storage or long-running “report jobs”
- Stateless Streamable HTTP only (no durable MCP sessions)
- Batch sizes capped (default 100)
- Import only into existing selectable IOC Sources

See also [`docs/releases/0.1.1-beta.4.md`](releases/0.1.1-beta.4.md) and migration `018_mcp_server.sql`.
