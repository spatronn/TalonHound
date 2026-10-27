# CIDR Indicators as IOC records

## Decision

A CIDR Indicator from the Threat Library is stored as an **`ip` (IPv4) or `ipv6` (IPv6) IOC whose observable keeps the canonical network and prefix**, for example `162.220.232.0/22` or `2607:99c0::/32`. No new observable type or migration is needed.

This is the IOC contract the catalog already uses:

- 2,167 EmergingThreats network rows are `observable_type = 'ip'` with a prefix. All of them are canonical.
- The public API type `ip` already accepted `/prefix`.
- The published-feed STIX serializer emits `ipv4-addr` / `ipv6-addr` `ISSUBSET` patterns for prefixed `ip` values.
- MISP export maps CIDR to `ip-dst`.

A separate `cidr` type would have split the same concept across two types and two partitions, and every consumer would have needed a new branch.

## Identity rules (`backend/lib/networkObservable.js`)

- A network is canonicalized: host bits are cleared and IPv6 is written in RFC 5952 form. `162.220.234.0/22` and `162.220.232.0/22` are one identity, and so are `2607:99C0::5/32` and `2607:99c0::/32`.
- The prefix is part of the identity. `162.220.232.0/22` and `162.220.232.0` are different IOCs.
- A network is never expanded into host IOCs and never truncated to its network address.
- These values are rejected:
  - an invalid prefix (`/33` for IPv4, `/129` for IPv6, or a non-numeric prefix);
  - a malformed address;
  - `/0`, which would cover the whole address space.
- An IPv6 address is an `ipv6` IOC. Before this change, the shared create path inferred `domain` for it.

## Layers

| Layer | Change |
|---|---|
| IOC create (manual / API / MCP / Threat Library) | `resolveIocStorageIdentity` handles network values first |
| API `type: ip` | Uses the same validator and returns the storage type (`ip` / `ipv6`) |
| MCP lookup input | A CIDR or IPv6 value without an explicit type is an IP value |
| Threat Library Create IOCs | `cidr` is creatable. `iocStorageIdentity` maps it to `ip` / `ipv6`. Existence lookup and creation use that identity. An invalid network is reported `unsupported`. |
| Threat Library catalog match / refresh link carry | `catalogLookupIdentity`: a `cidr` row matches its network IOC, never a host |
| Frontend | The review table mirrors creatability. The CIDR-specific "not an IOC record" note is removed. |

## Unchanged by design

- **Matching and blocking.** A host IP never matches a network IOC by containment. Matching stays exact-identity, as it already was for the EmergingThreats networks.
- **Enrichment.** Enrichment of an `ip` / `ipv6` IOC uses the address part (`extractIpLiteralFromIoc`), as it already does for the EmergingThreats networks.
