# External exposure map

The exposure map draws the relationships the platform has **observed** between an
organization's externally visible assets:

```text
Domain → IP address → Port / service → Web endpoint → Finding
```

It answers "what does this domain lead to on the internet, and what did we find there?"
It is **not attack-path analysis**: a line between two assets records a DNS answer, an open
port or an HTTP response. It never means that an attacker can use one asset to reach
another, and nothing on the map is inferred from shared IP addresses, certificates, hosting
providers or ordinary DNS relationships.

## Using it

- **Exposure map** (sidebar) shows one organization at a time — choose it in the top bar or
  on the page. It starts from the organization's domains (up to the ten highest-risk; pick an
  asset to focus when there are more). **Find an asset to start from** re-centres the map on
  any asset.
- **Asset → Exposure map** shows the same view starting from that asset.
- **Depth** (1–4 hops, default 2) and filters: findings (on by default), *unverified
  reports* (third-party findings nobody tested; off by default), *no longer observed*
  (relationships and assets that are gone; off by default), *technologies & certificates*
  (context; off by default because shared certificates and technologies create large,
  misleading hubs).
- **Click a node** for its type, status, scope, risk, first and last seen, what was left out
  ("Not shown: 575 × Subdomain of") and actions: **Expand** (load that node's neighbours,
  up to 100 more), **Start here**, **Open asset** / **Open finding**.
- **Click a line** for what it means ("DNS: this name resolved to this IP address"), whether it
  was observed or derived by the platform from names, which capability recorded it, when it
  was first and last seen, and its freshness.

### How to read it

| Line | Meaning |
|---|---|
| solid | current: observed in the last 14 days |
| dashed | stale: not observed for more than 14 days — may no longer be true |
| dotted, faded | inactive: no longer observed; kept as history (shown only with *no longer observed*) |
| dash-dot | historical: reported by a third-party database (e.g. exposure intelligence), not by your scans |
| short dashes to a finding | unverified: a third-party report nobody tested |

Nodes with a dashed border are known only from a third-party record, or are no longer
observed. A "+N" on a node means it has more relationships than were loaded; "+" alone means
it sits on the outer ring and may lead further. Findings carry a severity bar. Domain
naming relationships (`subdomain_of`) are marked *derived by the platform*: they come from
the names, not from a network connection.

## Bounds

Every request is bounded on the server, whatever the client asks for:

| Bound | Default | Allowed |
|---|---|---|
| Hops from the starting point | 2 | 1–4 |
| Nodes per map | 150 | 10–300 |
| Relationships per map | 3 × nodes | — |
| Neighbours per node, per direction and level | 25 | 5–100 (Expand uses 100) |
| Findings per asset | 3 (highest risk first; the rest counted) | — |
| Starting points without a chosen asset | 10 root domains | — |
| Database statement timeout | 3 s | — |
| Time budget for the whole map | 4 s | — |
| Nodes held in the browser across expansions | 600 | — |

Neighbours are ranked in PostgreSQL with a window function, so a domain with thousands of
subdomains costs one bounded query and returns 25 rows plus a count. The traversal is
breadth-first with a visited set, so cycles (CNAME loops, a name and an address pointing at
each other) end where they close. When a bound is hit, the map says which one ("node limit
reached", "time limit reached") instead of failing.

## Isolation

The map is built in the caller's tenant session (RLS) and restricted to one organization:
the starting asset's organization, and every relationship is filtered to it. Asking for an
asset in another organization or tenant — or naming an organization and an asset that does
not belong to it — returns 404. Results are cached for 30 seconds in the API process under a
key that includes the tenant, the caller's role and whether findings may be shown, so one
tenant's (or role's) map never answers another's request. Findings appear only for callers
with `findings:read`. Relationship sources are shown as capability labels, never engine names
(ADR-022).

## API

`GET /api/v1/exposure-map` — permission `assets:read`.

| Parameter | Meaning |
|---|---|
| `organization_id` or `asset_id` | where to start (one is required); `expand` = one node's neighbours |
| `depth`, `max_nodes`, `per_node` | bounds above |
| `include_findings`, `include_unverified`, `include_inactive`, `include_context` | filters above |

Response: `organization`, `root_ids`, `nodes[]` (`id`, `kind` asset/finding, `type`, `label`,
`status`, `scope_status`, `risk_score`, `first_seen`, `last_seen`, `depth`, `hidden`
{relation: count}, `third_party_only`, `more_beyond_depth`; findings also `severity`,
`unverified`, `finding_id`), `edges[]` (`relation`, `meaning`, `evidence`
observed/derived/unverified report, `source_label`, `first_seen`, `last_seen`, `age_days`,
`freshness` current/stale/inactive/historical/unverified, `active`), `truncated`,
`truncation_reasons`, `limits`, `elapsed_ms`, `notice`, `cached`.

## Future phase: attack-path analysis (not implemented)

Saying that one asset can be used to *reach* another needs evidence this platform does not
hold: authoritative cloud configuration (security groups, IAM policies, load-balancer
targets), identity data (which accounts and roles reach which systems), and internal network
topology (routes, firewall rules, segmentation). Without them, any "path" drawn from
external observations would be a guess presented as a finding — shared hosting or a shared
certificate proves nothing about reachability. A future phase would need:

1. read-only connectors to cloud providers and identity systems, with their own
   authorization and tenant isolation;
2. a model of trust and reachability that distinguishes observed facts from permissions;
3. explicit confidence and provenance on every inferred step, with human review before
   anything is presented as exploitable.

Until then the map stays what it is: a view of recorded external relationships.

## Measured cost

Same synthetic organization as in THREAT_CENTER.md (5 000 hostnames, ≈ 23 000
relationships), development workstation, PostgreSQL 18 in WSL:

| Request | Result | Time | Python peak memory |
|---|---|---|---|
| organization, depth 2, max 150 nodes | 76 nodes (root capped at 25 neighbours, "+4 975") | 70 ms | 1.2 MB |
| organization, depth 4, max 300 nodes | 300 nodes, 399 edges, node limit reached | 380 ms | 2.6 MB |
| a 600-subdomain domain, depth 2 (test suite) | 26 nodes, "+575" | < 5 s asserted | — |

Cached repeats within 30 s cost nothing. Not measured: concurrent requests, a production-sized
database, browsers rendering 600 nodes on low-end machines.
