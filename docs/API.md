# REST API

Interactive OpenAPI documentation: `https://<host>/api/docs` (Swagger UI) and
`/api/redoc`; machine-readable schema at `/api/openapi.json`.

## Authentication

| Method | Use |
|---|---|
| `POST /api/v1/auth/login` → `access_token` (Bearer, 15 min) + refresh cookie | Browser / interactive |
| `POST /api/v1/auth/refresh` with `X-CSRF-Token: <asm_csrf cookie>` | Rotate tokens |
| `Authorization: Bearer asmpat_…` | Automation (API tokens, created under Account → API tokens; scoped to one tenant and never above the owner's role) |

MFA-enabled accounts receive `{"mfa_required": true, "mfa_token": …}` from login and
complete with `POST /auth/mfa/verify`.

## Conventions

- JSON everywhere; timestamps are ISO-8601 UTC.
- Lists are paginated: `?page=1&page_size=50` (max 500) → `{items, total, page, page_size}`.
- Multi-value filters repeat the parameter: `?asset_type=subdomain&asset_type=ip_address`.
- Errors: `{"error": {"code": "...", "message": "...", "details": ...}}` with appropriate status
  codes (401 unauthorized/`token_expired`, 403 forbidden, 404 not found — also for other
  tenants' objects, 409 conflict, 422 validation/out-of-scope, 429 rate limited/quota).

## Resources

| Prefix | Operations |
|---|---|
| `/auth` | login, mfa/verify, refresh, logout, me, switch-tenant, password/forgot, password/reset, password/change, mfa/setup (body: `{"password"}`), mfa/enable, mfa/disable, api-tokens. Password change, MFA setup/enable/disable and API-token creation/revocation require an interactive session: API tokens get 403 |
| `/organizations` | list (with summary metrics), create, get, update (incl. scanning policy), delete |
| `/scopes` | list, create, bulk (domains accept `*.example.com`, stored as the domain with `include_subdomains`), update, delete, check (authorization test; a `*.` target is checked as the domain it stands for), `{id}/verification`, `{id}/verify`, `{id}/approve` (platform admin: approve an IP/CIDR entry when verification is required) |
| `/assets` | list (filters: type, status, scope, approval, unknown, owner, business_unit, criticality, tag, technology, asn, severity, risk range, first/last seen, q, sort), facets, export.csv, get, update, bulk-update, `{id}/timeline`, `{id}/observations` |
| `/findings` | list (filters: status/open_only, severity, risk level, category, asset, assignee, cve, kev, tag, q, `unverified` — third-party reports are excluded unless `unverified=true`), stats, export.csv, get, update (workflow), `{id}/activity`, `{id}/comments` |
| `/scans` | list, create (optional `targets` limits the scan to part of the scope — hostnames, IPs, CIDRs, `host:port` such as `app.example.com:8580`, or full URLs; a named port is probed and scanned even when the profile's port sweep would not reach it, and the host's other ports are left alone. Optional `auth_secret` + `auth_header_name` — a sign-in cookie/token for this scan's web application stages: stored encrypted, never returned, erased when the scan ends; `authenticated` reports whether one was given), get (with stages), cancel, `{id}/decisions` (authorization log), `{id}/artifacts`, artifact download |
| `/scan-profiles` | list, engines (capabilities: opaque `id` token, display name, scrubbed config schema), get, create, update, delete. Stages identify their engine by that token, which the API accepts back; plain engine names are still accepted for scripts and the CLI. Scan stages and findings expose capability **labels** only |
| `/schedules` | list, create, update, delete. Give `repeat` — `{frequency: daily\|weekly\|monthly, hour, minute, weekday (0 = Sunday), day}` — or a raw `cron` for a cadence the builder cannot express, but not both. Every schedule is returned with a `description` ("Every Sunday at 09:00") and, when it is one the builder can show, a `recurrence` |
| `/events` | list (filters: type, min_severity, asset, scan, acknowledged, include_baseline, since/until), acknowledge (bulk), `{id}/acknowledge` |
| `/dashboard` | summary, trends |
| `/reports` | list, create (executive, technical, asset_inventory, vulnerability, changes, risk_trend × html/pdf/csv), get, download |
| `/integrations` | types, list, create, update, delete, `{id}/test`, policies (CRUD), deliveries |
| `/credentials` | providers (with description, group, key format and whether a key can be checked), list (metadata only), set (`PUT /credentials/{provider}`), test (`POST /credentials/{provider}/test`), delete |
| `/users` | list, create/invite, update (role, active), remove, `POST /{id}/mfa/reset` (admin MFA reset) |
| `/tenants` | (platform admin) list, plans, create, update |
| `/settings` | get, update (inactivity rules, risk weights, scanning governance, detection rules, branding); `email` get/put + `email/test` (platform admin: the mail server, stored encrypted, overriding `ASM_SMTP_*`); `my-alerts` get/put (this user's own alerts, sent to their login address) |
| `/audit-logs` | list (each entry has a gapless per-tenant `chain_seq`), verify (sequence, hash links and hashes; returns `reason`) |
| `/intel` | feeds, `cve/{id}`, refresh (platform admin) |
| `/threats` | Threat Center (tenant view): list published advisories with this tenant's counts and freshness, get, `{id}/assets` (matches with evidence, linked findings, check outcome, remediation; filter `assessment`), `{id}/assets/export.csv`, `{id}/checks` (POST `{match_ids}`: run the approved check through the scan pipeline; 409 while one is active), `matches/{id}` (PATCH remediation). See [THREAT_CENTER.md](THREAT_CENTER.md) |
| `/threat-catalog` | (platform admin) advisories incl. drafts, create, `{id}/draft` (PUT), `{id}/publish`, `{id}/archive`, `{id}/restore`, `evaluate`; `checks` list and `checks/{key}` (PUT) — the approved-check allowlist |
| `/health`, `/health/ready` | liveness / readiness |

## Example: start a scan and follow it

```bash
TOKEN=asmpat_...
curl -s -H "Authorization: Bearer $TOKEN" https://asm.example.com/api/v1/scan-profiles | jq '.[] | {id, name}'
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"organization_id":"<org>","profile_id":"<profile>"}' https://asm.example.com/api/v1/scans
curl -s -H "Authorization: Bearer $TOKEN" "https://asm.example.com/api/v1/events?min_severity=high&since=2026-09-18T00:00:00Z"
```
