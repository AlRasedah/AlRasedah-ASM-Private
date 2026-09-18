# Risk scoring

Risk is **not** CVSS. Scores are 0–100 and every contribution is stored as a factor
(`risk_factors`), shown in the UI under "Why this risk score".

## Finding score

```text
technical severity      max(severity points, CVSS × 5.5)          critical 55 · high 40 · medium 25 · low 10 · info 2
+ exploitability        CISA KEV +20  (or public exploit +8)  +  EPSS × 18
+ exposure              internet-facing +5 · admin interface +10 · auth surface +4 · high-risk port +6
+ business context      criticality low 0 · medium 4 · high 9 · critical 14
+ threat context        unverified/unknown owner (shadow IT) +5 · unauthorized +10 · new asset (<7 d) +3
+ age                   +2 per 30 days open (max +8)
× confidence            0.6 + 0.4 × confidence
= clamp(0, 100)
```

Levels: critical ≥ 80, high ≥ 60, medium ≥ 35, low ≥ 15, otherwise info.

Examples (defaults):

| Finding (detection confidence 90 % unless noted) | Score |
|---|---|
| CVE-2018-13379 on a newly found, unverified VPN portal (CVSS 9.8, EPSS 0.97, KEV) | 100 (critical) |
| Same CVE without KEV/EPSS on an approved, medium-criticality asset seen for 90 days | 61 (high) |
| Exposed RDP (platform rule, confidence 85 %) on a newly found, unverified derived IP | 59 (medium) |
| Informational finding on an approved asset (confidence 80 %) | 10 (info) |

(Computed with the default weights by `backend/app/risk/engine.py`.)

## Asset score

- With open findings: highest finding score + 0.15 × the rest (max +15).
- Without findings: exposure/context factors only, capped at 45.
- Parents inherit children: hostname ← endpoints / resolved IPs ← ports ← services.

Organization score (dashboard): `0.8 × top asset + 0.2 × average of the next nine`.

## Tuning

Settings → Risk scoring weights (tenant-wide), stored in `tenants.settings.risk` and merged
over defaults (`backend/app/tenants/settings.py`). Saving recomputes all organizations.
Scores are also recomputed after every scan and nightly (age factors). Intelligence (KEV,
EPSS, CVSS) refreshes daily and re-enriches open findings.

Code: `backend/app/risk/engine.py` (pure, tested in `tests/backend/test_risk_engine.py`) and
`backend/app/risk/service.py`.
