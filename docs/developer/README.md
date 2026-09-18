# Exteriq ASM — Developer handbook

This handbook explains **how the application is built and why**, in enough detail that a
developer who has never seen the code can run it, find their way around, change it safely
and extend it. It complements the product-level docs in `docs/` (architecture overview,
deployment, security, risk, change detection, Wazuh, API).

## Reading order

| # | Chapter | Read it when |
|---|---|---|
| 1 | [Setting up a development environment](01-setup.md) | Day one |
| 2 | [Codebase tour](02-codebase-tour.md) | Day one — where everything lives |
| 3 | [Backend internals](03-backend-internals.md) | Before touching the API, auth, sessions or tenancy |
| 4 | [The scan pipeline, end to end](04-scan-pipeline.md) | Before touching scanning, ingestion, change detection or findings |
| 5 | [Data model and migrations](05-data-model.md) | Before touching models or writing queries |
| 6 | [Sensor framework](06-sensors.md) | Before touching or adding a scanner adapter |
| 7 | [Frontend](07-frontend.md) | Before touching the web UI (§7.8: the Al-Rasedah design system) |
| 8 | [Recipes: extending the platform](08-recipes.md) | When adding an endpoint, event type, detection rule, channel, report, page… |
| 9 | [Testing](09-testing.md) | Before opening a pull request |
| 10 | [Design decisions (ADR log)](10-design-decisions.md) | When you wonder "why is it like this?" |
| 11 | [Build log: how the app was made](11-build-log.md) | History, problems met during the build, verification status, open items |

## The one-paragraph mental model

A **tenant** owns **organizations**; each organization has an **authorized scope**
(domains, IPs, CIDRs). A **scan** runs a **profile** — an ordered list of **stages**, each
executed by a **sensor adapter** (Amass, dnsx, httpx, Nuclei, …) in an isolated worker.
Sensors return scanner-independent **observations** plus **coverage** ("I checked all of
this"). The **ingestion engine** turns observations into **assets**, **relationships**
and **findings**, compares them with history, and writes **events** for every
security-relevant change. Platform **detection rules** add findings, the **risk engine**
scores everything 0–100 with explanations, and the **notification engine** delivers
events matching tenant **policies** to email/webhook/Wazuh/Slack/Teams. PostgreSQL
Row-Level Security keeps tenants apart underneath all of it.

## Golden rules for contributors

1. **Never trust tool output or user input.** Validate at the edge (pydantic models with
   `extra="forbid"`, `asm_sensors.targets`, `app.assets.normalization`).
2. **Never execute through a shell** and never add a free-form "extra arguments" option to a
   sensor.
3. **Every active target goes through `ScopeChecker`.** No exceptions, no shortcuts.
4. **Tenant data is only touched in a tenant-scoped session.** Use a system session only
   for genuinely cross-tenant work, and switch to a tenant session as soon as you know
   the tenant.
5. **Only declare coverage you actually have.** Coverage drives "gone/closed/resolved"
   events; over-claiming creates false alarms.
6. **Record, don't overwrite.** Assets are deactivated, not deleted; findings are resolved,
   not deleted; the audit log is append-only.
7. **Every state change a human makes is audited** (`app.services.audit.record`).
8. Add a test with every behaviour change; the suites run in ~25 s.
