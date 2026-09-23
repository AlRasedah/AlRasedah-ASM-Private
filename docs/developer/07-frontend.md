# 7. Frontend

Stack: React 18 + TypeScript (strict) + Vite 6, React Router 6 (v7 future flags on),
TanStack Query 5 for server state, Recharts 3 for charts, lucide-react icons, plain CSS
built on the Al-Rasedah design tokens (§7.8).
No UI framework and no global state library: server state lives in React Query, the only
client state is the session (AuthContext) and the selected organization (OrgContext).

## 7.1 Boot and session

`main.tsx` → `QueryClientProvider` → `BrowserRouter` → `AuthProvider` → `App`.

`AuthProvider` on mount calls `refreshSession()`: if the refresh cookie is valid the API
returns a new access token, then `/auth/me` loads the user, tenant, role, permissions and
memberships. `ready` becomes true either way; `RequireAuth` then renders the app or
redirects to `/login` (remembering the original path).

`api/client.ts`:

- `accessToken` is a module variable — never written to storage (XSS cannot read it from
  localStorage because it is not there).
- `api(path, {method, body, query})` adds `Authorization`, serializes the query (arrays →
  repeated params), and on **401** calls `refreshSession()` once and retries; if refresh
  fails, `onUnauthenticated` clears the session and React Query cache.
- `refreshSession()` is **single-flight**: concurrent 401s share one refresh promise. This is
  required because the server rotates refresh tokens and treats reuse of an old one as
  theft (parallel refreshes would log the user out).
- The CSRF value is read from the `asm_csrf` cookie and sent as `X-CSRF-Token`.
- Errors become `ApiError(status, code, message, details)`; `ErrorBox` renders them,
  including validation detail lists.

## 7.2 Permissions in the UI

`useAuth().can("scope:write")` hides actions the user cannot perform (nav items, buttons,
editable fields). This is convenience only — the API enforces every permission.

## 7.3 Organization filter

`OrgContext` loads `/organizations` and keeps the selected organization id in
localStorage (`asm.org`, wrapped in try/catch). Pages pass `organization_id: orgId` to their
queries and include `orgId` in query keys so switching refetches everything.

## 7.4 Data fetching conventions

```tsx
const q = useQuery({ queryKey: ["assets", query], queryFn: () => api<Page<Asset>>("/assets", { query }) });
const m = useMutation({ mutationFn: (b) => api(`/assets/${id}`, { method: "PATCH", body: b }),
                        onSuccess: () => qc.invalidateQueries({ queryKey: ["asset", id] }) });
```

- Query keys start with the resource name (`assets`, `asset`, `findings`, `events`, `scans`,
  `scan`, `profiles`, `integrations`, `policies`, …) so mutations can invalidate by prefix.
- Polling: scans/reports use `refetchInterval` functions that poll quickly only while
  something is pending/running.
- Lists use server-side pagination (`Pagination` component, `page_size` 25–100).

## 7.5 URL-synced filters (`lib/useFilters.ts`)

Inventory, Findings and Changes keep filters in the query string so views are shareable and
survive reloads. `set(key, value)` updates one key (and resets `page`); **use `setMany` when
changing several keys at once** — two consecutive `setSearchParams` calls in one tick can
overwrite each other in React Router 6.

## 7.6 Components (`components/`)

| Component | Use |
|---|---|
| `Layout` | `Brand`/`BrandMark` (logo lockup), sidebar (permission-aware; a **Documentation** link under a "Help" section opens the offline user guide `public/user-guide.html` in a new tab — see §7.10), topbar (organization selector, tenant switcher when the user has several memberships, unacknowledged-change counter, account, sign out) |
| `ui.tsx` | `Card`, `PageHead`, `SeverityBadge`, `StatusBadge` (tone map for every status value), `RiskScore` (number + bar coloured by level), `Tags`, `Tabs` (ARIA roles), `Modal` (Esc/backdrop close), `Confirm`, `Pagination`, `Kpi`, `Field`, `JsonView`, `Empty`, `Loading`, `ErrorBox`, `useDebounced` |
| `Charts.tsx` | `TrendChart` (area) and `HBarChart` (horizontal bars) — shows an empty state instead of a meaningless chart when there is < 2 points; grid, tooltip and default bar colour come from tokens, series colours are passed as `var(--…)` |
| `Timeline.tsx` | event list used by Changes, asset timeline and scan changes (severity dot, type, baseline/acknowledged badges, previous → current diff) |

## 7.7 Pages

| Route | File | Notes |
|---|---|---|
| `/` | `dashboard/Dashboard.tsx` | KPIs, risk trend, growth, severity, recent changes, most exposed, top vulnerable, opened services, expiring certificates, technologies, hosting, ASNs; onboarding card when there are no organizations |
| `/inventory` | `assets/Inventory.tsx` | filters, sortable table, bulk update modal, CSV export; defaults to primary asset types |
| `/assets/:id` | `assets/AssetDetail.tsx` | tabs depend on asset type: overview (attributes, risk factors, ownership form), relationships, DNS, ports & services, web endpoints, technologies, certificates, findings, timeline, raw observations |
| `/shadow-it` | `assets/ShadowIT.tsx` | unverified/unknown/unauthorized active assets with one-click classification |
| `/findings`, `/findings/:id` | `findings/` | prioritized list; detail with workflow (transitions mirror the backend), activity log, evidence, references. A **DAST** badge (the finding's boolean `dast` field) marks findings dynamically confirmed by active web scanning. A second tab lists **unverified** findings — third-party reports awaiting confirmation (ADR-020) — which are excluded from the main list and from risk |
| `/threats`, `/threats/:id` | `threats/ThreatCenter.tsx`, `ThreatDetail.tsx` | advisories with this tenant's counts and assessment freshness; detail with KPIs (filters on click), affected products, KEV/EPSS, references (`rel="noopener noreferrer nofollow"`), matched assets with evidence, linked findings, owner, last check and remediation (modal, `findings:write`); **Check selected assets** only with `scans:run` and an approved check. Assessment words and hints live in `ASSESSMENT_LABELS` (`lib/format.ts`) — "not detected" always says it is not proof of safety |
| `/threats/catalog` | `threats/ThreatCatalog.tsx` | platform admins (`intel:admin`): advisory editor (structured affected-product/version-range form, approved check picker), publish/archive/restore with confirmation, approved-check allowlist |
| `/assets/:id` → Screenshots tab | `assets/Screenshots.tsx` | web endpoints only: latest image fetched as a blob through the API (object URL, revoked on unmount — there is no public image URL), metadata, last 10 attempts with state; **Capture screenshot** (`scans:run`), cancel, delete (`assets:write`); polls every 3 s while a capture is queued/running; when the feature is off it shows the server's reason instead of the button |
| `/settings` → Website screenshots | `pages/ScreenshotSettings.tsx` | tenant card (enable + cadence, saved with the page; disabled with the platform's reason when unavailable; usage vs limits) and the platform-admin policy card (`tenants:admin`) |
| `/exposure-map`, `/assets/:id` → Exposure map tab | `exposure/ExposureMapPage.tsx`, `exposure/ExposureGraph.tsx` | one organization at a time (explicit choice when "All organizations" is selected); optional start asset (search, "Start here"); SVG with columns in chain order (domains → IPs → ports/services → web → context → findings), line style by freshness, dashed nodes for third-party-only or inactive, "+N" for hidden neighbours; side panel explains a node or a line; **Expand** merges one node's neighbours (≤ 600 nodes client-side); filters refetch with `keepPreviousData` so the map does not blank. No graph library |
| `/changes` | `pages/Changes.tsx` | event feed, acknowledge |
| `/scans`, `/scans/:id` | `scans/Scans.tsx`, `ScanDetail.tsx` | start scan modal (profile description, active warning, optional targets, and — when the profile has a stage whose capability `accepts_login` — a session-cookie field for authenticated crawling, ADR-023); pipeline stages named by capability, scan changes, authorization log |
| `/scan-profiles` | `scans/Profiles.tsx` | built-in/custom profiles (JSON stage editor validated server-side), schedules. Stages identify their engine by the opaque `eng_…` token the API returned; the editor round-trips it untouched |
| `/organizations`, `/organizations/:id` | `pages/` | scope entries (bulk add incl. `*.example.com`, exclusions, active permission, ownership verification or platform-admin approval), scanning policy, scope checker |
| `/integrations` | `pages/Integrations.tsx` | notification channels, and **data-source API keys** grouped by what they do, each with a **Test** button. This is the one place third-party names are shown on purpose — the customer buys those keys |
| `/settings` | `pages/Settings.tsx` | tenant settings, plus the platform-admin **Email delivery** card (mail server + test send) that overrides `ASM_SMTP_*` (ADR-021) |
| `/account` | `pages/Account.tsx` | profile, password, MFA (password required), and **personal alerts** to the login address — on by default for high/critical |
| `/reports`, `/users`, `/audit`, `/platform` | `pages/` | as named |
| `/login`, `/reset-password` | `pages/` | public |

Pages are lazy-loaded in `App.tsx` (initial bundle ≈ 243 KB, 78 KB gzipped).

Terminology: the UI speaks in capabilities, never engines — "Certificate transparency",
"Deep subdomain enumeration", "Detection source: Vulnerability detection". The API sends no
engine name at all (ADR-022), so there is nothing to hide in the client and nothing to leak
through the network tab; when a component needs an engine identifier it uses the opaque
token. The exception is Integrations, which names the data sources whose keys the customer
supplies. If you are about to write a tool's name into a component, that string belongs in
the adapter's `display_name` instead.

## 7.8 Styling (`styles.css`) — the Al-Rasedah design system

The UI wears the Al-Rasedah Technology brand from alrasedah.com.sa: deep navy grounds,
one copper accent, Inter + IBM Plex Sans Arabic (ADR-019). Everything visual lives in
**one stylesheet**, `src/styles.css`, in this order:

1. **`@font-face`** for the self-hosted fonts in `src/fonts/` — Inter (variable, 400–700,
   Latin) and IBM Plex Sans Arabic (400/500/600/700). Vite fingerprints and bundles them;
   the nginx CSP (`font-src 'self'`) already allows them. No Google Fonts or other CDN.
2. **Tokens** as CSS custom properties:
   - brand ramps, theme-independent: `--brand-navy-950 … -700`, `--brand-copper-900 … -300`,
     `--copper-gradient`;
   - type (`--font-sans`, `--font-arabic`, `--font-mono`), shape (`--radius-xs|sm|control`,
     `--radius`, `--radius-lg|pill`), sizes (`--control-height[-sm]`, `--sidebar-width`,
     `--content-max`, `--icon-size`), layers (`--z-topbar|header|menu`);
   - semantic colours per theme — `:root, [data-theme="dark"]` (the default) and
     `[data-theme="light"]`.
3. **Component classes** — the same class vocabulary the components have always used
   (`.card`, `.btn.primary`, `.badge.sev-high`, `table.data`, `.timeline`, `.modal`, …) and
   the utilities (`.row`, `.stack`, `.grid.cols-N`, `.muted`, `.subtle`, `.small`, `.mono`).

### Semantic tokens — use these, never hex

| Token | Use |
|---|---|
| `--background`, `--background-subtle` | page ground; sidebar, JSON/code wells |
| `--surface`, `--surface-elevated`, `--surface-muted` | cards/tables/modals; buttons, hover rows, tooltips; tags, tracks, dark inputs |
| `--foreground`, `--foreground-muted`, `--foreground-subtle`, `--heading` | values; secondary text; metadata only (timestamps, table headers); titles |
| `--border`, `--border-strong` | hairlines; control outlines |
| `--brand`, `--brand-hover`, `--brand-active`, `--brand-foreground`, `--copper-tint` | the one accent (primary button, active nav/tab, running/new, default chart series); text on a brand fill; soft brand wash |
| `--link`, `--link-hover`, `--focus` | inline links; 3px `:focus-visible` outline |
| `--success`, `--danger`, `--warning`, `--info` | status text; `--warning` is copper (site notices) — console warning states use `--sev-high-text` |
| `--sev-critical|high|medium|low|info` | severity **marks**: dots, bars, chart series (`SEV_COLOR` in `lib/format.ts`) |
| `--sev-*-text`, `--ok-text` | severity/status **text** on tinted badges and error boxes |
| `--header-background`, `--overlay`, `--shadow-modal`, `--shadow-menu` | top bar; modal backdrop; floating layers |

Rules:

- **Copper is never a severity.** `--sev-high` (amber) sits close to copper in hue, so
  severity is always shown with its word (`SeverityBadge`), and warning states use
  `--sev-high-text`, not `--warning`/`--brand`.
- **No hex in TSX.** Components pass token references as strings — Recharts and lucide
  accept them: `color="var(--success)"`, `fill={colors?.[d.name] ?? "var(--brand)"}`,
  `colors={SEV_COLOR}`. This keeps both themes correct.
- `--copper-gradient` is only for the 64×3px `.rule` under a hero/page title (and the logo).
- Borders over shadows: separation is a 1px `--border`; shadows only on things that float.
- Text contrast is ≥ 4.5:1 on the grounds each token is meant for, in both themes, with two
  source values kept as-is: `--foreground-subtle` in light (3.9:1 on white — metadata only)
  and `--border-strong` (~2:1 — controls also have a fill or label).

### Themes and direction

Dark is the default (`index.html` keeps `color-scheme: dark`). The light theme is complete
in the stylesheet but **not wired to a toggle yet**: setting
`document.documentElement.dataset.theme = "light"` switches every token. Layout uses logical
properties throughout, and `[dir="rtl"]` / `html[lang="ar"]` switch the font stack to
`--font-arabic`, loosen line-height and drop uppercase letter-spacing — an Arabic mode still
needs translations, not CSS.

### Logo

`public/brand-symbol.svg` (the copper eye, 96×64, with its own gradients) is used by
`BrandMark` in `components/Layout.tsx` at 42×28 (sidebar, login, reset password) and is
also `public/favicon.svg`. Don't recolour it or draw it inline; the previous teal radar
mark is retired.

### Reference

The full design system — brand book (voice, colour, type, iconography, logo rules), every
token with its usage note and contrast, component guidelines and live previews — is kept
as the "Al-Rasedah" design-system reference; ask the product owner for access.
Its `components/bundle.css` is the component part of `styles.css`; when you change one,
change the other.

### Changing the look

- New colour → add a token to **both** theme blocks (check contrast in each), then use
  `var(--name)`; never a literal.
- New component → reuse existing classes first; new classes go in `styles.css` next to the
  closest family, sized with the shape/size tokens.
- After any UI change, rebuild the web image to see it in Docker:
  `docker compose up -d --build asm-web` (a plain restart reuses the old image), then
  hard-refresh the browser.

## 7.9 Tests

`src/test/pages.test.tsx` renders every route inside the real `App` with `vi.mock` replacing
`api()` by `mockApi()` (`src/test/fixtures.ts`), asserts expected text, and fails on React
errors logged to the console. Adding a page = add a fixture for its endpoints and a row in
the `pages` table. 27 tests, ~3 s. Note that the first run on a cold machine occasionally
fails on the dashboard and passes on rerun — a known flake, not a regression.

## 7.10 User guide (offline documentation)

`public/user-guide.html` is the **end-user** guide — a single, self-contained HTML file
(inline CSS/JS, inline SVG logo, no external fonts or CDN) so it works both uploaded to a
public website and served offline by the app. Vite copies `public/` verbatim into `dist/`,
so it deploys at `/user-guide.html`; the sidebar **Documentation** link (`Layout.tsx`) opens
it in a new tab. It is a **product/user** document: it describes screens and workflows and
deliberately contains **no source code, file paths, internal engine ids or configuration
secrets** — engine names appear only as user-facing capabilities (e.g. "Web Application Scan
(DAST)", "powered by OWASP ZAP"). Keep it in sync with product changes, and keep
**developer**-facing changes in this handbook instead. It is intentionally not part of the
React bundle and not covered by the Vitest suite (it ships no application code).
