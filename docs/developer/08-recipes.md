# 8. Recipes: extending the platform

Each recipe lists every file to touch. Follow them in order and add the tests mentioned.

## Add an API endpoint

1. Schema(s) in `app/schemas/<area>.py` (inputs subclass `Input` → `extra="forbid"`, strings
   stripped; outputs subclass `ORM` → `from_attributes`).
2. Service function in the domain module (raise `AppError` subclasses; `flush`, don't commit;
   `audit.record(...)` for human mutations).
3. Route in `app/api/v1/<area>.py`:
   ```python
   @router.post("/widgets", response_model=WidgetOut, status_code=201)
   def create_widget(body: WidgetCreate, principal: Principal = Depends(require(Permission.WIDGETS_WRITE)),
                     db: Session = Depends(get_db)) -> Widget:
       w = widgets.create(db, tenant_id=principal.require_tenant(), **body.model_dump())
       db.commit()
       return w
   ```
   Declare fixed paths (`/widgets/export.csv`) **before** parameterized ones (`/widgets/{id}`).
4. New router module? Add it to `app/api/v1/router.py`.
5. New permission? Add to `Permission` and the role sets in `app/auth/permissions.py`.
6. Test in `tests/backend/test_api_*.py` including a viewer/403 case and a cross-tenant/404 case.
7. Frontend type in `src/api/types.ts`.

## Add a tenant-owned table

See chapter 5.3 — model with `TenantScoped`, migration **with** `rls.tenant_isolation`,
entry in `TENANT_TABLES`.

## Add a sensor adapter

See [../SENSORS.md](../SENSORS.md#adding-a-scanner). Then use it in a profile (built-in:
`BUILTIN_PROFILES` in `app/scans/profiles.py`; the next `bootstrap()` refreshes built-ins).

Two things are easy to forget and both are caught by `tests/backend/test_engine_disclosure.py`:
give the adapter a `display_name` that distinguishes it from the other engines on its stage
(it is what the user reads on the Pipeline — see chapter 4.11), and add a `_KNOWN` mapping in
`app/scans/messages.py` for each way the tool reports failure in its own words.

## Add a new stage type

1. `StageType` in `workers/asm_sensors/base.py`.
2. Position in `STAGE_ORDER` and a user-facing label in `STAGE_LABELS` (`app/scans/profiles.py`).
3. Target selection branch in `app/scans/targets.build_targets`.
4. Adapter(s) declaring the stage in `stage_types`.

## Add an event type / change rule

1. Value in `EventType` (`app/models/enums.py`) — no migration (VARCHAR).
2. Pure function in `app/changes/detector.py` returning an `EventDraft` (with severity,
   title, previous/new state); unit test in `tests/backend/test_detector.py`.
3. Call it from the ingestion engine where the change becomes observable
   (`_apply_asset` for attribute changes, `_upsert_relations` for edges,
   `_apply_relation_coverage`/`_deactivate` for disappearance) or from maintenance for
   time-based events.
4. Scenario test in `tests/backend/test_change_detection.py`.
5. UI label in `EVENT_LABELS` (`frontend/src/lib/format.ts`); document it in
   `docs/CHANGE_DETECTION.md` and, if relevant, a Wazuh rule in `docs/integrations/wazuh.md`.

## Add a platform detection rule

1. Knowledge (ports, markers) in `app/changes/knowledge.py` if reusable.
2. Logic in `app/findings/rules.py` (`evaluate_port` / `evaluate_endpoint` or a new
   evaluator); return `FindingObservation`s with a **stable `rule_id`** (it is part of the
   fingerprint) and add the asset type to the evaluated set if needed.
3. Toggle in `DEFAULT_TENANT_SETTINGS["detection_rules"]` and in `DetectionRules`
   (`app/api/v1/settings.py`) and the Settings page.
4. Assert it in `tests/backend/test_pipeline.py`.

## Add a notification channel

1. Config model + `Channel` subclass with `send(config, secret, payloads)` in
   `app/integrations/channels.py`; use `_post_json` (SSRF guard, no redirects) for HTTP.
2. Register in `CHANNELS` and add the value to `IntegrationType`.
3. UI: `TYPE_HELP` and the form fields in `frontend/src/pages/Integrations.tsx`.
4. Test with a monkeypatched transport (see `test_notifications_webhook_and_wazuh`).

## Add a report type

1. `ReportType` value; title in `TITLES` and sections in `SECTIONS`
   (`app/reporting/service.py`); CSV columns in `render_csv` if CSV applies (and `CSV_TYPES`).
2. Data in `build_context`; markup in `templates/report.html` guarded by
   `{% if sections.<name> %}` (keep it JS-free; charts via `reporting/charts.py`).
3. Add it to `TYPES` in `frontend/src/pages/Reports.tsx`; extend `test_reports`.

## Add a setting

Default in `app/tenants/settings.py` → field in the `SettingsUpdate` sub-model
(`api/v1/settings.py`) → read it with `tenant_settings(tenant)[...]` → UI in
`pages/Settings.tsx`.

## Add a UI page

1. Component under the matching folder; fetch with React Query; guard actions with `can()`.
2. Lazy route in `App.tsx`; nav entry in `components/Layout.tsx` (permission-gated).
3. Fixture(s) in `src/test/fixtures.ts` and a row in `src/test/pages.test.tsx`.
4. Style it with the existing classes and tokens (chapter 7.8): no hex in TSX, copper only
   for the primary action/active state, severity via `SeverityBadge`/`SEV_COLOR`.

## Add or change a colour / visual token

1. Add the custom property to **both** theme blocks in `frontend/src/styles.css`
   (`:root, [data-theme="dark"]` and `[data-theme="light"]`); check text contrast ≥ 4.5:1
   (3:1 for marks) on the grounds it will sit on, in each theme.
2. Use it as `var(--name)` in CSS or as a string in TSX (`color="var(--name)"`).
3. Mirror the change in the design-system artifact's `tokens.json` (and `bundle.css` if a
   component class changed) so the reference stays true.
4. `npm run typecheck && npm test && npm run build`; to see it in Docker,
   `docker compose up -d --build asm-web`.

## Add a periodic task

Task in `app/workers/tasks.py` (name `asm.core.<name>`; open tenant sessions per tenant) →
schedule in `beat_schedule` (`app/workers/celery_app.py`) → pure logic in a service module
so it is testable without Celery.

## Add a plan/quota

Column on `Plan` (+ migration) or a key in `plans.features`; enforcement function in
`app/tenants/service.py` called from the relevant service; default values in `DEFAULT_PLANS`.
