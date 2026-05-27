# monitoring/ — Grafana Cloud dashboards + alerts as code

The **operations** surface (the analyst-facing counterpart lives in
`reporting/`). Five conceptual panels, four alert rules, all committed as
JSON / YAML — the Grafana Cloud tenant is configured by importing these
artifacts, no click-around state lives outside the repo.

```
pipeline.runs         ◄── grafana_ro role ──  Grafana Cloud
marts.mart_data_quality                       │
                                              ▼
                                      operator + public-share URL
```

Spec: `_private/specs/06-monitoring-grafana.md`. Read it for the
canonical SQL, alert semantics, and the eight acceptance criteria.

## Files

| File | Purpose |
|---|---|
| `dashboard.json` | One Grafana dashboard, six grid panels (Panel 3 is split into two stat halves per spec §3.3). Schema v39, refresh 5m, default range last 90 days. |
| `alerts.yaml` | Four alert rules in Grafana's `apiVersion: 1` provisioning format: freshness >8d (critical), run-failure (warning), volume anomaly drift-or-zero (warning), dbt test failures (warning). |
| `datasource.example.yaml` | Postgres datasource provisioning template — no secrets. |
| `README.md` | This file. |

## Pre-import: the `grafana_login` Postgres user

Grafana connects to Neon via a dedicated login user **with the
`grafana_ro` group role**, scoped to `marts.*` + `pipeline.runs` only.
The role is created by `sql/30_grafana_role.sql`; the login user is a
separate one-time creation against Neon (the password never lands in this
repo):

```sql
-- Run once against the live Neon DB (psql or Neon's SQL editor):
CREATE USER grafana_login WITH PASSWORD '<generated-strong-password>' IN ROLE grafana_ro;
```

Capture the password into a password manager and into Grafana Cloud's
secret store at provisioning time (next step). The `grafana_ro` role
itself has `NOLOGIN`; this user is the only path to it.

Verify the privilege boundary before exposing the user to Grafana:

```sql
-- As grafana_login:
SET ROLE grafana_ro;
SELECT 1 FROM raw.pulses LIMIT 1;     -- must fail: permission denied for schema raw
SELECT 1 FROM marts.mart_data_quality LIMIT 1;   -- must succeed
SELECT 1 FROM pipeline.runs LIMIT 1;             -- must succeed
```

This is acceptance criterion §2 from spec 06. Failing it = the role is
mis-scoped; do not import the dashboard until it passes.

## Provision the datasource

In Grafana Cloud → Connections → Data sources → Add data source →
PostgreSQL. Either:

1. Paste the values from `datasource.example.yaml` into the UI form
   (replacing `<neon-pooled-host>`, `<neon-db-name>`, and the password
   placeholder).
2. Or POST the YAML via Grafana's HTTP API (admin-only):
   `POST /api/datasources` with the YAML body.

Either way, **name the datasource `neon_ro`** so the dashboard's
`${DS_NEON_RO}` template variable resolves on import.

After provisioning, click **Save & test** — Grafana reports
`Database Connection OK`. If it doesn't, the most common causes are:

- `sslmode: require` is missing (Neon refuses non-SSL).
- The Neon host string is the un-pooled endpoint (use the pooled host).
- `postgresVersion` mis-set — Neon ships Postgres 15.x as of writing;
  adjust if it's bumped.

## Import the dashboard

In Grafana Cloud → Dashboards → New → Import → Upload JSON file →
`monitoring/dashboard.json`. Grafana prompts for the `DS_NEON_RO`
input — pick the `neon_ro` datasource you just created.

The dashboard contains six grid panels in the layout from spec §7. With
fewer than 2 successful `pipeline.runs` rows, time-series panels render
as a single dot or empty plot — this is expected (the seed fixture
only inserts one row). Real-world meaningful rendering kicks in after
~2 weekly runs.

### state-timeline plugin

Panel 1 ("Run health over time") uses the `state-timeline` panel type.
It's part of Grafana core since 8.x — no plugin install needed on
Grafana Cloud's current builds. If it ever renders as "Panel type not
found", install `grafana-statetimeline-panel` from the plugin catalog.

## Provision the alert rules

`alerts.yaml` carries four rules with the placeholder
`<NEON_RO_UID>` everywhere a datasource UID is referenced. Before
provisioning, substitute it with the actual UID from your Grafana
tenant:

1. Grafana → Connections → Data sources → `neon_ro` → look at the URL
   slug, e.g. `/datasources/edit/abc123def`. The UID is `abc123def`.
2. Sed it in-line for provisioning:

   ```bash
   sed 's/<NEON_RO_UID>/abc123def/g' monitoring/alerts.yaml > /tmp/alerts.yaml
   ```

3. Provision either via the Grafana Cloud UI
   (Alerting → Alert rules → Import) or via the HTTP API
   (`POST /api/v1/provisioning/alert-rules` per rule).

Contact points (where alerts are routed — Slack, PagerDuty, email,
etc.) are configured separately in Grafana Cloud's notification
policies UI; the rules themselves carry `severity` + `component`
labels that the operator's notification policy matches against.

## Public-share URL

Spec acceptance §7 requires a public-share URL renders all panels
without authentication. Public sharing is a Grafana Cloud tenant
feature, not in the JSON:

1. Open the dashboard → click the share icon → Public dashboard tab.
2. Enable. Grafana generates a `/public-dashboards/<uuid>` URL.
3. The public view hides the underlying queries (only renders the
   panels), so the read-only role's existence isn't even visually
   exposed.

Add the public URL to the project README once enabled.

## Round-trip check (acceptance §8)

The committed `dashboard.json` is the source of truth. To verify it
round-trips cleanly:

1. Import → make no edits → Dashboard settings → JSON Model → Save to
   file.
2. `diff` against the committed `dashboard.json` — Grafana adds a few
   default fields (e.g. `version` increments, computed UID) but the
   panels + targets + grid positions must be unchanged.

If a CI change in the future breaks the round-trip (e.g. a Grafana
version bump rewrites a panel option), re-export and commit the diff
with a note explaining the upstream change.

## CI

The `monitoring · validate` job in `.github/workflows/ci.yml` runs
`yaml.safe_load` on `alerts.yaml` + `datasource.example.yaml` and
`json.load` on `dashboard.json` on every push and PR. It catches
accidental syntax breakage; it does **not** verify Grafana semantics
(panel rendering, alert evaluation against live data) — those are
operator-side checks against the actual tenant.
