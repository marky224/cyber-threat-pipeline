# `cyber_threat_pipeline/analyst/` — the threat-data analyst

Ask the pipeline's data a plain-English question from your command line:

```bash
make ask Q="Which tags are on the most pulses?"
```

The analyst sends the question to Grok for one SQL query, checks the query,
runs its own rendering of it read-only against the 11 marts, and has Grok
explain the rows. It prints the SQL, up to 20 rows with the row count, the
explanation, and each call's tokens and dollars, then the total. It's a live
command, run from your own machine; CI runs only its offline tests and
`make analyst-check`.

## Settings

| Variable | What |
|---|---|
| `ANALYST_DATABASE_URL` | The pooled URL of `analyst_login`, the login in the read-only role `analyst_ro` (`sql/README.md`). Never the owner URL. Percent-encode the password's special characters (`%`, `@`, `/`, …); for a URL it can't read, `ask` says so without echoing it. |
| `XAI_API_KEY` | xAI key for Grok. |
| `ANALYST_GROK_MODEL` | Grok model for the analyst (default `grok-4.7`), apart from the brief's `GROK_MODEL`. |
| `ANTHROPIC_API_KEY` | For `make analyst-eval` only: Claude Haiku grades the explanations, and `PROVIDER=claude` runs the questions on Claude. |

`Settings` also needs `NEON_DATABASE_URL` and `OTX_API_KEY` present, as every
stage does; `ask` and the eval never open `NEON_DATABASE_URL`.

## Three walls

1. **The role.** `analyst_ro` can read only the 11 mart models: no USAGE on
   `raw` or `pipeline`, and no grant on the staging or intermediate relations
   dbt also builds into `marts`. The runner refuses a session that isn't a
   member of `analyst_ro`, or that can use `raw` or `pipeline`.
2. **The guard** (`guard.py`). One statement, and a query; only allow-listed
   syntax, functions and casts; only the 11 marts; no E'' or U&'' strings. It
   renders its own tree back to SQL with every table written `marts.<name>`
   and the outer LIMIT capped at 1,001, checks that rendering again, and the
   runner executes only that.
3. **The transaction** (`runner.py`). One `READ ONLY` transaction with a 5 s
   statement timeout, sent by the extended protocol (one command only), read
   as a stream that stops after 1,001 rows, then rolled back. No model call
   happens inside it.

Every model-written string and every value is printed with control characters
escaped.

## The eval

```bash
make analyst-eval                         # Grok (ANALYST_GROK_MODEL, temperature 0)
make analyst-eval PROVIDER=claude         # the same gold set on Claude (claude-sonnet-4-6)
make analyst-eval RECORD=1                # also save every reply body
```

It runs the 30 questions in `gold.toml` in order. For each one, the model
writes SQL; the guard checks it; then the gold query and the model's query run
in one `READ ONLY REPEATABLE READ` transaction, gold first, so both see the
same data, and their rows are compared (`compare.py`): column names are
ignored, extra model columns are allowed (up to 10), rows compare in order only
when the question says so, and numbers within the question's tolerance. A
refusal, `CANNOT_ANSWER`, a query error, a timeout or a result cut at the row
cap fails the question. After the transaction, the model explains its rows and
Claude Haiku counts the explanation's supported claims; that count is reported
and never decides a pass. The bar is 80% of the questions.

Each call is priced from `prices.py`, a dated table (read 2026-11-21, USD per
1M tokens). A call whose model has no row, whose usage is missing or doesn't
add up, or whose prompt is above its row's tier is "unpriced", and its run's
dollars read "incomplete", never a guess.

Reports go to `analyst-evals/` (gitignored, since they hold live mart values):
`<UTC stamp>-<provider>.json` and `.md` per run, and `compare.md`, the latest
run per provider side by side. With `RECORD=1`, each reply body (no headers, so
no key) goes under `<stamp>-<provider>-replies/`. The markdown escapes control
characters in every model-written string. The report also records
`brief_input.generated_at` at the start and the end, and warns when a dbt build
ran during the eval.

## The check

```bash
make analyst-check    # NEON_DATABASE_URL from the environment: the database's owner
```

Offline, after `dbt build`: CI's dbt job runs it on the seeded postgres:15, and
so does local proof. It checks that `analyst_ro` can read exactly the 11 marts
and has no USAGE on `raw`, `pipeline` or `dbt_test__audit`; that the schema
card's columns and types equal `information_schema.columns`; that every gold
query's rendering returns the same rows as its gold text, as `analyst_ro`; and
that a gold-echo eval (each question answered with its own gold SQL, no
explanation or judge) scores 100%.

## Exit codes

- `ask`: `0` an answer was printed · `1` the guard refused the query, the
  model replied `CANNOT_ANSWER`, or the query failed.
- `analyst-eval`: `0` once the run completes, whatever the accuracy.
- `analyst-check`: `0` every check passed · `1` one failed (each is printed).
- All three: `2` a setup error (a missing setting or key, no connection, an
  unreadable gold file, or a session that isn't `analyst_ro`'s). Through
  `make`, a non-zero exit makes `make` itself exit 2.

## Files

| File | What |
|---|---|
| `__main__.py` | the `ask`, `eval` and `check` commands |
| `guard.py` | the SQL guard |
| `runner.py` | the read-only runner |
| `prompt.py` | the SQL and explanation prompts, reply parsing, escaping |
| `schema.py` | the 11 mart names and the schema card the SQL prompt carries |
| `gold.toml` | the gold set: 30 questions with hand-checked SQL, for the eval |
| `compare.py` | the result match: does a model's result equal the gold result |
| `prices.py` | the dated price table and each call's dollars |
| `evaluate.py` | the eval loop, its totals and its reports |
| `check.py` | the offline check after `dbt build` |
