# `cyber_threat_pipeline/analyst/` — the threat-data analyst

Ask the pipeline's data a plain-English question from your command line:

```bash
make ask Q="Which tags are on the most pulses?"
```

The analyst sends the question to Grok for one SQL query, checks the query,
runs its own rendering of it read-only against the 11 marts, and has Grok
explain the rows. It prints the SQL, up to 20 rows with the row count, the
explanation, and each call's tokens. It's a live command, run from your own
machine; CI runs only its offline tests.

## Settings

| Variable | What |
|---|---|
| `ANALYST_DATABASE_URL` | The pooled URL of `analyst_login`, the login in the read-only role `analyst_ro` (`sql/README.md`). Never the owner URL. |
| `XAI_API_KEY` | xAI key for Grok. |
| `ANALYST_GROK_MODEL` | Grok model for the analyst (default `grok-4.7`), apart from the brief's `GROK_MODEL`. |

`Settings` also needs `NEON_DATABASE_URL` and `OTX_API_KEY` present, as every
stage does; the analyst never opens `NEON_DATABASE_URL`.

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

## Exit codes

`0` an answer was printed · `1` the guard refused the query, the model replied
`CANNOT_ANSWER`, or the query failed · `2` a setup error (a missing setting or
key, no connection, or a session that isn't `analyst_ro`'s).

## Files

| File | What |
|---|---|
| `__main__.py` | the `ask` command |
| `guard.py` | the SQL guard |
| `runner.py` | the read-only runner |
| `prompt.py` | the SQL and explanation prompts, reply parsing, escaping |
| `schema.py` | the 11 mart names and the schema card the SQL prompt carries |
| `gold.toml` | the gold set: 30 questions with hand-checked SQL, for the eval |
