# `cyber_threat_pipeline/analysis/` — LLM analyst brief

Reads the `marts.brief_input` mart and asks one or more LLMs to produce a
weekly threat-intel brief on the **same payload**. Writes
`reporting/pages/analyst-brief.md` for Evidence to render.

The page **regenerates on every `make analysis` run** and is gitignored —
don't expect a committed copy.

## Why several LLMs

The same prompt, side-by-side. Differences are **interpretation**, not
information. That comparison itself is the artifact; this is not a "best of"
or an ensemble.

Slots that resolve to the same `(provider, model)`, as in local dev where both
legacy slots default to Ollama, collapse to a single block. Distinct providers
render stacked, one block after another. Production runs Claude only.

## Providers

All providers conform to `query(prompt, ...) -> str`. Add a new one by
writing `<name>.py` with a `query_<name>` function + `DEFAULT_MODEL`, then
adding a `Provider(...)` entry to `providers.py`.

| Name | Module | Credential env var | Default model env var | Default |
|---|---|---|---|---|
| `claude` | `claude.py` (anthropic SDK) | `ANTHROPIC_API_KEY` | `CLAUDE_MODEL` | `claude-sonnet-4-6` |
| `grok` | `grok.py` (raw `requests`, xAI `/v1/chat/completions`) | `XAI_API_KEY` | `GROK_MODEL` | `grok-4` |
| `gpt` | `gpt.py` (openai SDK) | `OPENAI_API_KEY` | `OPENAI_MODEL` | `gpt-4o` |
| `gemini` | `gemini.py` (raw `requests`, Gemini REST `generateContent`) | `GOOGLE_API_KEY` | `GEMINI_MODEL` | `gemini-2.0-flash` |
| `local` | `local.py` (raw `requests`, OpenAI-compatible — Ollama by default) | `OLLAMA_BASE_URL` (URL, not a key) | `LOCAL_MODEL` | `llama3.1` |

## Configuration

`ANALYSIS_PROVIDERS` picks which providers run: a comma-separated list of
names from the table above, rendered in that order.

```
ANALYSIS_PROVIDERS=claude          # production (also the pipeline.yml default)
ANALYSIS_PROVIDERS=claude,grok     # two blocks on the same prompt
```

When `ANALYSIS_PROVIDERS` is empty, the legacy pair
`ANALYSIS_PRIMARY_PROVIDER` / `ANALYSIS_SECONDARY_PROVIDER` is used instead;
both default to `local`, which collapses to one block.

The orchestrator **fails fast at startup** if a selected cloud provider's
API key isn't in the environment. Local providers need only the base URL,
which has a sensible default (`http://localhost:11434`).

## Local re-run (Ollama)

```bash
# 1. Ollama running with a model pulled (one time):
ollama pull llama3.1
ollama serve   # listens on http://localhost:11434

# 2. From repo root:
make analysis                  # writes reporting/pages/analyst-brief.md
```

## Production re-run (cloud)

```bash
ANALYSIS_PROVIDERS=claude,grok \
ANTHROPIC_API_KEY=sk-ant-... \
XAI_API_KEY=xai-... \
NEON_DATABASE_URL=postgres://... \
  make analysis
```

Swap `grok` for `gpt` or `gemini` to compare against OpenAI or Google
instead; set the matching `OPENAI_API_KEY` / `GOOGLE_API_KEY`.

## Failure model

A provider 4xx/5xx **does not** kill the page. The orchestrator catches
per-provider, logs the exception, and renders
`_<provider> brief unavailable: <error type>: <message>_` in italics where
the brief would have gone. The other provider's brief still renders.

This is a deliberate departure from the legacy `send_to_llms.py`, which
silently embedded `"Error from Claude API: ..."` strings as if they were
the body text. Visible degradation beats fictional completeness.

## Grounding checks

Every brief that came back is checked against the `brief_input` row it was
written from (`eval.py`, pure and deterministic). The checks:

- the four sections and the 250-400 word band. The prompt asks for exactly
  four headings (`## Headline`, `## Emerging threats`,
  `## Contrast with the corpus`, `## Analyst caveats`), and only a `##`
  heading opens a section: bold labels, bold-only lines and other heading
  levels never do, and a `##` heading that names no section keeps the current
  one
- every Emerging-threats bullet cites a pulse id, and every id exists. With
  no `## Emerging threats` heading, the citation check reads every bullet in
  the brief instead of none
- quoted pulse names in any section, bullet or paragraph (headings and
  bold-only lines aren't read), and CVE ids, appear in the input. Every
  quote must be part of a name or tag of a pulse from the last 7 days, so
  a quoted country, tag or industry that no such pulse's name or tag
  contains counts as a failed fact. Trailing `, . ; : ! ?` and spaces
  inside the quotes are ignored: `"APT28,"` quotes the tag APT28
- every number is supported for its unit by the pulses its bullet cites
  (CVEs, countries, indicators, governments, pulses, percentages, "about N",
  "N+"); the module docstring has the rules
- no trend words ("spiked", "prior week", "shift"): the input has no
  previous-period figures

The page shows `Grounding: N/M facts verified by automated checks.` under
each provider heading, and `(id=…)` citations become links to the OTX pulse.
Each score is stored in `pipeline.brief_evals` (`sql/31_brief_evals.sql`),
which feeds the Grafana "Brief grounding" panel and the `ctp-brief-grounding`
alert (below 90%). Findings are logged as warnings in the job log.

`ANALYSIS_JUDGE=claude` (Claude Haiku 4.5, `ANTHROPIC_API_KEY`; its own client
with a 60 s timeout and no retries) or
`ANALYSIS_JUDGE=local` (Ollama) adds an optional judge that counts how many of
the brief's claims the input supports; `JUDGE_MODEL` overrides its model. No
other judge is accepted. Unset, it's off. The Claude judge sends
`temperature=0.3`, so a `JUDGE_MODEL` must accept a temperature parameter; the
default `claude-haiku-4-5` does. A model that rejects it makes the judge log a
warning and give no score.

All of this is warn-only. A crash in the checks or the judge, or a missing
table, is logged and the page still publishes.

## Spec

Authoritative: `_private/specs/04-analysis-llm.md`. If anything here
contradicts the spec, the spec wins.
