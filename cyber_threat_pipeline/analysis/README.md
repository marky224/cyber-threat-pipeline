# `cyber_threat_pipeline/analysis/` — LLM analyst brief

Reads the `marts.brief_input` mart and asks one or two LLMs to produce a
weekly threat-intel brief on the **same payload**. Writes
`reporting/pages/analyst-brief.md` for Evidence to render.

The page **regenerates on every `make analysis` run** and is gitignored —
don't expect a committed copy.

## Why two LLMs

The same prompt, side-by-side. Differences are **interpretation**, not
information. That comparison itself is the artifact; this is not a "best of"
or an ensemble.

When the two configured slots resolve to the same `(provider, model)` —
typical for local-dev where both default to the Ollama provider — the writer
collapses them to a single block. Production sets two distinct providers and
gets the two-tab layout.

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

Two env vars pick which providers run; each accepts any name from the table
above:

```
ANALYSIS_PRIMARY_PROVIDER=local      # default
ANALYSIS_SECONDARY_PROVIDER=local    # default — collapses to single block
```

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
ANALYSIS_PRIMARY_PROVIDER=claude \
ANALYSIS_SECONDARY_PROVIDER=grok \
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

## Spec

Authoritative: `_private/specs/04-analysis-llm.md`. If anything here
contradicts the spec, the spec wins.
