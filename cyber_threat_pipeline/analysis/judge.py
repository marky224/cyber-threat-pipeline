"""Optional LLM judge: how many of a brief's claims its input supports.

Off unless ``ANALYSIS_JUDGE`` is set. Only two judges are allowed:

- ``claude``: Claude Haiku 4.5 (``claude-haiku-4-5``) through the judge's own
  Anthropic client: 60 s timeout, no retries, so a slow judge can't push
  ``make analysis`` toward pipeline.yml's 30-minute job timeout before the
  page is written. Needs ``ANTHROPIC_API_KEY``.
- ``local``: the Ollama model (``LOCAL_MODEL``) through ``local.py``.

``JUDGE_MODEL`` overrides the model id. Any other value (``gpt``,
``gemini``, …) is logged and ignored: never a GPT or Gemini judge.

Warn-only, like the deterministic checks in ``eval.py``: ``judge()`` never
raises, and a missing key, failed call or unreadable reply gives ``None``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

import anthropic
from anthropic.types import TextBlock

from cyber_threat_pipeline.analysis import local
from cyber_threat_pipeline.core.config import Settings

logger = logging.getLogger(__name__)

JUDGE_PROVIDERS = frozenset({"claude", "local"})
DEFAULT_CLAUDE_JUDGE_MODEL = "claude-haiku-4-5"
_MAX_TOKENS = 4000
_CLAUDE_TIMEOUT_SECONDS = 60.0

_JUDGE_PROMPT = """\
You are checking a threat-intelligence brief against the only data its writer
was given. The writer's full prompt, including that data, is inside
<writer_prompt>; the brief is inside <brief>.

List every factual claim the brief makes: each number, name, attribution,
grouping or comparison. For each claim, decide whether the data in the writer's
prompt supports it. A claim the data does not mention is not supported.

Reply with JSON only, in exactly this shape:
{{"claims": [{{"claim": "<short quote>", "supported": true}}]}}

<writer_prompt>
{prompt}
</writer_prompt>

<brief>
{brief}
</brief>
"""


@dataclass(frozen=True)
class JudgeScore:
    """Claims the judge found supported, out of all claims it listed."""

    supported: int
    total: int
    model: str


def judge(prompt: str, brief: str, cfg: Settings) -> JudgeScore | None:
    """Ask the configured judge to score ``brief``; ``None`` when off or failed."""
    choice = cfg.analysis_judge.strip().lower()
    if not choice:
        return None
    if choice not in JUDGE_PROVIDERS:
        logger.warning("ANALYSIS_JUDGE=%r is not claude or local; judge skipped", choice)
        return None
    try:
        reply, model = _ask(choice, _JUDGE_PROMPT.format(prompt=prompt, brief=brief), cfg)
        return _parse(reply, model)
    except Exception as e:
        logger.warning("Brief judge (%s) failed: %s: %s", choice, type(e).__name__, e)
        return None


def _ask(choice: str, judge_prompt: str, cfg: Settings) -> tuple[str, str]:
    if choice == "claude":
        if cfg.anthropic_api_key is None:
            raise RuntimeError("ANTHROPIC_API_KEY isn't set")
        model = cfg.judge_model or DEFAULT_CLAUDE_JUDGE_MODEL
        return _ask_claude(judge_prompt, cfg.anthropic_api_key.get_secret_value(), model), model
    model = cfg.judge_model or local.DEFAULT_MODEL
    reply = local.query_local(
        judge_prompt, base_url=cfg.ollama_base_url, model=model, max_tokens=_MAX_TOKENS
    )
    return reply, model


def _ask_claude(judge_prompt: str, api_key: str, model: str) -> str:
    client = anthropic.Anthropic(api_key=api_key, timeout=_CLAUDE_TIMEOUT_SECONDS, max_retries=0)
    response = client.messages.create(
        model=model,
        max_tokens=_MAX_TOKENS,
        temperature=0.3,
        messages=[{"role": "user", "content": judge_prompt}],
    )
    for block in response.content:
        if isinstance(block, TextBlock):
            return block.text.strip()
    raise RuntimeError("judge reply contained no text block")


def _parse(reply: str, model: str) -> JudgeScore:
    """Read the judge's JSON, tolerating prose or a code fence around it."""
    match = re.search(r"\{.*\}", reply, re.DOTALL)
    if match is None:
        raise ValueError("judge reply has no JSON object")
    claims = json.loads(match.group(0)).get("claims")
    if not isinstance(claims, list) or not all(
        isinstance(c, dict) and isinstance(c.get("supported"), bool) for c in claims
    ):
        raise ValueError("judge reply has no claims list with true/false 'supported'")
    return JudgeScore(
        supported=sum(1 for c in claims if c["supported"]), total=len(claims), model=model
    )
