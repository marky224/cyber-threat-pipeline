"""The analyst eval's dated price table, and what one call cost.

Prices are USD per 1M tokens, read on ``PRICES_READ`` from xAI's models page
(docs.x.ai, developers, models) and Anthropic's pricing page. A call costs
(input - cached) x the input price, plus cached x the cached-input price, plus
billed output x the output price. Input counts every prompt token, cached ones
included, and billed output includes reasoning tokens when the provider reports
them apart (``Completion``'s fields mean the same for every provider).

A call is ``Unpriced``, never priced at a guess, when:

- its reply's model has no row here (a dated or renamed model id included);
- its usage wasn't reported or doesn't add up;
- its prompt is at or above the row's tier (grok-4.7's row is for prompts under
  200K tokens);
- it reports cached input and the row has no cached price. The Claude rows have
  none: the analyst's Claude calls send no ``cache_control``, so they neither
  read nor write a cache.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from cyber_threat_pipeline.analysis.completion import Completion

PRICES_READ = date(2026, 11, 21)

_MILLION = Decimal(1_000_000)


@dataclass(frozen=True)
class Price:
    """USD per 1M tokens; ``tier`` is the prompt size the row applies below, if any."""

    input: Decimal
    output: Decimal
    cached_input: Decimal | None = None
    tier: int | None = None


PRICES: dict[str, Price] = {
    "grok-4.7": Price(
        input=Decimal("2.00"), cached_input=Decimal("0.50"), output=Decimal("6.00"), tier=200_000
    ),
    "claude-sonnet-4-6": Price(input=Decimal("3.00"), output=Decimal("15.00")),
    "claude-haiku-4-5": Price(input=Decimal("1.00"), output=Decimal("5.00")),
}


@dataclass(frozen=True)
class Unpriced:
    """Why a call has no price."""

    reason: str


def dollars(completion: Completion) -> Decimal | Unpriced:
    """What one call cost, from its reply's model and tokens; see the module docstring."""
    price = PRICES.get(completion.model)
    if price is None:
        return Unpriced(f"no price for model {completion.model}")
    tokens = (completion.input_tokens, completion.cached_input_tokens, completion.output_tokens)
    if any(n is None for n in tokens):
        return Unpriced("usage not reported")
    prompt, cached, output = (int(n or 0) for n in tokens)
    if min(prompt, cached, output) < 0 or cached > prompt:
        return Unpriced("usage doesn't add up")
    if price.tier is not None and prompt >= price.tier:
        return Unpriced(f"prompt of {prompt:,} tokens is above the {price.tier:,}-token price tier")
    if cached and price.cached_input is None:
        return Unpriced(f"no cached-input price for model {completion.model}")
    cached_price = price.cached_input or Decimal(0)
    cost = (prompt - cached) * price.input + cached * cached_price + output * price.output
    return cost / _MILLION


def describe(cost: Decimal | Unpriced) -> str:
    """One call's cost as text: ``$0.000123``, or ``unpriced (<reason>)``."""
    return f"unpriced ({cost.reason})" if isinstance(cost, Unpriced) else f"${cost:.6f}"
