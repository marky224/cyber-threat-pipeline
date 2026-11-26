"""cyber_threat_pipeline.analyst.prices: the price table and what a call cost. Pure tests."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from cyber_threat_pipeline.analysis.completion import Completion
from cyber_threat_pipeline.analyst.prices import PRICES, PRICES_READ, Unpriced, dollars


def _call(
    model: str = "grok-4.7",
    *,
    input_tokens: int | None = 3_000,
    cached: int | None = 2_000,
    output: int | None = 500,
    reasoning: int | None = 300,
) -> Completion:
    return Completion(
        text="",
        model=model,
        stop_reason="stop",
        input_tokens=input_tokens,
        cached_input_tokens=cached,
        output_tokens=output,
        reasoning_tokens=reasoning,
        raw={},
    )


def test_the_table_is_dated_and_holds_the_three_models() -> None:
    assert date(2026, 11, 21) == PRICES_READ
    assert set(PRICES) == {"grok-4.7", "claude-sonnet-4-6", "claude-haiku-4-5"}


def test_a_grok_call_prices_uncached_cached_and_output_tokens() -> None:
    # (3,000 - 2,000) x $2 + 2,000 x $0.50 + 500 x $6, per 1M tokens.
    assert dollars(_call()) == Decimal("0.006")


@pytest.mark.parametrize(
    ("model", "expected"),
    [("claude-sonnet-4-6", Decimal("0.0165")), ("claude-haiku-4-5", Decimal("0.0055"))],
)
def test_a_claude_call_prices_input_and_output(model: str, expected: Decimal) -> None:
    # 3,000 x input + 500 x output, per 1M tokens.
    assert dollars(_call(model, cached=0, reasoning=None)) == expected


@pytest.mark.parametrize(
    ("call", "reason"),
    [
        pytest.param(_call(input_tokens=None), "usage not reported", id="no-input"),
        pytest.param(_call(cached=None), "usage not reported", id="no-cached"),
        pytest.param(_call(output=None), "usage not reported", id="no-output"),
        pytest.param(
            _call(input_tokens=None, cached=None, output=None, reasoning=None),
            "usage not reported",
            id="no-usage",
        ),
    ],
)
def test_a_call_with_missing_usage_is_unpriced(call: Completion, reason: str) -> None:
    assert dollars(call) == Unpriced(reason)


@pytest.mark.parametrize(
    ("call", "reason"),
    [
        pytest.param(_call("grok-4"), "no price for model grok-4", id="no-row"),
        pytest.param(
            _call("claude-sonnet-4-6-20261001", cached=0),
            "no price for model claude-sonnet-4-6-20261001",
            id="dated-id",
        ),
        pytest.param(_call(cached=4_000), "usage doesn't add up", id="cached-above-input"),
        pytest.param(_call(output=-1), "usage doesn't add up", id="negative"),
        pytest.param(
            _call(input_tokens=200_000, cached=0),
            "prompt of 200,000 tokens is above the 200,000-token price tier",
            id="above-tier",
        ),
        pytest.param(
            _call("claude-sonnet-4-6", cached=1),
            "no cached-input price for model claude-sonnet-4-6",
            id="claude-cache-read",
        ),
    ],
)
def test_a_call_that_cannot_be_priced_is_unpriced(call: Completion, reason: str) -> None:
    assert dollars(call) == Unpriced(reason)


def test_a_prompt_just_under_the_tier_is_priced() -> None:
    assert dollars(_call(input_tokens=199_999, cached=0, output=0)) == Decimal("0.399998")
