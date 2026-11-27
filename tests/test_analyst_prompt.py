"""The analyst's schema card, prompts, SQL-block extraction and escaping. Pure tests."""

from __future__ import annotations

import pytest

from cyber_threat_pipeline.analyst import prompt, schema
from cyber_threat_pipeline.analyst.guard import Refusal


def test_card_names_each_of_the_11_marts() -> None:
    assert {mart.name for mart in schema.MARTS} == schema.MART_NAMES
    card = schema.card()
    for name in schema.MART_NAMES:
        assert f"marts.{name}:" in card


def test_card_lists_84_columns_and_leaves_out_pulses_first_seen_this_month() -> None:
    assert sum(len(mart.columns) for mart in schema.MARTS) == 84
    assert "pulses_first_seen_this_month" not in schema.card()


def test_sql_prompt_holds_no_data_value() -> None:
    # Built from constants and the question only: the prefix is the same for every
    # question, and nothing else goes in.
    first, second = prompt.sql_prompt("q1?"), prompt.sql_prompt("another question?")
    prefix = prompt.sql_prompt("")
    assert first == prefix.removesuffix("\n") + "q1?\n"
    assert second == prefix.removesuffix("\n") + "another question?\n"
    assert schema.card() in prefix


def test_sql_prompt_stays_within_its_budget() -> None:
    assert len(prompt.sql_prompt("")) <= 14_000


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        pytest.param("```sql\nselect 1\n```", "select 1", id="block"),
        pytest.param("Here:\n```sql\nselect 1;\n```\nDone.", "select 1;", id="text-around"),
        pytest.param("```sql  \nselect 1\n```", "select 1", id="spaces-after-tag"),
        pytest.param(
            "CANNOT_ANSWER the marts hold no prices.",
            prompt.CannotAnswer("the marts hold no prices."),
            id="cannot-answer",
        ),
        pytest.param(
            "  CANNOT_ANSWER: no table has it",
            prompt.CannotAnswer("no table has it"),
            id="cannot-answer-colon",
        ),
        pytest.param(
            "CANNOT_ANSWER", prompt.CannotAnswer("(no reason given)"), id="cannot-answer-bare"
        ),
        pytest.param("select 1", Refusal("no single SQL block"), id="no-block"),
        pytest.param(
            "```sql\nselect 1\n```\n```sql\nselect 2\n```",
            Refusal("no single SQL block"),
            id="two-blocks",
        ),
        pytest.param("```sql\nselect 1", Refusal("no single SQL block"), id="unclosed"),
        pytest.param(
            "```sql\nselect 1\n```\n```sql\nselect 2",
            Refusal("no single SQL block"),
            id="second-unclosed",
        ),
        pytest.param("```postgres\nselect 1\n```", Refusal("no single SQL block"), id="other-tag"),
        pytest.param("", Refusal("no single SQL block"), id="empty"),
    ],
)
def test_extract_sql(reply: str, expected: object) -> None:
    assert prompt.extract_sql(reply) == expected


def test_explanation_prompt_shows_at_most_50_rows_and_the_count() -> None:
    rows = [(i, f"tag{i}") for i in range(60)]
    text = prompt.explanation_prompt("Q?", "SELECT 1", ["n", "tag"], rows, cut=False)
    assert "Question: Q?" in text and "SELECT 1" in text
    assert "60 rows. The first 50 are shown." in text
    assert "n | tag" in text and "49 | tag49" in text and "50 | tag50" not in text


def test_explanation_prompt_cuts_long_text_and_writes_null() -> None:
    text = prompt.explanation_prompt("Q?", "S", ["a", "b"], [("x" * 300, None)], cut=False)
    assert "x" * 200 + "..." in text and "x" * 201 not in text
    assert "| NULL" in text


def test_rows_text_is_the_explanation_prompt_s_rows_part() -> None:
    rows = [(i, f"tag{i}") for i in range(60)]
    part = prompt.rows_text(["n", "tag"], rows, cut=False)
    assert part.startswith("60 rows. The first 50 are shown.\n\nRows:\nn | tag\n")
    assert prompt.explanation_prompt("Q?", "S", ["n", "tag"], rows, cut=False).endswith(part)


def test_explanation_prompt_says_when_the_result_is_cut_or_empty() -> None:
    cut = prompt.explanation_prompt("Q?", "S", ["a"], [(1,)] * 1001, cut=True)
    assert "the result was cut at the row cap" in cut
    empty = prompt.explanation_prompt("Q?", "S", ["a"], [], cut=False)
    assert "No rows." in empty and "Rows:" not in empty


@pytest.mark.parametrize(
    ("text", "escaped"),
    [
        ("plain text", "plain text"),
        ("\x1b[2J\x1b]0;pwned\x07", "\\x1b[2J\\x1b]0;pwned\\x07"),
        ("a\rb", "a\\x0db"),
        ("csi\x9bm", "csi\\x9bm"),
        ("rtl‮override", "rtl\\u202eoverride"),
        ("line\u2028sep\u2029par", "line\\u2028sep\\u2029par"),
        ("two\nlines\tand tab", "two\nlines\tand tab"),
    ],
)
def test_escape_writes_control_and_format_characters_visibly(text: str, escaped: str) -> None:
    assert prompt.escape(text) == escaped


def test_escape_can_escape_newlines_too() -> None:
    assert prompt.escape("a\nb\tc", keep_newlines=False) == "a\\x0ab\\x09c"
