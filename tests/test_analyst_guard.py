"""cyber_threat_pipeline.analyst.guard: the threat-data analyst's SQL guard.

Pure tests, no database. Every hostile query is refused, and its reason is
asserted. Every gold query and every acceptance case passes, with a rendering
that is qualified (``marts.<name>``), capped (outer LIMIT at most 1,001) and
stable. Some cases pin how sqlglot 30.21.0 reads a construct, so a sqlglot bump
that changes it fails here first.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from sqlglot import exp

from cyber_threat_pipeline.analyst import guard
from cyber_threat_pipeline.analyst.schema import MART_NAMES

_REPO = Path(__file__).resolve().parents[1]
_GOLD_FILE = Path(guard.__file__).with_name("gold.toml")
_GOLD: list[dict[str, Any]] = tomllib.loads(_GOLD_FILE.read_text(encoding="utf-8"))["question"]
_CAPPED = f"LIMIT {guard.ROW_CAP + 1}"


def _reason(sql: str) -> str:
    result = guard.check(sql)
    assert isinstance(result, guard.Refusal), f"accepted: {result}"
    return result.reason


def _accepted(sql: str) -> guard.Checked:
    result = guard.check(sql)
    assert isinstance(result, guard.Checked), f"refused: {result}"
    return result


# --- what sqlglot 30.21.0 returns (the guard's rules rest on these) ----------


def test_sqlglot_reads_a_trailing_semicolon_as_one_statement() -> None:
    assert [type(s) for s in sqlglot.parse("select 1;", read="postgres")] == [exp.Select]


@pytest.mark.parametrize(
    ("sql", "node_class"),
    [
        pytest.param(r"select E'\\' as a", exp.ByteString, id="E-string"),
        pytest.param(r"select U&'\0041' as s", exp.UnicodeString, id="U&-string"),
    ],
)
def test_sqlglot_parses_escape_strings_to_their_own_class(
    sql: str, node_class: type[exp.Expr]
) -> None:
    assert sqlglot.parse_one(sql, read="postgres").find(node_class) is not None


# --- rules 1-3: size, one statement, a query ------------------------------------


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        pytest.param("select 1; select 2", "more than one statement", id="two-statements"),
        pytest.param("select 1;;", "more than one statement", id="two-semicolons"),
        pytest.param("", "query is empty", id="empty"),
        pytest.param(" \n\t ", "query is empty", id="whitespace"),
        pytest.param("-- select 1", "query is empty", id="line-comment-only"),
        pytest.param("/* select 1 */", "query is empty", id="block-comment-only"),
    ],
)
def test_statement_count_is_refused(sql: str, reason: str) -> None:
    assert _reason(sql) == reason


@pytest.mark.parametrize(
    ("sql", "node_class"),
    [
        ("insert into marts.mart_top_pulses (id) values ('x')", "Insert"),
        ("update marts.mart_top_pulses set name = 'x'", "Update"),
        ("delete from marts.mart_top_pulses", "Delete"),
        (
            "merge into marts.mart_top_pulses t using marts.mart_top_pulses s on true "
            "when matched then delete",
            "Merge",
        ),
        ("truncate marts.mart_top_pulses", "TruncateTable"),
        ("create table t as select 1", "Create"),
        ("create temp table t as select 1", "Create"),
        ("drop table marts.mart_top_pulses", "Drop"),
        ("alter table marts.mart_top_pulses add column x int", "Alter"),
        ("grant select on marts.mart_top_pulses to public", "Grant"),
        ("comment on table marts.mart_top_pulses is 'x'", "Comment"),
        ("copy marts.mart_top_pulses to stdout", "Copy"),
        ("copy (select 1) to program 'id'", "Copy"),
        ("do $$ begin perform 1; end $$", "Command"),
        ("call p()", "Command"),
        ("set statement_timeout = 0", "Set"),
        ("reset statement_timeout", "Command"),
        ("set role postgres", "Command"),
        ("set search_path = raw", "Set"),
        ("show all", "Command"),
        ("explain select 1", "Command"),
        ("explain analyze select 1", "Command"),
        ("begin", "Transaction"),
        ("commit", "Commit"),
        ("rollback", "Rollback"),
        ("savepoint s", "Alias"),
        ("prepare p as select 1", "Command"),
        ("execute p", "Command"),
        ("deallocate p", "Alias"),
        ("listen c", "Alias"),
        ("notify c", "Alias"),
        ("unlisten c", "Alias"),
        ("lock table marts.mart_top_pulses", "Command"),
        ("vacuum", "Command"),
        ("analyze", "Analyze"),
        ("declare c cursor for select 1", "Command"),
        ("fetch next from c", "Command"),
        ("discard all", "Alias"),
        ("load 'x'", "Command"),
        ("checkpoint", "Column"),
        ("refresh materialized view marts.mart_top_pulses", "Command"),
        ("reindex table marts.mart_top_pulses", "Command"),
    ],
)
def test_statement_that_is_not_a_query_is_refused(sql: str, node_class: str) -> None:
    assert _reason(sql) == f"not a query: {node_class}"


def test_cluster_is_refused_as_a_parse_error() -> None:
    assert _reason("cluster marts.mart_top_pulses").startswith("parse error: ")


@pytest.mark.parametrize(
    ("sql", "node_class"),
    [
        ("with d as (delete from marts.mart_top_pulses returning *) select * from d", "Delete"),
        (
            "with d as (insert into marts.mart_top_pulses (id) values ('x') returning *) "
            "select * from d",
            "Insert",
        ),
        (
            "with d as (update marts.mart_top_pulses set name = 'x' returning *) select * from d",
            "Update",
        ),
    ],
)
def test_data_modifying_cte_is_refused(sql: str, node_class: str) -> None:
    assert _reason(sql) == f"not a query: {node_class}"


@pytest.mark.parametrize(
    ("sql", "node_class"),
    [
        ("select * into t2 from marts.mart_top_pulses", "Into"),
        ("select * from marts.mart_top_pulses for update", "Lock"),
        ("select * from marts.mart_top_pulses for share", "Lock"),
        ("select * from marts.mart_top_pulses for no key update", "Lock"),
        ("select * from marts.mart_top_pulses for key share", "Lock"),
    ],
)
def test_select_into_and_row_locks_are_refused(sql: str, node_class: str) -> None:
    assert _reason(sql) == f"syntax not allowed: {node_class}"


def test_text_over_the_size_limit_is_refused() -> None:
    sql = "select 1" + " " * (guard.MAX_CHARS - len("select 1") + 1)
    assert _reason(sql) == "query is longer than 20,000 characters"


def test_text_at_the_size_limit_is_accepted() -> None:
    sql = "select 1" + " " * (guard.MAX_CHARS - len("select 1"))
    assert len(sql) == guard.MAX_CHARS
    assert _accepted(sql).sql == f"SELECT 1 {_CAPPED}"


def test_deeply_nested_text_is_refused() -> None:
    assert _reason("select " + "(" * 3000 + "1" + ")" * 3000) == "query is too deeply nested"


# --- rule 7: tables --------------------------------------------------------------


@pytest.mark.parametrize(
    ("table", "reason_name"),
    [
        # qualified
        ("raw.pulses", "raw.pulses"),
        ("raw.indicators", "raw.indicators"),
        ("raw.kev_vulnerabilities", "raw.kev_vulnerabilities"),
        ("pipeline.runs", "pipeline.runs"),
        ("pipeline.state", "pipeline.state"),
        ("pipeline.brief_evals", "pipeline.brief_evals"),
        (
            "dbt_test__audit.stg_otx__indicators_type_not_accepted",
            "dbt_test__audit.stg_otx__indicators_type_not_accepted",
        ),
        ("pg_catalog.pg_roles", "pg_catalog.pg_roles"),
        ("pg_catalog.pg_authid", "pg_catalog.pg_authid"),
        ("information_schema.tables", "information_schema.tables"),
        ("public.x", "public.x"),
        # unqualified
        ("pulses", "pulses"),
        ("runs", "runs"),
        ("pg_roles", "pg_roles"),
        ("pg_user", "pg_user"),
        ("pg_shadow", "pg_shadow"),
        ("pg_stat_activity", "pg_stat_activity"),
        ("pg_settings", "pg_settings"),
        ("pg_class", "pg_class"),
        # the staging and intermediate relations dbt builds into marts
        ("marts.stg_otx__pulses", "marts.stg_otx__pulses"),
        ("marts.stg_otx__indicators", "marts.stg_otx__indicators"),
        ("marts.int_indicator_freshness", "marts.int_indicator_freshness"),
        ("stg_otx__indicators", "stg_otx__indicators"),
        # quoted names compare exactly
        ('"raw"."pulses"', '"raw"."pulses"'),
        ('"marts"."stg_otx__pulses"', '"marts"."stg_otx__pulses"'),
        ('"MARTS".mart_top_pulses', '"MARTS".mart_top_pulses'),
        ('"Mart_Top_Pulses"', '"Mart_Top_Pulses"'),
        ('marts."mart_top_pulses "', 'marts."mart_top_pulses "'),
        # a catalog part
        ("ctp.marts.mart_top_pulses", "ctp.marts.mart_top_pulses"),
    ],
)
def test_table_outside_the_marts_is_refused(table: str, reason_name: str) -> None:
    assert _reason(f"select * from {table}") == f"table not allowed: {reason_name}"


def test_unicode_escaped_identifier_is_refused_as_a_parse_error() -> None:
    assert _reason(r'select * from U&"\0072aw".pulses').startswith("parse error: ")


def test_table_in_a_values_subquery_is_checked() -> None:
    # sqlglot's scope analysis yields no scope for a VALUES statement.
    assert _reason("values ((select count(*) from raw.pulses))") == "table not allowed: raw.pulses"


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        pytest.param(
            "select set_config('search_path', 'raw', true), * from marts.mart_top_pulses",
            "function not allowed: set_config",
            id="set_config",
        ),
        pytest.param(
            "with mart_top_pulses as (select * from raw.pulses) select * from mart_top_pulses",
            "CTE name shadows a mart: mart_top_pulses",
            id="cte-named-like-a-mart-reading-raw",
        ),
        pytest.param(
            "with mart_top_pulses as (select 1) select * from mart_top_pulses",
            "CTE name shadows a mart: mart_top_pulses",
            id="cte-named-like-a-mart",
        ),
        pytest.param(
            'with "mart_top_pulses" as (select 1) select * from mart_top_pulses',
            "CTE name shadows a mart: mart_top_pulses",
            id="quoted-cte-named-like-a-mart",
        ),
        pytest.param(
            "with p as (select * from raw.pulses) select * from p",
            "table not allowed: raw.pulses",
            id="cte-reading-raw",
        ),
        # Postgres folds the unquoted PG_ROLES to pg_roles, which isn't the
        # quoted CTE "PG_ROLES", so the query would read pg_catalog.pg_roles.
        pytest.param(
            'with "PG_ROLES" as (select 1) select * from PG_ROLES',
            "table not allowed: pg_roles",
            id="cte-name-that-postgres-folds-apart",
        ),
        # Without RECURSIVE, a CTE's own name in its body is the outer table.
        pytest.param(
            "with pg_roles as (select * from pg_roles) select * from pg_roles",
            "table not allowed: pg_roles",
            id="cte-body-reading-its-own-name",
        ),
        # A CTE isn't visible in the CTEs listed before it.
        pytest.param(
            "with b as (select * from pg_roles), pg_roles as (select 1) select * from b",
            "table not allowed: pg_roles",
            id="cte-read-before-it-is-defined",
        ),
    ],
)
def test_search_path_and_cte_tricks_are_refused(sql: str, reason: str) -> None:
    assert _reason(sql) == reason


# --- rules 4-6: functions, casts, strings ---------------------------------------


@pytest.mark.parametrize(
    ("call", "name"),
    [
        pytest.param("pg_sleep(1)", "pg_sleep", id="pg_sleep"),
        pytest.param("pg_sleep_for('1 second')", "pg_sleep_for", id="pg_sleep_for"),
        pytest.param("pg_sleep_until('2030-01-01')", "pg_sleep_until", id="pg_sleep_until"),
        pytest.param('"pg_sleep"(1)', "pg_sleep", id="pg_sleep-quoted"),
        pytest.param("PG_SLEEP(1)", "pg_sleep", id="pg_sleep-upper-case"),
        ("pg_read_file('x')", "pg_read_file"),
        ("pg_read_binary_file('x')", "pg_read_binary_file"),
        ("pg_ls_dir('.')", "pg_ls_dir"),
        ("pg_stat_file('x')", "pg_stat_file"),
        ("lo_import('x')", "lo_import"),
        ("lo_export(1, 'x')", "lo_export"),
        ("lo_get(1)", "lo_get"),
        ("dblink('x', 'select 1')", "dblink"),
        ("dblink_exec('x', 'select 1')", "dblink_exec"),
        ("dblink_connect('x')", "dblink_connect"),
        ("set_config('a', 'b', false)", "set_config"),
        ("current_setting('a')", "current_setting"),
        ("pg_advisory_lock(1)", "pg_advisory_lock"),
        ("pg_advisory_xact_lock(1)", "pg_advisory_xact_lock"),
        ("pg_try_advisory_lock(1)", "pg_try_advisory_lock"),
        ("pg_notify('c', 'x')", "pg_notify"),
        ("pg_terminate_backend(1)", "pg_terminate_backend"),
        ("pg_cancel_backend(1)", "pg_cancel_backend"),
        ("pg_reload_conf()", "pg_reload_conf"),
        ("query_to_xml('select 1', true, true, '')", "query_to_xml"),
        ("table_to_xml('raw.pulses', true, true, '')", "table_to_xml"),
        ("database_to_xml(true, true, '')", "database_to_xml"),
        ("cursor_to_xml('c', 1, true, true, '')", "cursor_to_xml"),
        ("ts_stat('select 1')", "ts_stat"),
        ("nextval('s')", "nextval"),
        ("setval('s', 1)", "setval"),
        ("txid_current()", "txid_current"),
    ],
)
def test_side_effect_function_is_refused(call: str, name: str) -> None:
    assert _reason(f"select {call}") == f"function not allowed: {name}"


@pytest.mark.parametrize(
    "sql",
    [
        pytest.param("select pg_catalog.pg_sleep(1)", id="pg_sleep-schema-qualified"),
        pytest.param(
            "select * from pg_catalog.jsonb_array_elements('[]')", id="allowed-name-in-from"
        ),
        pytest.param(
            "select d.key from marts.mart_data_quality q "
            "cross join lateral pg_catalog.jsonb_each_text(q.tlp_distribution) d",
            id="allowed-name-in-lateral",
        ),
    ],
)
def test_schema_qualified_function_is_refused(sql: str) -> None:
    assert _reason(sql) == "schema-qualified function calls are not allowed"


def test_function_in_from_is_refused_with_a_function_reason() -> None:
    assert _reason("select * from pg_ls_dir('.')") == "function not allowed: pg_ls_dir"


@pytest.mark.parametrize(
    ("cast", "type_name"),
    [
        ("'raw.pulses'::regclass", "regclass"),
        ("'pg_sleep'::regproc", "regproc"),
        ("1::oid", "oid"),
        ("'x'::xml", "xml"),
        ("'x'::bytea", "bytea"),
        ("'x'::marts.my_type", "marts.my_type"),
        ("'{1}'::int[]", "int[]"),
    ],
)
def test_cast_outside_the_built_in_types_is_refused(cast: str, type_name: str) -> None:
    assert _reason(f"select {cast}") == f"cast not allowed: {type_name}"


@pytest.mark.parametrize(
    "sql",
    [
        pytest.param(r"select E'\'; drop table x; --' as s", id="E-string-hiding-a-statement"),
        # sqlglot renders E'\\' as e'\', which Postgres reads as an escaped
        # quote, so the next string's contents would run as SQL.
        pytest.param(
            r"select E'\\' as a, ' , (select count(*) from raw.pulses), pg_sleep(4) -- ' as b "
            "from marts.mart_top_pulses",
            id="E-string-render-payload",
        ),
        pytest.param(
            r"select tag from marts.mart_threat_tags where tag ~ E'\\d'", id="E-string-regex"
        ),
        pytest.param(r"select U&'\0041' as s", id="U&-string"),
    ],
)
def test_escape_string_is_refused(sql: str) -> None:
    assert _reason(sql) == "escape strings are not allowed"


def test_semicolon_in_a_plain_string_with_a_backslash_counts_as_two_statements() -> None:
    # In a plain string a backslash is literal, so Postgres sees the string end
    # at the second quote and a DROP after it.
    assert (
        _reason(r"select '\'; drop table marts.mart_top_pulses; --'") == "more than one statement"
    )


def test_unclosed_comment_is_refused_as_a_parse_error() -> None:
    assert _reason("select 1 /* unclosed ; drop table x").startswith("parse error: ")


def test_sql_that_sqlglot_raises_a_plain_error_on_is_refused() -> None:
    # sqlglot raises ValueError, not a SqlglotError, on this numeric literal.
    sql = "select round(.100.0 * 2, 1) from marts.mart_cve_enrichment"
    assert _reason(sql) == "parse error: Invalid numeric literal: '0.100.0'"


# --- rule 8: rendering, cap and fixpoint ------------------------------------------


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        # date_part's unit string comes back as bare, upper-cased SQL in
        # EXTRACT(<unit> FROM x). With no identifier in it, the rendering is a
        # fixpoint as text, so only checking the rendering again catches what
        # it runs.
        pytest.param(
            "select date_part('epoch from current_date), pg_sleep(4), extract(year', created) "
            "as a from marts.mart_top_pulses",
            "rendering is not stable: function not allowed: pg_sleep",
            id="date_part-unit-pg_sleep-text-fixpoint",
        ),
        pytest.param(
            "select date_part('epoch from x), (select count(*) from raw.pulses), pg_sleep(4), "
            "extract(year', created) as a from marts.mart_top_pulses",
            "rendering is not stable: function not allowed: pg_sleep",
            id="date_part-unit-pg_sleep",
        ),
        pytest.param(
            "select date_part('epoch from x), (select count(*) from raw.pulses), "
            "extract(year', created) as a from marts.mart_top_pulses",
            "rendering is not stable: table not allowed: raw.pulses",
            id="date_part-unit-raw",
        ),
    ],
)
def test_rendering_that_reads_as_another_query_is_refused(sql: str, reason: str) -> None:
    assert _reason(sql) == reason


def test_rendering_that_changes_when_rendered_again_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fixpoint check, with a patched renderer (a test double)."""
    real_render: Callable[[exp.Expr, list[exp.Table]], str] = guard._render
    calls: list[str] = []

    def second_rendering_differs(tree: exp.Expr, tables: list[exp.Table]) -> str:
        rendering = real_render(tree, tables)
        calls.append(rendering)
        return rendering if len(calls) == 1 else rendering + " "

    monkeypatch.setattr(guard, "_render", second_rendering_differs)
    assert _reason(_GOLD[0]["sql"]) == "rendering is not stable"
    assert len(calls) == 2


@pytest.mark.parametrize(
    ("sql", "rendering"),
    [
        ("select 1 -- ; drop table x", f"SELECT 1 {_CAPPED}"),
        ("select 1 /* ; drop table x */", f"SELECT 1 {_CAPPED}"),
        ("select 1 /* a /* nested */ ; drop table x */", f"SELECT 1 {_CAPPED}"),
        ("select ';drop table x' as s", f"SELECT ';drop table x' AS s {_CAPPED}"),
        ("select $$;drop table x;$$ as s", f"SELECT ';drop table x;' AS s {_CAPPED}"),
        ("select $t$;drop$t$ as s", f"SELECT ';drop' AS s {_CAPPED}"),
        ("select 1; -- trailing comment", f"SELECT 1 {_CAPPED}"),
    ],
)
def test_hidden_text_is_accepted_and_rendered_as_data(sql: str, rendering: str) -> None:
    assert _accepted(sql).sql == rendering


@pytest.mark.parametrize(
    ("sql", "rendering", "marts"),
    [
        pytest.param(
            "with pulses as (select 1 as x) select * from pulses",
            f"WITH pulses AS (SELECT 1 AS x) SELECT * FROM pulses {_CAPPED}",
            (),
            id="cte-named-like-a-raw-table",
        ),
        pytest.param(
            "SELECT * FROM MARTS.MART_TOP_PULSES",
            f"SELECT * FROM marts.mart_top_pulses {_CAPPED}",
            ("mart_top_pulses",),
            id="unquoted-names-fold",
        ),
        pytest.param(
            "select tag from mart_threat_tags",
            f"SELECT tag FROM marts.mart_threat_tags {_CAPPED}",
            ("mart_threat_tags",),
            id="unqualified-mart",
        ),
        pytest.param(
            "select v.x from (values (1), (2)) as v(x)",
            f"SELECT v.x FROM (VALUES (1), (2)) AS v(x) {_CAPPED}",
            (),
            id="values-subquery",
        ),
        pytest.param(
            "select e.elem ->> 'type' as type from marts.brief_input b "
            "cross join lateral jsonb_array_elements(b.top_types) as e(elem)",
            "SELECT e.elem ->> 'type' AS type FROM marts.brief_input AS b "
            f"CROSS JOIN LATERAL JSONB_ARRAY_ELEMENTS(b.top_types) AS e(elem) {_CAPPED}",
            ("brief_input",),
            id="lateral-jsonb_array_elements",
        ),
        pytest.param(
            "select tag, rank() over (order by pulse_count desc) as r from marts.mart_threat_tags",
            "SELECT tag, RANK() OVER (ORDER BY pulse_count DESC) AS r "
            f"FROM marts.mart_threat_tags {_CAPPED}",
            ("mart_threat_tags",),
            id="window-function",
        ),
        pytest.param(
            "select count(*) filter (where in_kev) from marts.mart_cve_enrichment",
            f"SELECT COUNT(*) FILTER(WHERE in_kev) FROM marts.mart_cve_enrichment {_CAPPED}",
            ("mart_cve_enrichment",),
            id="filter",
        ),
        pytest.param(
            "select e.ord from marts.brief_input b "
            "cross join lateral jsonb_array_elements(b.top_types) with ordinality as e(elem, ord)",
            "SELECT e.ord FROM marts.brief_input AS b CROSS JOIN LATERAL "
            f"JSONB_ARRAY_ELEMENTS(b.top_types) WITH ORDINALITY AS e(elem, ord) {_CAPPED}",
            ("brief_input",),
            id="with-ordinality",
        ),
        pytest.param(
            "select e.value from marts.brief_input b, jsonb_array_elements(b.top_types) e",
            "SELECT e.value FROM marts.brief_input AS b, "
            f"JSONB_ARRAY_ELEMENTS(b.top_types) AS e {_CAPPED}",
            ("brief_input",),
            id="function-in-from",
        ),
    ],
)
def test_acceptance_case_is_accepted(sql: str, rendering: str, marts: tuple[str, ...]) -> None:
    checked = _accepted(sql)
    assert checked.sql == rendering
    assert checked.marts == marts


@pytest.mark.parametrize(
    ("sql", "rendering"),
    [
        pytest.param(
            "select tag from marts.mart_threat_tags limit 5000",
            f"SELECT tag FROM marts.mart_threat_tags {_CAPPED}",
            id="limit-5000",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags",
            f"SELECT tag FROM marts.mart_threat_tags {_CAPPED}",
            id="no-limit",
        ),
        # sqlglot drops LIMIT ALL as no limit (with no FROM it can't parse it).
        pytest.param(
            "select tag from marts.mart_threat_tags limit all",
            f"SELECT tag FROM marts.mart_threat_tags {_CAPPED}",
            id="limit-all",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags limit null",
            f"SELECT tag FROM marts.mart_threat_tags {_CAPPED}",
            id="limit-null",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags limit 1 + 1",
            f"SELECT tag FROM marts.mart_threat_tags {_CAPPED}",
            id="limit-expression",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags limit 10",
            "SELECT tag FROM marts.mart_threat_tags LIMIT 10",
            id="limit-10-kept",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags limit 1001 offset 5",
            "SELECT tag FROM marts.mart_threat_tags LIMIT 1001 OFFSET 5",
            id="limit-at-the-cap-kept",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags fetch first 5000 rows only",
            "SELECT tag FROM marts.mart_threat_tags FETCH FIRST 1001 ROWS ONLY",
            id="fetch-first-5000",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags fetch first 10 rows only",
            "SELECT tag FROM marts.mart_threat_tags FETCH FIRST 10 ROWS ONLY",
            id="fetch-first-10-kept",
        ),
        pytest.param(
            "select tag from mart_threat_tags union select industry from mart_top_industries",
            "SELECT tag FROM marts.mart_threat_tags UNION "
            f"SELECT industry FROM marts.mart_top_industries {_CAPPED}",
            id="set-operation",
        ),
        pytest.param("values (1), (2)", f"VALUES (1), (2) {_CAPPED}", id="values"),
        pytest.param(
            "select * from (select tag from marts.mart_threat_tags limit 5000) t",
            f"SELECT * FROM (SELECT tag FROM marts.mart_threat_tags LIMIT 5000) AS t {_CAPPED}",
            id="inner-limit-untouched",
        ),
    ],
)
def test_outer_limit_is_capped(sql: str, rendering: str) -> None:
    assert _accepted(sql).sql == rendering


@pytest.mark.parametrize(
    "sql",
    [
        # WITH TIES returns every row tied with the last, so the count caps nothing.
        pytest.param(
            "select g from generate_series(1, 5000) g order by g * 0 fetch first 1 rows with ties",
            id="with-ties-1",
        ),
        pytest.param(
            "select g from generate_series(1, 5000) g order by g * 0 "
            "fetch first 5000 rows with ties",
            id="with-ties-5000",
        ),
        pytest.param(
            "select tag from marts.mart_threat_tags fetch first 5 percent rows only", id="percent"
        ),
    ],
)
def test_fetch_with_ties_or_percent_is_refused(sql: str) -> None:
    assert _reason(sql) == "FETCH WITH TIES and PERCENT are not allowed"


def test_fetch_rows_only_is_accepted_and_capped() -> None:
    sql = "select g from generate_series(1, 5000) g order by g fetch first 5 rows only"
    assert _accepted(sql).sql == (
        "SELECT g FROM GENERATE_SERIES(1, 5000) AS g ORDER BY g FETCH FIRST 5 ROWS ONLY"
    )


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        # sqlglot keeps only the leading number and unit: Postgres reads 1 day 12:00:00.
        pytest.param(
            "select interval '1 day 12:00'",
            "rendering changes an interval literal: '1 day 12:00'",
            id="interval-time-part-dropped",
        ),
        # Postgres reads '7 days ago' as -7 days; the rendering says +7 days.
        pytest.param(
            "select now() - interval '7 days ago'",
            "rendering changes an interval literal: '7 days ago'",
            id="interval-ago-dropped",
        ),
        # An error in Postgres; the rendering would run as 1 day.
        pytest.param(
            "select interval '1 day x'",
            "rendering changes an interval literal: '1 day x'",
            id="interval-bad-text-dropped",
        ),
        # Postgres prints '%Y' as '%6'; the rendering would print the year.
        pytest.param(
            "select to_char(current_date, '%Y')",
            "rendering changes a to_char format: '%Y'",
            id="to_char-format-converted",
        ),
        # Postgres cuts '1.5' at the field (1 hour); the rendering's '1.5 HOUR' is 1:30.
        pytest.param(
            "select interval '1.5' hour",
            "rendering changes an interval literal: '1.5' hour",
            id="interval-fraction-hour",
        ),
        pytest.param(
            "select interval '0.5' day",
            "rendering changes an interval literal: '0.5' day",
            id="interval-fraction-day",
        ),
        pytest.param(
            "select interval '1.5' month",
            "rendering changes an interval literal: '1.5' month",
            id="interval-fraction-month",
        ),
        pytest.param(
            "select interval '-1.5' hour",
            "rendering changes an interval literal: '-1.5' hour",
            id="interval-negative-fraction-hour",
        ),
        # Postgres reads the field word as a limit and drops the smaller units (0 here);
        # the rendering writes it as a column alias and keeps them (36 hours).
        pytest.param(
            "select interval '36 hours' day",
            "rendering changes an interval literal: '36 hours' day",
            id="interval-units-then-day",
        ),
        pytest.param(
            "select interval '2 hours 30 minutes' hour",
            "rendering changes an interval literal: '2 hours 30 minutes' hour",
            id="interval-units-then-hour",
        ),
        pytest.param(
            "select now() - interval '1 day 12 hours' day",
            "rendering changes an interval literal: '1 day 12 hours' day",
            id="interval-units-then-day-in-arithmetic",
        ),
    ],
)
def test_literal_the_rendering_changes_is_refused(sql: str, reason: str) -> None:
    assert _reason(sql) == reason


@pytest.mark.parametrize(
    "sql",
    [
        # sqlglot converts a string anywhere in the format argument ('%Y' to 'YYYY'),
        # which the token check can't see once the string is nested.
        pytest.param("select to_char(current_date, ('%Y'))", id="parenthesized"),
        pytest.param("select to_char(current_date, '%Y'::text)", id="cast-operator"),
        pytest.param("select to_char(current_date, cast('%Y' as text))", id="cast"),
        pytest.param("select to_char(current_date, coalesce('%Y', 'x'))", id="coalesce"),
    ],
)
def test_to_char_format_that_is_not_one_string_literal_is_refused(sql: str) -> None:
    assert _reason(sql) == "to_char format must be one string literal"


@pytest.mark.parametrize(
    ("sql", "rendering"),
    [
        # A change of case alone doesn't count: Postgres reads interval text either way.
        ("select interval '7 days'", f"SELECT INTERVAL '7 DAYS' {_CAPPED}"),
        ("select interval '1 day 2 hours'", f"SELECT INTERVAL '1 day 2 hours' {_CAPPED}"),
        ("select interval '1' day", f"SELECT INTERVAL '1 DAY' {_CAPPED}"),
        ("select interval '-1' hour", f"SELECT INTERVAL '-1 HOUR' {_CAPPED}"),
        (
            "select to_char(current_date, 'YYYY-MM')",
            f"SELECT TO_CHAR(CURRENT_DATE, 'YYYY-MM') {_CAPPED}",
        ),
    ],
)
def test_literal_the_rendering_keeps_is_accepted(sql: str, rendering: str) -> None:
    assert _accepted(sql).sql == rendering


def test_attribute_notation_is_read_as_a_column() -> None:
    """Postgres runs t.pg_typeof as pg_typeof(t); the guard sees a column (module docstring)."""
    checked = _accepted("select t.pg_typeof from marts.mart_top_pulses t")
    assert checked.sql == f"SELECT t.pg_typeof FROM marts.mart_top_pulses AS t {_CAPPED}"
    assert checked.functions == ()


# --- the gold set ---------------------------------------------------------------


def _outer_limit(sql: str) -> int:
    limit = sqlglot.parse_one(sql, read="postgres").args["limit"]
    count = limit.args["count"] if isinstance(limit, exp.Fetch) else limit.expression
    return int(count.this)


@pytest.mark.parametrize("question", _GOLD, ids=[q["id"] for q in _GOLD])
def test_gold_query_passes_the_guard(question: dict[str, Any]) -> None:
    checked = _accepted(question["sql"])
    assert checked.marts == tuple(sorted(question["marts"]))
    rendered = sqlglot.parse_one(checked.sql, read="postgres")
    for table in rendered.find_all(exp.Table):
        if table.name in MART_NAMES:
            assert table.db == "marts", checked.sql
    assert _outer_limit(checked.sql) <= guard.ROW_CAP + 1
    # Stable: the rendering, checked again, renders to itself.
    assert _accepted(checked.sql).sql == checked.sql


_FIELDS = {
    "id",
    "question",
    "marts",
    "kind",
    "difficulty",
    "ordered",
    "tolerance",
    "sql",
    "checkable",
}
_REQUIRED = _FIELDS - {"tolerance"}


def test_gold_file_fields() -> None:
    assert len(_GOLD) == 30
    for q in _GOLD:
        assert _REQUIRED <= q.keys() <= _FIELDS, q["id"]
        assert re.fullmatch(r"q[0-9]{2}", q["id"])
        assert isinstance(q["question"], str) and q["question"].strip()
        assert isinstance(q["sql"], str) and q["sql"].strip()
        assert isinstance(q["checkable"], str) and q["checkable"].strip()
        assert q["marts"] and set(q["marts"]) <= MART_NAMES, q["id"]
        assert q["kind"] == ("join" if len(q["marts"]) > 1 else "single"), q["id"]
        assert q["difficulty"] in {"easy", "medium", "hard"}
        assert isinstance(q["ordered"], bool)
        tolerance = q.get("tolerance", 0)
        assert isinstance(tolerance, int | float) and tolerance >= 0, q["id"]


def test_gold_ids_are_unique_and_in_order() -> None:
    ids = [q["id"] for q in _GOLD]
    assert ids == sorted(set(ids))


def test_gold_set_covers_every_mart() -> None:
    assert {mart for q in _GOLD for mart in q["marts"]} == MART_NAMES


def test_gold_checkable_names_no_private_ids() -> None:
    for q in _GOLD:
        assert not re.search(r"\b(D|G|DM)-[0-9]", q["checkable"]), q["id"]


def test_mart_names_match_the_dbt_mart_models() -> None:
    models = {path.stem for path in (_REPO / "transform" / "models" / "marts").glob("*.sql")}
    assert models == MART_NAMES
