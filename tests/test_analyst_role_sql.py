"""sql/33_analyst_role.sql: the threat-data analyst's read-only role.

``analyst_ro`` reads the 11 mart models only, through dbt's ``+grants``. It gets
no schema-wide or default grant, so the staging and intermediate relations dbt
also builds into ``marts`` stay closed to it, and it has no USAGE on ``raw`` or
``pipeline``. The probe relations stand in for dbt's models; every test drops
the ones it made, so none is left for a later check of what ``analyst_ro`` can
read.

DB-integration (gated on NEON_DATABASE_URL, see conftest.py).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import psycopg
import pytest

from tests.conftest import SQL_DIR

_SQL_33 = SQL_DIR / "33_analyst_role.sql"

_PROBE_MART = "marts.analyst_probe_mart"
_PROBE_TABLE = "marts.analyst_probe_table"
_PROBE_VIEW = "marts.analyst_probe_stg_view"
_CREATE_PROBE = "analyst_probe_create"
_CREATE_SCHEMAS = ("marts", "raw", "pipeline", "public")


@pytest.fixture()
def cur(pg_conn: psycopg.Connection) -> Iterator[psycopg.Cursor[Any]]:
    """An owner cursor; afterwards it resets the role and drops every probe."""
    with pg_conn.cursor() as cur:
        try:
            yield cur
        finally:
            cur.execute("reset role")
            cur.execute(f"drop view if exists {_PROBE_VIEW}")
            cur.execute(f"drop table if exists {_PROBE_MART}, {_PROBE_TABLE}")
            for schema in _CREATE_SCHEMAS:
                cur.execute(f"drop table if exists {schema}.{_CREATE_PROBE}")


def _analyst_ro_can_select(cur: psycopg.Cursor[Any], relation: str) -> bool:
    cur.execute("select has_table_privilege('analyst_ro', %s, 'select')", (relation,))
    row = cur.fetchone()
    assert row is not None
    return bool(row[0])


def test_analyst_ro_is_nologin(cur: psycopg.Cursor[Any]) -> None:
    cur.execute("select rolcanlogin from pg_roles where rolname = 'analyst_ro'")
    assert cur.fetchone() == (False,)


def test_analyst_ro_has_usage_on_marts_only(cur: psycopg.Cursor[Any]) -> None:
    cur.execute(
        "select n.nspname, a.privilege_type from pg_namespace n, aclexplode(n.nspacl) a"
        " where a.grantee = 'analyst_ro'::regrole"
    )
    assert cur.fetchall() == [("marts", "USAGE")]
    for schema, expected in (("marts", True), ("raw", False), ("pipeline", False)):
        cur.execute("select has_schema_privilege('analyst_ro', %s, 'usage')", (schema,))
        assert cur.fetchone() == (expected,), schema


def test_sql33_grants_select_on_no_relation(cur: psycopg.Cursor[Any]) -> None:
    # SELECT on the marts comes from dbt's +grants only, never from sql/33.
    cur.execute(
        "select c.oid::regclass::text from pg_class c, aclexplode(c.relacl) a"
        " where a.grantee = 'analyst_ro'::regrole"
    )
    assert cur.fetchall() == []


def test_analyst_ro_has_no_default_privileges(cur: psycopg.Cursor[Any]) -> None:
    cur.execute(
        "select count(*) from pg_default_acl d, aclexplode(d.defaclacl) a"
        " where a.grantee = 'analyst_ro'::regrole"
    )
    assert cur.fetchone() == (0,)


def test_analyst_ro_has_no_privilege_on_raw_or_pipeline(cur: psycopg.Cursor[Any]) -> None:
    cur.execute(
        "select c.oid::regclass::text, c.relkind = 'S' from pg_class c"
        " join pg_namespace n on n.oid = c.relnamespace"
        " where n.nspname in ('raw', 'pipeline') and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')"
    )
    relations = dict(cur.fetchall())
    # Guards against a query that matches nothing and passes vacuously.
    assert {"raw.pulses", "raw.indicators", "pipeline.runs"} <= relations.keys()
    for relation, is_sequence in relations.items():
        if is_sequence:
            cur.execute(
                "select has_sequence_privilege('analyst_ro', %s, 'usage, select, update')",
                (relation,),
            )
        else:
            cur.execute(
                "select has_table_privilege('analyst_ro', %s,"
                " 'select, insert, update, delete, truncate, references, trigger')",
                (relation,),
            )
        assert cur.fetchone() == (False,), relation


@pytest.mark.parametrize(
    "table",
    ["raw.pulses", "raw.indicators", "pipeline.runs", "pipeline.state", "pipeline.brief_evals"],
)
def test_analyst_ro_is_denied_raw_and_pipeline_tables(cur: psycopg.Cursor[Any], table: str) -> None:
    # As the owner first: "permission denied for schema" fires before any table
    # lookup, so without this a missing or misspelled table would pass.
    cur.execute("select to_regclass(%s) is not null", (table,))
    assert cur.fetchone() == (True,), f"{table} does not exist"
    cur.execute("set role analyst_ro")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(f"select 1 from {table} limit 1")


def test_analyst_ro_reads_a_probe_mart_granted_as_dbt_grants(cur: psycopg.Cursor[Any]) -> None:
    cur.execute(f"create table {_PROBE_MART} (x int)")
    cur.execute(f"insert into {_PROBE_MART} values (1)")
    # The statement dbt's +grants issues after it builds a mart.
    cur.execute(f"grant select on {_PROBE_MART} to analyst_ro")
    cur.execute("set role analyst_ro")
    cur.execute(f"select x from {_PROBE_MART}")
    assert cur.fetchall() == [(1,)]


def test_analyst_ro_cannot_read_a_staging_view(cur: psycopg.Cursor[Any]) -> None:
    # Made by the owner in marts, as dbt makes a staging view, after sql/30's
    # default privileges: grafana_ro gets SELECT on it, analyst_ro must not.
    cur.execute(f"create view {_PROBE_VIEW} as select id from raw.pulses")
    cur.execute("select has_table_privilege('grafana_ro', %s, 'select')", (_PROBE_VIEW,))
    assert cur.fetchone() == (True,), "sql/30's default privileges didn't reach the probe"
    assert _analyst_ro_can_select(cur, _PROBE_VIEW) is False
    cur.execute("set role analyst_ro")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(f"select id from {_PROBE_VIEW}")


def test_analyst_ro_cannot_read_an_ungranted_table_in_marts(cur: psycopg.Cursor[Any]) -> None:
    # Like the incremental stg_otx__indicators: a table in marts with no +grants.
    cur.execute(f"create table {_PROBE_TABLE} as select id from raw.pulses")
    assert _analyst_ro_can_select(cur, _PROBE_TABLE) is False
    cur.execute("set role analyst_ro")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute(f"select id from {_PROBE_TABLE}")


def test_analyst_ro_cannot_create_anywhere(cur: psycopg.Cursor[Any]) -> None:
    cur.execute(
        "select nspname from pg_namespace where has_schema_privilege('analyst_ro', oid, 'create')"
    )
    assert cur.fetchall() == []
    cur.execute("select has_database_privilege('analyst_ro', current_database(), 'create')")
    assert cur.fetchone() == (False,)
    cur.execute("set role analyst_ro")
    for schema in _CREATE_SCHEMAS:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(f"create table {schema}.{_CREATE_PROBE} (x int)")


def test_sql33_rerun_on_a_populated_marts_grants_nothing(cur: psycopg.Cursor[Any]) -> None:
    # conftest runs sql/33 while marts is empty; on Neon, marts already holds
    # every dbt relation when sql/33 is applied. The probes stand in for a dbt
    # staging view and the incremental stg_otx__indicators, made by the owner
    # with sql/30's default privileges in force, before the re-run.
    cur.execute(f"create view {_PROBE_VIEW} as select id from raw.pulses")
    cur.execute(f"create table {_PROBE_TABLE} as select id from raw.pulses")
    for probe in (_PROBE_VIEW, _PROBE_TABLE):
        cur.execute("select has_table_privilege('grafana_ro', %s, 'select')", (probe,))
        assert cur.fetchone() == (True,), f"sql/30's default privileges didn't reach {probe}"
    cur.execute(_SQL_33.read_text())
    assert _analyst_ro_can_select(cur, _PROBE_VIEW) is False
    assert _analyst_ro_can_select(cur, _PROBE_TABLE) is False
    cur.execute(
        "select c.oid::regclass::text from pg_class c, aclexplode(c.relacl) a"
        " where a.grantee = 'analyst_ro'::regrole"
    )
    assert cur.fetchall() == []


@pytest.mark.parametrize("scope", ["in schema marts", ""], ids=["in_schema_marts", "global"])
def test_sql33_rerun_revokes_a_stray_default_grant(cur: psycopg.Cursor[Any], scope: str) -> None:
    try:
        cur.execute(f"alter default privileges {scope} grant select on tables to analyst_ro")
    finally:
        # The re-run under test is also the cleanup: it leaves the default
        # privileges as the session's own sql/33 run set them.
        cur.execute(_SQL_33.read_text())
    cur.execute(
        "select count(*) from pg_default_acl d, aclexplode(d.defaclacl) a"
        " where a.grantee = 'analyst_ro'::regrole"
    )
    assert cur.fetchone() == (0,)
    cur.execute(f"create view {_PROBE_VIEW} as select id from raw.pulses")
    assert _analyst_ro_can_select(cur, _PROBE_VIEW) is False
