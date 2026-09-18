#!/usr/bin/env python3
"""Create a non-superuser application role and database for local development/tests.

The application role must NOT be a superuser and must NOT have BYPASSRLS,
otherwise PostgreSQL Row-Level Security would silently not apply.

Usage:
    python scripts/dev_db.py --admin-url postgresql://postgres:postgres@127.0.0.1:55432/postgres \
        --role asm --password asm --database asm_dev [--recreate]
"""

from __future__ import annotations

import argparse

import psycopg
from psycopg import sql


def ensure(admin_url: str, role: str, password: str, database: str, recreate: bool = False) -> None:
    with psycopg.connect(admin_url, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        if not exists:
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOCREATEROLE")
                         .format(sql.Identifier(role), sql.Literal(password)))
        if recreate:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database)))
        if not conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (database,)).fetchone():
            conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(database), sql.Identifier(role)))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--admin-url", required=True)
    p.add_argument("--role", default="asm")
    p.add_argument("--password", default="asm")
    p.add_argument("--database", default="asm_dev")
    p.add_argument("--recreate", action="store_true")
    a = p.parse_args()
    ensure(a.admin_url, a.role, a.password, a.database, a.recreate)
    print(f"ready: postgresql+psycopg://{a.role}:***@<host>/{a.database}")
