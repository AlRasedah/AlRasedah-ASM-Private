"""SQL for Row-Level Security policies, used by migrations."""

from __future__ import annotations

TENANT_EXPR = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
BYPASS_EXPR = "current_setting('app.bypass_rls', true) = 'on'"
USER_EXPR = "NULLIF(current_setting('app.user_id', true), '')::uuid"


def tenant_isolation(table: str) -> list[str]:
    cond = f"({BYPASS_EXPR} OR tenant_id = {TENANT_EXPR})"
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS tenant_isolation ON {table}",
        f"CREATE POLICY tenant_isolation ON {table} USING {cond} WITH CHECK {cond}",
    ]


def scan_profiles_policy() -> list[str]:
    read = f"({BYPASS_EXPR} OR tenant_id IS NULL OR tenant_id = {TENANT_EXPR})"
    write = f"({BYPASS_EXPR} OR tenant_id = {TENANT_EXPR})"
    return [
        "ALTER TABLE scan_profiles ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE scan_profiles FORCE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS profiles_read ON scan_profiles",
        "DROP POLICY IF EXISTS profiles_write ON scan_profiles",
        "DROP POLICY IF EXISTS profiles_update ON scan_profiles",
        "DROP POLICY IF EXISTS profiles_delete ON scan_profiles",
        f"CREATE POLICY profiles_read ON scan_profiles FOR SELECT USING {read}",
        f"CREATE POLICY profiles_write ON scan_profiles FOR INSERT WITH CHECK {write}",
        f"CREATE POLICY profiles_update ON scan_profiles FOR UPDATE USING {write} WITH CHECK {write}",
        f"CREATE POLICY profiles_delete ON scan_profiles FOR DELETE USING {write}",
    ]


def audit_logs_policy() -> list[str]:
    read = f"({BYPASS_EXPR} OR tenant_id = {TENANT_EXPR})"
    insert = f"({BYPASS_EXPR} OR tenant_id = {TENANT_EXPR})"
    return [
        "ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS audit_read ON audit_logs",
        "DROP POLICY IF EXISTS audit_insert ON audit_logs",
        f"CREATE POLICY audit_read ON audit_logs FOR SELECT USING {read}",
        f"CREATE POLICY audit_insert ON audit_logs FOR INSERT WITH CHECK {insert}",
        # Append-only: no UPDATE/DELETE policies exist, and a trigger blocks them
        # even for sessions that bypass RLS.
        """
        CREATE OR REPLACE FUNCTION asm_audit_immutable() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'audit_logs is append-only';
        END;
        $$ LANGUAGE plpgsql
        """,
        "DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs",
        "CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION asm_audit_immutable()",
    ]


def users_policy() -> list[str]:
    # A tenant session sees only users who are members of that tenant, plus itself.
    cond = (
        f"({BYPASS_EXPR} OR id = {USER_EXPR} OR EXISTS (SELECT 1 FROM tenant_memberships m "
        f"WHERE m.user_id = users.id AND m.tenant_id = {TENANT_EXPR}))"
    )
    return [
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE users FORCE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS users_visibility ON users",
        f"CREATE POLICY users_visibility ON users USING {cond} WITH CHECK ({BYPASS_EXPR} OR id = {USER_EXPR})",
    ]


def tenants_policy() -> list[str]:
    cond = f"({BYPASS_EXPR} OR id = {TENANT_EXPR})"
    return [
        "ALTER TABLE tenants ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE tenants FORCE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS tenant_self ON tenants",
        f"CREATE POLICY tenant_self ON tenants USING {cond} WITH CHECK ({BYPASS_EXPR})",
    ]


def catalog_policy(table: str, visible: str) -> list[str]:
    """A global table every tenant may *read* where ``visible`` holds (e.g. published
    advisories), and that only system sessions — platform administration — may write."""
    read = f"({BYPASS_EXPR} OR ({visible}))"
    write = f"({BYPASS_EXPR})"
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS catalog_read ON {table}",
        f"DROP POLICY IF EXISTS catalog_write ON {table}",
        f"DROP POLICY IF EXISTS catalog_update ON {table}",
        f"DROP POLICY IF EXISTS catalog_delete ON {table}",
        f"CREATE POLICY catalog_read ON {table} FOR SELECT USING {read}",
        f"CREATE POLICY catalog_write ON {table} FOR INSERT WITH CHECK {write}",
        f"CREATE POLICY catalog_update ON {table} FOR UPDATE USING {write} WITH CHECK {write}",
        f"CREATE POLICY catalog_delete ON {table} FOR DELETE USING {write}",
    ]


def private_tables_policy(table: str) -> list[str]:
    """Tables only ever touched by system sessions (auth internals)."""
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS system_only ON {table}",
        f"CREATE POLICY system_only ON {table} USING ({BYPASS_EXPR}) WITH CHECK ({BYPASS_EXPR})",
    ]
