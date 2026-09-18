"""Test configuration shared by all suites.

Environment is configured *before* any application module is imported.
Database tests need a PostgreSQL server; point ``ASM_TEST_ADMIN_URL`` at a
superuser connection (default: local test instance on port 55432). The suite
creates a dedicated non-superuser role so Row-Level Security really applies.
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault("ASM_ENV", "test")
os.environ.setdefault("ASM_SECRET_KEY", "test-secret-key-0123456789-abcdefghijklmnop")
os.environ.setdefault("ASM_SENSOR_MODE", "inline")
os.environ.setdefault("ASM_ALLOW_NON_PUBLIC_SCOPE", "true")
os.environ.setdefault("ASM_COOKIE_SECURE", "false")
os.environ.setdefault("ASM_LOG_JSON", "false")
os.environ.setdefault("ASM_STORAGE_LOCAL_PATH", tempfile.mkdtemp(prefix="asm-test-storage-"))
os.environ.setdefault("ASM_TEST_ADMIN_URL", "postgresql://postgres:postgres@127.0.0.1:55432/postgres")
os.environ.setdefault("ASM_TEST_DB_NAME", "asm_test")
os.environ.setdefault("ASM_TEST_DB_ROLE", "asm_test")
os.environ["ASM_DATABASE_URL"] = (
    f"postgresql+psycopg://{os.environ['ASM_TEST_DB_ROLE']}:{os.environ['ASM_TEST_DB_ROLE']}@"
    f"{os.environ['ASM_TEST_ADMIN_URL'].split('@', 1)[1].rsplit('/', 1)[0]}/{os.environ['ASM_TEST_DB_NAME']}"
)
