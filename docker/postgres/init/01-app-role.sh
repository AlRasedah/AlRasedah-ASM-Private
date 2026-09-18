#!/bin/sh
# Runs once, on first initialization of the PostgreSQL data volume.
#
# The application connects as a dedicated role that is NOT a superuser and does
# NOT have BYPASSRLS. This is required for Row-Level Security tenant isolation
# to be enforced (superusers always bypass RLS).
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_user="$ASM_DB_USER" -v app_password="$ASM_DB_PASSWORD" -v app_db="$ASM_DB_NAME" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS',
              :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'app_db', :'app_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'app_db') \gexec
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$ASM_DB_NAME" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$ASM_DB_NAME" \
  -v app_user="$ASM_DB_USER" <<'SQL'
SELECT format('GRANT ALL ON SCHEMA public TO %I', :'app_user') \gexec
SQL
