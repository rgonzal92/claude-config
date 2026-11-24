#!/usr/bin/env python3
"""PreToolUse hook: require approval for destructive database operations."""

from __future__ import annotations

import os
import re

from _hook_common import emit_pre, get_command, read_event, split_shell_segments

ALWAYS_DESTRUCTIVE_BINS = {"dropdb", "dropuser"}
SQL_CLIS = {"psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "cqlsh", "clickhouse-client", "cockroach", "duckdb"}
MONGO_CLIS = {"mongosh", "mongo"}
REDIS_CLIS = {"redis-cli", "valkey-cli"}

SQL_DESTRUCTIVE_RE = re.compile(
    r"\b("
    r"DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|ROLE|USER|TRIGGER|FUNCTION|SEQUENCE)"
    r"|TRUNCATE\b"
    r"|DELETE\s+FROM\b"
    r"|ALTER\s+TABLE\b[^;]*\bDROP\b"
    r")",
    re.IGNORECASE,
)
SQL_UPDATE_RE = re.compile(r"\bUPDATE\s+\S+\s+SET\b", re.IGNORECASE)
MONGO_DESTRUCTIVE_RE = re.compile(r"\b(dropDatabase|deleteMany)\b|\.(drop|remove)\s*\(")
REDIS_DESTRUCTIVE_RE = re.compile(r"\b(FLUSHALL|FLUSHDB|SHUTDOWN)\b", re.IGNORECASE)


def _unwrap_runner(tokens: list[str]) -> list[str]:
    if not tokens:
        return tokens
    base = os.path.basename(tokens[0])
    if base in {"npx", "bunx"} and len(tokens) > 1:
        i = 1
        while i < len(tokens) and tokens[i].startswith("-"):
            i += 1
        return tokens[i:]
    if base in {"pnpm", "yarn", "uv", "poetry", "bundle"} and len(tokens) > 2 and tokens[1] in {"exec", "run"}:
        return tokens[2:]
    if base in {"python", "python3"} and len(tokens) > 2 and tokens[1] == "-m":
        return tokens[2:]
    return tokens


def _check_segment(raw_tokens: list[str]) -> str | None:
    tokens = _unwrap_runner(raw_tokens)
    if not tokens:
        return None
    base = os.path.basename(tokens[0])
    joined = " ".join(tokens[1:])

    if base in ALWAYS_DESTRUCTIVE_BINS:
        return f"Destructive database command (`{base}`) requires explicit user approval."

    if base == "pg_restore" and any(t in ("-c", "--clean") for t in tokens[1:]):
        return "Destructive `pg_restore --clean` requires explicit user approval."

    if base == "prisma":
        if "reset" in tokens or "--force-reset" in tokens or "--accept-data-loss" in tokens:
            return "Destructive Prisma database operation requires explicit user approval."
        if "migrate" in tokens and "deploy" in tokens:
            return "Applying production migrations (`prisma migrate deploy`) requires explicit user approval."
        return None

    if base == "drizzle-kit" and any(t in {"push", "drop"} for t in tokens[1:]):
        return f"Destructive/schema-mutating `drizzle-kit` command requires explicit user approval."

    if base == "alembic" and "downgrade" in tokens[1:]:
        return "Database migration rollback (`alembic downgrade`) requires explicit user approval."

    if base == "flyway" and any(t in {"clean", "repair"} for t in tokens[1:]):
        return "Destructive Flyway database operation requires explicit user approval."

    if base == "liquibase" and any(t in {"drop-all", "dropAll", "rollback"} for t in tokens[1:]):
        return "Destructive Liquibase database operation requires explicit user approval."

    if base in {"rails", "rake"} and any(
        t in {"db:drop", "db:reset", "db:purge", "db:migrate:reset", "db:rollback"} for t in tokens[1:]
    ):
        return "Destructive Rails database task requires explicit user approval."

    if base == "knex" and "migrate:rollback" in tokens[1:]:
        return "Database migration rollback (`knex migrate:rollback`) requires explicit user approval."

    if any(os.path.basename(t) == "manage.py" for t in tokens) and any(
        t in {"flush", "reset_db", "sqlflush"} for t in tokens
    ):
        return "Destructive Django database command requires explicit user approval."

    if base in SQL_CLIS:
        if SQL_DESTRUCTIVE_RE.search(joined):
            return f"Destructive SQL operation via `{base}` requires explicit user approval."
        if SQL_UPDATE_RE.search(joined) and not re.search(r"\bWHERE\b", joined, re.IGNORECASE):
            return f"Unfiltered SQL `UPDATE` without `WHERE` via `{base}` requires explicit user approval."
        return None

    if base in MONGO_CLIS and MONGO_DESTRUCTIVE_RE.search(joined):
        return f"Destructive MongoDB operation via `{base}` requires explicit user approval."

    if base in REDIS_CLIS and REDIS_DESTRUCTIVE_RE.search(joined):
        return f"Destructive Redis/Valkey operation via `{base}` requires explicit user approval."

    return None


def main() -> None:
    event = read_event()
    if not event:
        return
    cmd = get_command(event)
    if not cmd:
        emit_pre(event.agent, "allow")
        return

    for seg in split_shell_segments(cmd):
        reason = _check_segment(seg)
        if reason:
            emit_pre(event.agent, "ask", reason)
            return

    emit_pre(event.agent, "allow")


if __name__ == "__main__":
    main()
