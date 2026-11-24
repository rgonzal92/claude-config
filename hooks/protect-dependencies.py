#!/usr/bin/env python3
"""PreToolUse hook: require approval for dependency installation, removal, or upgrades."""

from __future__ import annotations

import os

from _hook_common import emit_pre, get_command, read_event, split_shell_segments

NPM_MUTATE = {"install", "i", "add", "update", "up", "upgrade", "uninstall", "remove", "rm", "un", "link", "dedupe"}
PNPM_YARN_BUN_MUTATE = {"add", "update", "up", "upgrade", "remove", "rm", "uninstall"}
PIP_MUTATE = {"install", "uninstall"}
CARGO_MUTATE = {"add", "remove", "update", "install", "uninstall"}
SYS_PM_MUTATE = {
    "install",
    "upgrade",
    "dist-upgrade",
    "full-upgrade",
    "remove",
    "purge",
    "uninstall",
    "autoremove",
    "reinstall",
}


def _first_subcommand(tokens: list[str]) -> str | None:
    for tok in tokens[1:]:
        if not tok.startswith("-"):
            return tok
    return None


def _check_pacman(base: str, rest: list[str]) -> str | None:
    for tok in rest:
        if not tok.startswith("-") or tok.startswith("--"):
            continue
        flags = tok[1:]
        # Allow query (-Q*) and sync search/info (-Ss, -Si, -Sg, -Sl)
        if "Q" in flags:
            return None
        if "S" in flags and not any(c in flags for c in ("s", "i", "g", "l")):
            return f"System package install/upgrade (`{base} {tok}`) requires explicit user approval."
        if "R" in flags or "U" in flags:
            return f"System package modification (`{base} {tok}`) requires explicit user approval."
    return None


def _check_segment(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    base = os.path.basename(tokens[0])
    rest = tokens[1:]
    sub = _first_subcommand(tokens)

    if base == "npm":
        if sub in NPM_MUTATE or (sub == "audit" and "fix" in rest):
            return f"Dependency modification (`npm {sub}`) requires explicit user approval."
        return None

    if base in {"pnpm", "yarn", "bun"}:
        if sub in PNPM_YARN_BUN_MUTATE:
            return f"Dependency modification (`{base} {sub}`) requires explicit user approval."
        if sub in {"install", "i"} and not any(t in {"--frozen-lockfile", "--immutable"} for t in rest):
            return f"Dependency install (`{base} {sub}`) requires explicit user approval."
        return None

    if base in {"pip", "pip3"} and sub in PIP_MUTATE:
        return f"Python dependency modification (`{base} {sub}`) requires explicit user approval."

    if base in {"python", "python3"} and len(tokens) >= 4 and tokens[1] == "-m" and tokens[2] == "pip":
        pip_sub = _first_subcommand(tokens[2:])
        if pip_sub in PIP_MUTATE:
            return f"Python dependency modification (`{base} -m pip {pip_sub}`) requires explicit user approval."
        return None

    if base == "uv":
        if sub in {"add", "remove"}:
            return f"Python dependency modification (`uv {sub}`) requires explicit user approval."
        if sub == "pip":
            uv_pip_sub = _first_subcommand(rest[rest.index("pip") :])
            if uv_pip_sub in PIP_MUTATE:
                return f"Python dependency modification (`uv pip {uv_pip_sub}`) requires explicit user approval."
        if sub == "tool":
            uv_tool_sub = _first_subcommand(rest[rest.index("tool") :])
            if uv_tool_sub in {"install", "upgrade", "uninstall"}:
                return f"Tool installation (`uv tool {uv_tool_sub}`) requires explicit user approval."
        if sub == "lock" and any(t in {"-U", "--upgrade"} or t.startswith("--upgrade-package") for t in rest):
            return "Lockfile upgrade (`uv lock --upgrade`) requires explicit user approval."
        return None

    if base in {"poetry", "pipenv"} and sub in {"add", "remove", "update", "install", "uninstall"}:
        return f"Python dependency modification (`{base} {sub}`) requires explicit user approval."

    if base == "cargo" and sub in CARGO_MUTATE:
        return f"Rust dependency modification (`cargo {sub}`) requires explicit user approval."

    if base == "go":
        if sub in {"get", "install"}:
            return f"Go dependency modification (`go {sub}`) requires explicit user approval."
        if sub == "mod" and len(rest) > 1 and rest[1] == "edit":
            return "Go module modification (`go mod edit`) requires explicit user approval."
        return None

    if base == "dotnet" and sub in {"add", "remove"} and "package" in rest:
        return f".NET package modification (`dotnet {sub} package`) requires explicit user approval."

    if base in {"bundle", "gem"} and sub in {"add", "update", "install", "uninstall"}:
        return f"Ruby dependency modification (`{base} {sub}`) requires explicit user approval."

    if base in {"pacman", "paru", "yay"}:
        return _check_pacman(base, rest)

    if base in {"apt", "apt-get", "dnf", "yum", "brew"} and sub in SYS_PM_MUTATE:
        return f"System package modification (`{base} {sub}`) requires explicit user approval."

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
