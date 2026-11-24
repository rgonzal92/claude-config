"""Shared I/O and shell/path helpers for Claude Code and Antigravity hooks."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass
from typing import Any

SHELL_TOOLS = {"Bash", "run_command"}
PATH_KEYS = (
    "file_path",
    "notebook_path",
    "path",
    "Path",
    "TargetFile",
    "AbsolutePath",
    "SearchPath",
    "DirectoryPath",
)
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
WRAPPER_NO_ARG = {"env", "command", "nohup", "nice", "time", "exec", "builtin"}
SHELL_BINS = {"sh", "bash", "zsh", "dash", "ksh"}
GIT_VALUE_FLAGS = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
}


@dataclass(frozen=True)
class HookEvent:
    agent: str  # "claude" | "antigravity"
    event_name: str
    tool_name: str
    tool_input: dict[str, Any]
    cwd: str


def read_event() -> HookEvent | None:
    raw = sys.stdin.read().strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    cwd = payload.get("cwd") or os.getcwd()
    if "toolCall" in payload and isinstance(payload["toolCall"], dict):
        tc = payload["toolCall"]
        return HookEvent(
            agent="antigravity",
            event_name=str(payload.get("hookEventName") or "PreToolUse"),
            tool_name=str(tc.get("name") or ""),
            tool_input=tc.get("args") if isinstance(tc.get("args"), dict) else {},
            cwd=str(cwd),
        )
    return HookEvent(
        agent="claude",
        event_name=str(payload.get("hook_event_name") or "PreToolUse"),
        tool_name=str(payload.get("tool_name") or ""),
        tool_input=payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {},
        cwd=str(cwd),
    )


def get_command(event: HookEvent) -> str | None:
    if event.tool_name not in SHELL_TOOLS:
        return None
    cmd = event.tool_input.get("command") or event.tool_input.get("CommandLine")
    return cmd if isinstance(cmd, str) and cmd.strip() else None


def get_file_paths(event: HookEvent) -> list[str]:
    paths: list[str] = []
    for key in PATH_KEYS:
        val = event.tool_input.get(key)
        if isinstance(val, str) and val.strip():
            paths.append(val)
    return paths


def emit_pre(agent: str, decision: str, reason: str = "") -> None:
    if agent == "antigravity":
        if decision == "allow":
            out: dict[str, Any] = {"decision": "allow"}
        elif decision == "deny":
            out = {"decision": "deny", "reason": reason}
        else:
            out = {"decision": "force_ask", "reason": reason}
        print(json.dumps(out))
        return

    if decision == "allow":
        return
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )


def emit_post_block(agent: str, reason: str) -> None:
    if agent == "antigravity":
        print("{}")
        return
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": reason,
                },
            }
        )
    )


def emit_post_allow(agent: str) -> None:
    if agent == "antigravity":
        print("{}")


def _split_raw_segments(command: str) -> list[str]:
    """Split a shell command on unquoted control operators (&&, ||, ;, |, newlines)."""
    segments: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            buf.append(ch)
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            if command[i : i + 2] in ("&&", "||"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 2
                continue
            if ch in (";", "|", "\n"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        segments.append(tail)
    return segments


def _tokenize(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def strip_wrappers(tokens: list[str]) -> list[str]:
    """Strip leading env assignments and wrapper commands (sudo, env, timeout, etc.)."""
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if ENV_ASSIGN_RE.match(tok):
            i += 1
            continue
        base = os.path.basename(tok)
        if base == "sudo":
            i += 1
            while i < n and tokens[i].startswith("-"):
                flag = tokens[i]
                i += 1
                if flag in ("-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t") and i < n:
                    i += 1
            continue
        if base == "timeout":
            i += 1
            while i < n and tokens[i].startswith("-"):
                flag = tokens[i]
                i += 1
                if flag in ("-s", "-k", "--signal", "--kill-after") and i < n:
                    i += 1
            if i < n:
                i += 1  # duration argument
            continue
        if base in WRAPPER_NO_ARG:
            i += 1
            while i < n and tokens[i].startswith("-"):
                i += 1
            continue
        break
    return tokens[i:]


def split_shell_segments(command: str, _depth: int = 0) -> list[list[str]]:
    """Return tokenized command segments, recursively expanding `sh/bash -c ...`."""
    if _depth > 3:
        return []
    result: list[list[str]] = []
    for raw_seg in _split_raw_segments(command):
        tokens = strip_wrappers(_tokenize(raw_seg))
        if not tokens:
            continue
        result.append(tokens)
        base = os.path.basename(tokens[0])
        if base in SHELL_BINS:
            for idx, tok in enumerate(tokens[1:], start=1):
                if tok in ("-c", "-lc", "-ec", "-xc") and idx + 1 < len(tokens):
                    result.extend(split_shell_segments(tokens[idx + 1], _depth + 1))
                    break
    return result


def git_subcommand(tokens: list[str]) -> tuple[str | None, list[str]]:
    """Extract the git subcommand and remaining args, skipping git global options."""
    if not tokens or os.path.basename(tokens[0]) != "git":
        return None, []
    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in GIT_VALUE_FLAGS:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return tok, tokens[i + 1 :]
    return None, []
