#!/usr/bin/env python3
"""PreToolUse hook: enforce Conventional Commits and prohibit AI attribution."""

from __future__ import annotations

import os
import re
from pathlib import Path

from _hook_common import emit_pre, get_command, git_subcommand, read_event, split_shell_segments

CONVENTIONAL_RE = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: .+$"
)
HEREDOC_WRAP_RE = re.compile(
    r'^\$\(\s*cat\s+<<-?\s*[\'"]?([A-Za-z0-9_]+)[\'"]?\s*\n(.*?)\n\1\s*\)$',
    re.DOTALL,
)
ATTRIBUTION_PATTERNS = [
    (
        "Co-Authored-By AI trailer",
        re.compile(
            r"co-authored-by\s*:.*\b(claude|anthropic|openai|chatgpt|gpt|copilot|gemini|antigravity|cursor|windsurf|aider|codex|llm|ai)\b|co-authored-by\s*:.*noreply@(anthropic|openai)\.com",
            re.IGNORECASE,
        ),
    ),
    (
        "AI generated-by notice",
        re.compile(
            r"\b(generated|authored|written|created|assisted)\s+(with|by)\b.*\b(ai|llm|claude|anthropic|chatgpt|gpt|copilot|gemini|antigravity|cursor|windsurf|aider|codex)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "AI-assisted reference",
        re.compile(r"\bai[- ](assisted|generated|authored)\b", re.IGNORECASE),
    ),
    (
        "Emoji generated-by notice",
        re.compile(r"🤖\s*generated", re.IGNORECASE),
    ),
]


HEREDOC_INLINE_RE = re.compile(
    r"<<-?\s*['\"]?([A-Za-z0-9_]+)['\"]?\s*\n(.*?)\n\1(?:\s|$)",
    re.DOTALL,
)


def _unwrap_heredoc(msg: str) -> str:
    m = HEREDOC_WRAP_RE.match(msg.strip())
    return m.group(2) if m else msg


def _extract_commit_message(rest: list[str], cwd: str, raw_cmd: str) -> str | None:
    parts: list[str] = []
    i = 0
    n = len(rest)
    while i < n:
        tok = rest[i]
        if tok == "--":
            break
        if tok in ("-m", "--message") and i + 1 < n:
            parts.append(_unwrap_heredoc(rest[i + 1]))
            i += 2
            continue
        if tok.startswith("--message="):
            parts.append(_unwrap_heredoc(tok.split("=", 1)[1]))
            i += 1
            continue
        if tok.startswith("-") and not tok.startswith("--") and "m" in tok[1:]:
            # Supports combined short flags like `-am "msg"` or attached `-m"msg"`
            idx = tok.index("m")
            trailing = tok[idx + 1 :]
            if trailing:
                parts.append(_unwrap_heredoc(trailing))
                i += 1
            elif i + 1 < n:
                parts.append(_unwrap_heredoc(rest[i + 1]))
                i += 2
            else:
                i += 1
            continue
        if tok in ("-F", "--file") and i + 1 < n:
            fpath = rest[i + 1]
            i += 2
            if fpath == "-":
                hm = HEREDOC_INLINE_RE.search(raw_cmd)
                if hm:
                    parts.append(hm.group(2))
            else:
                p = Path(os.path.expanduser(fpath))
                if not p.is_absolute():
                    p = Path(cwd) / p
                if p.is_file():
                    parts.append(p.read_text(encoding="utf-8", errors="replace"))
            continue
        if tok.startswith("--file="):
            fpath = tok.split("=", 1)[1]
            if fpath == "-":
                hm = HEREDOC_INLINE_RE.search(raw_cmd)
                if hm:
                    parts.append(hm.group(2))
            else:
                p = Path(os.path.expanduser(fpath))
                if not p.is_absolute():
                    p = Path(cwd) / p
                if p.is_file():
                    parts.append(p.read_text(encoding="utf-8", errors="replace"))
            i += 1
            continue
        i += 1

    return "\n\n".join(parts) if parts else None


def _validate_message(message: str) -> str | None:
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    if not lines:
        return "Commit message is empty. Use Conventional Commits format: `type(scope): description`."

    subject = lines[0]
    if not CONVENTIONAL_RE.match(subject):
        return (
            f"Commit subject does not follow Conventional Commits: `{subject}`. "
            "Expected `type(optional-scope): description` with lowercase type "
            "(feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert)."
        )

    for label, pattern in ATTRIBUTION_PATTERNS:
        if pattern.search(message):
            return f"Commit message contains prohibited AI/agent attribution ({label}). Remove all AI attribution."

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
        sub, rest = git_subcommand(seg)
        if sub != "commit":
            continue
        message = _extract_commit_message(rest, event.cwd, cmd)
        if message is None:
            continue
        error = _validate_message(message)
        if error:
            emit_pre(event.agent, "deny", error)
            return

    emit_pre(event.agent, "allow")


if __name__ == "__main__":
    main()
