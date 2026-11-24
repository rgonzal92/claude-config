#!/usr/bin/env python3
"""PostToolUse hook (Claude Code): detect secrets introduced into modified files."""

from __future__ import annotations

import os
import re
from pathlib import Path

from _hook_common import emit_post_allow, emit_post_block, read_event

MAX_FILE_BYTES = 512 * 1024

HIGH_CONFIDENCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\b(?:gh[pous]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-|svcacct-)[A-Za-z0-9_-]{20,}\b")),
    ("Stripe Live Key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]

URL_CRED_RE = re.compile(
    r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s/@]+:([^@\s/]{4,})@"
)

ASSIGNMENT_RE = re.compile(
    r"""(?i)\b(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key|client[_-]?secret|db[_-]?password|password)\b\s*[:=]\s*["']([^"'\s]{10,})["']"""
)
PLACEHOLDER_SUBSTRINGS = (
    "example",
    "placeholder",
    "changeme",
    "dummy",
    "sample",
    "your_",
    "your-",
    "fake",
    "test_",
    "mock",
    "xxxx",
    "****",
    "<",
    "${",
    "redacted",
)


def _is_placeholder(val: str) -> bool:
    low = val.lower()
    if any(sub in low for sub in PLACEHOLDER_SUBSTRINGS):
        return True
    if len(set(val)) <= 2:
        return True
    return False


def _extract_content_and_path(tool_name: str, tool_input: dict) -> tuple[str, str]:
    file_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    chunks: list[str] = []

    if tool_name == "Write" and isinstance(tool_input.get("content"), str):
        chunks.append(tool_input["content"])
    elif tool_name == "Edit" and isinstance(tool_input.get("new_string"), str):
        chunks.append(tool_input["new_string"])
    elif tool_name == "MultiEdit" and isinstance(tool_input.get("edits"), list):
        for edit in tool_input["edits"]:
            if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                chunks.append(edit["new_string"])
    elif tool_name == "NotebookEdit" and isinstance(tool_input.get("new_source"), str):
        chunks.append(tool_input["new_source"])

    if not chunks and file_path:
        p = Path(os.path.expanduser(file_path))
        try:
            if p.is_file() and p.stat().st_size <= MAX_FILE_BYTES:
                chunks.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass

    return "\n".join(chunks), file_path


def scan_text(text: str) -> list[str]:
    findings: list[str] = []
    seen: set[tuple[str, int]] = set()

    for lineno, line in enumerate(text.splitlines(), start=1):
        for label, pattern in HIGH_CONFIDENCE_PATTERNS:
            if pattern.search(line) and (label, lineno) not in seen:
                seen.add((label, lineno))
                findings.append(f"{label} (line {lineno})")
        for m in URL_CRED_RE.finditer(line):
            if not _is_placeholder(m.group(1)) and ("URL Embedded Credentials", lineno) not in seen:
                seen.add(("URL Embedded Credentials", lineno))
                findings.append(f"URL Embedded Credentials (line {lineno})")
        for m in ASSIGNMENT_RE.finditer(line):
            val = m.group(2)
            if not _is_placeholder(val) and ("Hardcoded Secret", lineno) not in seen:
                seen.add(("Hardcoded Secret", lineno))
                findings.append(f"Hardcoded Secret `{m.group(1)}` (line {lineno})")

    return findings


def main() -> None:
    event = read_event()
    if not event:
        return

    text, file_path = _extract_content_and_path(event.tool_name, event.tool_input)
    if not text:
        emit_post_allow(event.agent)
        return

    findings = scan_text(text)
    if not findings:
        emit_post_allow(event.agent)
        return

    target_label = os.path.basename(file_path) if file_path else "modified content"
    summary = "; ".join(findings[:5])
    extra = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
    emit_post_block(
        event.agent,
        f"Potential secret detected in `{target_label}`: {summary}{extra}. "
        "Remove hardcoded credentials and use environment variables or secret management.",
    )


if __name__ == "__main__":
    main()
