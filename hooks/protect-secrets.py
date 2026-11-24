#!/usr/bin/env python3
"""PreToolUse hook: block access to protected credentials and sensitive secret files."""

from __future__ import annotations

import os
import re
from pathlib import Path

from _hook_common import emit_pre, get_command, get_file_paths, read_event, split_shell_segments

SAFE_ENV_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.schema",
}
PROTECTED_BASENAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".credentials.json",
    "credentials.json",
    "credentials.tfrc.json",
    "secrets.yaml",
    "secrets.yml",
    ".secrets",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
}
PROTECTED_EXTS = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"}
SECRET_JSON_RE = re.compile(r"^(service[-_]?account.*|.*secret.*)\.json$", re.IGNORECASE)
HOME_PROTECTED_REL = (
    ".aws/credentials",
    ".kube/config",
    ".docker/config.json",
    ".config/gh/hosts.yml",
    ".config/glab-cli/config.yml",
    ".pi/agent/auth.json",
    ".claude/.credentials.json",
    ".terraform.d/credentials.tfrc.json",
)
HOME_PROTECTED_DIRS = (".gnupg",)


def _check_single_path(path_str: str, home_str: str) -> str | None:
    norm = os.path.normpath(path_str)
    base = os.path.basename(norm)
    lower_base = base.lower()

    if lower_base in SAFE_ENV_NAMES or lower_base.endswith(".pub"):
        return None

    if lower_base == ".env" or lower_base.startswith(".env."):
        return f"Protected environment file: {base}"

    if lower_base in PROTECTED_BASENAMES:
        return f"Protected credential/secret file: {base}"

    _, ext = os.path.splitext(lower_base)
    if ext in PROTECTED_EXTS and not lower_base.startswith("."):
        return f"Protected key/certificate file: {base}"

    if SECRET_JSON_RE.match(base):
        return f"Protected secret JSON file: {base}"

    if norm.startswith(home_str + "/.ssh/") and lower_base.startswith("id_"):
        return f"Protected SSH private key: {base}"

    for rel in HOME_PROTECTED_REL:
        if norm == os.path.join(home_str, rel):
            return f"Protected credential store: ~/{rel}"

    for rel_dir in HOME_PROTECTED_DIRS:
        target_dir = os.path.join(home_str, rel_dir)
        if norm == target_dir or norm.startswith(target_dir + "/"):
            return f"Protected keystore directory: ~/{rel_dir}"

    return None


def check_path(raw_path: str, cwd: str) -> str | None:
    if not raw_path or raw_path.startswith(("http://", "https://")):
        return None
    home_str = str(Path.home()).rstrip("/")
    expanded = os.path.expanduser(raw_path)
    full = expanded if os.path.isabs(expanded) else os.path.join(cwd, expanded)

    reason = _check_single_path(full, home_str)
    if reason:
        return reason

    try:
        real = os.path.realpath(full)
    except OSError:
        return None
    if real != os.path.normpath(full):
        return _check_single_path(real, home_str)
    return None


def _candidate_tokens_from_shell(cmd: str) -> list[str]:
    candidates: list[str] = []
    for seg in split_shell_segments(cmd):
        for tok in seg[1:]:
            cleaned = tok.lstrip("<>@")
            if not cleaned:
                continue
            if "=" in cleaned and not cleaned.startswith(("/", ".", "~")):
                _, val = cleaned.split("=", 1)
                if val:
                    candidates.append(val.lstrip("@"))
            elif not cleaned.startswith("-"):
                candidates.append(cleaned)
    return candidates


def main() -> None:
    event = read_event()
    if not event:
        return

    for path in get_file_paths(event):
        reason = check_path(path, event.cwd)
        if reason:
            emit_pre(event.agent, "deny", f"Blocked access to sensitive file ({reason}).")
            return

    cmd = get_command(event)
    if cmd:
        for tok in _candidate_tokens_from_shell(cmd):
            reason = check_path(tok, event.cwd)
            if reason:
                emit_pre(event.agent, "deny", f"Blocked shell access to sensitive file ({reason}).")
                return

    emit_pre(event.agent, "allow")


if __name__ == "__main__":
    main()
